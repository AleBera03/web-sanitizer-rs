//! Sub-resource references: which attributes name one, and how the sanitised
//! document is pointed at the local copies afterwards.
//!
//! Extraction happens in the sanitising pass, on elements that survived every
//! rule, so a `<script>` that was removed or an `href` already rewritten to the
//! placeholder never becomes a request. Only the reference *strings* are
//! collected here; resolving them against the document base and deciding
//! whether to fetch them belongs to the engine, which owns the budgets.
//!
//! Rewriting is a second pass over the sanitised bytes, because the local name
//! of an asset is only known once it has been fetched and sanitised. Matching is
//! by the literal attribute value, which is exactly what the first pass saw.

use std::cell::RefCell;
use std::collections::HashMap;

use lol_html::html_content::Element;
use lol_html::{HandlerTypes, HtmlRewriter, Settings, element};

use crate::policy::SubresourceType;

/// One reference as written in the document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// Attribute value verbatim, the key the rewrite pass matches on.
    pub raw: String,
    /// What the referencing element claims it is. The *sniffed* type of the
    /// body decides in the end; this only fills the gap for bodies that no
    /// magic-byte table can recognise, like CSS and JavaScript.
    pub kind: SubresourceType,
}

/// Collect the references of one element, and remember a `<base href>`.
pub(super) fn collect<H: HandlerTypes>(
    el: &Element<'_, '_, H>,
    out: &RefCell<Vec<Reference>>,
    base: &RefCell<Option<String>>,
) {
    let tag = el.tag_name();
    match tag.as_str() {
        "base" => {
            // the first `<base href>` wins, as in the HTML standard
            if let Some(href) = el.get_attribute("href")
                && base.borrow().is_none()
            {
                *base.borrow_mut() = Some(href);
            }
        }
        "link" if is_stylesheet(el) => push(out, el.get_attribute("href"), SubresourceType::Css),
        "script" => push(out, el.get_attribute("src"), SubresourceType::Js),
        "img" => push(out, el.get_attribute("src"), SubresourceType::Image),
        "source" => {
            push(out, el.get_attribute("src"), SubresourceType::Image);
            for candidate in srcset_urls(&el.get_attribute("srcset").unwrap_or_default()) {
                push(out, Some(candidate), SubresourceType::Image);
            }
        }
        _ => {}
    }
}

fn push(out: &RefCell<Vec<Reference>>, raw: Option<String>, kind: SubresourceType) {
    let Some(raw) = raw else { return };
    let raw = raw.trim().to_string();
    if raw.is_empty() {
        return;
    }
    out.borrow_mut().push(Reference { raw, kind });
}

/// `rel` is a space-separated set of keywords, matched case-insensitively.
fn is_stylesheet<H: HandlerTypes>(el: &Element<'_, '_, H>) -> bool {
    el.get_attribute("rel").is_some_and(|rel| {
        rel.split_whitespace()
            .any(|kw| kw.eq_ignore_ascii_case("stylesheet"))
    })
}

/// URLs of a `srcset` candidate list. Each candidate is a URL optionally
/// followed by a width or density descriptor.
fn srcset_urls(value: &str) -> Vec<String> {
    value
        .split(',')
        .filter_map(|candidate| candidate.split_whitespace().next())
        .filter(|url| !url.is_empty())
        .map(String::from)
        .collect()
}

/// Rebuild a `srcset`, substituting the URLs the map knows and keeping every
/// descriptor untouched.
fn rewrite_srcset(value: &str, map: &HashMap<String, String>) -> String {
    value
        .split(',')
        .map(|candidate| {
            let trimmed = candidate.trim();
            match trimmed.split_once(char::is_whitespace) {
                Some((url, descriptor)) => match map.get(url) {
                    Some(local) => format!("{local} {}", descriptor.trim()),
                    None => trimmed.to_string(),
                },
                None => map
                    .get(trimmed)
                    .cloned()
                    .unwrap_or_else(|| trimmed.to_string()),
            }
        })
        .filter(|candidate| !candidate.is_empty())
        .collect::<Vec<String>>()
        .join(", ")
}

/// Point the sanitised document at the local sanitised copies (`rewrite_refs`).
///
/// Keys are the reference strings the sanitising pass reported; anything not in
/// the map — a sub-resource that was refused, or one nobody fetched — keeps the
/// value the sanitiser left it with.
pub fn rewrite_references(input: &[u8], map: &HashMap<String, String>) -> Vec<u8> {
    if map.is_empty() {
        return input.to_vec();
    }
    let mut output: Vec<u8> = Vec::with_capacity(input.len());
    let result = {
        let mut rewriter = HtmlRewriter::new(
            Settings {
                element_content_handlers: vec![element!("link, script, img, source", |el| {
                    rewrite_element(el, map);
                    Ok(())
                })],
                ..Settings::default()
            },
            |c: &[u8]| output.extend_from_slice(c),
        );
        match rewriter.write(input) {
            Ok(()) => rewriter.end(),
            Err(e) => Err(e),
        }
    };
    // the bytes were already sanitised: a rewriter failure here costs the
    // reference rewriting, never the sanitisation
    match result {
        Ok(()) => output,
        Err(_) => input.to_vec(),
    }
}

fn rewrite_element<H: HandlerTypes>(el: &mut Element<'_, '_, H>, map: &HashMap<String, String>) {
    for name in ["href", "src"] {
        if let Some(value) = el.get_attribute(name)
            && let Some(local) = map.get(value.trim())
        {
            let _ = el.set_attribute(name, local);
        }
    }
    if let Some(srcset) = el.get_attribute("srcset") {
        let rewritten = rewrite_srcset(&srcset, map);
        if rewritten != srcset {
            let _ = el.set_attribute("srcset", &rewritten);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::html::tests_support::sanitize_default;

    fn references(html: &str) -> Vec<Reference> {
        sanitize_default(html).references
    }

    fn raws(html: &str) -> Vec<String> {
        references(html).into_iter().map(|r| r.raw).collect()
    }

    // extraction

    #[test]
    fn the_four_reference_shapes_are_extracted_with_their_kind() {
        let html = concat!(
            r#"<link rel="stylesheet" href="/a.css">"#,
            r#"<img src="/b.png">"#,
            r#"<source src="/c.png">"#,
            r#"<source srcset="/d.png 1x, /e.png 2x">"#,
        );
        let refs = references(html);
        assert_eq!(
            refs,
            [
                Reference {
                    raw: "/a.css".into(),
                    kind: SubresourceType::Css
                },
                Reference {
                    raw: "/b.png".into(),
                    kind: SubresourceType::Image
                },
                Reference {
                    raw: "/c.png".into(),
                    kind: SubresourceType::Image
                },
                Reference {
                    raw: "/d.png".into(),
                    kind: SubresourceType::Image
                },
                Reference {
                    raw: "/e.png".into(),
                    kind: SubresourceType::Image
                },
            ]
        );
    }

    #[test]
    fn an_allow_listed_script_src_is_a_js_reference() {
        use crate::policy::HtmlRules;
        let rules = HtmlRules {
            script_allowlist: vec!["https://cdn.example".to_string()],
            ..HtmlRules::default()
        };
        let outcome = crate::html::tests_support::sanitize_with(
            r#"<script src="https://cdn.example/lib.js"></script>"#,
            &rules,
        );
        assert_eq!(
            outcome.references,
            [Reference {
                raw: "https://cdn.example/lib.js".into(),
                kind: SubresourceType::Js
            }]
        );
    }

    #[test]
    fn a_removed_script_leaves_no_reference() {
        // the element did not survive, so there is nothing to fetch
        assert!(raws(r#"<script src="https://evil.example/x.js"></script>"#).is_empty());
    }

    #[test]
    fn a_neutralised_url_is_not_a_reference_to_fetch() {
        // the dangerous-scheme rule already rewrote it to the placeholder
        assert_eq!(raws(r#"<img src="javascript:alert(1)">"#), ["#blocked"]);
    }

    #[test]
    fn a_link_that_is_not_a_stylesheet_is_ignored() {
        assert!(raws(r#"<link rel="icon" href="/favicon.ico">"#).is_empty());
        assert!(raws(r#"<link href="/x.css">"#).is_empty());
        // the keyword may sit in a set, in any case
        assert_eq!(
            raws(r#"<link rel="alternate StyleSheet" href="/x.css">"#),
            ["/x.css"]
        );
    }

    #[test]
    fn empty_and_whitespace_values_are_not_references() {
        assert!(raws(r#"<img src="">"#).is_empty());
        assert!(raws(r#"<img src="   ">"#).is_empty());
        assert!(raws(r#"<source srcset=" , ">"#).is_empty());
    }

    #[test]
    fn the_first_base_href_wins() {
        let outcome = sanitize_default(
            r#"<base href="http://a.test/dir/"><base href="http://b.test/"><img src="x.png">"#,
        );
        assert_eq!(outcome.base.as_deref(), Some("http://a.test/dir/"));
    }

    #[test]
    fn a_document_without_base_reports_none() {
        assert_eq!(sanitize_default("<img src=\"x.png\">").base, None);
    }

    // srcset parsing

    #[test]
    fn srcset_candidates_keep_only_their_url() {
        assert_eq!(srcset_urls("/a.png 1x, /b.png 2x"), ["/a.png", "/b.png"]);
        assert_eq!(srcset_urls("/a.png"), ["/a.png"]);
        assert_eq!(srcset_urls("  /a.png   480w  "), ["/a.png"]);
        assert!(srcset_urls("").is_empty());
        assert!(srcset_urls(" , , ").is_empty());
    }

    // rewriting

    #[test]
    fn known_references_are_pointed_at_their_local_copy() {
        let map = HashMap::from([
            (
                "/a.css".to_string(),
                "0-page.html.assets/asset-0.css".to_string(),
            ),
            (
                "/b.png".to_string(),
                "0-page.html.assets/asset-1.png".to_string(),
            ),
        ]);
        let html = r#"<link rel="stylesheet" href="/a.css"><img src="/b.png"><img src="/c.gif">"#;
        let out = String::from_utf8(rewrite_references(html.as_bytes(), &map)).unwrap();
        assert!(out.contains(r#"href="0-page.html.assets/asset-0.css""#));
        assert!(out.contains(r#"src="0-page.html.assets/asset-1.png""#));
        // untouched: nobody fetched it
        assert!(out.contains(r#"src="/c.gif""#));
    }

    #[test]
    fn srcset_is_rewritten_candidate_by_candidate_keeping_descriptors() {
        let map = HashMap::from([("/d.png".to_string(), "assets/asset-0.png".to_string())]);
        let html = r#"<source srcset="/d.png 1x, /e.png 2x">"#;
        let out = String::from_utf8(rewrite_references(html.as_bytes(), &map)).unwrap();
        assert!(out.contains("assets/asset-0.png 1x"), "{out}");
        assert!(out.contains("/e.png 2x"), "{out}");
    }

    #[test]
    fn an_empty_map_returns_the_document_byte_identical() {
        let html = r#"<img src="/b.png">"#;
        let out = rewrite_references(html.as_bytes(), &HashMap::new());
        assert_eq!(out, html.as_bytes());
    }

    #[test]
    fn rewriting_never_touches_other_elements() {
        let map = HashMap::from([("/x".to_string(), "local".to_string())]);
        let html = r#"<a href="/x">link</a><form action="/x"></form>"#;
        let out = String::from_utf8(rewrite_references(html.as_bytes(), &map)).unwrap();
        assert_eq!(out, html);
    }

    #[test]
    fn malformed_input_does_not_panic_while_rewriting() {
        let map = HashMap::from([("/x".to_string(), "local".to_string())]);
        let _ = rewrite_references(b"<img src=/x <<< <script", &map);
    }
}
