//! HTML structural sanitisation on `lol_html`.
//!
//! A single streaming pass over the byte stream applies five rules, each
//! reporting a [`SanitisationAction`] with an exact source `location` (byte
//! offset from `lol_html`, line derived from newline positions):
//!
//! | Rule | rule_id | default action |
//! |---|---|---|
//! | disallowed `<script>` | `html.script.disallowed` | remove |
//! | inline `on*` handlers | `html.attr.event_handler` | remove |
//! | `javascript:`/`data:` URLs | `html.attr.dangerous_scheme` | rewrite |
//! | disallowed frame/object | `html.frame.disallowed` | placeholder |
//! | `<meta http-equiv=refresh>` | `html.meta.refresh` | remove |
//!
//! Why `lol_html` and not a DOM: it is a streaming tokenizer, so a `<script>`
//! split across a read boundary is still caught and memory stays bounded.
//! We feed raw bytes (never `rewrite_str`) so malformed
//! or non-UTF-8 input degrades gracefully instead of panicking.
//!
//!
//!
//! URL block-list / homograph inspection runs on the URL-bearing attributes of surviving elements
//! and delegates classification to [`crate::urlcheck::UrlChecker`], mapping the
//! verdict to the URL policy action:
//!
//! | Rule | rule_id | category |
//! |---|---|---|
//! | host on a block-list | `url.blocklist` | `blocklist` |
//! | homograph of protected domain | `url.homograph` | `homograph` |
//! | `xn--` IDN host (report) | `url.idn` | `idn_url` |
//! | control-char / host-split | `url.malformed` | `malformed` |

mod entity;

use std::cell::{Cell, RefCell};

use lol_html::html_content::{ContentType, Element};
use lol_html::{HandlerTypes, HtmlRewriter, Settings, element};

use crate::policy::{Action, HtmlRules};
use crate::report::{Location, MAX_FRAGMENT_BYTES, SanitisationAction, truncate_fragment};
use crate::urlcheck::{UrlChecker, Verdict};

// CONSTANTS
const CATEGORY_XSS: &str = "xss";
/// Attributes url correlated.
const HTML_ATTRIBUTES: &[&str] = &["href", "src", "action", "formaction", "data", "poster"];

/// Result of sanitising one HTML document.
pub struct HtmlOutcome {
    /// Rewritten bytes. Meaningless (and to be discarded by the caller) when
    /// [`refused`](Self::refused) is set.
    pub output: Vec<u8>,
    /// Every rule that fired, in document order.
    pub actions: Vec<SanitisationAction>,
    /// A rule whose policy action is `refuse` fired, or the rewriter failed:
    /// the engine (step 8) turns this into a `refused` input status.
    pub refused: bool,
}

/// sanitize `input` as HTML under `rules`, returning the rewritten bytes and a
/// report action per transformation. Never panics on hostile input: a rewriter
/// error is treated as a refusal rather than emitting unsanitized bytes.
pub fn sanitize_html(input: &[u8], rules: &HtmlRules, url: &UrlChecker) -> HtmlOutcome {
    let newlines: Vec<usize> = input
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'\n')
        .map(|(i, _)| i)
        .collect();
    let ctx = Ctx {
        rules,
        url,
        input,
        newlines: &newlines,
        actions: RefCell::new(Vec::new()),
        refused: Cell::new(false),
    };

    let mut output: Vec<u8> = Vec::with_capacity(input.len());
    let result = {
        let mut rewriter = HtmlRewriter::new(
            Settings {
                element_content_handlers: vec![element!("*", |el| {
                    ctx.handle(el);
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
        // `rewriter` is dropped here, releasing its borrows of `output`/`ctx`.
    };

    if result.is_err() {
        // refuse rather than leak bytes
        return HtmlOutcome {
            output: Vec::new(),
            actions: ctx.actions.into_inner(),
            refused: true,
        };
    }
    HtmlOutcome {
        output,
        actions: ctx.actions.into_inner(),
        refused: ctx.refused.get(),
    }
}

/// Per-document handler state. Interior mutability lets the single `lol_html`
/// element closure (which borrows `&Ctx`) push actions and flag refusals. It contains
/// a interiorly mutable set of [`SanitisationAction`]
struct Ctx<'a> {
    rules: &'a HtmlRules,
    url: &'a UrlChecker<'a>,
    input: &'a [u8],
    newlines: &'a [usize],
    actions: RefCell<Vec<SanitisationAction>>,
    refused: Cell<bool>,
}

impl Ctx<'_> {
    /// Dispatch one element: removal/replacement rules first (they consume the
    /// element), then attribute-level cleaning on survivors.
    fn handle<H: HandlerTypes>(&self, el: &mut Element<'_, '_, H>) {
        let tag = el.tag_name();
        let consumed = match tag.as_str() {
            "script" => self.script_rule(el),
            "iframe" | "object" | "embed" => self.frame_rule(el, &tag),
            "meta" => self.meta_refresh_rule(el),
            _ => false,
        };
        if consumed {
            return; // element was removed or replaced; nothing left to clean
        }
        self.strip_event_handlers(el);
        self.neutralise_dangerous_schemes(el);
        self.url_check(el);
    }

    /// Remove a `<script>` unless its `src` origin is allow-listed. An
    /// inline script (no `src`) has no origin and is never allow-listed.
    fn script_rule<H: HandlerTypes>(&self, el: &mut Element<'_, '_, H>) -> bool {
        let action = self.rules.action_script;
        let allowed = action == Action::Allow
            || el
                .get_attribute("src")
                .is_some_and(|src| origin_allowed(&src, &self.rules.script_allowlist));
        if allowed {
            return false;
        }
        let location = self.location(el);
        let original = self.element_fragment(el);
        let replacement = self.apply_element_action(el, action);
        self.record(SanitisationAction {
            rule_id: "html.script.disallowed".to_string(),
            category: CATEGORY_XSS.to_string(),
            location,
            original,
            action,
            replacement,
        });
        true
    }

    /// replace `<iframe>`/`<object>`/`<embed>` whose target origin is not
    /// allow-listed with an inert placeholder element.
    fn frame_rule<H: HandlerTypes>(&self, el: &mut Element<'_, '_, H>, tag: &str) -> bool {
        let action = self.rules.action_frame;
        // `<object>` carries its target in `data`; the others use `src`.
        let target_attr = if tag == "object" { "data" } else { "src" };
        let allowed = action == Action::Allow
            || el
                .get_attribute(target_attr)
                .is_some_and(|t| origin_allowed(&t, &self.rules.frame_origin_allowlist));
        if allowed {
            return false;
        }
        let location = self.location(el);
        let original = self.element_fragment(el);
        let replacement = self.apply_element_action(el, action);
        self.record(SanitisationAction {
            rule_id: "html.frame.disallowed".to_string(),
            category: CATEGORY_XSS.to_string(),
            location,
            original,
            action,
            replacement,
        });
        true
    }

    /// remove `<meta http-equiv="refresh">` (case-insensitive).
    fn meta_refresh_rule<H: HandlerTypes>(&self, el: &mut Element<'_, '_, H>) -> bool {
        let is_refresh = el
            .get_attribute("http-equiv")
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("refresh"));
        if !is_refresh {
            return false;
        }
        let action = self.rules.action_meta_refresh;
        if action == Action::Allow {
            return false;
        }
        let location = self.location(el);
        let original = self.element_fragment(el);
        let replacement = self.apply_element_action(el, action);
        self.record(SanitisationAction {
            rule_id: "html.meta.refresh".to_string(),
            category: CATEGORY_XSS.to_string(),
            location,
            original,
            action,
            replacement,
        });
        true
    }

    /// Remove every attribute whose name begins with `on` (prefix match,
    /// not an enumerated list — the whole `on*` event-handler space).
    fn strip_event_handlers<H: HandlerTypes>(&self, el: &mut Element<'_, '_, H>) {
        let action = self.rules.action_event_handler;
        if action == Action::Allow {
            return;
        }
        let handlers: Vec<String> = el
            .attributes()
            .iter()
            .map(|a| a.name())
            .filter(|n| n.get(..2).is_some_and(|p| p.eq_ignore_ascii_case("on")))
            .collect();
        for name in handlers {
            let value = el.get_attribute(&name).unwrap_or_default();
            let location = self.location(el);
            let original = attr_fragment(&name, &value);
            el.remove_attribute(&name);
            if action == Action::Refuse {
                self.refused.set(true);
            }
            self.record(SanitisationAction {
                rule_id: "html.attr.event_handler".to_string(),
                category: CATEGORY_XSS.to_string(),
                location,
                original,
                action,
                replacement: None,
            });
        }
    }

    /// Neutralise `javascript:`/`data:` schemes in `href`/`src`/`action`
    /// after entity-decoding and control-char stripping.
    fn neutralise_dangerous_schemes<H: HandlerTypes>(&self, el: &mut Element<'_, '_, H>) {
        let action = self.rules.action_dangerous_scheme;
        if action == Action::Allow {
            return;
        }
        for name in ["href", "src", "action"] {
            let Some(value) = el.get_attribute(name) else {
                continue;
            };
            if !entity::is_dangerous_scheme(&value) {
                continue;
            }
            let location = self.location(el);
            let original = attr_fragment(name, &value);
            let neutralised_url = self.url.rules().placeholder_url.clone();
            let replacement = match action {
                Action::Remove => {
                    el.remove_attribute(name);
                    None
                }
                // Rewrite/Placeholder/Refuse all defang the URL in place; refuse
                // additionally flags the whole input for the engine.
                _ => {
                    let _ = el.set_attribute(name, neutralised_url.as_str());
                    if action == Action::Refuse {
                        self.refused.set(true);
                    }
                    Some(neutralised_url)
                }
            };
            self.record(SanitisationAction {
                rule_id: "html.attr.dangerous_scheme".to_string(),
                category: CATEGORY_XSS.to_string(),
                location,
                original,
                action,
                replacement,
            });
        }
    }

    /// Inspect every URL-bearing attribute of a surviving
    /// element and, per the [`UrlChecker`] verdict, apply the URL policy. Runs
    /// after scheme neutralisation, so a `javascript:` value already rewritten
    /// to `#blocked` parses as a hostless relative ref and is left alone here.
    fn url_check<H: HandlerTypes>(&self, el: &mut Element<'_, '_, H>) {
        let rules = self.url.rules();
        for name in HTML_ATTRIBUTES {
            let Some(value) = el.get_attribute(name) else {
                continue;
            };
            let (rule_id, category, action) = match self.url.check(&value) {
                Verdict::Clean => continue,
                Verdict::Blocked => ("url.blocklist", "blocklist", rules.action_blocked),
                Verdict::Homograph => ("url.homograph", "homograph", rules.action_homograph),
                Verdict::Idn => ("url.idn", "idn_url", Action::Allow),
                Verdict::Malformed => ("url.malformed", "malformed", rules.action_blocked),
            };
            let location = self.location(el);
            let original = attr_fragment(name, &value);
            let replacement = self.apply_url_action(el, name, action, &rules.placeholder_url);
            self.record(SanitisationAction {
                rule_id: rule_id.to_string(),
                category: category.to_string(),
                location,
                original,
                action,
                replacement,
            });
        }
    }

    /// Apply an attribute-level URL action, returning the recorded replacement.
    /// `remove` drops the attribute; `rewrite`/`placeholder`/`refuse` set it to
    /// the configured placeholder URL (refuse also flags the input); `allow`
    /// leaves it untouched (report-only).
    fn apply_url_action<H: HandlerTypes>(
        &self,
        el: &mut Element<'_, '_, H>,
        name: &str,
        action: Action,
        placeholder: &str,
    ) -> Option<String> {
        match action {
            Action::Allow => None,
            Action::Remove => {
                el.remove_attribute(name);
                None
            }
            _ => {
                let _ = el.set_attribute(name, placeholder);
                if action == Action::Refuse {
                    self.refused.set(true);
                }
                Some(placeholder.to_string())
            }
        }
    }

    /// Apply an element-level action, returning the replacement string recorded
    /// in the report (`None` when the element is simply removed).
    fn apply_element_action<H: HandlerTypes>(
        &self,
        el: &mut Element<'_, '_, H>,
        action: Action,
    ) -> Option<String> {
        match action {
            Action::Placeholder => {
                let pf = self.rules.placeholder_frame.clone();
                el.replace(pf.as_str(), ContentType::Html);
                Some(pf)
            }
            Action::Refuse => {
                el.remove();
                self.refused.set(true);
                None
            }
            // Remove, and Rewrite (no meaningful in-place rewrite of a whole
            // element), both strip it.
            Action::Remove | Action::Rewrite => {
                el.remove();
                None
            }
            Action::Allow => None,
        }
    }

    fn record(&self, action: SanitisationAction) {
        self.actions.borrow_mut().push(action);
    }

    /// Source location of an element's start tag: byte offset straight from
    /// `lol_html`, line derived by counting preceding newlines.
    fn location<H: HandlerTypes>(&self, el: &Element<'_, '_, H>) -> Location {
        let byte_offset = el.source_location().bytes().start;
        let line = self.newlines.partition_point(|&p| p < byte_offset) as u64 + 1;
        Location {
            line,
            byte_offset: byte_offset as u64,
        }
    }

    /// Exact source bytes of an element's start tag, truncated for the report.
    fn element_fragment<H: HandlerTypes>(&self, el: &Element<'_, '_, H>) -> String {
        let raw = self.input.get(el.source_location().bytes()).unwrap_or(&[]);
        let head = &raw[..raw.len().min(MAX_FRAGMENT_BYTES)];
        truncate_fragment(&String::from_utf8_lossy(head), MAX_FRAGMENT_BYTES)
    }
}

/// Reconstruct an `name="value"` fragment for the report, truncated to the
/// action-fragment budget.
fn attr_fragment(name: &str, value: &str) -> String {
    truncate_fragment(&format!("{name}=\"{value}\""), MAX_FRAGMENT_BYTES)
}

/// True if `url_str` parses to an absolute URL whose origin (or bare host) is
/// on `allowlist`. An empty allow-list allows nothing; a relative/malformed
/// URL is never allow-listed.
fn origin_allowed(url_str: &str, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return false;
    }
    match url::Url::parse(url_str) {
        Ok(u) => {
            let origin = u.origin().ascii_serialization();
            allowlist
                .iter()
                .any(|a| a == &origin || Some(a.as_str()) == u.host_str())
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use super::*;
    use crate::policy::UrlRules;
    use crate::policy::blockset::BlockSet;
    use crate::policy::protectedset::SkeletonSet;
    use crate::tests_helper::set_from::SetFrom;
    use crate::urlcheck::cache::VerdictCache;

    static EMPTY_BLOCKSET: LazyLock<BlockSet> = LazyLock::new(BlockSet::default);
    static EMPTY_SKELETONSET: LazyLock<SkeletonSet> = LazyLock::new(SkeletonSet::default);
    static DEFAULT_VERDICTCACHE: LazyLock<VerdictCache> = LazyLock::new(VerdictCache::default);
    static DEFAULT_RULES: LazyLock<UrlRules> = LazyLock::new(UrlRules::default);

    const FRAME_PLACEHOLDER: &str = "<div class=\"sanitized-placeholder\"></div>";

    /// A URL checker that never fires: empty block-list, no protected domains.
    fn no_url_checker() -> UrlChecker<'static> {
        UrlChecker::new(&EMPTY_BLOCKSET, &EMPTY_SKELETONSET, &DEFAULT_RULES)
    }

    fn run(html: &str) -> HtmlOutcome {
        sanitize_html(html.as_bytes(), &HtmlRules::default(), &no_url_checker())
    }

    fn run_with(html: &str, rules: &HtmlRules) -> HtmlOutcome {
        sanitize_html(html.as_bytes(), rules, &no_url_checker())
    }

    fn out(o: &HtmlOutcome) -> String {
        String::from_utf8(o.output.clone()).unwrap()
    }

    // SCRIPT

    #[test]
    fn inline_script_is_removed_and_reported() {
        let o = run("<p>hi</p><script>alert(1)</script><p>bye</p>");
        assert!(!out(&o).contains("alert"));
        assert!(!out(&o).contains("<script"));
        assert_eq!(o.actions.len(), 1);
        let a = &o.actions[0];
        assert_eq!(a.rule_id, "html.script.disallowed");
        assert_eq!(a.category, "xss");
        assert_eq!(a.action, Action::Remove);
        assert!(a.original.contains("<script"));
        assert!(!o.refused);
    }

    #[test]
    fn script_src_off_allowlist_is_removed() {
        let o = run(r#"<script src="https://evil.example/x.js"></script>"#);
        assert!(!out(&o).contains("<script"));
        assert!(!out(&o).contains("</script>"));
        assert_eq!(o.actions.len(), 1);
    }

    #[test]
    fn script_src_on_allowlist_survives() {
        let rules = HtmlRules {
            script_allowlist: vec!["https://cdn.example".to_string()],
            ..Default::default()
        };
        let o = run_with(
            r#"<script src="https://cdn.example/lib.js"></script>"#,
            &rules,
        );
        assert!(out(&o).contains("cdn.example"));
        assert!(o.actions.is_empty());
    }

    #[test]
    fn script_location_offset_and_line_are_exact() {
        // Byte offset of `<script>` on line 2.
        let html = "<html>\n  <script>alert(1)</script>";
        let o = run(html);
        let loc = o.actions[0].location;
        assert_eq!(loc.line, 2);
        assert_eq!(
            loc.byte_offset as usize,
            html.find("<script").unwrap() as u64 as usize
        );
    }

    // EVENT HANDLERS

    #[test]
    fn event_handlers_are_stripped_by_prefix() {
        let o = run(r#"<img src="/a.png" onerror="steal()" ONCLICK="x()">"#);
        let s = out(&o);
        assert!(!s.to_ascii_lowercase().contains("onerror"));
        assert!(!s.to_ascii_lowercase().contains("onclick"));
        assert!(s.contains(r#"src="/a.png""#)); // benign attr untouched
        assert_eq!(o.actions.len(), 2);
        assert!(
            o.actions
                .iter()
                .all(|a| a.rule_id == "html.attr.event_handler")
        );
    }

    // DANGEROUS SCHEMES

    #[test]
    fn javascript_href_is_rewritten_to_blocked() {
        let o = run(r#"<a href="javascript:alert(1)">x</a>"#);
        let s = out(&o);
        assert!(s.contains(r##"href="#blocked""##));
        assert!(!s.contains("javascript"));
        assert_eq!(o.actions[0].rule_id, "html.attr.dangerous_scheme");
        assert_eq!(o.actions[0].action, Action::Rewrite);
        assert_eq!(o.actions[0].replacement.as_deref(), Some("#blocked"));
    }

    #[test]
    fn entity_encoded_javascript_scheme_does_not_survive() {
        let o = run(r#"<a href="java&#115;cript:alert(1)">x</a>"#);
        let s = out(&o);
        assert!(s.contains(r##"href="#blocked""##));
        assert!(!s.to_ascii_lowercase().contains("script:"));
    }

    #[test]
    fn data_scheme_in_iframe_src_is_handled() {
        // iframe with data: src — the frame rule fires first (placeholder),
        // which already removes the active payload.
        let o = run(r#"<iframe src="data:text/html,<script>alert(1)</script>"></iframe>"#);
        assert!(!out(&o).contains("<iframe"));
        assert_eq!(o.actions[0].rule_id, "html.frame.disallowed");
    }

    #[test]
    fn benign_href_is_untouched() {
        let o = run(r#"<a href="https://example.com/page">x</a>"#);
        assert!(out(&o).contains("https://example.com/page"));
        assert!(o.actions.is_empty());
    }

    // FRAMES

    #[test]
    fn iframe_off_allowlist_is_placeholdered() {
        let o = run(r#"<iframe src="https://ads.evil/frame"></iframe>"#);
        let s = out(&o);
        assert!(!s.contains("<iframe"));
        assert!(s.contains("sanitized-placeholder"));
        assert_eq!(o.actions[0].rule_id, "html.frame.disallowed");
        assert_eq!(o.actions[0].action, Action::Placeholder);
        assert_eq!(o.actions[0].replacement.as_deref(), Some(FRAME_PLACEHOLDER));
    }

    #[test]
    fn object_and_embed_are_placeholdered() {
        let o = run(r#"<object data="https://x.evil/o"></object><embed src="https://x.evil/e">"#);
        assert!(!out(&o).contains("<object"));
        assert!(!out(&o).contains("<embed"));
        assert_eq!(o.actions.len(), 2);
    }

    #[test]
    fn frame_on_allowlist_survives() {
        let rules = HtmlRules {
            frame_origin_allowlist: vec!["https://trusted.example".to_string()],
            ..Default::default()
        };
        let o = run_with(
            r#"<iframe src="https://trusted.example/ok"></iframe>"#,
            &rules,
        );
        assert!(out(&o).contains("<iframe"));
        assert!(o.actions.is_empty());
    }

    // META REFRESH

    #[test]
    fn meta_refresh_is_removed() {
        let o = run(
            r#"<meta http-equiv="refresh" content="0;url=http://evil/"><meta charset="utf-8">"#,
        );
        let s = out(&o);
        assert!(!s.contains("refresh"));
        assert!(s.contains(r#"charset="utf-8""#)); // unrelated meta kept
        assert_eq!(o.actions.len(), 1);
        assert_eq!(o.actions[0].rule_id, "html.meta.refresh");
    }

    #[test]
    fn meta_refresh_matches_case_insensitively() {
        let o = run(r#"<meta HTTP-EQUIV="Refresh" content="0">"#);
        assert!(!out(&o).contains("meta"));
        assert_eq!(o.actions.len(), 1);
    }

    // CROSS-CUTTING BEHAVIOUR

    #[test]
    fn benign_document_passes_through_byte_identical() {
        // SC-2: a permissive-enough document with no matches is unchanged.
        let html = "<!doctype html><html><head><title>Hi</title></head><body><p>Hello <a href=\"/x\">world</a></p></body></html>";
        let o = run(html);
        assert_eq!(out(&o), html);
        assert!(o.actions.is_empty());
        assert!(!o.refused);
    }

    #[test]
    fn empty_input_produces_empty_output() {
        let o = run("");
        assert!(o.output.is_empty());
        assert!(o.actions.is_empty());
        assert!(!o.refused);
    }

    #[test]
    fn multiple_rules_fire_in_one_document() {
        let html = concat!(
            "<meta http-equiv=\"refresh\" content=\"0\">",
            "<script>bad()</script>",
            "<a href=\"javascript:x\" onclick=\"y\">l</a>",
            "<iframe src=\"http://evil/\"></iframe>",
        );
        let o = run(html);
        let ids: Vec<&str> = o.actions.iter().map(|a| a.rule_id.as_str()).collect();
        assert!(ids.contains(&"html.meta.refresh"));
        assert!(ids.contains(&"html.script.disallowed"));
        assert!(ids.contains(&"html.attr.dangerous_scheme"));
        assert!(ids.contains(&"html.attr.event_handler"));
        assert!(ids.contains(&"html.frame.disallowed"));
    }

    #[test]
    fn refuse_action_sets_refused_flag() {
        let rules = HtmlRules {
            action_script: Action::Refuse,
            ..Default::default()
        };
        let o = run_with("<script>alert(1)</script>", &rules);
        assert!(o.refused);
        assert_eq!(o.actions[0].action, Action::Refuse);
    }

    #[test]
    fn malformed_input_does_not_panic() {
        // Truncated tags / stray brackets: best-effort, never a panic. Reaching
        // this line at all (and serialising the output) is the assertion.
        let o = run("<script<div onclick= <<< <a href=javascript:1");
        let _ = out(&o);
    }

    #[test]
    fn non_utf8_bytes_do_not_panic() {
        let bytes = [b'<', b'p', b'>', 0xFF, 0xFE, b'<', b'/', b'p', b'>'];
        let o = sanitize_html(&bytes, &HtmlRules::default(), &no_url_checker());
        let _ = o.output; // must have completed without panicking
    }

    // URL INSPECTION

    fn run_urls(html: &str, blocklist: &[&str], protected: &[&str]) -> HtmlOutcome {
        let blockset = BlockSet::set_from_list(blocklist);
        let rules = UrlRules {
            protected_domains: protected.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        };
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let checker = UrlChecker::new(&blockset, &skeletons, &verdicache, &rules);
        sanitize_html(html.as_bytes(), &HtmlRules::default(), &checker)
    }

    #[test]
    fn blocklisted_anchor_is_rewritten_to_placeholder() {
        // rewrite to placeholder_url.
        let o = run_urls(
            r#"<a href="http://evil.com/phish">x</a>"#,
            &["0.0.0.0 evil.com"],
            &[],
        );
        let s = out(&o);
        assert!(s.contains(r##"href="#blocked""##));
        assert!(!s.contains("evil.com"));
        assert_eq!(o.actions.len(), 1);
        assert_eq!(o.actions[0].rule_id, "url.blocklist");
        assert_eq!(o.actions[0].category, "blocklist");
        assert_eq!(o.actions[0].action, Action::Rewrite);
        assert_eq!(o.actions[0].replacement.as_deref(), Some("#blocked"));
        assert!(o.actions[0].original.contains("evil.com"));
    }

    #[test]
    fn blocklist_matches_resource_references_and_forms() {
        // anchors, forms, and resource references are all inspected
        let o = run_urls(
            r#"<img src="http://ads.evil.com/p.gif"><form action="http://evil.com/post"></form>"#,
            &["0.0.0.0 evil.com"],
            &[],
        );
        assert_eq!(o.actions.len(), 2);
        assert!(o.actions.iter().all(|a| a.rule_id == "url.blocklist"));
        let s = out(&o);
        assert!(!s.contains("evil.com"));
    }

    #[test]
    fn protocol_relative_blocklisted_anchor_is_rewritten() {
        // //host/path names a host even without a scheme
        // a block-listed one is rewritten end-to-end just like an absolute URL.
        let o = run_urls(
            r#"<a href="//evil.com/phish">x</a>"#,
            &["0.0.0.0 evil.com"],
            &[],
        );
        let s = out(&o);
        assert!(s.contains(r##"href="#blocked""##));
        assert!(!s.contains("evil.com"));
        assert_eq!(o.actions.len(), 1);
        assert_eq!(o.actions[0].rule_id, "url.blocklist");
        assert_eq!(o.actions[0].action, Action::Rewrite);
        assert!(o.actions[0].original.contains("evil.com"));
    }

    #[test]
    fn malformed_protocol_relative_anchor_is_neutralised() {
        // a nested host/split (fullwidth `＠`) inside a protocol-relative
        // reference is neutralised, never emitted verbatim
        let o = run_urls("<a href=\"//example.com\u{FF20}evil.com/\">x</a>", &[], &[]);
        assert_eq!(o.actions.len(), 1);
        assert_eq!(o.actions[0].rule_id, "url.malformed");
        assert_eq!(o.actions[0].action, Action::Rewrite);
        let s = out(&o);
        assert!(s.contains(r##"href="#blocked""##));
        assert!(!s.contains("evil.com"));
    }

    #[test]
    fn homograph_anchor_fires_homograph_action() {
        // Cyrillic-а spoof of a protected domain
        let spoof = "http://p\u{0430}ypal.com/login";
        let o = run_urls(&format!(r#"<a href="{spoof}">x</a>"#), &[], &["paypal.com"]);
        assert_eq!(o.actions.len(), 1);
        assert_eq!(o.actions[0].rule_id, "url.homograph");
        assert_eq!(o.actions[0].action, Action::Rewrite);
        assert!(out(&o).contains(r##"href="#blocked""##));
    }

    #[test]
    fn plain_idn_is_reported_but_left_in_place() {
        // an `xn--` host that is not a spoof is report-only (allow)
        let o = run_urls("<a href=\"http://xn--mnchen-3ya.de/\">x</a>", &[], &[]);
        assert_eq!(o.actions.len(), 1);
        assert_eq!(o.actions[0].rule_id, "url.idn");
        assert_eq!(o.actions[0].category, "idn_url");
        assert_eq!(o.actions[0].action, Action::Allow);
        // Report-only: the URL survives unchanged.
        assert!(out(&o).contains("xn--mnchen-3ya.de"));
    }

    #[test]
    fn control_char_url_is_neutralised() {
        // embedded CR/LF host-split → malformed, neutralised
        let o = run_urls("<a href=\"http://exa\r\nmple.com/\">x</a>", &[], &[]);
        assert_eq!(o.actions.len(), 1);
        assert_eq!(o.actions[0].rule_id, "url.malformed");
        assert_eq!(o.actions[0].action, Action::Rewrite);
        assert!(out(&o).contains(r##"href="#blocked""##));
    }

    #[test]
    fn benign_and_relative_urls_are_untouched() {
        let o = run_urls(
            r#"<a href="https://example.com/ok">x</a><img src="/local.png">"#,
            &["0.0.0.0 evil.com"],
            &["paypal.com"],
        );
        assert!(o.actions.is_empty());
        assert!(out(&o).contains("https://example.com/ok"));
        assert!(out(&o).contains(r#"src="/local.png""#));
    }

    #[test]
    fn neutralised_scheme_is_not_double_processed_by_url_rule() {
        // rewrites `javascript:` to `#blocked`
        //the URL rule then sees a hostless relative ref and records nothing further.
        let o = run_urls(
            r#"<a href="javascript:alert(1)">x</a>"#,
            &["0.0.0.0 evil.com"],
            &[],
        );
        assert_eq!(o.actions.len(), 1);
        assert_eq!(o.actions[0].rule_id, "html.attr.dangerous_scheme");
    }
}
