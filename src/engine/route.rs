//! Type-specific dispatch: which handler runs on the sniffed bytes, and which
//! of the per-input budgets that handler is the only one to care about.
//!
//! HTML is the only type that carries sub-resource references, so it is the only
//! branch that fills [`RouteOutcome::references`]; every other handler leaves it
//! empty and the engine's sub-resource loop simply has nothing to do.

use crate::html;
use crate::html::Reference;
use crate::policy::Policy;
use crate::report::SanitisationAction;
use crate::scan::active::{ScanOutcome, scan_active_content};
use crate::scan::dos::scan_dos_risks;
use crate::sniff::{MimeType, SniffOutcome};
use crate::urlcheck::UrlChecker;

pub struct RouteOutcome {
    pub output: Vec<u8>,
    pub actions: Vec<SanitisationAction>,
    pub refused: bool,
    /// Sub-resource references, non-empty only for HTML. The engine decides
    /// whether they are merely inspected or also fetched.
    pub references: Vec<Reference>,
    /// `<base href>` of an HTML document, the base its references resolve against.
    pub base: Option<String>,
}

impl RouteOutcome {
    /// Result of a handler that has no references to report.
    fn scanned(output: Vec<u8>, actions: Vec<SanitisationAction>, refused: bool) -> RouteOutcome {
        RouteOutcome {
            output,
            actions,
            refused,
            references: Vec::new(),
            base: None,
        }
    }

    /// A refusal that keeps no output.
    fn refused(action: SanitisationAction) -> RouteOutcome {
        RouteOutcome::scanned(Vec::new(), vec![action], true)
    }
}

/// Scanners speak in terms of their own outcome, so every scanning branch is a
/// single conversion and new branches cost nothing.
impl From<ScanOutcome> for RouteOutcome {
    fn from(scan: ScanOutcome) -> RouteOutcome {
        RouteOutcome::scanned(scan.output.unwrap_or_default(), scan.actions, scan.refused)
    }
}

pub fn route(
    sniff_outcome: SniffOutcome,
    policy: &Policy,
    url: &UrlChecker,
    _depth: u32, // TEMP: not yet used, but may be for budget policies
) -> RouteOutcome {
    match sniff_outcome.mime_type {
        Some(MimeType::TextHtml) => {
            let html_outcome =
                html::sanitize_html(&sniff_outcome.output.unwrap_or_default(), &policy.html, url);
            RouteOutcome {
                output: html_outcome.output,
                actions: html_outcome.actions,
                refused: html_outcome.refused,
                references: html_outcome.references,
                base: html_outcome.base,
            }
        }
        Some(MimeType::ApplicationPdf) | Some(MimeType::ImageTiff) => {
            scan_active_content(sniff_outcome, &policy.subresources).into()
        }
        Some(MimeType::ApplicationZip) => {
            if let Some(action) = scan_dos_risks(&sniff_outcome, &policy.subresources) {
                return RouteOutcome {
                    output: Vec::new(),
                    actions: vec![action],
                    refused: true,
                    references: Vec::new(),
                    base: None
                };
            }
            scan_active_content(sniff_outcome, &policy.subresources).into()
        }

        Some(MimeType::ApplicationXml) => {
            if let Some(action) = scan_dos_risks(&sniff_outcome, &policy.subresources) {
                return RouteOutcome {
                    output: Vec::new(),
                    actions: vec![action],
                    refused: true,
                    references: Vec::new(),
                    base: None
                };
            }
            scan_active_content(sniff_outcome, &policy.subresources).into()
        }

        Some(MimeType::ImageSvg) => scan_active_content(sniff_outcome, &policy.subresources).into(),

        _ => RouteOutcome::scanned(sniff_outcome.output.unwrap_or_default(), Vec::new(), false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::html::tests_support::no_url_checker;

    fn sniffed(mime: Option<MimeType>, data: &[u8]) -> SniffOutcome {
        SniffOutcome {
            output: Some(data.to_vec()),
            mime_type: mime,
            actions: Vec::new(),
            refused: false,
        }
    }

    #[test]
    fn html_is_sanitised_and_its_references_come_back() {
        let body = br#"<link rel="stylesheet" href="/a.css"><script>alert(1)</script>"#;
        let outcome = route(
            sniffed(Some(MimeType::TextHtml), body),
            &Policy::builtin(),
            &no_url_checker(),
            0,
        );
        assert!(!String::from_utf8_lossy(&outcome.output).contains("alert"));
        assert_eq!(outcome.actions.len(), 1);
        assert_eq!(outcome.references.len(), 1);
        assert_eq!(outcome.references[0].raw, "/a.css");
    }

    #[test]
    fn html_reports_its_base() {
        let body = br#"<base href="http://a.test/dir/"><img src="x.png">"#;
        let outcome = route(
            sniffed(Some(MimeType::TextHtml), body),
            &Policy::builtin(),
            &no_url_checker(),
            0,
        );
        assert_eq!(outcome.base.as_deref(), Some("http://a.test/dir/"));
    }

    #[test]
    fn unknown_bytes_pass_through_without_references() {
        let outcome = route(
            sniffed(None, b"payload"),
            &Policy::builtin(),
            &no_url_checker(),
            0,
        );
        assert_eq!(outcome.output, b"payload");
        assert!(outcome.references.is_empty());
        assert!(outcome.base.is_none());
        assert!(!outcome.refused);
    }

    #[test]
    fn an_image_carries_no_references_to_fetch() {
        let outcome = route(
            sniffed(Some(MimeType::ImagePng), b"\x89PNG\r\n\x1a\n"),
            &Policy::builtin(),
            &no_url_checker(),
            0,
        );
        assert!(outcome.references.is_empty());
    }
}
