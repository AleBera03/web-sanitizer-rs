use crate::html;
use crate::policy::Policy;
use crate::report::SanitisationAction;
use crate::scan::active::scan_active_content;
use crate::scan::dos::scan_dos_risks;
use crate::sniff::{MimeType, SniffOutcome};
use crate::urlcheck::UrlChecker;

pub struct RouteOutcome {
    pub output: Vec<u8>,
    pub actions: Vec<SanitisationAction>,
    pub refused: bool,
}

pub fn route(
    sniff_outcome: SniffOutcome,
    policy: &Policy,
    url: &UrlChecker,
    _depth: u32,
) -> RouteOutcome {
    match sniff_outcome.mime_type {
        Some(MimeType::TextHtml) => {
            let html_outcome =
                html::sanitize_html(&sniff_outcome.output.unwrap_or_default(), &policy.html, url);
            RouteOutcome {
                output: html_outcome.output,
                actions: html_outcome.actions,
                refused: html_outcome.refused,
            }
        }
        Some(MimeType::ApplicationPdf) | Some(MimeType::ImageTiff) => {
            let scan_outcome = scan_active_content(sniff_outcome, &policy.subresources);
            RouteOutcome {
                output: scan_outcome.output.unwrap_or_default(),
                actions: scan_outcome.actions,
                refused: scan_outcome.refused,
            }
        }
        Some(MimeType::ApplicationZip) => {
            if let Some(action) = scan_dos_risks(&sniff_outcome) {
                return RouteOutcome {
                    output: Vec::new(),
                    actions: vec![action],
                    refused: true,
                };
            }

            let scan_outcome = scan_active_content(sniff_outcome, &policy.subresources);
            RouteOutcome {
                output: scan_outcome.output.unwrap_or_default(),
                actions: scan_outcome.actions,
                refused: scan_outcome.refused,
            }
        }

        Some(MimeType::ApplicationXml) => {
            if let Some(action) = scan_dos_risks(&sniff_outcome) {
                //TODO pass budget policies as argument
                return RouteOutcome {
                    output: Vec::new(),
                    actions: vec![action],
                    refused: true,
                };
            }

            let scan_outcome = scan_active_content(sniff_outcome, &policy.subresources);
            RouteOutcome {
                output: scan_outcome.output.unwrap_or_default(),
                actions: scan_outcome.actions,
                refused: scan_outcome.refused,
            }
        }

        Some(MimeType::ImageSvg) => {
            let scan_outcome = scan_active_content(sniff_outcome, &policy.subresources);
            RouteOutcome {
                output: scan_outcome.output.unwrap_or_default(),
                actions: scan_outcome.actions,
                refused: scan_outcome.refused,
            }
        }
        _ => RouteOutcome {
            output: sniff_outcome.output.unwrap_or_default(),
            actions: Vec::new(),
            refused: false,
        },
    }
}
