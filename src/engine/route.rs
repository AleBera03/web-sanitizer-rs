use crate::html;
use crate::policy::Policy;
use crate::report::SanitisationAction;
use crate::scan::active::scan_active_content;
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
            let output = sniff_outcome.output.unwrap_or_default();
            let mime = sniff_outcome.mime_type.unwrap();
            let sanitized = scan_active_content(output, mime);
            RouteOutcome {
                output: sanitized,
                actions: Vec::new(),
                refused: false,
            }
        }
        Some(MimeType::ApplicationZip) => {
            // TODO: check ratio budget (policy.budgets.max_decompress_ratio), then
            // bounded inflate + re-sniff via a recursive route() call, capped by `depth`
            // TODO: check for active content
            RouteOutcome {
                output: sniff_outcome.output.unwrap_or_default(),
                actions: Vec::new(),
                refused: false,
            }
        }
        Some(MimeType::ApplicationXml | MimeType::ImageSvg) => {
            // TODO: check ratio budget (policy.budgets.max_decompress_ratio), then
            // bounded inflate + re-sniff via a recursive route() call, capped by `depth`
            // TODO: check for active content
            RouteOutcome {
                output: sniff_outcome.output.unwrap_or_default(),
                actions: Vec::new(),
                refused: false,
            }
        }
        _ => RouteOutcome {
            output: sniff_outcome.output.unwrap_or_default(),
            actions: Vec::new(),
            refused: false,
        },
    }
}
