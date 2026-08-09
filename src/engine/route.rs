use crate::sniff::MimeType;

pub enum RouteOutcome {
    pub output: Vec<u8>,
    pub actions: Vec<SanitisationAction>,
    pub refused: bool,
}

pub fn route(
    sniff_outcome: SniffOutcome,
    policy: &Policy,
    url: &UrlChecker,
    depth: u32,
) -> RouteOutcome {
    match sniff_outcome.mime_type {
        Some(MimeType::TextHtml) => {
            let html_outcome = html::sanitize_html(&sniff_outcome.output.unwrap_or_default(), &policy.html, url);
            RouteOutcome { output: html_outcome.output, actions: html_outcome.actions, refused: html_outcome.refused }
        }
        Some(MimeType::ApplicationPdf) | Some(MimeType::ImageTiff) => {
            let scan_outcome = scan::scan_content(sniff_outcome);
            RouteOutcome { output: scan_outcome.output.unwrap_or_default(), actions: scan_outcome.actions, refused: scan_outcome.refused }
        }
        Some(MimeType::ApplicationZip) => {
            // check ratio budget (policy.budgets.max_decompress_ratio), then
            // bounded inflate + re-sniff via a recursive route() call, capped by `depth`
            todo!()
        }
        Some(MimeType::ApplicationXml | MimeType::ImageSvg) => {
            // check ratio budget (policy.budgets.max_decompress_ratio), then
            // bounded inflate + re-sniff via a recursive route() call, capped by `depth`
            todo!()
        }
        _ => RouteOutcome {
            output: sniff_outcome.output.unwrap_or_default(),
            actions: Vec::new(),
            refused: false,
        },
    }
}