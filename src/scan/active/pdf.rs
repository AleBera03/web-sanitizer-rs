use crate::scan::utilities::find_bytes;

const PDF_JAVASCRIPT: &[u8] = b"/JavaScript";
const PDF_JS: &[u8] = b"/JS";
const PDF_OPEN_ACTION: &[u8] = b"/OpenAction";
const PDF_ADDITIONAL_ACTIONS: &[u8] = b"/AA";
const PDF_LAUNCH: &[u8] = b"/Launch";

const PDF_ACTIVE_CONTENT_MARKERS: &[&[u8]] = &[
    PDF_JAVASCRIPT,
    PDF_JS,
    PDF_OPEN_ACTION,
    PDF_ADDITIONAL_ACTIONS,
    PDF_LAUNCH,
];

pub fn pdf_has_active_content(data: &[u8]) -> Option<usize> {
    PDF_ACTIVE_CONTENT_MARKERS
        .iter()
        .find_map(|marker| find_bytes(data, marker))
}
