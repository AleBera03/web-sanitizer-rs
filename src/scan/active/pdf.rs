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

#[cfg(test)]

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_pdf_has_no_active_content() {
        let data = b"%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF";
        assert_eq!(pdf_has_active_content(data), None);
    }

    #[test]
    fn detects_javascript_marker() {
        let data = b"%PDF-1.7\n3 0 obj\n<< /S /JavaScript /JS (app.alert('hi');) >>\nendobj";
        assert!(pdf_has_active_content(data).is_some());
    }

    #[test]
    fn detects_openaction_marker() {
        let data = b"%PDF-1.7\n1 0 obj\n<< /OpenAction 3 0 R >>\nendobj";
        assert!(pdf_has_active_content(data).is_some());
    }

    #[test]
    fn detects_launch_marker() {
        let data = b"%PDF-1.7\n1 0 obj\n<< /Launch (calc.exe) >>\nendobj";
        assert!(pdf_has_active_content(data).is_some());
    }

    #[test]
    fn empty_input_has_no_active_content() {
        assert_eq!(pdf_has_active_content(b""), None);
    }
}