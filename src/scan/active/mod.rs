mod tiff;
use crate::report::SanitisationAction;
use crate::sniff::{MimeType, SniffOutcome};

use tiff::tiff_has_structural_risk;
use crate::scan::dos::zip::zip_has_active_content;

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

pub struct ScanOutcome {
    pub output: Option<Vec<u8>>,
    pub actions: Vec<SanitisationAction>,
    pub refused: bool,
}

fn scan_active_content(input: SniffOutcome) -> ScanOutcome {
    let data = input.output.unwrap_or_default();

    let has_active_content = match input.mime_type {
        Some(MimeType::ApplicationPdf) => scan_pdf(data),
        Some(MimeType::ImageTiff) => scan_tiff(data),
        Some(MimeType::ApplicationZip) => scan_zip(data),
        Some(MimeType::ApplicationXml) | Some(MimeType::ImageSvg) => scan_xml(data),
        _ => false,
    };

    if has_active_content {
        //TODO: in base alla policy faccio refuse o flag
        ScanOutcome {
            output: None,
            actions: vec![SanitisationAction::ActiveContentDetected],
            refused: true,
        }
    } else {
        ScanOutcome {
            output: Some(data),
            actions: Vec::new(),
            refused: false,
        }
    }
}

fn scan_pdf(data: Vec<u8>) -> bool {
    PDF_ACTIVE_CONTENT_MARKERS
        .iter()
        .any(|marker| contains_bytes(&data, marker))
}

fn scan_tiff(data: Vec<u8>) -> bool {
    tiff_has_structural_risk(&data) 
}

fn scan_zip(data: Vec<u8>) -> bool {
    zip_has_active_content(&data)
}

fn scan_xml(data: Vec<u8>) -> bool {
    // Placeholder for actual XML scanning logic
    xml_has_active_content(&data) {

    }
}

fn scan_svg(data: Vec<u8>) -> bool {
    // Placeholder for actual SVG scanning logic
    svg_has_active_content(&data) {

    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

