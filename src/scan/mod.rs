use crate::SniffOutcome;
use crate::report::SanitisationAction;
use crate::sniff::MimeType;

use std::path::Path;
use url::Url;

pub struct ScanOutcome {
    pub output: Option<Vec<u8>>,
    pub actions: Vec<SanitisationAction>,
    pub refused: bool,
}

pub fn scan_content(input: SniffOutcome) -> ScanOutcome {
    if input
        .mime_type
        .is_some_and(MimeType::may_carry_active_content)
    {
        let output = input.output.map(scan_active_content);

        ScanOutcome {
            output,
            actions: Vec::new(),
            refused: false,
        }
    } else {
        ScanOutcome {
            output: input.output,
            actions: Vec::new(),
            refused: false,
        }
    }
}

fn scan_active_content(data: Vec<u8>) -> Vec<u8> {
    // Placeholder for actual scanning logic
    data
}

fn scan_pdf(data: Vec<u8>) -> Vec<u8> {
    // Placeholder for actual PDF scanning logic
    data
}

fn scan_tiff(data: Vec<u8>) -> Vec<u8> {
    // Placeholder for actual TIFF scanning logic
    data
}

fn rewrite_pdf(data: Vec<u8>) -> Vec<u8> {
    // Placeholder for actual PDF rewriting logic
    data
}

fn rewrite_tiff(data: Vec<u8>) -> Vec<u8> {
    // Placeholder for actual TIFF rewriting logic
    data
}
