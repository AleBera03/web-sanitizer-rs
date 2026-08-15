mod pdf;
mod svg;
mod tiff;

use crate::policy::{Action, ActiveContentAction, SubresourcesRules};
use crate::report::{Location, MAX_FRAGMENT_BYTES, SanitisationAction, truncate_fragment};
use crate::scan::dos::xml::xml_has_active_content;
use crate::scan::dos::zip::zip_has_active_content;
use crate::sniff::{MimeType, SniffOutcome};
use pdf::pdf_has_active_content;
use svg::svg_has_active_content;
use tiff::tiff_has_structural_risk;

pub struct ScanOutcome {
    pub output: Option<Vec<u8>>,
    pub actions: Vec<SanitisationAction>,
    pub refused: bool,
}

pub fn scan_active_content(input: SniffOutcome, rules: &SubresourcesRules) -> ScanOutcome {
    let data = input.output.unwrap_or_default();

    let detected_actions: Vec<SanitisationAction> = match input.mime_type {
        Some(MimeType::ApplicationPdf) => pdf_has_active_content(&data)
            .map(|o| vec![single_action("scan.pdf.active_content", o, &data)])
            .unwrap_or_default(),
        Some(MimeType::ImageTiff) => tiff_has_structural_risk(&data)
            .map(|o| vec![single_action("scan.tiff.structural_risk", o, &data)])
            .unwrap_or_default(),
        Some(MimeType::ApplicationZip) => zip_has_active_content(&data)
            .map(|o| vec![single_action("scan.zip.macro_present", o, &data)])
            .unwrap_or_default(),
        Some(MimeType::ApplicationXml) => xml_has_active_content(&data)
            .map(|o| vec![single_action("scan.xml.xxe", o, &data)])
            .unwrap_or_default(),
        Some(MimeType::ImageSvg) => svg_has_active_content(&data),
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

    // Re-stamp: the detected actions carry whatever `sanitize_html`/format
    // detection produced internally; the *applied* action is the coarse
    // subresource-level decision.
    let actions = detected_actions
        .into_iter()
        .map(|a| SanitisationAction {
            action: policy_action,
            ..a
        })
        .collect();

    ScanOutcome {
        output: if refused { None } else { Some(data) },
        actions,
        refused,
    }
}

fn single_action(rule_id: &str, offset: usize, data: &[u8]) -> SanitisationAction {
    let fragment_end = (offset + MAX_FRAGMENT_BYTES).min(data.len());
    SanitisationAction {
        rule_id: rule_id.to_string(),
        category: "active_content".to_string(),
        location: Location {
            line: 0,
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
