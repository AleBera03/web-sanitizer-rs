pub mod xml;
pub mod zip;

use crate::policy::{Action, ActiveContentAction, SubresourcesRules};
use crate::report::{Location, MAX_FRAGMENT_BYTES, SanitisationAction, truncate_fragment};
use crate::sniff::{MimeType, SniffOutcome};
use xml::xml_has_dos_risk;
use zip::zip_has_dos_risk;

pub struct DosScanOutcome {
    pub output: Option<Vec<u8>>,
    pub actions: Vec<SanitisationAction>,
    pub refused: bool,
}

pub fn scan_dos_risks(input: &SniffOutcome, rules: &SubresourcesRules) -> DosScanOutcome {
    let data = input.output.as_deref.unwrap_or_default();

    let hit: Option<(&str, usize)> = match input.mime_type {
        Some(MimeType::ApplicationXml) => {
            xml_has_dos_risk(&data).map(|o| ("scan.xml.entity_expansion", o))
        }
        Some(MimeType::ApplicationZip) => {
            zip_has_dos_risk(&data).map(|o| ("scan.zip.bomb_risk", o))
        }
        _ => None,
    };

    let Some((rule_id, offset)) = hit else {
        return DosScanOutcome {
            output: Some(data),
            actions: Vec::new(),
            refused: false,
        };
    };

    let action = match rules.active_content_rule {
        ActiveContentAction::Allow => Action::Allow,
        ActiveContentAction::Reject => Action::Refuse,
    };
    let refused = action == Action::Refuse;

    let fragment_end = (offset + MAX_FRAGMENT_BYTES).min(data.len());
    let original = truncate_fragment(
        &String::from_utf8_lossy(&data[offset..fragment_end]),
        MAX_FRAGMENT_BYTES,
    );

    DosScanOutcome {
        output: if refused { None } else { Some(data) },
        actions: vec![SanitisationAction {
            rule_id: rule_id.to_string(),
            category: "dos".to_string(),
            location: Location {
                line: 0,
                byte_offset: offset as u64,
            },
            original,
            action,
            replacement: None,
        }],
        refused,
    }
}
