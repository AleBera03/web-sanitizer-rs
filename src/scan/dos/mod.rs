pub mod xml;
pub mod zip;

use crate::policy::Action;
use crate::policy::SubresourcesRules;
use crate::report::{Location, MAX_FRAGMENT_BYTES, SanitisationAction, truncate_fragment};
use crate::sniff::{MimeType, SniffOutcome};
use xml::xml_has_dos_risk;
use zip::zip_has_dos_risk;

pub fn scan_dos_risks(
    input: &SniffOutcome,
    rules: &SubresourcesRules,
) -> Option<SanitisationAction> {
    let data = input.data.as_slice();

    let (rule_id, offset) = match input.mime_type() {
        Some(MimeType::ApplicationXml) => {
            xml_has_dos_risk(data, &rules.xml_budget).map(|o| ("scan.xml.entity_expansion", o))?
        }
        Some(MimeType::ApplicationZip) => {
            zip_has_dos_risk(data, &rules.zip_budget).map(|o| ("scan.zip.bomb_risk", o))?
        }
        _ => return None,
    };

    let fragment_end = (offset + MAX_FRAGMENT_BYTES).min(data.len());
    let original = truncate_fragment(
        &String::from_utf8_lossy(&data[offset..fragment_end]),
        MAX_FRAGMENT_BYTES,
    );

    Some(SanitisationAction {
        rule_id: rule_id.to_string(),
        category: "dos".to_string(),
        location: Location {
            line: 0,
            byte_offset: offset as u64,
        },
        original,
        action: Action::Refuse,
        replacement: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sniff::MimeVerdict;

    fn sniff_outcome(mime: MimeType, data: &[u8]) -> SniffOutcome {
        SniffOutcome {
            data: data.to_vec(),
            verdict: MimeVerdict {
                declared: None,
                sniffed: Some(mime),
            },
            actions: Vec::new(),
        }
    }

    fn rules() -> SubresourcesRules {
        SubresourcesRules::default()
    }

    #[test]
    fn xml_with_no_dos_risk_returns_none() {
        let outcome = sniff_outcome(MimeType::ApplicationXml, b"<root>hi</root>");
        assert!(scan_dos_risks(&outcome, &rules()).is_none());
    }

    #[test]
    fn xml_with_dos_risk_returns_refuse_action() {
        let outcome = sniff_outcome(
            MimeType::ApplicationXml,
            /* TODO payload billion-laughs */ b"...",
        );
        let action = scan_dos_risks(&outcome, &rules()).expect("expected a DOS action");
        assert_eq!(action.rule_id, "scan.xml.entity_expansion");
        assert_eq!(action.category, "dos");
        assert_eq!(action.action, Action::Refuse);
    }

    #[test]
    fn zip_with_dos_risk_returns_refuse_action() {
        let outcome = sniff_outcome(
            MimeType::ApplicationZip,
            /* TODO zip-bomb metadata */ &[],
        );
        let action = scan_dos_risks(&outcome, &rules()).expect("expected a DOS action");
        assert_eq!(action.rule_id, "scan.zip.bomb_risk");
    }

    #[test]
    fn unrelated_mime_type_returns_none() {
        let outcome = sniff_outcome(MimeType::ImageJpeg, b"\xFF\xD8\xFF");
        assert!(scan_dos_risks(&outcome, &rules()).is_none());
    }

    #[test]
    fn empty_data_carries_no_risk() {
        let outcome = sniff_outcome(MimeType::ApplicationXml, b"");
        assert!(scan_dos_risks(&outcome, &rules()).is_none());
    }
}
