pub mod image;
pub mod xml;
pub mod zip;

use crate::policy::Action;
use crate::policy::{Budgets, SubresourcesRules};
use crate::report::{Location, MAX_FRAGMENT_BYTES, SanitisationAction, truncate_fragment};
use crate::sniff::{MimeType, SniffOutcome};
use image::image_has_dos_risk;
use xml::xml_has_dos_risk;
use zip::zip_has_dos_risk;

pub fn scan_dos_risks(
    input: &SniffOutcome,
    rules: &SubresourcesRules,
    budgets: &Budgets,
) -> Option<SanitisationAction> {
    let data = input.data.as_slice();

    let (rule_id, offset, original) = match input.mime_type() {
        Some(MimeType::ApplicationXml) => {
            let offset = xml_has_dos_risk(data, &rules.xml_budget)?;
            ("scan.xml.entity_expansion", offset, fragment(data, offset))
        }
        Some(MimeType::ApplicationZip) => {
            let offset = zip_has_dos_risk(data, &rules.zip_budget)?;
            ("scan.zip.bomb_risk", offset, fragment(data, offset))
        }
        Some(mime) => {
            let claimed = image_has_dos_risk(data, mime, budgets.max_image_pixels)?;
            (
                "scan.image.dimensions",
                claimed.offset,
                format!("{claimed}, budget {}", budgets.max_image_pixels),
            )
        }
        None => return None,
    };

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

fn fragment(data: &[u8], offset: usize) -> String {
    let end = (offset + MAX_FRAGMENT_BYTES).min(data.len());
    truncate_fragment(
        &String::from_utf8_lossy(&data[offset..end]),
        MAX_FRAGMENT_BYTES,
    )
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

    fn budgets() -> Budgets {
        Budgets::default()
    }

    fn png(width: u32, height: u32) -> Vec<u8> {
        let mut out = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        out.extend_from_slice(&13u32.to_be_bytes());
        out.extend_from_slice(b"IHDR");
        out.extend_from_slice(&width.to_be_bytes());
        out.extend_from_slice(&height.to_be_bytes());
        out.extend_from_slice(&[0x08, 0x02, 0x00, 0x00, 0x00]);
        out
    }

    #[test]
    fn xml_with_no_dos_risk_returns_none() {
        let outcome = sniff_outcome(MimeType::ApplicationXml, b"<root>hi</root>");
        assert!(scan_dos_risks(&outcome, &rules(), &budgets()).is_none());
    }

    #[test]
    fn an_oversized_raster_is_a_refuse_action() {
        let outcome = sniff_outcome(MimeType::ImagePng, &png(65535, 65535));
        let action = scan_dos_risks(&outcome, &rules(), &budgets()).expect("expected a DOS action");
        assert_eq!(action.rule_id, "scan.image.dimensions");
        assert_eq!(action.category, "dos");
        assert_eq!(action.action, Action::Refuse);
        assert_eq!(action.location.byte_offset, 16);
        assert_eq!(
            action.original,
            "65535x65535 = 4294836225 pixels, budget 50000000"
        );
    }

    #[test]
    fn an_ordinary_raster_carries_no_risk() {
        let outcome = sniff_outcome(MimeType::ImagePng, &png(1920, 1080));
        assert!(scan_dos_risks(&outcome, &rules(), &budgets()).is_none());
    }

    #[test]
    fn a_raised_budget_admits_a_larger_raster() {
        let outcome = sniff_outcome(MimeType::ImagePng, &png(65535, 65535));
        let generous = Budgets {
            max_image_pixels: u64::MAX,
            ..Budgets::default()
        };
        assert!(scan_dos_risks(&outcome, &rules(), &generous).is_none());
    }

    #[test]
    fn a_type_that_carries_no_raster_returns_none() {
        let outcome = sniff_outcome(MimeType::TextHtml, b"<!DOCTYPE html>");
        assert!(scan_dos_risks(&outcome, &rules(), &budgets()).is_none());
    }

    #[test]
    fn xml_with_dos_risk_returns_refuse_action() {
        let outcome = sniff_outcome(
            MimeType::ApplicationXml,
            /* TODO payload billion-laughs */ b"...",
        );
        let action = scan_dos_risks(&outcome, &rules(), &budgets()).expect("expected a DOS action");
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
        let action = scan_dos_risks(&outcome, &rules(), &budgets()).expect("expected a DOS action");
        assert_eq!(action.rule_id, "scan.zip.bomb_risk");
    }

    #[test]
    fn a_header_too_short_to_read_returns_none() {
        let outcome = sniff_outcome(MimeType::ImageJpeg, b"\xFF\xD8\xFF");
        assert!(scan_dos_risks(&outcome, &rules(), &budgets()).is_none());
    }

    #[test]
    fn empty_data_carries_no_risk() {
        let outcome = sniff_outcome(MimeType::ApplicationXml, b"");
        assert!(scan_dos_risks(&outcome, &rules(), &budgets()).is_none());
    }
}
