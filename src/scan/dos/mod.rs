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

    fn billion_laughs_payload() -> &'static [u8] {
        br#"<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
 <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
 <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
 <!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">
 <!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">
 <!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">
 <!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">
 <!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">
]>
<lolz>&lol9;</lolz>"#
    }

    fn zip_bomb_metadata() -> Vec<u8> {
        let name = b"bomb.bin";
        let compressed: u32 = 1;
        let uncompressed: u32 = 1_000_000;

        let mut entry = Vec::new();
        entry.extend_from_slice(&[0x50, 0x4B, 0x01, 0x02]); // central dir signature
        entry.extend_from_slice(&[0, 0]); // version made by
        entry.extend_from_slice(&[0, 0]); // version needed
        entry.extend_from_slice(&[0, 0]); // flags
        entry.extend_from_slice(&[0, 0]); // compression method
        entry.extend_from_slice(&[0, 0]); // mod time
        entry.extend_from_slice(&[0, 0]); // mod date
        entry.extend_from_slice(&[0, 0, 0, 0]); // crc-32
        entry.extend_from_slice(&compressed.to_le_bytes());
        entry.extend_from_slice(&uncompressed.to_le_bytes());
        entry.extend_from_slice(&(name.len() as u16).to_le_bytes()); // filename_len
        entry.extend_from_slice(&0u16.to_le_bytes()); // extra_len
        entry.extend_from_slice(&0u16.to_le_bytes()); // comment_len
        entry.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        entry.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        entry.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        entry.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        entry.extend_from_slice(name);

        let mut data = entry.clone();
        data.extend_from_slice(&[0x50, 0x4B, 0x05, 0x06]); // EOCD signature
        data.extend_from_slice(&0u16.to_le_bytes()); // disk number
        data.extend_from_slice(&0u16.to_le_bytes()); // disk with CD start
        data.extend_from_slice(&1u16.to_le_bytes()); // entries, this disk
        data.extend_from_slice(&1u16.to_le_bytes()); // entries, total
        data.extend_from_slice(&(entry.len() as u32).to_le_bytes()); // CD size
        data.extend_from_slice(&0u32.to_le_bytes()); // CD offset
        data.extend_from_slice(&0u16.to_le_bytes()); // comment length

        data
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
        let outcome = sniff_outcome(MimeType::ApplicationXml, billion_laughs_payload());
        let action = scan_dos_risks(&outcome, &rules(), &budgets()).expect("expected a DOS action");
        assert_eq!(action.rule_id, "scan.xml.entity_expansion");
        assert_eq!(action.category, "dos");
        assert_eq!(action.action, Action::Refuse);
    }

    #[test]
    fn zip_with_dos_risk_returns_refuse_action() {
        let outcome = sniff_outcome(MimeType::ApplicationZip, &zip_bomb_metadata());
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
