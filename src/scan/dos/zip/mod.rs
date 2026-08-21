use crate::scan::utilities::{read_u16, read_u32};
use crate::policy::ZipBudgets;

// CONSTANTS
const EOCD_SIGNATURE: &[u8] = &[0x50, 0x4B, 0x05, 0x06];
const CENTRAL_DIR_ENTRY_SIGNATURE: &[u8] = &[0x50, 0x4B, 0x01, 0x02];
const CENTRAL_DIR_ENTRY_FIXED_LEN: usize = 46;
const EOCD_MAX_COMMENT_LEN: usize = 65535;

const VBA_PROJECT_MARKER: &[u8] = b"vbaProject.bin";

pub struct ZipEntry<'a> {
    pub name: &'a [u8],
    pub name_offset: usize,
    pub compressed_size: u32,
    pub uncompressed_size: u32,
}

/// OOXML sub-kind inferred from entry name prefixes, when recognisable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OoxmlKind {
    Word,
    Excel,
    PowerPoint,
}

fn find_eocd(data: &[u8]) -> Option<usize> {
    let search_start = data.len().saturating_sub(22 + EOCD_MAX_COMMENT_LEN);
    (search_start..=data.len().saturating_sub(4))
        .rev()
        .find(|&i| data[i..i + 4] == *EOCD_SIGNATURE)
}

/// Walks the central directory and returns every entry's name and declared
/// sizes. Reads only metadata; never decompresses entry contents. Returns
/// `None` if the file doesn't look like a well-formed ZIP.
pub fn entries(data: &[u8], max_entry_count: u32) -> Option<Vec<ZipEntry<'_>>> {
    let eocd_offset = find_eocd(data)?;
    let entry_count = read_u16(data, eocd_offset + 10, true)?;
    if entry_count as u32 > max_entry_count {
        return None;
    }
    let cd_offset = read_u32(data, eocd_offset + 16, true)? as usize;

    let mut offset = cd_offset;
    let mut result = Vec::with_capacity(entry_count as usize);

    for _ in 0..entry_count {
        if data.get(offset..offset + 4) != Some(CENTRAL_DIR_ENTRY_SIGNATURE) {
            return None;
        }
        let compressed_size = read_u32(data, offset + 20, true)?;
        let uncompressed_size = read_u32(data, offset + 24, true)?;
        let filename_len = read_u16(data, offset + 28, true)? as usize;
        let extra_len = read_u16(data, offset + 30, true)? as usize;
        let comment_len = read_u16(data, offset + 32, true)? as usize;

        let name_start = offset + CENTRAL_DIR_ENTRY_FIXED_LEN;
        let name = data.get(name_start..name_start + filename_len)?;

        result.push(ZipEntry {
            name,
            name_offset: name_start,
            compressed_size,
            uncompressed_size,
        });

        offset = name_start + filename_len + extra_len + comment_len;
    }

    Some(result)
}

/// True if the archive contains a VBA project stream, the marker of an
/// OOXML document carrying macros.
pub fn zip_has_active_content(data: &[u8], budget: &ZipBudgets) -> Option<usize> {
    entries(data, budget.max_entry_count)?
        .iter()
        .find(|e| e.name.ends_with(VBA_PROJECT_MARKER))
        .map(|e| e.name_offset)
}

pub fn zip_has_dos_risk(data: &[u8], budget: &ZipBudgets) -> Option<usize> {
    let Some(entries) = entries(data, budget.max_entry_count) else {
        return Some(0); // unreadable/malformed: treat as risky
    };

    let mut total_uncompressed: u64 = 0;
    for entry in &entries {
        let ratio = entry.uncompressed_size as f64 / entry.compressed_size.max(1) as f64;
        if ratio > budget.max_compression_ratio {
            return Some(entry.name_offset);
        }
        total_uncompressed += entry.uncompressed_size as u64;
        if total_uncompressed > budget.max_total_uncompressed_bytes {
            return Some(0);
        }
    }
    None
}

/// Infers the OOXML document kind from entry name prefixes (`word/`,
/// `xl/`, `ppt/`). `None` if the archive doesn't look like an OOXML package.
pub fn zip_ooxml_kind(data: &[u8], budget: &ZipBudgets) -> Option<OoxmlKind> {
    let entries = entries(data, budget.max_entry_count)?;
    entries.iter().find_map(|e| {
        if e.name.starts_with(b"word/") {
            Some(OoxmlKind::Word)
        } else if e.name.starts_with(b"xl/") {
            Some(OoxmlKind::Excel)
        } else if e.name.starts_with(b"ppt/") {
            Some(OoxmlKind::PowerPoint)
        } else {
            None
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> ZipBudgets {
        ZipBudgets::default()
    }

    // ---- fixture builder -----------------------------------------------

    fn central_entry(name: &[u8], compressed: u32, uncompressed: u32) -> Vec<u8> {
        let mut e = Vec::new();
        e.extend_from_slice(CENTRAL_DIR_ENTRY_SIGNATURE); // signature
        e.extend_from_slice(&[0, 0]); // version made by
        e.extend_from_slice(&[0, 0]); // version needed
        e.extend_from_slice(&[0, 0]); // flags
        e.extend_from_slice(&[0, 0]); // compression method
        e.extend_from_slice(&[0, 0]); // mod time
        e.extend_from_slice(&[0, 0]); // mod date
        e.extend_from_slice(&[0, 0, 0, 0]); // crc-32
        e.extend_from_slice(&compressed.to_le_bytes());
        e.extend_from_slice(&uncompressed.to_le_bytes());
        e.extend_from_slice(&(name.len() as u16).to_le_bytes()); // filename_len
        e.extend_from_slice(&0u16.to_le_bytes()); // extra_len
        e.extend_from_slice(&0u16.to_le_bytes()); // comment_len
        e.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        e.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        e.extend_from_slice(&0u32.to_le_bytes()); // external attrs
        e.extend_from_slice(&0u32.to_le_bytes()); // local header offset
        e.extend_from_slice(name);
        e
    }

    /// Builds a minimal well-formed ZIP: central directory + EOCD only, no
    /// local headers or real compressed data — everything `entries()` reads
    /// lives in these two sections.
    fn build_zip(entries: &[(&[u8], u32, u32)]) -> Vec<u8> {
        let mut central_dir = Vec::new();
        for (name, compressed, uncompressed) in entries {
            central_dir.extend(central_entry(name, *compressed, *uncompressed));
        }

        let cd_offset = 0u32; // central directory placed at the very start
        let mut data = central_dir.clone();

        data.extend_from_slice(EOCD_SIGNATURE);
        data.extend_from_slice(&0u16.to_le_bytes()); // disk number
        data.extend_from_slice(&0u16.to_le_bytes()); // disk with CD start
        data.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // entries, this disk
        data.extend_from_slice(&(entries.len() as u16).to_le_bytes()); // entries, total
        data.extend_from_slice(&(central_dir.len() as u32).to_le_bytes()); // CD size
        data.extend_from_slice(&cd_offset.to_le_bytes()); // CD offset
        data.extend_from_slice(&0u16.to_le_bytes()); // comment length

        data
    }

    // ---- entries() -------------------------------------------------------

    #[test]
    fn entries_parses_a_well_formed_archive() {
        let data = build_zip(&[(b"word/document.xml", 100, 200)]);
        let entries = entries(&data, budget().max_entry_count).expect("expected Some entries");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, b"word/document.xml");
        assert_eq!(entries[0].compressed_size, 100);
        assert_eq!(entries[0].uncompressed_size, 200);
    }

    #[test]
    fn entries_returns_none_for_garbage_bytes() {
        let data = b"not a zip file at all";
        assert!(entries(data, budget().max_entry_count).is_none());
    }

    #[test]
    fn entries_parses_multiple_entries_in_order() {
        let data = build_zip(&[
            (b"word/document.xml", 10, 20),
            (b"word/vbaProject.bin", 30, 40),
        ]);
        let entries = entries(&data, budget().max_entry_count).expect("expected Some entries");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, b"word/document.xml");
        assert_eq!(entries[1].name, b"word/vbaProject.bin");
    }

    // ---- zip_has_active_content -------------------------------------------

    #[test]
    fn detects_vba_project_marker() {
        let data = build_zip(&[(b"word/vbaProject.bin", 10, 10)]);
        assert!(zip_has_active_content(&data, &budget()).is_some());
    }

    #[test]
    fn no_marker_means_no_active_content() {
        let data = build_zip(&[(b"word/document.xml", 10, 10)]);
        assert_eq!(zip_has_active_content(&data, &budget()), None);
    }

    // ---- zip_has_dos_risk --------------------------------------------------

    #[test]
    fn high_compression_ratio_is_flagged() {
        // uncompressed / compressed = 1000 / 1 = 1000, oltre MAX_COMPRESSION_RATIO (100)
        let data = build_zip(&[(b"bomb.bin", 1, 1000)]);
        assert!(zip_has_dos_risk(&data, &budget()).is_some());
    }

    #[test]
    fn normal_compression_ratio_is_not_flagged() {
        // rapporto 1:1, nessun rischio
        let data = build_zip(&[(b"normal.bin", 1000, 1000)]);
        assert_eq!(zip_has_dos_risk(&data, &budget()), None);
    }

    #[test]
    fn cumulative_uncompressed_size_over_budget_is_flagged() {
        // rapporto sano (1:1) ma dimensione totale oltre MAX_TOTAL_UNCOMPRESSED_BYTES (1 GiB)
        let huge = 1_200_000_000u32;
        let data = build_zip(&[(b"big.bin", huge, huge)]);
        assert!(zip_has_dos_risk(&data, &budget()).is_some());
    }

    #[test]
    fn malformed_archive_is_treated_as_risky() {
        let data = b"garbage";
        assert_eq!(zip_has_dos_risk(data, &budget()), Some(0));
    }

    // ---- zip_ooxml_kind -----------------------------------------------------

    #[test]
    fn detects_word_from_entry_prefix() {
        let data = build_zip(&[(b"word/document.xml", 10, 10)]);
        assert_eq!(zip_ooxml_kind(&data, &budget()), Some(OoxmlKind::Word));
    }

    #[test]
    fn detects_excel_from_entry_prefix() {
        let data = build_zip(&[(b"xl/workbook.xml", 10, 10)]);
        assert_eq!(zip_ooxml_kind(&data, &budget()), Some(OoxmlKind::Excel));
    }

    #[test]
    fn detects_powerpoint_from_entry_prefix() {
        let data = build_zip(&[(b"ppt/presentation.xml", 10, 10)]);
        assert_eq!(
            zip_ooxml_kind(&data, &budget()),
            Some(OoxmlKind::PowerPoint)
        );
    }

    #[test]
    fn generic_zip_without_office_prefixes_is_none() {
        let data = build_zip(&[(b"readme.txt", 10, 10)]);
        assert_eq!(zip_ooxml_kind(&data, &budget()), None);
    }
}
