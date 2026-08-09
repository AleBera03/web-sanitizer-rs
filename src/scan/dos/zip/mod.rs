use crate::scan::utilities::{read_u16, read_u32};

// CONSTANTS
const EOCD_SIGNATURE: &[u8] = &[0x50, 0x4B, 0x05, 0x06];
const CENTRAL_DIR_ENTRY_SIGNATURE: &[u8] = &[0x50, 0x4B, 0x01, 0x02];
const CENTRAL_DIR_ENTRY_FIXED_LEN: usize = 46;
const EOCD_MAX_COMMENT_LEN: usize = 65535;

const VBA_PROJECT_MARKER: &[u8] = b"vbaProject.bin";

const MAX_COMPRESSION_RATIO: f64 = 100.0;
const MAX_TOTAL_UNCOMPRESSED_BYTES: u64 = 1024 * 1024 * 1024; // 1 GiB
const MAX_ENTRY_COUNT: u32 = 10_000;

pub struct ZipEntry<'a> {
    pub name: &'a [u8],
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
pub fn entries(data: &[u8]) -> Option<Vec<ZipEntry<'_>>> {
    let eocd_offset = find_eocd(data)?;
    let entry_count = read_u16(data, eocd_offset + 10, true)?;
    if entry_count as u32 > MAX_ENTRY_COUNT {
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
            compressed_size,
            uncompressed_size,
        });

        offset = name_start + filename_len + extra_len + comment_len;
    }

    Some(result)
}

/// True if the archive contains a VBA project stream, the marker of an
/// OOXML document carrying macros.
pub fn zip_has_active_content(data: &[u8]) -> bool {
    let Some(entries) = entries(data) else {
        return false;
    };
    entries
        .iter()
        .any(|entry| entry.name.ends_with(VBA_PROJECT_MARKER))
}

/// True if declared compression ratios, total uncompressed size, or entry
/// count exceed sane bounds ("zip bomb" heuristic).
pub fn zip_bomb_risk(data: &[u8]) -> bool {
    let Some(entries) = entries(data) else {
        return true; // unreadable/malformed: treat as risky
    };

    let mut total_uncompressed: u64 = 0;
    for entry in &entries {
        let ratio = entry.uncompressed_size as f64 / entry.compressed_size.max(1) as f64;
        if ratio > MAX_COMPRESSION_RATIO {
            return true;
        }
        total_uncompressed += entry.uncompressed_size as u64;
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES {
            return true;
        }
    }
    false
}

/// Infers the OOXML document kind from entry name prefixes (`word/`,
/// `xl/`, `ppt/`). `None` if the archive doesn't look like an OOXML package.
pub fn zip_ooxml_kind(data: &[u8]) -> Option<OoxmlKind> {
    let entries = entries(data)?;
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
    //use super::*;

    // TODO: build minimal well-formed ZIP byte fixtures (central directory
    // only is enough, no need for real compressed data) covering:
    // - entries() on a valid archive
    // - zip_has_active_content: true when a "word/vbaProject.bin" entry is present
    // - zip_bomb_risk: true when declared ratio exceeds MAX_COMPRESSION_RATIO
    // - zip_ooxml_kind: Word / Excel / PowerPoint / None
}
