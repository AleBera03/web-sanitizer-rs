use crate::SniffOutcome;
use crate::report::SanitisationAction;
use crate::sniff::MimeType;

use std::path::Path;
use url::Url;

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

const TIFF_ENTRY_LEN: usize = 12;

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
    let has_active_content = PDF_ACTIVE_CONTENT_MARKERS
        .iter()
        .any(|marker| contains_bytes(&data, marker));

    if has_active_content {
        // TODO: implement action based on policy
    }

    data //TEMP
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn scan_tiff(data: Vec<u8>) -> Vec<u8> {
    if tiff_has_structural_risk(&data) {
        //TODO: perform action based on policy
    }

    data //TEMP
}

fn tiff_is_little_endian(data: &[u8]) -> Option<bool> {
    match data.get(0..2)? {
        b"II" => Some(true),
        b"MM" => Some(false),
        _ => None,
    }
}

fn read_u16(data: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    let b = data.get(offset..offset + 2)?;
    Some(if little_endian {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    })
}

fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let b = data.get(offset..offset + 4)?;
    Some(if little_endian {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    })
}

/// Walks the IFD chain checking bounds and cycles. True if the file is
/// malformed (out-of-bounds offset, truncated entries, or a cyclic chain).
fn tiff_has_structural_risk(data: &[u8]) -> bool {
    let Some(little_endian) = tiff_is_little_endian(data) else {
        return true;
    };
    let Some(mut ifd_offset) = read_u32(data, 4, little_endian) else {
        return true;
    };

    let mut visited = std::collections::HashSet::new();

    while ifd_offset != 0 {
        let offset = ifd_offset as usize;
        if !visited.insert(offset) {
            return true; // cycle
        }

        let Some(entry_count) = read_u16(data, offset, little_endian) else {
            return true; // out of bounds
        };

        let entries_start = offset + 2;
        let entries_end = entries_start + entry_count as usize * TIFF_ENTRY_LEN;
        if data.get(entries_start..entries_end).is_none() {
            return true; // entries run past end of file
        }

        let Some(next) = read_u32(data, entries_end, little_endian) else {
            return true;
        };
        ifd_offset = next;
    }

    false
}

fn rewrite_pdf(data: Vec<u8>) -> Vec<u8> {
    // Placeholder for actual PDF rewriting logic
    data
}

/// Truncates the IFD chain at the last structurally valid IFD, zeroing out
/// its "next IFD offset" field. Leaves `data` untouched if the header itself
/// is unreadable or the chain is already valid end-to-end.
fn rewrite_tiff(data: Vec<u8>) -> Vec<u8> {
    let Some(little_endian) = tiff_is_little_endian(&data) else {
        return data;
    };
    let Some(mut ifd_offset) = read_u32(&data, 4, little_endian) else {
        return data;
    };

    let mut visited = std::collections::HashSet::new();
    let mut last_next_offset_field: Option<usize> = None;
    let mut truncated = false;

    while ifd_offset != 0 {
        let offset = ifd_offset as usize;
        if !visited.insert(offset) {
            truncated = true;
            break;
        }

        let Some(entry_count) = read_u16(&data, offset, little_endian) else {
            truncated = true;
            break;
        };

        let entries_start = offset + 2;
        let entries_end = entries_start + entry_count as usize * TIFF_ENTRY_LEN;
        if data.get(entries_start..entries_end).is_none() {
            truncated = true;
            break;
        }

        let Some(next) = read_u32(&data, entries_end, little_endian) else {
            truncated = true;
            break;
        };

        last_next_offset_field = Some(entries_end);
        ifd_offset = next;
    }

    if truncated {
        if let Some(field_offset) = last_next_offset_field {
            write_u32(&mut data, field_offset, 0, little_endian);
        } else {
            // The very first IFD was already invalid: nothing valid to keep.
            write_u32(&mut data, 4, 0, little_endian);
        }
    }

    data
}

fn write_u32(data: &mut [u8], offset: usize, value: u32, little_endian: bool) {
    let bytes = if little_endian {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    data[offset..offset + 4].copy_from_slice(&bytes);
}

fn scan_zip(data: Vec<u8>) -> Vec<u8> {
    // Placeholder for actual ZIP scanning logic
    data
}
