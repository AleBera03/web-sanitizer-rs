use crate::scan::utilities::{read_u16, read_u32};

const TIFF_ENTRY_LEN: usize = 12;

fn tiff_is_little_endian(data: &[u8]) -> Option<bool> {
    match data.get(0..2)? {
        b"II" => Some(true),
        b"MM" => Some(false),
        _ => None,
    }
}

/// Walks the IFD chain checking bounds and cycles. True if the file is
/// malformed (out-of-bounds offset, truncated entries, or a cyclic chain).
pub fn tiff_has_structural_risk(data: &[u8]) -> Option<usize> {
    let Some(little_endian) = tiff_is_little_endian(data) else {
        return Some(0);
    };
    let Some(mut ifd_offset) = read_u32(data, 4, little_endian) else {
        return Some(4);
    };

    let mut visited = std::collections::HashSet::new();

    while ifd_offset != 0 {
        let offset = ifd_offset as usize;
        if !visited.insert(offset) {
            return Some(offset); // cycle
        }

        let Some(entry_count) = read_u16(data, offset, little_endian) else {
            return Some(offset); // out of bounds
        };

        let entries_start = offset + 2;
        let entries_end = entries_start + entry_count as usize * TIFF_ENTRY_LEN;
        if data.get(entries_start..entries_end).is_none() {
            return Some(entries_start); // entries run past end of file
        }

        let Some(next) = read_u32(data, entries_end, little_endian) else {
            return Some(entries_end); // next IFD offset out of bounds
        };
        ifd_offset = next;
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiff_little_endian_with_no_structural_risk_returns_none() {
        
    }

    #[test]
    fn tiff_big_endian_with_no_structural_risk_returns_none() {

    }

    #[test]
    fn tiff_with_malformed_header_returns_offset_0() {

    }

    #[test]
    fn tiff_too_short_for_ifd_pointer_returns_offset_4() {

    }

    #[test]
    fn tiff_with_cycles_returns_offset() {

    }

    #[test]
    fn tiff_ifd_pointer_beyond_file_length_returns_offset() { } {

    }

    #[test]
    fn tiff_with_entries_past_eof_returns_offset() {

    }

    #[test]
    fn tiff_with_next_ifd_pointer_oob_returns_offset() {

    }

}