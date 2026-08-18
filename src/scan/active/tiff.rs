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

    // ---- fixture builder -----------------------------------------------
    fn ifd_bytes(entry_count: u16, next_ifd_offset: u32) -> Vec<u8> {
        let mut ifd = Vec::new();
        ifd.extend_from_slice(&entry_count.to_le_bytes());
        ifd.extend(std::iter::repeat(0u8).take(entry_count as usize * TIFF_ENTRY_LEN));
        ifd.extend_from_slice(&next_ifd_offset.to_le_bytes());
        ifd
    }

    fn tiff_header_le(first_ifd_offset: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(b"II"); // little-endian
        h.extend_from_slice(&42u16.to_le_bytes());
        h.extend_from_slice(&first_ifd_offset.to_le_bytes());
        h
    }

    fn tiff_header_be(first_ifd_offset: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(b"MM");
        h.extend_from_slice(&42u16.to_be_bytes());
        h.extend_from_slice(&first_ifd_offset.to_be_bytes());
        h
    }

    #[test]
    fn tiff_little_endian_with_no_structural_risk_returns_none() {
        let mut data = tiff_header_le(0);
        data.extend(ifd_bytes(0, 0));
        assert_eq!(tiff_has_structural_risk(&data), None);
    }

    #[test]
    fn tiff_big_endian_with_no_structural_risk_returns_none() {
        let mut data = tiff_header_be(0);
        data.extend(ifd_bytes(0, 4));
        assert_eq!(tiff_has_structural_risk(&data), None);
    }

    #[test]
    fn tiff_le_with_malformed_header_returns_offset_0() {
        let data = b"XX";
        assert_eq!(tiff_has_structural_risk(data), Some(0));
    }

    #[test]
    fn tiff_le_too_short_for_ifd_pointer_returns_offset_4() {
        let data = &[b'I', b'I', 42, 0];
        assert_eq!(tiff_has_structural_risk(data), Some(4));
    }

    #[test]
    fn tiff_le_with_cycles_returns_offset() {
        let mut data = tiff_header_le(8);
        data.extend(ifd_bytes(0, 8));
        assert_eq!(tiff_has_structural_risk(&data), Some(8));
    }

    #[test]
    fn tiff_le_ifd_pointer_beyond_file_length_returns_offset() {
        let data = tiff_header_le(1000);
        assert_eq!(tiff_has_structural_risk(&data), Some(1000));
    }

    #[test]
    fn tiff_le_with_entries_past_eof_returns_offset() {
        let mut data = tiff_header_le(8);
        data.extend_from_slice(&5u16.to_le_bytes());
        data.extend_from_slice(&[0u8; 12]);
        assert_eq!(tiff_has_structural_risk(&data), Some(10));
    }

    #[test]
    fn tiff_le_with_next_ifd_pointer_oob_returns_offset() {
        let mut data = tiff_header_le(8);
        data.extend_from_slice(&0u16.to_le_bytes());
        assert_eq!(tiff_has_structural_risk(&data), Some(10));
    }

    #[test]
    fn tiff__be_too_short_for_ifd_pointer_returns_offset_4() {
        let data = &[b'M', b'M', 42, 0];
        assert_eq!(tiff_has_structural_risk(data), Some(4));
    }

    #[test]
    fn tiff_be_with_cycles_returns_offset() {
        let mut data = tiff_header_be(8);
        data.extend(ifd_bytes(0, 8));
        assert_eq!(tiff_has_structural_risk(&data), Some(8));
    }

    #[test]
    fn tiff_be_ifd_pointer_beyond_file_length_returns_offset() {
        let data = tiff_header_be(1000);
        assert_eq!(tiff_has_structural_risk(&data), Some(1000));
    }

    #[test]
    fn tiff_be_with_entries_past_eof_returns_offset() {
        let mut data = tiff_header_be(8);
        data.extend_from_slice(&5u16.to_be_bytes());
        data.extend_from_slice(&[0u8; 12]);
        assert_eq!(tiff_has_structural_risk(&data), Some(10));
    }

    #[test]
    fn tiff_be_with_next_ifd_pointer_oob_returns_offset() {
        let mut data = tiff_header_be(8);
        data.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(tiff_has_structural_risk(&data), Some(10));
    }
}
