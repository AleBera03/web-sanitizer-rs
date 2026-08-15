/// Reads a little- or big-endian `u16` at `offset`, or `None` if out of bounds.
pub(crate) fn read_u16(data: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    let b = data.get(offset..offset + 2)?;
    Some(if little_endian {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    })
}

/// Reads a little- or big-endian `u32` at `offset`, or `None` if out of bounds.
pub(crate) fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let b = data.get(offset..offset + 4)?;
    Some(if little_endian {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    })
}

/// Checks if `needle` is present in `haystack`.
pub(crate) fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// Returns position of needle or none if not found
pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}
