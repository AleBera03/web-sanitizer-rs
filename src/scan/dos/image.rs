use std::fmt;

use crate::scan::utilities::{read_u16, read_u32};
use crate::sniff::MimeType;

const TIFF_IMAGE_WIDTH: u16 = 0x0100;
const TIFF_IMAGE_LENGTH: u16 = 0x0101;
const TIFF_SHORT: u16 = 3;
const TIFF_LONG: u16 = 4;
const TIFF_ENTRY_LEN: usize = 12;
const JPEG_NOT_A_FRAME: &[u8] = &[0xC4, 0xC8, 0xCC];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dimensions {
    pub width: u64,
    pub height: u64,
    pub offset: usize,
}

impl Dimensions {
    pub fn pixels(self) -> u64 {
        self.width.saturating_mul(self.height)
    }
}

impl fmt::Display for Dimensions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}x{} = {} pixels",
            self.width,
            self.height,
            self.pixels()
        )
    }
}

pub fn image_dimensions(data: &[u8], mime: MimeType) -> Option<Dimensions> {
    match mime {
        MimeType::ImagePng => png(data),
        MimeType::ImageGif => gif(data),
        MimeType::ImageJpeg => jpeg(data),
        MimeType::ImageWebp => webp(data),
        MimeType::ImageTiff => tiff(data),
        _ => None,
    }
}

/// The offset of the claim, when it is over budget.
pub fn image_has_dos_risk(data: &[u8], mime: MimeType, max_pixels: u64) -> Option<Dimensions> {
    let claimed = image_dimensions(data, mime)?;
    (claimed.pixels() > max_pixels).then_some(claimed)
}

/// `IHDR` is required to be the first chunk, so both fields sit at a fixed
/// offset: 8 signature bytes, then a 4-byte length and a 4-byte type.
fn png(data: &[u8]) -> Option<Dimensions> {
    if data.get(12..16)? != b"IHDR" {
        return None;
    }
    Some(Dimensions {
        width: read_u32(data, 16, false)? as u64,
        height: read_u32(data, 20, false)? as u64,
        offset: 16,
    })
}

/// The logical screen descriptor follows the six-byte signature.
fn gif(data: &[u8]) -> Option<Dimensions> {
    Some(Dimensions {
        width: read_u16(data, 6, true)? as u64,
        height: read_u16(data, 8, true)? as u64,
        offset: 6,
    })
}

/// JPEG keeps the size in a frame header that can sit behind any number of
/// other segments, so the segment chain has to be walked to reach it.
fn jpeg(data: &[u8]) -> Option<Dimensions> {
    let mut at = 2; // past the start-of-image marker
    while at + 3 < data.len() {
        if data[at] != 0xFF {
            at += 1;
            continue;
        }
        let marker = data[at + 1];
        match marker {
            // fill byte: the marker starts at the next one
            0xFF => at += 1,
            // standalone markers carry no length field
            0x01 | 0xD0..=0xD9 => at += 2,
            0xC0..=0xCF if !JPEG_NOT_A_FRAME.contains(&marker) => {
                // precision, then height, then width
                let payload = at + 4;
                return Some(Dimensions {
                    height: read_u16(data, payload + 1, false)? as u64,
                    width: read_u16(data, payload + 3, false)? as u64,
                    offset: payload + 1,
                });
            }
            _ => {
                let length = read_u16(data, at + 2, false)? as usize;
                // a segment shorter than its own length field would not advance
                if length < 2 {
                    return None;
                }
                at += 2 + length;
            }
        }
    }
    None
}

/// A RIFF container whose first chunk says which of the three encodings it is,
/// and each of them stores the canvas differently.
fn webp(data: &[u8]) -> Option<Dimensions> {
    if data.get(8..12)? != b"WEBP" {
        return None;
    }
    match data.get(12..16)? {
        b"VP8X" => {
            // canvas dimensions are 24-bit, stored minus one
            let width = read_u24(data, 24)? + 1;
            let height = read_u24(data, 27)? + 1;
            Some(Dimensions {
                width,
                height,
                offset: 24,
            })
        }
        b"VP8L" => {
            // 0x2F, then 14 bits of width-1 and 14 bits of height-1
            if data.get(20)? != &0x2F {
                return None;
            }
            let bits = read_u32(data, 21, true)? as u64;
            Some(Dimensions {
                width: (bits & 0x3FFF) + 1,
                height: ((bits >> 14) & 0x3FFF) + 1,
                offset: 21,
            })
        }
        b"VP8 " => {
            // a three-byte frame tag, then the start code, then the size
            if data.get(23..26)? != [0x9D, 0x01, 0x2A] {
                return None;
            }
            Some(Dimensions {
                width: (read_u16(data, 26, true)? & 0x3FFF) as u64,
                height: (read_u16(data, 28, true)? & 0x3FFF) as u64,
                offset: 26,
            })
        }
        _ => None,
    }
}

/// The first directory holds the two tags. Later directories describe extra
/// pages, which a decoder reaches only after the first one is already allocated.
fn tiff(data: &[u8]) -> Option<Dimensions> {
    let little_endian = match data.get(0..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let directory = read_u32(data, 4, little_endian)? as usize;
    let entries = read_u16(data, directory, little_endian)? as usize;

    let mut width = None;
    let mut height = None;
    let mut offset = directory;

    for index in 0..entries {
        let entry = directory + 2 + index * TIFF_ENTRY_LEN;
        let tag = read_u16(data, entry, little_endian)?;
        if tag != TIFF_IMAGE_WIDTH && tag != TIFF_IMAGE_LENGTH {
            continue;
        }
        // a single short or long sits inline in the value field
        let value = match read_u16(data, entry + 2, little_endian)? {
            TIFF_SHORT => read_u16(data, entry + 8, little_endian)? as u64,
            TIFF_LONG => read_u32(data, entry + 8, little_endian)? as u64,
            _ => continue,
        };
        match tag {
            TIFF_IMAGE_WIDTH => {
                width = Some(value);
                offset = entry + 8;
            }
            _ => height = Some(value),
        }
    }

    Some(Dimensions {
        width: width?,
        height: height?,
        offset,
    })
}

fn read_u24(data: &[u8], offset: usize) -> Option<u64> {
    let b = data.get(offset..offset + 3)?;
    Some(u64::from(b[0]) | u64::from(b[1]) << 8 | u64::from(b[2]) << 16)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn png_header(width: u32, height: u32) -> Vec<u8> {
        let mut out = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        out.extend_from_slice(&13u32.to_be_bytes());
        out.extend_from_slice(b"IHDR");
        out.extend_from_slice(&width.to_be_bytes());
        out.extend_from_slice(&height.to_be_bytes());
        out.extend_from_slice(&[0x08, 0x02, 0x00, 0x00, 0x00]);
        out
    }

    fn gif_header(width: u16, height: u16) -> Vec<u8> {
        let mut out = b"GIF89a".to_vec();
        out.extend_from_slice(&width.to_le_bytes());
        out.extend_from_slice(&height.to_le_bytes());
        out.extend_from_slice(&[0x00, 0x00, 0x00]);
        out
    }

    fn jpeg_header(width: u16, height: u16) -> Vec<u8> {
        let mut out = vec![0xFF, 0xD8];
        // an APP0 segment first, so the walk has something to step over
        out.extend_from_slice(&[0xFF, 0xE0, 0x00, 0x10]);
        out.extend_from_slice(b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0");
        out.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
        out.extend_from_slice(&height.to_be_bytes());
        out.extend_from_slice(&width.to_be_bytes());
        out.extend_from_slice(&[0x03]);
        out
    }

    fn webp_vp8x(width: u32, height: u32) -> Vec<u8> {
        let mut out = b"RIFF".to_vec();
        out.extend_from_slice(&30u32.to_le_bytes());
        out.extend_from_slice(b"WEBPVP8X");
        out.extend_from_slice(&10u32.to_le_bytes());
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        out.extend_from_slice(&(width - 1).to_le_bytes()[..3]);
        out.extend_from_slice(&(height - 1).to_le_bytes()[..3]);
        out
    }

    fn tiff_header(width: u32, height: u32, little_endian: bool) -> Vec<u8> {
        let mut out = if little_endian {
            let mut v = b"II".to_vec();
            v.extend_from_slice(&42u16.to_le_bytes());
            v.extend_from_slice(&8u32.to_le_bytes());
            v.extend_from_slice(&2u16.to_le_bytes());
            v
        } else {
            let mut v = b"MM".to_vec();
            v.extend_from_slice(&42u16.to_be_bytes());
            v.extend_from_slice(&8u32.to_be_bytes());
            v.extend_from_slice(&2u16.to_be_bytes());
            v
        };
        for (tag, value) in [(TIFF_IMAGE_WIDTH, width), (TIFF_IMAGE_LENGTH, height)] {
            if little_endian {
                out.extend_from_slice(&tag.to_le_bytes());
                out.extend_from_slice(&TIFF_LONG.to_le_bytes());
                out.extend_from_slice(&1u32.to_le_bytes());
                out.extend_from_slice(&value.to_le_bytes());
            } else {
                out.extend_from_slice(&tag.to_be_bytes());
                out.extend_from_slice(&TIFF_LONG.to_be_bytes());
                out.extend_from_slice(&1u32.to_be_bytes());
                out.extend_from_slice(&value.to_be_bytes());
            }
        }
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }

    #[test]
    fn png_dimensions_come_from_the_ihdr() {
        let found = image_dimensions(&png_header(1920, 1080), MimeType::ImagePng).unwrap();
        assert_eq!(found.width, 1920);
        assert_eq!(found.height, 1080);
        assert_eq!(found.offset, 16);
    }

    #[test]
    fn the_scenario_png_is_over_budget() {
        // the evil-origin body: 65535 x 65535 in 69 bytes
        let bomb = png_header(65535, 65535);
        let found = image_has_dos_risk(&bomb, MimeType::ImagePng, 50_000_000).unwrap();
        assert_eq!(found.pixels(), 4_294_836_225);
        assert_eq!(found.to_string(), "65535x65535 = 4294836225 pixels");
    }

    #[test]
    fn a_png_within_budget_is_no_risk() {
        let ordinary = png_header(1920, 1080);
        assert!(image_has_dos_risk(&ordinary, MimeType::ImagePng, 50_000_000).is_none());
    }

    #[test]
    fn the_budget_boundary_is_exact() {
        let exact = png_header(1000, 1000);
        assert!(image_has_dos_risk(&exact, MimeType::ImagePng, 1_000_000).is_none());
        assert!(image_has_dos_risk(&exact, MimeType::ImagePng, 999_999).is_some());
    }

    #[test]
    fn a_png_without_an_ihdr_first_reads_nothing() {
        let mut odd = png_header(10, 10);
        odd[12..16].copy_from_slice(b"gAMA");
        assert!(image_dimensions(&odd, MimeType::ImagePng).is_none());
    }

    #[test]
    fn gif_dimensions_are_little_endian() {
        let found = image_dimensions(&gif_header(800, 600), MimeType::ImageGif).unwrap();
        assert_eq!((found.width, found.height), (800, 600));
    }

    #[test]
    fn a_gif_bomb_is_caught() {
        let bomb = gif_header(65535, 65535);
        assert!(image_has_dos_risk(&bomb, MimeType::ImageGif, 50_000_000).is_some());
    }

    #[test]
    fn jpeg_dimensions_come_from_the_frame_header() {
        let found = image_dimensions(&jpeg_header(4032, 3024), MimeType::ImageJpeg).unwrap();
        assert_eq!((found.width, found.height), (4032, 3024));
    }

    #[test]
    fn a_jpeg_bomb_is_caught_behind_other_segments() {
        let bomb = jpeg_header(65535, 65535);
        assert!(image_has_dos_risk(&bomb, MimeType::ImageJpeg, 50_000_000).is_some());
    }

    #[test]
    fn a_jpeg_huffman_table_is_not_a_frame_header() {
        // 0xC4 sits in the SOF range but describes a table
        let mut data = vec![0xFF, 0xD8, 0xFF, 0xC4, 0x00, 0x05, 0x00, 0x00, 0x00];
        data.extend_from_slice(&[0xFF, 0xC0, 0x00, 0x11, 0x08]);
        data.extend_from_slice(&100u16.to_be_bytes());
        data.extend_from_slice(&200u16.to_be_bytes());
        data.push(0x03);
        let found = image_dimensions(&data, MimeType::ImageJpeg).unwrap();
        assert_eq!((found.width, found.height), (200, 100));
    }

    #[test]
    fn webp_canvas_dimensions_are_stored_minus_one() {
        let found = image_dimensions(&webp_vp8x(2000, 1500), MimeType::ImageWebp).unwrap();
        assert_eq!((found.width, found.height), (2000, 1500));
    }

    #[test]
    fn a_webp_bomb_is_caught() {
        let bomb = webp_vp8x(16_777_216, 16_777_216);
        assert!(image_has_dos_risk(&bomb, MimeType::ImageWebp, 50_000_000).is_some());
    }

    #[test]
    fn tiff_dimensions_come_from_the_first_directory() {
        for little_endian in [true, false] {
            let found =
                image_dimensions(&tiff_header(3000, 2000, little_endian), MimeType::ImageTiff)
                    .unwrap();
            assert_eq!(
                (found.width, found.height),
                (3000, 2000),
                "le={little_endian}"
            );
        }
    }

    #[test]
    fn a_tiff_bomb_is_caught() {
        let bomb = tiff_header(100_000, 100_000, true);
        assert!(image_has_dos_risk(&bomb, MimeType::ImageTiff, 50_000_000).is_some());
    }

    #[test]
    fn a_type_with_no_raster_has_no_dimensions() {
        assert!(image_dimensions(b"<svg/>", MimeType::ImageSvg).is_none());
        assert!(image_dimensions(b"%PDF-1.7", MimeType::ApplicationPdf).is_none());
    }

    #[test]
    fn a_truncated_header_reads_nothing_and_does_not_panic() {
        for mime in [
            MimeType::ImagePng,
            MimeType::ImageGif,
            MimeType::ImageJpeg,
            MimeType::ImageWebp,
            MimeType::ImageTiff,
        ] {
            for length in 0..24 {
                let truncated = vec![0xFFu8; length];
                let _ = image_has_dos_risk(&truncated, mime, 50_000_000);
            }
        }
    }

    #[test]
    fn a_jpeg_of_only_markers_terminates() {
        let data = vec![0xFF; 4096];
        assert!(image_dimensions(&data, MimeType::ImageJpeg).is_none());
    }

    #[test]
    fn the_pixel_count_saturates_instead_of_overflowing() {
        let claimed = Dimensions {
            width: u64::MAX,
            height: u64::MAX,
            offset: 0,
        };
        assert_eq!(claimed.pixels(), u64::MAX);
    }
}
