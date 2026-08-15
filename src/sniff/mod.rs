use crate::input::InputSource;
use crate::policy::{Action, Policy, SniffAction};
use crate::report::{Location, SanitisationAction};
use crate::scan::dos::zip::{OoxmlKind, zip_ooxml_kind};
use crate::sniff::MimeType::{
    ApplicationPdf, ApplicationXml, ApplicationZip, AudioFlac, AudioMp3, AudioWav, ImageGif,
    ImageJpeg, ImagePng, ImageSvg, ImageTiff, ImageWebp, TextHtml, VideoAvi, VideoMp4,
};

use std::path::Path;
use std::sync::Arc;
use url::Url;

// CONSTANTS
// magic numbers for sniffing file types
const JPEG: &[u8] = &[0xFF, 0xD8, 0xFF];
const PNG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const GIF87A: &[u8] = b"GIF87a";
const GIF89A: &[u8] = b"GIF89a";
const HTML_DOCTYPE: &[u8] = b"<!DOCTYPE html>";
const PDF: &[u8] = b"%PDF-";
const XML: &[u8] = b"<?xml";
const FLAC: &[u8] = b"fLaC";
const SVG: &[u8] = b"<svg";
// MP3 files can start with "ID3" or with a frame sync (0xFF 0xFB)
const MP3_ID3: &[u8] = b"ID3";
const MP3_FRAME_SYNC: &[u8] = &[0xFF, 0xFB];
const AVI_TYPE: &[u8] = b"AVI ";
const WAVE_TYPE: &[u8] = b"WAVE";
// MP4 files does not have the magic number at offset 0
const MP4_FTYP: &[u8] = b"ftyp";
const MP4_FTYP_OFFSET: usize = 4;
// TIFF has 2 variants for endiannes
const TIFF_LE: &[u8] = b"II*\0";
const TIFF_BE: &[u8] = b"MM\0*";
// ZIP files (including DOCX, XLSX, PPTX) start with "PK" and then a version number
const ZIP_OOXML: &[u8] = b"PK\x03\x04";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimeType {
    ImageJpeg,
    ImagePng,
    ImageGif,
    ImageWebp,
    ImageSvg,
    ImageTiff,
    TextHtml,
    ApplicationPdf,
    ApplicationZip,
    ApplicationXml,
    AudioFlac,
    AudioMp3,
    AudioWav,
    VideoAvi,
    VideoMp4,
    WordDocx,
    ExcelXlsx,
    PowerPointPptx,
    WordDoc,
    ExcelXls,
    PowerPointPpt,
}

impl MimeType {
    pub fn may_carry_active_content(self) -> bool {
        matches!(self, MimeType::ApplicationPdf | MimeType::ImageTiff)
    }
}

pub struct AcquiredInput {
    pub source: InputSource,
    pub data: Vec<u8>,
}

impl AcquiredInput {
    pub fn new(source: InputSource, data: Vec<u8>) -> Self {
        Self { source, data }
    }
}

pub struct SniffOutcome {
    pub output: Option<Vec<u8>>,
    pub mime_type: Option<MimeType>,
    pub actions: Vec<SanitisationAction>,
    pub refused: bool,
}

pub fn sniff_input(input: AcquiredInput, policy: Arc<Policy>, verbose: u8) -> SniffOutcome {
    let _ = verbose;
    let declared_mime = read_declared_mime(&input);
    let actual_mime = read_actual_mime(&input);

    if declared_mime != actual_mime {
        let action = match policy.subresources.sniff_rule {
            SniffAction::Reject => Action::Refuse,
            SniffAction::Rewrite => Action::Rewrite,
        };
        let output = if matches!(policy.subresources.sniff_rule, SniffAction::Rewrite) {
            Some(input.data.clone())
        } else {
            None
        };
        let original = format!("declared={:?} actual={:?}", declared_mime, actual_mime);
        return SniffOutcome {
            output,
            mime_type: actual_mime,
            actions: vec![mismatch_action(action, original)],
            refused: matches!(policy.subresources.sniff_rule, SniffAction::Reject),
        };
    }

    SniffOutcome {
        output: Some(input.data),
        mime_type: actual_mime,
        actions: Vec::new(),
        refused: false,
    }
}

fn mismatch_action(action: Action, original: String) -> SanitisationAction {
    SanitisationAction {
        rule_id: "sniff.mime_mismatch".to_string(),
        category: "sniff".to_string(),
        location: Location {
            line: 0,
            byte_offset: 0,
        },
        original,
        action,
        replacement: None,
    }
}

fn read_declared_mime(input: &AcquiredInput) -> Option<MimeType> {
    let ext = match &input.source {
        InputSource::Bytes { name, .. } => {
            if !name.is_empty() {
                read_mime_from_bytes(name)
            } else {
                None
            }
        }

        InputSource::File(path) => read_mime_from_file(path),
        InputSource::Url(url) => read_mime_from_url(url),
        InputSource::MalformedUrl(_) => None,
    }?;

    mime_from_extension(ext)
}

//TODO riordinare i tipi per macrotipi così rimane più leggibile
fn read_actual_mime(input: &AcquiredInput) -> Option<MimeType> {
    if input.data.starts_with(JPEG) {
        Some(ImageJpeg)
    } else if input.data.starts_with(PNG) {
        Some(ImagePng)
    } else if input.data.starts_with(GIF87A) || input.data.starts_with(GIF89A) {
        Some(ImageGif)
    } else if input.data.starts_with(HTML_DOCTYPE) {
        Some(TextHtml)
    } else if input.data.starts_with(PDF) {
        Some(ApplicationPdf)
    } else if input.data.starts_with(TIFF_LE) || input.data.starts_with(TIFF_BE) {
        Some(ImageTiff)
    } else if input.data.starts_with(ZIP_OOXML) {
        match zip_ooxml_kind(&input.data) {
            Some(OoxmlKind::Word) => Some(MimeType::WordDocx),
            Some(OoxmlKind::Excel) => Some(MimeType::ExcelXlsx),
            Some(OoxmlKind::PowerPoint) => Some(MimeType::PowerPointPptx),
            None => Some(MimeType::ApplicationZip),
        }
    } else if input.data.starts_with(FLAC) {
        Some(AudioFlac)
    } else if input.data.starts_with(MP3_ID3) || input.data.starts_with(MP3_FRAME_SYNC) {
        Some(AudioMp3)
    } else if input.data.starts_with(WAVE_TYPE) {
        Some(AudioWav)
    } else if input.data.starts_with(AVI_TYPE) {
        Some(VideoAvi)
    } else if input.data.len() > MP4_FTYP_OFFSET
        && &input.data[MP4_FTYP_OFFSET..MP4_FTYP_OFFSET + MP4_FTYP.len()] == MP4_FTYP
    {
        Some(VideoMp4)
    } else if input.data.starts_with(XML) {
        Some(ApplicationXml)
    } else if input.data.starts_with(SVG) {
        Some(ImageSvg)
    } else {
        None
    }
}

fn read_mime_from_bytes(name: &str) -> Option<&str> {
    Path::new(name).extension()?.to_str()
}

fn read_mime_from_file(path: &Path) -> Option<&str> {
    path.extension()?.to_str()
}

fn read_mime_from_url(url: &Url) -> Option<&str> {
    let last_segment = url.path_segments()?.next_back()?;
    if last_segment.is_empty() {
        return None;
    }
    Path::new(last_segment).extension()?.to_str()
}

/// Converts file extension to MIME type. Returns None if the extension is not recognized.
fn mime_from_extension(ext: &str) -> Option<MimeType> {
    match ext.to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" => Some(ImageJpeg),
        "png" => Some(ImagePng),
        "gif" => Some(ImageGif),
        "webp" => Some(ImageWebp),
        "svg" => Some(ImageSvg),
        "html" | "htm" => Some(TextHtml),
        "pdf" => Some(ApplicationPdf),
        "tif" | "tiff" => Some(ImageTiff),
        "zip" => Some(ApplicationZip),
        "xml" => Some(ApplicationXml),
        "flac" => Some(AudioFlac),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn bytes_input(name: &str, data: &[u8]) -> AcquiredInput {
        AcquiredInput {
            source: InputSource::Bytes {
                name: name.to_string(),
                data: data.to_vec(),
            },
            data: data.to_vec(),
        }
    }

    fn file_input(path: &str, data: &[u8]) -> AcquiredInput {
        AcquiredInput {
            source: InputSource::File(PathBuf::from(path)),
            data: data.to_vec(),
        }
    }

    fn url_input(url: &str, data: &[u8]) -> AcquiredInput {
        AcquiredInput {
            source: InputSource::Url(Url::parse(url).unwrap()),
            data: data.to_vec(),
        }
    }

    #[test]
    fn detects_jpeg_from_magic_bytes() {
        let input = bytes_input("x", &[0xFF, 0xD8, 0xFF, 0x00]);
        assert_eq!(read_actual_mime(&input), Some(MimeType::ImageJpeg));
    }

    #[test]
    fn detects_png_from_magic_bytes() {
        let input = bytes_input("x", &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        assert_eq!(read_actual_mime(&input), Some(MimeType::ImagePng));
    }

    #[test]
    fn detects_gif87a_and_gif89a() {
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"GIF87a...")),
            Some(MimeType::ImageGif)
        );
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"GIF89a...")),
            Some(MimeType::ImageGif)
        );
    }

    #[test]
    fn detects_html_doctype() {
        let input = bytes_input("x", b"<!DOCTYPE html><html></html>");
        assert_eq!(read_actual_mime(&input), Some(MimeType::TextHtml));
    }

    #[test]
    fn detects_pdf() {
        let input = bytes_input("x", b"%PDF-1.7 ...");
        assert_eq!(read_actual_mime(&input), Some(MimeType::ApplicationPdf));
    }

    #[test]
    fn detects_tiff_little_and_big_endian() {
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"II*\0...")),
            Some(MimeType::ImageTiff)
        );
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"MM\0*...")),
            Some(MimeType::ImageTiff)
        );
    }

    #[test]
    fn detects_zip_ooxml() {
        let input = bytes_input("x", &[0x50, 0x4B, 0x03, 0x04, 0x00]);
        assert_eq!(read_actual_mime(&input), Some(MimeType::ApplicationZip));
    }

    #[test]
    fn unrecognised_bytes_yield_none() {
        let input = bytes_input("x", b"not a known format");
        assert_eq!(read_actual_mime(&input), None);
    }

    // ---- declared MIME (extension-based) -----------------------------------

    #[test]
    fn declared_mime_from_bytes_name_extension() {
        let input = bytes_input("photo.jpeg", b"");
        assert_eq!(read_declared_mime(&input), Some(MimeType::ImageJpeg));
    }

    #[test]
    fn declared_mime_from_bytes_empty_name_is_none() {
        let input = bytes_input("", b"");
        assert_eq!(read_declared_mime(&input), None);
    }

    #[test]
    fn declared_mime_from_file_path_extension() {
        let input = file_input("/tmp/report.pdf", b"");
        assert_eq!(read_declared_mime(&input), Some(MimeType::ApplicationPdf));
    }

    #[test]
    fn declared_mime_from_url_path_extension() {
        let input = url_input("https://example.com/assets/logo.png", b"");
        assert_eq!(read_declared_mime(&input), Some(MimeType::ImagePng));
    }

    #[test]
    fn declared_mime_from_url_without_extension_is_none() {
        let input = url_input("https://example.com/assets/", b"");
        assert_eq!(read_declared_mime(&input), None);
    }

    #[test]
    fn declared_mime_for_malformed_url_is_none() {
        let input = AcquiredInput {
            source: InputSource::MalformedUrl("ht!tp://broken".to_string()),
            data: Vec::new(),
        };
        assert_eq!(read_declared_mime(&input), None);
    }

    #[test]
    fn declared_mime_is_case_insensitive() {
        let input = bytes_input("IMAGE.PNG", b"");
        assert_eq!(read_declared_mime(&input), Some(MimeType::ImagePng));
    }

    #[test]
    fn unrecognised_extension_is_none() {
        let input = bytes_input("archive.rar", b"");
        assert_eq!(read_declared_mime(&input), None);
    }

    // ---- sniff_input ---------------------------------------------------------

    #[test]
    fn sniff_input_reports_detected_mime_type() {
        let input = bytes_input("photo.jpg", &[0xFF, 0xD8, 0xFF, 0x00]);
        let outcome = sniff_input(input, Arc::new(Policy::builtin()), 0);
        assert_eq!(outcome.mime_type, Some(MimeType::ImageJpeg));
    }

    #[test]
    fn sniff_input_on_unrecognised_bytes_has_no_mime_type() {
        let input = bytes_input("x", b"not a known format");
        let outcome = sniff_input(input, Arc::new(Policy::builtin()), 0);
        assert_eq!(outcome.mime_type, None);
    }

    #[test]
    fn sniff_input_handles_declared_actual_mismatch_without_panicking() {
        let input = bytes_input(
            "fake.jpg",
            &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        );
        let outcome = sniff_input(input, Arc::new(Policy::builtin()), 0);
        assert_eq!(outcome.mime_type, Some(MimeType::ImagePng));
    }
}
