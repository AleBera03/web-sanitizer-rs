use crate::input::InputSource;
use crate::policy::{Action, SubresourcesRules};
use crate::report::{Location, SanitisationAction};
use crate::scan::dos::zip::{OoxmlKind, zip_ooxml_kind};
use crate::sniff::MimeType::{
    ApplicationPdf, ApplicationXml, ApplicationZip, AudioFlac, AudioMp3, AudioWav, ExcelXlsx,
    ImageGif, ImageJpeg, ImagePng, ImageSvg, ImageTiff, ImageWebp, PowerPointPptx, TextCss,
    TextHtml, TextJavascript, VideoAvi, VideoMp4, WordDocx,
};

use std::path::Path;
use url::Url;

// CONSTANTS
// magic numbers for sniffing file types
const JPEG: &[u8] = &[0xFF, 0xD8, 0xFF];
const PNG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
const GIF87A: &[u8] = b"GIF87a";
const GIF89A: &[u8] = b"GIF89a";
const HTML_DOCTYPE: &[u8] = b"<!DOCTYPE html>";
const HTML_DOCTYPE_CASE: &[u8] = b"<!doctype html>";
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
    TextCss,
    TextJavascript,
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
    /// The name that goes into a report, the same string a server would send
    /// as `Content-Type`.
    pub fn label(self) -> &'static str {
        match self {
            MimeType::ImageJpeg => "image/jpeg",
            MimeType::ImagePng => "image/png",
            MimeType::ImageGif => "image/gif",
            MimeType::ImageWebp => "image/webp",
            MimeType::ImageSvg => "image/svg+xml",
            MimeType::ImageTiff => "image/tiff",
            MimeType::TextHtml => "text/html",
            MimeType::TextCss => "text/css",
            MimeType::TextJavascript => "text/javascript",
            MimeType::ApplicationPdf => "application/pdf",
            MimeType::ApplicationZip => "application/zip",
            MimeType::ApplicationXml => "application/xml",
            MimeType::AudioFlac => "audio/flac",
            MimeType::AudioMp3 => "audio/mpeg",
            MimeType::AudioWav => "audio/wav",
            MimeType::VideoAvi => "video/x-msvideo",
            MimeType::VideoMp4 => "video/mp4",
            MimeType::WordDocx => {
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
            }
            MimeType::ExcelXlsx => {
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            }
            MimeType::PowerPointPptx => {
                "application/vnd.openxmlformats-officedocument.presentationml.presentation"
            }
            MimeType::WordDoc => "application/msword",
            MimeType::ExcelXls => "application/vnd.ms-excel",
            MimeType::PowerPointPpt => "application/vnd.ms-powerpoint",
        }
    }

    /// Canonical file extension of the type, without the dot. Callers that
    /// write a sniffed body to disk name it from this, never from a URL.
    pub fn extension(self) -> &'static str {
        match self {
            MimeType::ImageJpeg => "jpg",
            MimeType::ImagePng => "png",
            MimeType::ImageGif => "gif",
            MimeType::ImageWebp => "webp",
            MimeType::ImageSvg => "svg",
            MimeType::ImageTiff => "tiff",
            MimeType::TextHtml => "html",
            MimeType::TextCss => "css",
            MimeType::TextJavascript => "js",
            MimeType::ApplicationPdf => "pdf",
            MimeType::ApplicationZip => "zip",
            MimeType::ApplicationXml => "xml",
            MimeType::AudioFlac => "flac",
            MimeType::AudioMp3 => "mp3",
            MimeType::AudioWav => "wav",
            MimeType::VideoAvi => "avi",
            MimeType::VideoMp4 => "mp4",
            MimeType::WordDocx => "docx",
            MimeType::ExcelXlsx => "xlsx",
            MimeType::PowerPointPptx => "pptx",
            MimeType::WordDoc => "doc",
            MimeType::ExcelXls => "xls",
            MimeType::PowerPointPpt => "ppt",
        }
    }
}

pub struct AcquiredInput {
    pub source: InputSource,
    pub data: Vec<u8>,
    pub declared_mime: Option<String>,
}

impl AcquiredInput {
    pub fn new(source: InputSource, data: Vec<u8>) -> Self {
        Self {
            source,
            data,
            declared_mime: None,
        }
    }

    /// Records the `Content-Type` the server sent.
    pub fn declaring(mut self, header: Option<String>) -> Self {
        self.declared_mime = header;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MimeVerdict {
    pub declared: Option<MimeType>,
    pub sniffed: Option<MimeType>,
}

impl MimeVerdict {
    pub fn effective(self) -> Option<MimeType> {
        self.sniffed.or(self.declared)
    }

    pub fn contradicted(self) -> bool {
        matches!((self.declared, self.sniffed), (Some(d), Some(s)) if d != s)
    }
}

pub struct SniffOutcome {
    pub data: Vec<u8>,
    pub verdict: MimeVerdict,
    pub actions: Vec<SanitisationAction>,
}

impl SniffOutcome {
    pub fn mime_type(&self) -> Option<MimeType> {
        self.verdict.effective()
    }
}

pub fn sniff_input(input: AcquiredInput, rules: &SubresourcesRules, verbose: u8) -> SniffOutcome {
    let _ = verbose;
    let verdict = MimeVerdict {
        declared: read_declared_mime(&input),
        sniffed: read_actual_mime(&input, &rules.zip_budget),
    };

    let actions = match verdict.contradicted() {
        true => vec![mismatch_action(verdict)],
        false => Vec::new(),
    };

    SniffOutcome {
        data: input.data,
        verdict,
        actions,
    }
}

fn mismatch_action(verdict: MimeVerdict) -> SanitisationAction {
    let (declared, sniffed) = match (verdict.declared, verdict.sniffed) {
        (Some(d), Some(s)) => (d.label(), s.label()),
        _ => ("unknown", "unknown"),
    };
    SanitisationAction {
        rule_id: "sniff.mime_mismatch".to_string(),
        category: "sniff".to_string(),
        location: Location {
            line: 0,
            byte_offset: 0,
        },
        original: format!("declared={declared} sniffed={sniffed}"),
        action: Action::Rewrite,
        replacement: None,
    }
}

fn read_declared_mime(input: &AcquiredInput) -> Option<MimeType> {
    if let Some(mime) = input
        .declared_mime
        .as_deref()
        .and_then(mime_from_content_type)
    {
        return Some(mime);
    }
    mime_from_extension(read_extension(&input.source)?)
}

fn read_extension(source: &InputSource) -> Option<&str> {
    match source {
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
    }
}

// TODO: riordinare i tipi per macrotipi così rimane più leggibile
fn read_actual_mime(
    input: &AcquiredInput,
    zip_budget: &crate::policy::ZipBudgets,
) -> Option<MimeType> {
    if input.data.starts_with(JPEG) {
        Some(ImageJpeg)
    } else if input.data.starts_with(PNG) {
        Some(ImagePng)
    } else if input.data.starts_with(GIF87A) || input.data.starts_with(GIF89A) {
        Some(ImageGif)
    } else if input.data.starts_with(HTML_DOCTYPE) || input.data.starts_with(HTML_DOCTYPE_CASE) {
        Some(TextHtml)
    } else if input.data.starts_with(PDF) {
        Some(ApplicationPdf)
    } else if input.data.starts_with(TIFF_LE) || input.data.starts_with(TIFF_BE) {
        Some(ImageTiff)
    } else if input.data.starts_with(ZIP_OOXML) {
        match zip_ooxml_kind(&input.data, zip_budget) {
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
    // TEMP: the length check used to be `> MP4_FTYP_OFFSET` while the slice
    // needs 8 bytes, so any input of 5..7 bytes panicked. `get` states the same
    // condition without indexing out of range.
    } else if input
        .data
        .get(MP4_FTYP_OFFSET..MP4_FTYP_OFFSET + MP4_FTYP.len())
        == Some(MP4_FTYP)
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
        "css" => Some(TextCss),
        "js" | "mjs" => Some(TextJavascript),
        "pdf" => Some(ApplicationPdf),
        "tif" | "tiff" => Some(ImageTiff),
        "zip" => Some(ApplicationZip),
        "xml" => Some(ApplicationXml),
        "flac" => Some(AudioFlac),
        "mp3" => Some(AudioMp3),
        "wav" => Some(AudioWav),
        "avi" => Some(VideoAvi),
        "mp4" => Some(VideoMp4),
        "docx" => Some(WordDocx),
        "xlsx" => Some(ExcelXlsx),
        "pptx" => Some(PowerPointPptx),
        _ => None,
    }
}

/// The type a `Content-Type` header declares.
/// Parameters such as `; charset=utf-8` are dropped.
pub fn mime_from_content_type(header: &str) -> Option<MimeType> {
    let essence = header
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match essence.as_str() {
        "image/jpeg" | "image/jpg" => Some(ImageJpeg),
        "image/png" => Some(ImagePng),
        "image/gif" => Some(ImageGif),
        "image/webp" => Some(ImageWebp),
        "image/svg+xml" => Some(ImageSvg),
        "image/tiff" => Some(ImageTiff),
        "text/html" | "application/xhtml+xml" => Some(TextHtml),
        "text/css" => Some(TextCss),
        "text/javascript"
        | "application/javascript"
        | "application/x-javascript"
        | "text/ecmascript"
        | "application/ecmascript"
        | "text/jscript"
        | "text/livescript" => Some(TextJavascript),
        "application/pdf" => Some(ApplicationPdf),
        "application/zip" => Some(ApplicationZip),
        "application/xml" | "text/xml" => Some(ApplicationXml),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use crate::policy::ZipBudgets;
    use std::path::PathBuf;

    use super::*;

    fn budget() -> ZipBudgets {
        ZipBudgets::default()
    }

    fn bytes_input(name: &str, data: &[u8]) -> AcquiredInput {
        AcquiredInput::new(
            InputSource::Bytes {
                name: name.to_string(),
                data: data.to_vec(),
            },
            data.to_vec(),
        )
    }

    fn file_input(path: &str, data: &[u8]) -> AcquiredInput {
        AcquiredInput::new(InputSource::File(PathBuf::from(path)), data.to_vec())
    }

    fn url_input(url: &str, data: &[u8]) -> AcquiredInput {
        AcquiredInput::new(InputSource::Url(Url::parse(url).unwrap()), data.to_vec())
    }

    fn served(mime: Option<&str>, data: &[u8]) -> AcquiredInput {
        url_input("https://example.com/resource", data).declaring(mime.map(String::from))
    }

    #[test]
    fn detects_jpeg_from_magic_bytes() {
        let input = bytes_input("x", &[0xFF, 0xD8, 0xFF, 0x00]);
        assert_eq!(
            read_actual_mime(&input, &budget()),
            Some(MimeType::ImageJpeg)
        );
    }

    #[test]
    fn detects_png_from_magic_bytes() {
        let input = bytes_input("x", &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        assert_eq!(
            read_actual_mime(&input, &budget()),
            Some(MimeType::ImagePng)
        );
    }

    #[test]
    fn detects_gif87a_and_gif89a() {
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"GIF87a..."), &budget()),
            Some(MimeType::ImageGif)
        );
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"GIF89a..."), &budget()),
            Some(MimeType::ImageGif)
        );
    }

    #[test]
    fn detects_html_doctype() {
        let input = bytes_input("x", b"<!DOCTYPE html><html></html>");
        assert_eq!(
            read_actual_mime(&input, &budget()),
            Some(MimeType::TextHtml)
        );
    }

    #[test]
    fn detects_pdf() {
        let input = bytes_input("x", b"%PDF-1.7 ...");
        assert_eq!(
            read_actual_mime(&input, &budget()),
            Some(MimeType::ApplicationPdf)
        );
    }

    #[test]
    fn detects_tiff_little_and_big_endian() {
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"II*\0..."), &budget()),
            Some(MimeType::ImageTiff)
        );
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"MM\0*..."), &budget()),
            Some(MimeType::ImageTiff)
        );
    }

    #[test]
    fn detects_zip_ooxml() {
        let input = bytes_input("x", &[0x50, 0x4B, 0x03, 0x04, 0x00]);
        assert_eq!(
            read_actual_mime(&input, &budget()),
            Some(MimeType::ApplicationZip)
        );
    }

    #[test]
    fn detects_flac_mp3_wav_avi_and_mp4() {
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"fLaC\x00\x00\x00"), &budget()),
            Some(MimeType::AudioFlac)
        );
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"ID3\x03\x00\x00"), &budget()),
            Some(MimeType::AudioMp3)
        );
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"\xFF\xFB\x90\x00\x00"), &budget()),
            Some(MimeType::AudioMp3)
        );
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"RIFF\x24\x00\x00\x00WAVE"), &budget()),
            Some(MimeType::AudioWav)
        );
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"AVI "), &budget()),
            Some(MimeType::VideoAvi)
        );
        assert_eq!(
            read_actual_mime(&bytes_input("x", b"\x00\x00\x00\x00ftypmp41"), &budget()),
            Some(MimeType::VideoMp4)
        );
    }

    #[test]
    fn detects_xml_and_svg() {
        assert_eq!(
            read_actual_mime(
                &bytes_input("x", b"<?xml version=\"1.0\"?><root/>"),
                &budget()
            ),
            Some(MimeType::ApplicationXml)
        );
        assert_eq!(
            read_actual_mime(
                &bytes_input("x", b"<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>"),
                &budget()
            ),
            Some(MimeType::ImageSvg)
        );
    }

    #[test]
    fn unrecognised_bytes_yield_none() {
        let input = bytes_input("x", b"not a known format");
        assert_eq!(read_actual_mime(&input, &budget()), None);
    }

    // ---- declared MIME (extension-based) -----------------------------------
    // (invariati: read_declared_mime non prende zip_budget, nessuna modifica qui sotto)

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
        let input = AcquiredInput::new(
            InputSource::MalformedUrl("ht!tp://broken".to_string()),
            Vec::new(),
        );
        assert_eq!(read_declared_mime(&input), None);
    }

    #[test]
    fn declared_mime_supports_css_and_javascript_extensions() {
        assert_eq!(
            read_declared_mime(&bytes_input("site.css", b"")),
            Some(MimeType::TextCss)
        );
        assert_eq!(
            read_declared_mime(&bytes_input("app.js", b"")),
            Some(MimeType::TextJavascript)
        );
        assert_eq!(
            read_declared_mime(&bytes_input("app.mjs", b"")),
            Some(MimeType::TextJavascript)
        );
    }

    // ---- declared MIME (header-based) ----------------------------------------

    #[test]
    fn the_header_declares_before_the_extension() {
        let input =
            url_input("https://example.com/logo.png", b"").declaring(Some("image/gif".to_string()));
        assert_eq!(read_declared_mime(&input), Some(MimeType::ImageGif));
    }

    #[test]
    fn an_unknown_header_falls_back_to_the_extension() {
        let input = url_input("https://example.com/logo.png", b"")
            .declaring(Some("application/octet-stream".to_string()));
        assert_eq!(read_declared_mime(&input), Some(MimeType::ImagePng));
    }

    #[test]
    fn no_header_and_no_extension_declare_nothing() {
        assert_eq!(read_declared_mime(&served(None, b"")), None);
    }

    #[test]
    fn declared_mime_is_case_insensitive() {
        let input = bytes_input("IMAGE.PNG", b"");
        assert_eq!(read_declared_mime(&input), Some(MimeType::ImagePng));
    }

    #[test]
    fn declared_mime_supports_svg_html_pdf_and_media_extensions() {
        assert_eq!(
            read_declared_mime(&bytes_input("page.html", b"")),
            Some(MimeType::TextHtml)
        );
        assert_eq!(
            read_declared_mime(&bytes_input("doc.pdf", b"")),
            Some(MimeType::ApplicationPdf)
        );
        assert_eq!(
            read_declared_mime(&bytes_input("icon.svg", b"")),
            Some(MimeType::ImageSvg)
        );
        assert_eq!(
            read_declared_mime(&bytes_input("song.flac", b"")),
            Some(MimeType::AudioFlac)
        );
        assert_eq!(
            read_declared_mime(&bytes_input("track.mp3", b"")),
            Some(MimeType::AudioMp3)
        );
        assert_eq!(
            read_declared_mime(&bytes_input("clip.wav", b"")),
            Some(MimeType::AudioWav)
        );
        assert_eq!(
            read_declared_mime(&bytes_input("video.mp4", b"")),
            Some(MimeType::VideoMp4)
        );
        assert_eq!(
            read_declared_mime(&bytes_input("data.xml", b"")),
            Some(MimeType::ApplicationXml)
        );
    }

    #[test]
    fn unrecognised_extension_is_none() {
        let input = bytes_input("archive.rar", b"");
        assert_eq!(read_declared_mime(&input), None);
    }

    // ---- the verdict ---------------------------------------------------------

    #[test]
    fn a_signature_is_the_effective_type() {
        let verdict = MimeVerdict {
            declared: None,
            sniffed: Some(MimeType::ImageJpeg),
        };
        assert_eq!(verdict.effective(), Some(MimeType::ImageJpeg));
        assert!(!verdict.contradicted());
    }

    #[test]
    fn a_declaration_fills_the_gap_a_signature_leaves() {
        let verdict = MimeVerdict {
            declared: Some(MimeType::TextJavascript),
            sniffed: None,
        };
        assert_eq!(verdict.effective(), Some(MimeType::TextJavascript));
        assert!(!verdict.contradicted());
    }

    #[test]
    fn a_signature_beats_a_declaration_that_disagrees() {
        let verdict = MimeVerdict {
            declared: Some(MimeType::ImagePng),
            sniffed: Some(MimeType::TextHtml),
        };
        assert_eq!(verdict.effective(), Some(MimeType::TextHtml));
        assert!(verdict.contradicted());
    }

    #[test]
    fn two_agreeing_sources_are_no_contradiction() {
        let verdict = MimeVerdict {
            declared: Some(MimeType::ImagePng),
            sniffed: Some(MimeType::ImagePng),
        };
        assert!(!verdict.contradicted());
    }

    #[test]
    fn nothing_known_is_no_type_and_no_contradiction() {
        let verdict = MimeVerdict {
            declared: None,
            sniffed: None,
        };
        assert_eq!(verdict.effective(), None);
        assert!(!verdict.contradicted());
    }

    // ---- sniff_input ---------------------------------------------------------

    #[test]
    fn sniff_input_reports_detected_mime_type() {
        let input = bytes_input("photo.jpg", &[0xFF, 0xD8, 0xFF, 0x00]);
        let rules = SubresourcesRules::default();
        let outcome = sniff_input(input, &rules, 0);
        assert_eq!(outcome.mime_type(), Some(MimeType::ImageJpeg));
        assert!(outcome.actions.is_empty());
    }

    #[test]
    fn sniff_input_on_unrecognised_bytes_has_no_mime_type() {
        let input = bytes_input("x", b"not a known format");
        let rules = SubresourcesRules::default();
        let outcome = sniff_input(input, &rules, 0);
        assert_eq!(outcome.mime_type(), None);
        assert_eq!(outcome.verdict.sniffed, None);
    }

    #[test]
    fn a_contradiction_is_recorded_and_the_bytes_are_kept() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let input = bytes_input("fake.jpg", &png);
        let rules = SubresourcesRules::default();
        let outcome = sniff_input(input, &rules, 0);
        assert_eq!(outcome.mime_type(), Some(MimeType::ImagePng));
        assert_eq!(outcome.data, png);
        assert_eq!(outcome.actions.len(), 1);
        assert_eq!(outcome.actions[0].rule_id, "sniff.mime_mismatch");
        assert_eq!(outcome.actions[0].action, Action::Rewrite);
        assert_eq!(
            outcome.actions[0].original,
            "declared=image/jpeg sniffed=image/png"
        );
    }

    #[test]
    fn a_generic_declaration_does_not_hide_the_sniffed_type() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let outcome = sniff_input(
            served(Some("application/octet-stream"), &png),
            &SubresourcesRules::default(),
            0,
        );
        assert_eq!(outcome.mime_type(), Some(MimeType::ImagePng));
        assert_eq!(outcome.verdict.declared, None);
        assert!(outcome.actions.is_empty());
    }

    #[test]
    fn an_unsniffable_body_takes_the_declared_type() {
        let outcome = sniff_input(
            served(Some("text/javascript"), b"This is just plain text."),
            &SubresourcesRules::default(),
            0,
        );
        assert_eq!(outcome.verdict.sniffed, None);
        assert_eq!(outcome.mime_type(), Some(MimeType::TextJavascript));
        assert!(outcome.actions.is_empty());
    }

    #[test]
    fn a_signature_overrules_a_script_declaration() {
        let png = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let outcome = sniff_input(
            served(Some("text/javascript"), &png),
            &SubresourcesRules::default(),
            0,
        );
        assert_eq!(outcome.mime_type(), Some(MimeType::ImagePng));
        assert_eq!(outcome.actions[0].rule_id, "sniff.mime_mismatch");
    }

    #[test]
    fn html_declared_as_an_image_is_still_html() {
        let outcome = sniff_input(
            served(Some("image/png"), b"<!doctype html><script>1</script>"),
            &SubresourcesRules::default(),
            0,
        );
        assert_eq!(outcome.mime_type(), Some(MimeType::TextHtml));
        assert_eq!(outcome.actions.len(), 1);
    }

    #[test]
    fn html_without_a_doctype_is_html_when_declared() {
        let outcome = sniff_input(
            served(
                Some("text/html; charset=utf-8"),
                b"<html><script>1</script></html>",
            ),
            &SubresourcesRules::default(),
            0,
        );
        assert_eq!(outcome.verdict.sniffed, None);
        assert_eq!(outcome.mime_type(), Some(MimeType::TextHtml));
    }

    #[test]
    fn an_empty_body_with_no_declaration_has_no_type() {
        let outcome = sniff_input(served(None, b""), &SubresourcesRules::default(), 0);
        assert_eq!(outcome.mime_type(), None);
        assert!(outcome.data.is_empty());
    }

    // ---- labels, extensions, content types ---------------------------------

    #[test]
    fn a_label_is_a_content_type_a_server_could_have_sent() {
        assert_eq!(MimeType::ImagePng.label(), "image/png");
        assert_eq!(MimeType::TextHtml.label(), "text/html");
    }

    #[test]
    fn every_type_has_a_non_empty_extension_without_a_dot() {
        for mime in [
            MimeType::ImageJpeg,
            MimeType::ImagePng,
            MimeType::ImageSvg,
            MimeType::TextHtml,
            MimeType::ApplicationPdf,
            MimeType::ApplicationZip,
            MimeType::WordDocx,
            MimeType::VideoMp4,
        ] {
            let ext = mime.extension();
            assert!(!ext.is_empty());
            assert!(!ext.contains('.'));
            assert!(!ext.contains('/'));
        }
    }

    #[test]
    fn a_content_type_is_read_without_its_parameters() {
        assert_eq!(
            mime_from_content_type("text/html; charset=utf-8"),
            Some(MimeType::TextHtml)
        );
        assert_eq!(
            mime_from_content_type("  IMAGE/PNG  "),
            Some(MimeType::ImagePng)
        );
        assert_eq!(mime_from_content_type("text/css"), Some(MimeType::TextCss));
        assert_eq!(mime_from_content_type("application/octet-stream"), None);
        assert_eq!(mime_from_content_type(""), None);
        assert_eq!(mime_from_content_type(";charset=utf-8"), None);
    }

    #[test]
    fn every_javascript_spelling_is_understood() {
        for header in [
            "text/javascript",
            "text/javascript; charset=utf-8",
            "application/javascript",
            "application/x-javascript",
            "text/ecmascript",
            "application/ecmascript",
            "text/jscript",
            "text/livescript",
            "TEXT/JAVASCRIPT",
        ] {
            assert_eq!(
                mime_from_content_type(header),
                Some(MimeType::TextJavascript),
                "{header}"
            );
        }
    }

    #[test]
    fn text_types_have_labels_and_extensions() {
        assert_eq!(MimeType::TextJavascript.label(), "text/javascript");
        assert_eq!(MimeType::TextJavascript.extension(), "js");
        assert_eq!(MimeType::TextCss.label(), "text/css");
        assert_eq!(MimeType::TextCss.extension(), "css");
    }
}
