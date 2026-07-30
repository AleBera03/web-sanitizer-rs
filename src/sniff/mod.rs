use crate::input::InputSource;

use std::path::Path;
use url::Url;

pub struct AcquiredInput {
    source: InputSource,
    data: Vec<u8>,
}

pub struct SniffOutcome {
    pub source: InputSource,
    pub bytes_in: usize,
    pub bytes_out: usize,
    pub duration_ms: u128,
    pub status: SniffStatus,
    pub actions: Vec<SniffAction>,
    pub error: Option<String>,
}

pub fn sniff_input(input: AcquiredInput, verbose: u8) -> SniffOutcome {
    let declared_mime = read_declared_mime(input, verbose);
    let actual_mime = read_actual_mime(input, verbose);

    if declared_mime != actual_mime {
        //TEMP
        eprintln!(
            "Declared MIME type ({:?}) does not match actual MIME type ({:?}) for source {:?}",
            declared_mime, actual_mime, input.source
        );
    }
    //TODO: return SniffOutcome with actual_mime and other details
}

fn read_declared_mime(input: AcquiredInput, verbose: u8) -> Option<String> {
    //TODO: return + error handling
    match AcquiredInput.source {
        InputSource::Bytes { data, name } => {
            if name.is_not_empty() {
                read_mime_from_bytes(name, verbose);
            }
        }

        InputSource::File { path } => {
            read_mime_from_file(path, verbose);
        }
        InputSource::Url { url } => {
            read_mime_from_url(url, verbose);
        }
    }
}

fn read_actual_mime(
    declared_mime: Option<String>,
    input: AcquiredInput,
    verbose: u8,
) -> Option<String> {
    //TODO: return + error handling
    //TODO: sniff from input.data
}

fn read_mime_from_bytes(name: &str, verbose: u8) -> Option<String> {
    //TODO map extension to mime type?
    Path::new(&name).extension()?.to_str()
}

fn read_mime_from_file(path: &Path, verbose: u8) -> Option<String> {
    //TODO map extension to mime type?
    path.extension()?.to_str()
}

fn read_mime_from_url(url: Url, verbose: u8) -> Option<String> {
    //TODO map extension to mime type?
    let last_segment = url.path_segments()?.next_back()?;
    if last_segment.is_empty() {
        return None;
    }
    Path::new(last_segment).extension()?.to_str()
}
