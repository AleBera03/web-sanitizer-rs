use lopdf::{Dictionary, Document, Object};

const DANGEROUS_KEYS: &[&[u8]] = &[b"JavaScript", b"JS", b"OpenAction", b"AA", b"Launch"];

/// True if any object in the document (dictionary, stream dictionary, or
/// nested array) carries a key associated with active content. Detection
/// only — does not modify `data`. Returns `Some(0)` on a hit (no meaningful
/// byte offset is available once the document is parsed into objects; `0`
/// is the same "whole document" sentinel used elsewhere for file-level
/// findings), `None` if clean or unparsable as a PDF.
pub fn pdf_has_active_content(data: &[u8]) -> Option<usize> {
    let doc = Document::load_mem(data).ok()?;
    let has_marker = doc
        .objects
        .values()
        .any(|obj| object_has_dangerous_keys(obj));
    has_marker.then_some(0)
}

/// Loads `data` as a PDF and strips every dictionary key associated with
/// active content (`/JavaScript`, `/JS`, `/OpenAction`, `/AA`, `/Launch`),
/// walking nested dictionaries, streams, and arrays. Returns `None` if the
/// input can't be parsed as a PDF or re-serialised.
pub fn sanitize_pdf(data: &[u8]) -> Option<Vec<u8>> {
    let mut doc = Document::load_mem(data).ok()?;

    let object_ids: Vec<_> = doc.objects.keys().copied().collect();
    for id in object_ids {
        if let Some(obj) = doc.objects.get_mut(&id) {
            strip_dangerous_keys(obj);
        }
    }

    let mut output = Vec::new();
    doc.save_to(&mut output).ok()?;
    Some(output)
}

fn object_has_dangerous_keys(obj: &Object) -> bool {
    match obj {
        Object::Dictionary(dict) => dict_has_dangerous_keys(dict),
        Object::Stream(stream) => dict_has_dangerous_keys(&stream.dict),
        Object::Array(arr) => arr.iter().any(object_has_dangerous_keys),
        _ => false,
    }
}

fn dict_has_dangerous_keys(dict: &Dictionary) -> bool {
    let direct_hit = DANGEROUS_KEYS.iter().any(|key| dict.has(key));
    direct_hit
        || dict
            .iter()
            .any(|(_, value)| object_has_dangerous_keys(value))
}

fn strip_dangerous_keys(obj: &mut Object) {
    match obj {
        Object::Dictionary(dict) => strip_from_dict(dict),
        Object::Stream(stream) => strip_from_dict(&mut stream.dict),
        Object::Array(arr) => {
            for item in arr.iter_mut() {
                strip_dangerous_keys(item);
            }
        }
        _ => {}
    }
}

fn strip_from_dict(dict: &mut Dictionary) {
    for key in DANGEROUS_KEYS {
        dict.remove(*key);
    }
    for (_, value) in dict.iter_mut() {
        strip_dangerous_keys(value);
    }
}
