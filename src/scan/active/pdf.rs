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

#[cfg(test)]
mod tests {
    use super::*;

    fn serialized_document(objects: impl IntoIterator<Item = Object>) -> Vec<u8> {
        let mut document = Document::with_version("1.7");
        for object in objects {
            document.add_object(object);
        }

        let mut output = Vec::new();
        document.save_to(&mut output).unwrap();
        output
    }

    fn dictionary_with_key(key: &[u8]) -> Object {
        let mut dictionary = Dictionary::new();
        dictionary.set(key, Object::Boolean(true));
        Object::Dictionary(dictionary)
    }

    #[test]
    fn clean_pdf_is_not_reported() {
        let data = serialized_document([Object::Dictionary(Dictionary::from_iter([
            (b"Type", Object::Name(b"Catalog".to_vec())),
        ]))]);

        assert_eq!(pdf_has_active_content(&data), None);
    }

    #[test]
    fn every_dangerous_key_is_detected() {
        for key in DANGEROUS_KEYS {
            let data = serialized_document([dictionary_with_key(key)]);

            assert_eq!(pdf_has_active_content(&data), Some(0), "key {:?}", key);
        }
    }

    #[test]
    fn dangerous_keys_are_detected_in_nested_arrays_and_dictionaries() {
        let mut nested_dictionary = Dictionary::new();
        nested_dictionary.set(b"JS", Object::Boolean(true));

        let nested = Object::Array(vec![Object::Dictionary(Dictionary::from_iter([
            (
                b"Nested".to_vec(),
                Object::Dictionary(nested_dictionary),
            ),
        ]))]);
        let mut outer = Dictionary::new();
        outer.set(b"Contents", nested);
        let data = serialized_document([Object::Dictionary(outer)]);

        assert_eq!(pdf_has_active_content(&data), Some(0));
    }

    #[test]
    fn dangerous_keys_are_detected_in_stream_dictionaries() {
        let mut stream_dictionary = Dictionary::new();
        stream_dictionary.set(b"OpenAction", Object::Boolean(true));
        let data = serialized_document([Object::Stream(lopdf::Stream::new(
            stream_dictionary,
            Vec::new(),
        ))]);

        assert_eq!(pdf_has_active_content(&data), Some(0));
    }

    #[test]
    fn invalid_pdf_is_not_reported_or_sanitized() {
        let data = b"not a PDF";

        assert_eq!(pdf_has_active_content(data), None);
        assert_eq!(sanitize_pdf(data), None);
    }

    #[test]
    fn sanitizing_removes_dangerous_keys_recursively() {
        let mut nested_dictionary = Dictionary::new();
        nested_dictionary.set(b"Launch", Object::Boolean(true));

        let mut stream_dictionary = Dictionary::new();
        stream_dictionary.set(b"AA", Object::Boolean(true));
        stream_dictionary.set(
            b"Nested",
            Object::Array(vec![Object::Dictionary(nested_dictionary)]),
        );

        let mut root = Dictionary::new();
        root.set(b"JavaScript", Object::Boolean(true));
        root.set(
            b"Stream",
            Object::Stream(lopdf::Stream::new(stream_dictionary, Vec::new())),
        );
        let data = serialized_document([Object::Dictionary(root)]);
        let sanitized = sanitize_pdf(&data).unwrap();

        assert_eq!(pdf_has_active_content(&sanitized), None);
        assert!(sanitized.len() > 0);
    }

    #[test]
    fn sanitizing_does_not_modify_input() {
        let data = serialized_document([dictionary_with_key(b"JS")]);
        let original = data.clone();

        let _ = sanitize_pdf(&data);

        assert_eq!(data, original);
    }
}
