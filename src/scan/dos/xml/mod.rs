use std::collections::{HashMap, HashSet};

use crate::scan::utilities::find_bytes;

// constants - declaration to look for in the XML content to detect potential XXE attacks
const XML_ENTITY_DECL: &[u8] = b"<!ENTITY";
const XML_ENTITY_SYSTEM: &[u8] = b"SYSTEM";
const XML_ENTITY_PUBLIC: &[u8] = b"PUBLIC";
// constants - limits for the XML entity expansion to prevent DoS attacks (spostare dentro policy?)
const MAX_ENTITY_DEPTH: usize = 20;
const MAX_EXPANDED_SIZE: u64 = 10 * 1024 * 1024; // 10 MiB, arbitrary sane cap
const MAX_ENTITY_COUNT: usize = 10_000;

const XML_ACTIVE_CONTENT_MARKERS: &[&[u8]] =
    &[XML_ENTITY_DECL, XML_ENTITY_SYSTEM, XML_ENTITY_PUBLIC];

pub fn xml_has_active_content(data: &[u8]) -> Option<usize> {
    XML_ACTIVE_CONTENT_MARKERS
        .iter()
        .find_map(|marker| find_bytes(data, marker))
}

fn skip_whitespace(data: &[u8], mut pos: usize) -> Option<usize> {
    while pos < data.len() && data[pos].is_ascii_whitespace() {
        pos += 1;
    }
    (pos < data.len()).then_some(pos)
}

fn read_token(data: &[u8], start: usize) -> Option<(&[u8], usize)> {
    let len = data[start..].iter().position(|b| b.is_ascii_whitespace())?;
    Some((&data[start..start + len], start + len))
}

fn read_quoted(data: &[u8], pos: usize) -> Option<(&[u8], usize)> {
    let quote = *data.get(pos)?;
    if quote != b'"' && quote != b'\'' {
        return None;
    }
    let content_start = pos + 1;
    let len = data[content_start..].iter().position(|&b| b == quote)?;
    Some((
        &data[content_start..content_start + len],
        content_start + len + 1,
    ))
}

/// Extracts internal entity declarations (`<!ENTITY name "value">`) into a
/// name → replacement-text map. External entities (`SYSTEM`/`PUBLIC`) are
/// skipped: they reference outside resources, not part of in-file expansion.
fn parse_entities(data: &[u8]) -> Option<HashMap<Vec<u8>, Vec<u8>>> {
    let mut entities = HashMap::new();
    let mut pos = 0;

    while let Some(rel) = find_bytes(&data[pos..], XML_ENTITY_DECL) {
        let after_decl = pos + rel + XML_ENTITY_DECL.len();
        let Some(after_ws) = skip_whitespace(data, after_decl) else {
            break;
        };
        let Some((name, after_name)) = read_token(data, after_ws) else {
            break;
        };
        let Some(after_name_ws) = skip_whitespace(data, after_name) else {
            break;
        };

        if data[after_name_ws..].starts_with(XML_ENTITY_SYSTEM)
            || data[after_name_ws..].starts_with(XML_ENTITY_PUBLIC)
        {
            pos = after_name_ws;
            continue;
        }

        let Some((value, after_value)) = read_quoted(data, after_name_ws) else {
            pos = after_name_ws;
            continue;
        };

        entities.insert(name.to_vec(), value.to_vec());
        pos = after_value;

        if entities.len() > MAX_ENTITY_COUNT {
            return None;
        }
    }

    Some(entities)
}

/// Recursively computes the expanded byte size of `name`'s replacement text,
/// bailing out (`None`) on a cycle, excessive depth, or a size past the cap.
fn expanded_size(
    name: &[u8],
    entities: &HashMap<Vec<u8>, Vec<u8>>,
    visiting: &mut HashSet<Vec<u8>>,
    depth: usize,
) -> Option<u64> {
    if depth > MAX_ENTITY_DEPTH {
        return None;
    }
    if !visiting.insert(name.to_vec()) {
        return None; // cycle: this entity is already being expanded up the call chain
    }

    let Some(value) = entities.get(name) else {
        visiting.remove(name);
        return Some(0); // undeclared reference: nothing further to expand
    };

    let mut size: u64 = 0;
    let mut pos = 0;
    while let Some(rel) = find_bytes(&value[pos..], b"&") {
        let amp = pos + rel;
        size += (amp - pos) as u64;

        let Some(semi_rel) = value[amp + 1..].iter().position(|&b| b == b';') else {
            size += (value.len() - amp) as u64;
            pos = value.len();
            break;
        };
        let ref_name = &value[amp + 1..amp + 1 + semi_rel];

        let Some(sub) = expanded_size(ref_name, entities, visiting, depth + 1) else {
            visiting.remove(name);
            return None;
        };
        size += sub;
        if size > MAX_EXPANDED_SIZE {
            visiting.remove(name);
            return None;
        }
        pos = amp + 1 + semi_rel + 1;
    }
    size += (value.len() - pos) as u64;

    visiting.remove(name);
    (size <= MAX_EXPANDED_SIZE).then_some(size)
}

pub fn xml_has_dos_risk(data: &[u8]) -> Option<usize> {
    let Some(entities) = parse_entities(data) else {
        return Some(0);
    };

    entities.iter().find_map(|(name, _)| {
        let mut visiting = HashSet::new();
        expanded_size(name, &entities, &mut visiting, 0)
            .is_none()
            .then_some(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xml_doc(inner: &str) -> Vec<u8> {
        format!("<?xml version=\"1.0\"?><root>{inner}</root>").into_bytes()
    }

    #[test]
    fn xml_has_active_content_detects_entity_declarations() {
        let payload = br#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x "hello">]><root>&x;</root>"#;
        assert_eq!(xml_has_active_content(payload), Some(0));
    }

    #[test]
    fn xml_has_active_content_ignores_plain_xml() {
        let payload = xml_doc("safe content");
        assert_eq!(xml_has_active_content(&payload), None);
    }

    #[test]
    fn xml_has_active_content_detects_external_entity_markers() {
        let payload = br#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY x SYSTEM "file:///etc/passwd">]><root/>"#;
        assert_eq!(xml_has_active_content(payload), Some(0));
    }

    #[test]
    fn xml_has_dos_risk_returns_none_for_safe_xml() {
        let payload = xml_doc("normal-text");
        assert_eq!(xml_has_dos_risk(&payload), None);
    }

    #[test]
    fn xml_has_dos_risk_detects_recursive_entity_expansion() {
        let payload = br#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY a "&b;"> <!ENTITY b "&a;">]><root>&a;</root>"#;
        assert_eq!(xml_has_dos_risk(payload), Some(0));
    }

    #[test]
    fn xml_has_dos_risk_treats_malformed_entity_blocks_as_risky() {
        let payload = br#"<?xml version="1.0"?><!DOCTYPE root [<!ENTITY a "&b;"> <!ENTITY b "&a;">]"#;
        assert_eq!(xml_has_dos_risk(payload), Some(0));
    }
}
