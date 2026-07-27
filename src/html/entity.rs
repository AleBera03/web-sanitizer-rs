//! Minimal HTML entity decoding, scoped to dangerous-scheme detection.
//!
//! This is deliberately **not** a full HTML entity table. Its only job is to
//! make `href`/`src`/`action` values readable enough to spot a `javascript:`
//! or `data:` scheme hiding behind character references — `java&#115;cript:`
//! and `javascript&colon;` must not survive. The decoded string is used for
//! *detection only* and then discarded.

/// Every entry is a character an attacker would use to break
/// up `javascript:`/`data:` or reconstruct the `:` separator. Matched only
/// with a trailing `;` to avoid decoding benign `&amp=…` query fragments.
const NAMED: &[(&str, char)] = &[
    ("colon", ':'),
    ("Tab", '\t'),
    ("NewLine", '\n'),
    ("sol", '/'),
    ("semi", ';'),
    ("lpar", '('),
    ("rpar", ')'),
    ("num", '#'),
    ("period", '.'),
    ("comma", ','),
    ("quot", '"'),
    ("apos", '\''),
    ("amp", '&'),
];

/// Decode HTML character references (numeric decimal/hex and the small named
/// set above) in a single left-to-right pass. Non-entity bytes pass through
/// untouched, so multi-byte UTF-8 and stray `&` are preserved.
pub fn decode_entities(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'&'
            && let Some((ch, consumed)) = decode_one(&bytes[i..])
        {
            let mut buf = [0u8; 4];
            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            i += consumed;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Decode a single entity at the start of `s` (which begins with `&`).
/// Returns the decoded character and how many bytes it consumed, or `None`
/// if `s` does not open a recognised entity.
fn decode_one(s: &[u8]) -> Option<(char, usize)> {
    debug_assert_eq!(s[0], b'&');
    if s.len() < 3 {
        return None;
    }
    if s[1] == b'#' {
        let hex = matches!(s[2], b'x' | b'X');
        let start = if hex { 3 } else { 2 };
        let mut j = start;
        while j < s.len()
            && (if hex {
                s[j].is_ascii_hexdigit()
            } else {
                s[j].is_ascii_digit()
            })
        {
            j += 1;
        }
        if j == start {
            return None;
        }
        let digits = std::str::from_utf8(&s[start..j]).ok()?;
        let code = u32::from_str_radix(digits, if hex { 16 } else { 10 }).ok()?;
        let ch = char::from_u32(code)?;
        let consumed = if s.get(j) == Some(&b';') { j + 1 } else { j };
        return Some((ch, consumed));
    }
    // require the closing `;` so we never eat benign `&amp=…`
    for (name, ch) in NAMED {
        let end = 1 + name.len();
        if s.len() > end && &s[1..end] == name.as_bytes() && s[end] == b';' {
            return Some((*ch, end + 1));
        }
    }
    None
}

/// True if `raw` resolves to a `javascript:` or `data:`
/// scheme after HTML-entity decoding and stripping of whitespace and control characters.
pub fn is_dangerous_scheme(raw: &str) -> bool {
    let decoded = decode_entities(raw);
    let stripped: String = decoded
        .chars()
        .filter(|c| !c.is_whitespace() && !c.is_control())
        .collect();
    let lower = stripped.to_ascii_lowercase();
    lower.starts_with("javascript:") || lower.starts_with("data:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_numeric_reference() {
        assert_eq!(decode_entities("java&#115;cript:x"), "javascript:x");
        assert_eq!(decode_entities("&#106;&#97;va"), "java");
    }

    #[test]
    fn hex_numeric_reference() {
        assert_eq!(decode_entities("&#x6a;avascript:"), "javascript:");
        assert_eq!(decode_entities("&#X3A;"), ":");
    }

    #[test]
    fn numeric_reference_without_semicolon() {
        // `&#115` (no `;`) stops at the non-digit and still decodes to `s`.
        assert_eq!(decode_entities("java&#115cript"), "javascript");
        assert_eq!(decode_entities("&#115no-semi"), "sno-semi");
    }

    #[test]
    fn named_colon_reference() {
        assert_eq!(
            decode_entities("javascript&colon;alert"),
            "javascript:alert"
        );
    }

    #[test]
    fn named_without_semicolon_is_left_alone() {
        // Query fragments like `?amp=1` must not be mangled into `?&=1`.
        assert_eq!(
            decode_entities("http://x/?amp=1&colon=2"),
            "http://x/?amp=1&colon=2"
        );
    }

    #[test]
    fn stray_ampersand_passes_through() {
        assert_eq!(decode_entities("a & b"), "a & b");
        assert_eq!(decode_entities("http://x?a=1&b=2"), "http://x?a=1&b=2");
    }

    #[test]
    fn multibyte_utf8_survives_decoding() {
        assert_eq!(decode_entities("café &#233;"), "café é");
    }

    #[test]
    fn dangerous_plain_schemes() {
        assert!(is_dangerous_scheme("javascript:alert(1)"));
        assert!(is_dangerous_scheme("JavaScript:alert(1)"));
        assert!(is_dangerous_scheme("data:text/html,<script>"));
        assert!(is_dangerous_scheme("  javascript:alert(1)"));
    }

    #[test]
    fn dangerous_schemes_via_entities_and_control_chars() {
        assert!(is_dangerous_scheme("java&#115;cript:alert(1)"));
        assert!(is_dangerous_scheme("javascript&colon;alert(1)"));
        assert!(is_dangerous_scheme("java\tscript:alert(1)"));
        assert!(is_dangerous_scheme("jav\u{0000}ascript:alert(1)"));
        assert!(is_dangerous_scheme("&#x6a;avascript:alert(1)"));
    }

    #[test]
    fn benign_schemes_are_not_flagged() {
        assert!(!is_dangerous_scheme("https://example.com/data:x"));
        assert!(!is_dangerous_scheme("/relative/path"));
        assert!(!is_dangerous_scheme("#anchor"));
        assert!(!is_dangerous_scheme("mailto:a@b.com"));
        assert!(!is_dangerous_scheme("http://example.com/?a=1&amp;b=2"));
    }
}
