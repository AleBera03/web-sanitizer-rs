use std::time::Duration;

use url::Url;
use web_sanitizer::input::InputSource;

use web_sanitizer::fixture::{FixtureServer, Resource};

const ONE_PIXEL_PNG: [u8; 69] = [
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
    0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0x00,
    0x00, 0x03, 0x01, 0x01, 0x00, 0xc9, 0xfe, 0x92, 0xef, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e,
    0x44, 0xae, 0x42, 0x60, 0x82,
];

pub const LATENCY: Duration = Duration::from_millis(2);

// every sub-resource a corpus input can name is answered from here, so a
// fetching run measures the sanitiser rather than somebody else's server
fn by_extension(path: &str) -> Option<Resource> {
    let clean = path.split('?').next().unwrap_or(path);
    match clean.rsplit('.').next().unwrap_or("") {
        "css" => Some(Resource::new(
            "text/css",
            b"body { margin: 0; color: #333; }\n".to_vec(),
        )),
        "js" | "mjs" => Some(Resource::new(
            "text/javascript",
            b"export const ready = true;\n".to_vec(),
        )),
        "png" | "jpg" | "jpeg" | "gif" | "webp" | "avif" | "ico" | "svg" => {
            Some(Resource::new("image/png", ONE_PIXEL_PNG.to_vec()))
        }
        _ => Some(Resource::new("text/plain", b"fixture\n".to_vec())),
    }
}

pub fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "text/javascript",
        "json" => "application/json",
        "svg" => "image/svg+xml",
        "xml" => "application/xml",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "txt" | "md" => "text/plain",
        _ => "application/octet-stream",
    }
}

pub struct Origin {
    server: FixtureServer,
}

impl Origin {
    pub fn start() -> Origin {
        let server = FixtureServer::start_on(LATENCY, "127.0.0.1");
        server.fallback(by_extension);
        Origin { server }
    }

    #[allow(dead_code)]
    pub fn requests(&self) -> usize {
        self.server.hits()
    }

    // an input is published under its own name, and an HTML body has its
    // absolute references pointed back here so nothing leaves the machine
    pub fn publish(&self, name: &str, bytes: &[u8]) -> InputSource {
        let kind = content_type(name);
        let body = match kind == "text/html" {
            true => anchor(&String::from_utf8_lossy(bytes), self.server.base()).into_bytes(),
            false => bytes.to_vec(),
        };
        let path = format!("/corpus/{name}");
        self.server.route(&path, Resource::new(kind, body));
        let url = Url::parse(&self.server.url(&path)).expect("the fixture base is a valid URL");
        InputSource::Url(url)
    }
}

// Only hosts that would otherwise reach the real public web are pointed at the
// fixture. Everything the URL policy exists to catch - IP literals, reserved
// names, look-alike hosts, malformed authorities - is left exactly as written.
const RESERVED: [&str; 4] = [".example", ".invalid", ".test", ".localhost"];

fn should_anchor(authority: &str) -> bool {
    let host = authority.rsplit('@').next().unwrap_or(authority);
    let host = host.split(':').next().unwrap_or(host);
    if host.is_empty() || host.starts_with('[') {
        return false;
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
    {
        return false;
    }
    if !host.contains('.') {
        return false;
    }
    if host
        .split('.')
        .all(|label| !label.is_empty() && label.chars().all(|c| c.is_ascii_digit()))
    {
        return false;
    }
    !RESERVED.iter().any(|suffix| host.ends_with(suffix))
}

// Both spellings of an absolute reference are pointed at the fixture: the full
// `scheme://host/...` and the protocol-relative `//host/...` that resolves
// against the document's own scheme. Missing the second one sends a real
// request to a real host, which is the whole thing this exists to prevent.
fn anchor(page: &str, base: &str) -> String {
    let target = format!("{base}/r/");
    let mut out = String::with_capacity(page.len());
    let mut rest = page;
    while let Some(at) = rest.find("//") {
        let previous = match at {
            0 => out.as_bytes().last().copied(),
            _ => Some(rest.as_bytes()[at - 1]),
        };
        let after = at + 2;
        let host_end = rest[after..]
            .find(['/', '"', '\'', '<', ' '])
            .map(|i| after + i)
            .unwrap_or(rest.len());
        let authority = &rest[after..host_end];

        // `://` belongs to a scheme, anything else is protocol-relative and only
        // counts where an attribute value can start
        let (cut, rewrite) = match previous {
            Some(b':') => {
                let scheme_end = at - 1;
                let scheme_start = rest[..scheme_end]
                    .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '+' && c != '-' && c != '.')
                    .map(|i| i + 1)
                    .unwrap_or(0);
                let scheme = &rest[scheme_start..scheme_end];
                let known =
                    scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https");
                (scheme_start, known && should_anchor(authority))
            }
            Some(b'"') | Some(b'\'') | Some(b'=') | Some(b'(') | Some(b' ') | None => {
                (at, should_anchor(authority))
            }
            _ => (at, false),
        };

        match rewrite {
            true => {
                out.push_str(&rest[..cut]);
                out.push_str(&target);
            }
            false => out.push_str(&rest[..after]),
        }
        rest = &rest[after..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_published_page_is_named_by_its_own_url() {
        let origin = Origin::start();
        let source = origin.publish("a.html", b"<p>hi</p>");
        match source {
            InputSource::Url(url) => {
                assert!(url.as_str().ends_with("/corpus/a.html"), "{url}");
                assert_eq!(url.host_str(), Some("127.0.0.1"));
            }
            _ => panic!("a published input is fetched by URL"),
        }
    }

    #[test]
    fn absolute_references_are_pointed_back_at_the_fixture() {
        let rewritten = anchor(
            "<img src=\"https://cdn.wikimedia.org/a.png\"><a href=\"http://kernel.org/b\">",
            "http://localhost:9",
        );
        assert!(
            rewritten.contains("http://localhost:9/r/cdn.wikimedia.org/a.png"),
            "{rewritten}"
        );
        assert!(
            rewritten.contains("http://localhost:9/r/kernel.org/b"),
            "{rewritten}"
        );
    }

    #[test]
    fn a_reserved_name_is_left_for_the_url_policy_to_catch() {
        let rewritten = anchor(
            "<a href=\"https://evil.example/drop\"><a href=\"https://support@bank.example/x\">",
            "http://localhost:9",
        );
        assert!(
            rewritten.contains("https://evil.example/drop"),
            "{rewritten}"
        );
        assert!(
            rewritten.contains("https://support@bank.example/x"),
            "{rewritten}"
        );
    }

    #[test]
    fn what_the_url_policy_must_see_is_never_rewritten() {
        for authority in [
            "127.0.0.1:8080",
            "169.254.169.254",
            "10.0.0.5",
            "\u{0430}pple.com",
            "[::1::2]:99999",
            "evil.example",
            "support@bank.example",
            "localhost",
        ] {
            assert!(!should_anchor(authority), "{authority} was rewritten");
        }
        for authority in ["cdn.wikimedia.org", "kernel.org", "www.example.org.uk"] {
            assert!(should_anchor(authority), "{authority} was left alone");
        }
    }

    #[test]
    fn a_protocol_relative_reference_is_pointed_at_the_fixture_too() {
        let rewritten = anchor(
            "<img src=\"//upload.wikimedia.org/a.png\"><a href='//el.wikipedia.org/wiki/x'>",
            "http://localhost:9",
        );
        assert!(
            rewritten.contains("http://localhost:9/r/upload.wikimedia.org/a.png"),
            "{rewritten}"
        );
        assert!(
            rewritten.contains("http://localhost:9/r/el.wikipedia.org/wiki/x"),
            "{rewritten}"
        );
        assert!(!rewritten.contains("\"//"), "{rewritten}");
    }

    #[test]
    fn a_double_slash_that_is_not_a_reference_is_left_alone() {
        for text in [
            "<p>see a//b for details</p>",
            "<style>/* a comment // here */</style>",
            "<a href=\"//evil.example/x\">",
        ] {
            let rewritten = anchor(text, "http://localhost:9");
            assert_eq!(rewritten, text, "{text}");
        }
    }

    #[test]
    fn a_scheme_that_is_not_http_is_untouched() {
        let rewritten = anchor(
            "<a href=\"ftp://files.kernel.org/x\">",
            "http://localhost:9",
        );
        assert!(
            rewritten.contains("ftp://files.kernel.org/x"),
            "{rewritten}"
        );
    }

    #[test]
    fn a_body_that_is_not_html_is_published_untouched() {
        let origin = Origin::start();
        let bytes = vec![
            0x89, b'P', b'N', b'G', b'h', b't', b't', b'p', b':', b'/', b'/',
        ];
        let _ = origin.publish("a.png", &bytes);
        assert_eq!(content_type("a.png"), "image/png");
    }

    #[test]
    fn every_type_the_corpus_carries_has_a_content_type() {
        for (name, expected) in [
            ("a.html", "text/html"),
            ("a.css", "text/css"),
            ("a.js", "text/javascript"),
            ("a.svg", "image/svg+xml"),
            ("a.xml", "application/xml"),
            ("a.pdf", "application/pdf"),
            ("a.zip", "application/zip"),
            ("a.png", "image/png"),
        ] {
            assert_eq!(content_type(name), expected, "{name}");
        }
    }

    #[test]
    fn an_unknown_reference_still_gets_an_answer() {
        assert!(by_extension("/r/x.css").is_some());
        assert!(by_extension("/r/x.png?v=2").is_some());
        assert!(by_extension("/r/whatever").is_some());
    }
}
