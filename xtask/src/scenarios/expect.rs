use std::collections::BTreeMap;

pub const SECRET: &str = "s3cr3t-harness-token";
pub const SENTINEL: &str = "ssrf-sentinel";

pub struct Expectation {
    pub http: &'static [u16],
    pub status: &'static [&'static str],
    pub rules: &'static [&'static str],
    pub forbidden: &'static [&'static str],
    pub sniffed: Option<&'static str>,
    pub max_wall_ms: Option<u128>,
}

impl Expectation {
    const fn new(
        http: &'static [u16],
        status: &'static [&'static str],
        rules: &'static [&'static str],
        forbidden: &'static [&'static str],
    ) -> Expectation {
        Expectation {
            http,
            status,
            rules,
            forbidden,
            sniffed: None,
            max_wall_ms: None,
        }
    }

    const fn sniffing(mut self, mime: &'static str) -> Expectation {
        self.sniffed = Some(mime);
        self
    }

    const fn within(mut self, millis: u128) -> Expectation {
        self.max_wall_ms = Some(millis);
        self
    }
}

pub struct FetchExpectation {
    pub max_attempted: Option<usize>,
    pub min_budget_exceeded: Option<usize>,
    pub blocked: &'static [&'static str],
    pub forbidden: &'static [&'static str],
}

pub fn table() -> BTreeMap<&'static str, Expectation> {
    let mut table = BTreeMap::new();
    table.insert(
        "script-tag",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["html.script.disallowed"],
            &["<script"],
        ),
    );
    table.insert(
        "inline-handler",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["html.attr.event_handler", "html.attr.dangerous_scheme"],
            &["onerror", "onclick", "javascript:"],
        ),
    );
    table.insert(
        "meta-refresh",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["html.meta.refresh"],
            &["http-equiv"],
        ),
    );
    table.insert(
        "iframe-embed",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["html.frame.disallowed"],
            &["<iframe"],
        ),
    );
    table.insert(
        "object-embed",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["html.frame.disallowed"],
            &["<object", "<embed", "javascript:"],
        ),
    );
    table.insert(
        "data-uri",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["html.attr.dangerous_scheme"],
            &["data:"],
        ),
    );
    table.insert(
        "echo-headers",
        Expectation::new(
            &[200],
            &["clean", "sanitised"],
            &[],
            &[SECRET, "cookie:", "authorization:"],
        ),
    );
    table.insert(
        "ssrf-internal-reference",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["ssrf.link_local", "ssrf.private"],
            &[
                "169.254.169.254",
                "10.0.0.1",
                "192.168.1.1",
                "localhost:8080",
            ],
        ),
    );
    table.insert(
        "idn-homograph",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["url.idn", "url.homograph"],
            &["://www.аррӏе", "://ɡoogle", "://рaypal"],
        ),
    );
    table.insert(
        "host-split",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["url.userinfo", "url.normalised"],
            &["．", "trusted.example.com@", "%2eevil"],
        ),
    );
    table.insert(
        "recursive-include",
        Expectation::new(&[200], &["clean", "sanitised"], &[], &[]),
    );
    table.insert(
        "resource-count-bomb",
        Expectation::new(&[200], &["clean", "sanitised"], &[], &[]),
    );
    table.insert(
        "malformed",
        Expectation::new(&[200], &["clean", "sanitised"], &[], &["<script>"]),
    );
    table.insert(
        "malicious",
        Expectation::new(
            &[200],
            &["refused"],
            &[
                "scan.css.dangerous_scheme",
                "scan.css.expression",
                "scan.css.import",
            ],
            &[],
        ),
    );
    table.insert(
        "html-disguised-as-png",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["sniff.mime_mismatch", "html.script.disallowed"],
            &["<script"],
        ),
    );
    table.insert(
        "png-magic-plus-html",
        Expectation::new(&[200], &["clean", "sanitised"], &[], &[]).sniffing("image/png"),
    );
    table.insert(
        "pdf-served-as-html",
        Expectation::new(
            &[200],
            &["clean", "sanitised"],
            &["sniff.mime_mismatch"],
            &[],
        )
        .sniffing("application/pdf"),
    );
    table.insert(
        "text-disguised-as-javascript",
        Expectation::new(&[200], &["refused"], &["scan.script.active_type"], &[]),
    );
    table.insert(
        "gzip-bomb",
        Expectation::new(&[502, 413], &["fetch_error", "budget_exceeded"], &[], &[]),
    );
    table.insert(
        "xml-bomb",
        Expectation::new(
            &[200, 413],
            &["refused", "budget_exceeded"],
            &["scan.xml.entity_expansion"],
            &[],
        ),
    );
    table.insert(
        "triple-hop-to-script-html",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["html.script.disallowed"],
            &["<script"],
        ),
    );
    table.insert(
        "hop-two",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["html.script.disallowed"],
            &["<script"],
        ),
    );
    table.insert(
        "final-script",
        Expectation::new(
            &[200],
            &["sanitised"],
            &["html.script.disallowed"],
            &["<script"],
        ),
    );
    table.insert(
        "large-payload",
        Expectation::new(&[413], &["budget_exceeded"], &[], &[]),
    );
    table.insert(
        "slow-drip",
        Expectation::new(&[502], &["fetch_error"], &[], &[]).within(35_000),
    );
    table.insert(
        "path-traversal",
        Expectation::new(&[200], &["clean", "sanitised"], &[], &[]),
    );
    table.insert(
        "huge-dimensions",
        Expectation::new(
            &[200, 413],
            &["refused", "budget_exceeded"],
            &["scan.image.dimensions"],
            &[],
        ),
    );
    table.insert(
        "scripted-pdf",
        Expectation::new(&[200], &["refused"], &["scan.pdf.active_content"], &[]),
    );
    table.insert(
        SENTINEL,
        Expectation::new(&[200], &["sanitised"], &["ssrf.loopback"], &["/x.png"]),
    );
    table
}

pub fn fetch_table() -> BTreeMap<&'static str, FetchExpectation> {
    let mut table = BTreeMap::new();
    table.insert(
        "resource-count-bomb",
        FetchExpectation {
            max_attempted: Some(32),
            min_budget_exceeded: Some(1),
            blocked: &[],
            forbidden: &[],
        },
    );
    table.insert(
        "recursive-include",
        FetchExpectation {
            max_attempted: Some(2),
            min_budget_exceeded: None,
            blocked: &[],
            forbidden: &[],
        },
    );
    table.insert(
        SENTINEL,
        FetchExpectation {
            max_attempted: None,
            min_budget_exceeded: None,
            blocked: &["ssrf_blocked"],
            forbidden: &["/s.css"],
        },
    );
    table
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_covers_every_category_the_criteria_name() {
        let table = table();
        for name in [
            "script-tag",
            "html-disguised-as-png",
            "xml-bomb",
            "echo-headers",
            "ssrf-internal-reference",
        ] {
            assert!(table.contains_key(name), "{name} is missing");
        }
    }

    #[test]
    fn a_scenario_that_must_be_refused_names_the_rule_that_refuses_it() {
        let table = table();
        let css = &table["malicious"];
        assert_eq!(css.status, &["refused"]);
        assert!(css.rules.contains(&"scan.css.expression"));
    }

    #[test]
    fn the_slow_scenario_carries_a_deadline() {
        assert_eq!(table()["slow-drip"].max_wall_ms, Some(35_000));
        assert!(table()["script-tag"].max_wall_ms.is_none());
    }

    #[test]
    fn a_sniffed_type_is_recorded_only_where_it_matters() {
        assert_eq!(table()["png-magic-plus-html"].sniffed, Some("image/png"));
        assert!(table()["script-tag"].sniffed.is_none());
    }

    #[test]
    fn the_fetch_table_caps_the_request_count_of_the_bomb() {
        assert_eq!(fetch_table()["resource-count-bomb"].max_attempted, Some(32));
        assert_eq!(fetch_table()[SENTINEL].blocked, &["ssrf_blocked"]);
    }

    #[test]
    fn the_header_expectation_forbids_the_secret_coming_back() {
        assert!(table()["echo-headers"].forbidden.contains(&SECRET));
    }
}
