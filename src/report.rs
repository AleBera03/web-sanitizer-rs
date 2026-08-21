//! Contract definition of JSON report schema

use serde::{Deserialize, Serialize};

use crate::policy::Action;

/// Max bytes of original content quoted in a report action
pub const MAX_FRAGMENT_BYTES: usize = 200;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunReport {
    pub run: RunSummary,
    pub inputs: Vec<InputReport>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunSummary {
    /// RFC 3339 UTC timestamp of run start.
    pub started: String,
    /// Policy path, or `"builtin"`.
    pub policy: String,
    pub workers: usize,
    pub inputs_total: u64,
    pub inputs_ok: u64,
    pub inputs_refused: u64,
    pub inputs_errored: u64,
    pub cache_hits: u64,
    pub resolve_cache_hits: u64,
    pub fetch_subresources: bool,
    pub subresources_fetched: u64,
    pub subresources_refused: u64,
    pub ssrf_blocked: u64,
}

/// Counters the engine hands to the aggregator. Separated from the summary so
/// the derived `inputs_*` totals stay the aggregator's own single-writer
/// business.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RunCounters {
    pub cache_hits: u64,
    pub resolve_cache_hits: u64,
    pub fetch_subresources: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InputReport {
    pub id: String,
    pub source: String,
    pub status: InputStatus,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration_ms: u64,
    pub actions: Vec<SanitisationAction>,
    /// Human-readable cause for error statuses.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
    /// Present only when sub-resource fetching ran for this input: omitted,
    /// never `null`, when the feature is off.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub subresources: Option<Vec<SubresourceReport>>,
}

/// One sub-resource of one parent input. Nested under its parent and never a
/// top-level input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubresourceReport {
    /// Absolute URL the reference resolved to.
    pub url: String,
    /// URL after redirects, absent when no response was ever received.
    pub final_url: Option<String>,
    pub depth: u32,
    pub status: InputStatus,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration_ms: u64,
    pub declared_mime: Option<String>,
    pub sniffed_mime: Option<String>,
    /// Set when the SSRF guard refused the request before connecting.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub block: Option<GuardBlock>,
    pub actions: Vec<SanitisationAction>,
    /// Human-readable cause for error statuses.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error: Option<String>,
}

/// Why the guard refused, in the terms the audit needs: which rule, which
/// address it fired on, and at which redirect hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardBlock {
    pub rule_id: String,
    pub category: String,
    pub resolved_address: String,
    pub hop: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InputStatus {
    Sanitised,
    Clean,
    Refused,
    BudgetExceeded,
    FetchError,
    IoError,
    UnsupportedScheme,
    MalformedUrl,
    InternalError,
    /// Refused by the SSRF guard before any connection was opened.
    SsrfBlocked,
    /// Symlinks escaping the tree root.
    SkippedSymlink,
}

impl InputStatus {
    /// Summary bucket: [`Bucket`] (schema `run` counters).
    /// Skipped symlinks count as errored — they were requested but not processed.
    /// (Just remember `errored` != `refused` )
    fn bucket(self) -> Bucket {
        match self {
            InputStatus::Sanitised | InputStatus::Clean => Bucket::Ok,
            // an SSRF block is a policy refusal, not an environment failure
            InputStatus::Refused | InputStatus::BudgetExceeded | InputStatus::SsrfBlocked => {
                Bucket::Refused
            }
            InputStatus::FetchError
            | InputStatus::IoError
            | InputStatus::UnsupportedScheme
            | InputStatus::MalformedUrl
            | InputStatus::InternalError
            | InputStatus::SkippedSymlink => Bucket::Errored,
        }
    }
}

enum Bucket {
    Ok,
    Refused,
    Errored,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SanitisationAction {
    pub rule_id: String,
    pub category: String,
    pub location: Location,
    /// Original fragment, truncated to [`MAX_FRAGMENT_BYTES`].
    pub original: String,
    pub action: Action,
    pub replacement: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Location {
    pub line: u64,
    pub byte_offset: u64,
}

impl RunReport {
    /// Assemble a report from per-input results, computing the summary counters.
    pub fn assemble(
        started: String,
        policy: String,
        workers: usize,
        counters: RunCounters,
        inputs: Vec<InputReport>,
    ) -> RunReport {
        let mut report = RunReport {
            run: RunSummary {
                started,
                policy,
                workers,
                inputs_total: 0,
                inputs_ok: 0,
                inputs_refused: 0,
                inputs_errored: 0,
                cache_hits: counters.cache_hits,
                resolve_cache_hits: counters.resolve_cache_hits,
                fetch_subresources: counters.fetch_subresources,
                subresources_fetched: 0,
                subresources_refused: 0,
                ssrf_blocked: 0,
            },
            inputs: Vec::with_capacity(inputs.len()),
        };
        for input in inputs {
            report.push(input);
        }
        report
    }

    /// Append one per-input report, keeping the summary counters consistent.
    /// Used by the engine for processed inputs and by front-ends for inputs
    /// rejected before processing (e.g. skipped symlinks).
    ///
    /// Sub-resource totals are folded in here rather than counted by the
    /// workers: the aggregator is the single writer of everything derived, so
    /// the same input list yields the same summary at any `--jobs` value.
    pub fn push(&mut self, input: InputReport) {
        self.run.inputs_total += 1;
        match input.status.bucket() {
            Bucket::Ok => self.run.inputs_ok += 1,
            Bucket::Refused => self.run.inputs_refused += 1,
            Bucket::Errored => self.run.inputs_errored += 1,
        }
        if input.status == InputStatus::SsrfBlocked {
            self.run.ssrf_blocked += 1;
        }
        for sub in input.subresources.iter().flatten() {
            match sub.status {
                InputStatus::SsrfBlocked => {
                    self.run.ssrf_blocked += 1;
                    self.run.subresources_refused += 1;
                }
                InputStatus::Refused | InputStatus::BudgetExceeded => {
                    self.run.subresources_refused += 1;
                }
                // a body came back and was processed
                InputStatus::Sanitised | InputStatus::Clean => self.run.subresources_fetched += 1,
                _ => {}
            }
        }
        self.inputs.push(input);
    }

    /// - 0 for errored inputs
    /// - 1 if at least one input was refused (refuse action or budget exceeded), else 0
    /// - 2 for config/usage errors. They never reach report assembly.
    pub fn exit_code(&self) -> i32 {
        if self.run.inputs_refused > 0 { 1 } else { 0 }
    }
}

/// Truncate a fragment to at most `max` bytes on a UTF-8 boundary
pub fn truncate_fragment(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::Zoned;

    fn sample_input(status: InputStatus) -> InputReport {
        InputReport {
            id: "input-0".into(),
            source: "test.html".into(),
            status,
            bytes_in: 10,
            bytes_out: 10,
            duration_ms: 1,
            actions: Vec::new(),
            error: None,
            subresources: None,
        }
    }

    fn sample_sub(url: &str, status: InputStatus) -> SubresourceReport {
        SubresourceReport {
            url: url.into(),
            final_url: None,
            depth: 1,
            status,
            bytes_in: 0,
            bytes_out: 0,
            duration_ms: 0,
            declared_mime: None,
            sniffed_mime: None,
            block: None,
            actions: Vec::new(),
            error: None,
        }
    }

    #[test]
    fn status_strings_match_spec_exactly() {
        let cases = [
            (InputStatus::Sanitised, "sanitised"),
            (InputStatus::Clean, "clean"),
            (InputStatus::Refused, "refused"),
            (InputStatus::BudgetExceeded, "budget_exceeded"),
            (InputStatus::FetchError, "fetch_error"),
            (InputStatus::IoError, "io_error"),
            (InputStatus::UnsupportedScheme, "unsupported_scheme"),
            (InputStatus::InternalError, "internal_error"),
            (InputStatus::SsrfBlocked, "ssrf_blocked"),
            (InputStatus::SkippedSymlink, "skipped_symlink"),
        ];
        for (status, expected) in cases {
            assert_eq!(
                serde_json::to_value(status).unwrap(),
                serde_json::Value::String(expected.into())
            );
        }
    }

    #[test]
    fn serialised_shape_matches_normative_schema() {
        let mut report = RunReport::assemble(
            "2026-07-18T22:25:00Z".into(),
            "builtin".into(),
            8,
            RunCounters {
                cache_hits: 42,
                ..RunCounters::default()
            },
            vec![sample_input(InputStatus::Clean)],
        );
        report.inputs[0].actions.push(SanitisationAction {
            rule_id: "html.script.disallowed".into(),
            category: "xss".into(),
            location: Location {
                line: 10,
                byte_offset: 512,
            },
            original: "<script>alert(1)</script>".into(),
            action: Action::Remove,
            replacement: None,
        });
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["run"]["policy"], "builtin");
        assert_eq!(v["run"]["workers"], 8);
        assert_eq!(v["run"]["cache_hits"], 42);
        assert_eq!(v["inputs"][0]["id"], "input-0");
        let action = &v["inputs"][0]["actions"][0];
        assert_eq!(action["rule_id"], "html.script.disallowed");
        assert_eq!(action["category"], "xss");
        assert_eq!(action["location"]["byte_offset"], 512);
        assert_eq!(action["action"], "remove");
        assert!(action["replacement"].is_null());
        // `error` is additive and must be absent on success
        assert!(v["inputs"][0].get("error").is_none());
        assert_eq!(v["run"]["fetch_subresources"], false);
        // `subresources` is omitted, not null, when fetching is off
        assert!(v["inputs"][0].get("subresources").is_none());
    }

    #[test]
    fn subresource_entries_nest_under_their_parent() {
        let mut parent = sample_input(InputStatus::Sanitised);
        let mut blocked = sample_sub(
            "http://169.254.169.254/latest/meta-data/",
            InputStatus::SsrfBlocked,
        );
        blocked.block = Some(GuardBlock {
            rule_id: "ssrf.link_local".into(),
            category: "ssrf".into(),
            resolved_address: "169.254.169.254:80".into(),
            hop: 0,
        });
        parent.subresources = Some(vec![
            blocked,
            sample_sub("http://cdn.example/a.css", InputStatus::Clean),
        ]);

        let report = RunReport::assemble(
            "2026-07-18T22:25:00Z".into(),
            "builtin".into(),
            1,
            RunCounters {
                fetch_subresources: true,
                ..RunCounters::default()
            },
            vec![parent],
        );
        let v = serde_json::to_value(&report).unwrap();
        let sub = &v["inputs"][0]["subresources"][0];
        assert_eq!(sub["status"], "ssrf_blocked");
        assert_eq!(sub["depth"], 1);
        assert_eq!(sub["block"]["rule_id"], "ssrf.link_local");
        assert_eq!(sub["block"]["resolved_address"], "169.254.169.254:80");
        assert!(sub["final_url"].is_null());
        // a refused sub-resource never becomes a top-level input
        assert_eq!(v["inputs"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn subresource_totals_are_folded_into_the_summary() {
        let mut parent = sample_input(InputStatus::Sanitised);
        parent.subresources = Some(vec![
            sample_sub("http://a/1.css", InputStatus::Clean),
            sample_sub("http://a/2.js", InputStatus::Sanitised),
            sample_sub("http://10.0.0.5/x", InputStatus::SsrfBlocked),
            sample_sub("http://a/3.png", InputStatus::BudgetExceeded),
            sample_sub("http://a/4.gif", InputStatus::FetchError),
        ]);
        let report = RunReport::assemble(
            Zoned::now().to_string(),
            "builtin".into(),
            1,
            RunCounters {
                fetch_subresources: true,
                ..RunCounters::default()
            },
            vec![parent],
        );
        assert_eq!(report.run.subresources_fetched, 2);
        assert_eq!(report.run.subresources_refused, 2); // ssrf + budget
        assert_eq!(report.run.ssrf_blocked, 1);
        // a refused sub-resource never fails its parent's exit code
        assert_eq!(report.run.inputs_refused, 0);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn a_blocked_input_url_is_a_refusal() {
        let report = RunReport::assemble(
            Zoned::now().to_string(),
            "builtin".into(),
            1,
            RunCounters::default(),
            vec![sample_input(InputStatus::SsrfBlocked)],
        );
        assert_eq!(report.run.inputs_refused, 1);
        assert_eq!(report.run.ssrf_blocked, 1);
        assert_eq!(report.exit_code(), 1);
    }

    #[test]
    fn resolve_cache_hits_reach_the_summary() {
        let report = RunReport::assemble(
            Zoned::now().to_string(),
            "builtin".into(),
            1,
            RunCounters {
                fetch_subresources: true,
                resolve_cache_hits: 7,
                ..RunCounters::default()
            },
            Vec::new(),
        );
        let v = serde_json::to_value(&report).unwrap();
        assert_eq!(v["run"]["resolve_cache_hits"], 7);
        assert_eq!(v["run"]["fetch_subresources"], true);
    }

    #[test]
    fn round_trips_through_json() {
        let mut input = sample_input(InputStatus::BudgetExceeded);
        input.subresources = Some(vec![sample_sub("http://a/1.css", InputStatus::Clean)]);
        let report = RunReport::assemble(
            Zoned::now().to_string(),
            "builtin".into(),
            1,
            RunCounters::default(),
            vec![input],
        );
        let json = serde_json::to_string(&report).unwrap();
        let back: RunReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, report);
    }

    #[test]
    fn summary_counters_and_exit_code() {
        let report = RunReport::assemble(
            Zoned::now().to_string(),
            "builtin".into(),
            4,
            RunCounters::default(),
            vec![
                sample_input(InputStatus::Clean),
                sample_input(InputStatus::Sanitised),
                sample_input(InputStatus::BudgetExceeded),
                sample_input(InputStatus::FetchError),
                sample_input(InputStatus::SkippedSymlink),
            ],
        );
        assert_eq!(report.run.inputs_total, 5);
        assert_eq!(report.run.inputs_ok, 2);
        assert_eq!(report.run.inputs_refused, 1);
        assert_eq!(report.run.inputs_errored, 2);
        assert_eq!(report.exit_code(), 1);

        let clean = RunReport::assemble(
            Zoned::now().to_string(),
            "builtin".into(),
            1,
            RunCounters::default(),
            vec![
                sample_input(InputStatus::Clean),
                sample_input(InputStatus::IoError),
            ],
        );
        assert_eq!(clean.exit_code(), 0); // errored != refused
    }

    #[test]
    fn fragment_truncation_respects_utf8_boundaries() {
        assert_eq!(truncate_fragment("short", 200), "short");
        let s = "aé"; // 'é' is 2 bytes starting at index 1
        assert_eq!(truncate_fragment(s, 2), "a");
        let long = "x".repeat(300);
        assert_eq!(truncate_fragment(&long, MAX_FRAGMENT_BYTES).len(), 200);
    }
}
