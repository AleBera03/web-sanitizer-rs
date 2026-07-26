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
            InputStatus::Refused | InputStatus::BudgetExceeded => Bucket::Refused,
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
        cache_hits: u64,
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
                cache_hits,
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
    pub fn push(&mut self, input: InputReport) {
        self.run.inputs_total += 1;
        match input.status.bucket() {
            Bucket::Ok => self.run.inputs_ok += 1,
            Bucket::Refused => self.run.inputs_refused += 1,
            Bucket::Errored => self.run.inputs_errored += 1,
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
            42,
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
    }

    #[test]
    fn round_trips_through_json() {
        let report = RunReport::assemble(
            Zoned::now().to_string(),
            "builtin".into(),
            1,
            0,
            vec![sample_input(InputStatus::BudgetExceeded)],
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
            0,
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
            0,
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
