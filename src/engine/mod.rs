//! The engine: per-input pipeline acquire -> sniff -> route -> sanitise -> report.
//!
//! ## `sniff`
//! When an host receive a byte's blob, it has to _understand_ what it is. There are 3 ways
//! to determinate a type:
//! - **what the server declares**: header `Content-Type: image/png`
//! - **file name**: extension `.png`
//! - **actual byte analysis**: studying of file content
//!
//! _Sniffing_: retrieving a file type analyzing the actual byte content
//!
//! _MIME confusion_: the final goal of an attacker is forcing 2 consumers to
//! _differently understand_ the same byte stream.
//!
//! Therefore, _sniffer_ compares a table of possible kinds of MIME content type with initial
//! bytes of a fetched file.
//!
//! ## `route`
//! After `sniff` phase, `route` dispatch handler for each kind of content, under which
//! limits. Let's see possibilites:
//! - html --> [`crate::html::sanitize_html`]
//! - xml/svg --> [entity scan](https://en.wikipedia.org/wiki/Billion_laughs_attack). xml and svg are
//!   given near because svg is just an xml file
//! - scan, image --> header-only dimensions
//! - gzip --> bounded inflate then re-sniff
//! - everything else --> byte-identical pass-through
//! ### Type-specific Budgets
//! `max_input_bytes` is already spent by the pipeline, but `max_entity_expansions` only means something for XML,
//! `max_image_pixels` only for images, `max_decompress_ratio` only for
//! compressed bodies. `route` is the only place that knows which one applies.
//! ### Mime Mismatch
//! When the sniffed type contradicts the declared
//! `Content-Type`, the action is recorded and the **sniffed** type wins
//! ### Status
//! The handler's result is mapped onto [`InputStatus`] —
//! `Clean` (no action), `Sanitized` (at least one), `Refused`, `BudgetExceeded`
//!
//! Gzip re-enters `route` after inflating, so the recursion carries a depth cap
//! The ratio budget alone is not sufficient.
//!
//!
//! ## Development status
//! ### Completed
//! - acquire
//! - input-bytes budget
//! - some of panic isolation
//!
//! ### Missing
//! - sniff and route within pipeline
//! - integration of [`crate::html::sanitize_html`]
//! - the worker pool that will replace the sequential loop in
//!   [`Engine::process_batch`] behind the same signature

pub mod route;
pub mod sniff;

use std::fs;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::Instant;

use jiff::Zoned;

use crate::fetch::Fetcher;
use crate::input::InputSource;
use crate::policy::protectedset::SkeletonSet;
use crate::policy::{ConfigError, Policy, blockset::BlockSet};
use crate::report::{InputReport, InputStatus, RunReport};
use crate::sniff::AcquiredInput;

#[allow(
    dead_code,
    reason = "waiting for completation of entire engine
    pipeline to call sanitize_html"
)]
pub struct Engine {
    policy: Arc<Policy>,
    blockset: BlockSet,
    skeletonset: SkeletonSet,
    fetcher: Arc<dyn Fetcher>,
}

/// Result of processing one input: the report plus the sanitized bytes when
/// processing produced output (refused/errored inputs have none). The bytes
/// travel with the report because both front-ends need them — the CLI writes
/// them to the output directory, the server returns them inline.
pub struct Outcome {
    pub report: InputReport,
    pub sanitized: Option<Vec<u8>>,
}

impl Engine {
    /// Compiles the policy's block-lists; a malformed list is a config error
    /// (exit 2) before any input is touched.
    pub fn new(policy: Policy, fetcher: Arc<dyn Fetcher>) -> Result<Engine, ConfigError> {
        let blockset = BlockSet::from_files(&policy.urls.blocklists)?;
        let skeletonset = SkeletonSet::build(
            policy
                .urls
                .protected_domains
                .iter()
                .map(|s| s.as_str())
                .collect(),
        )?;
        Ok(Engine {
            policy: Arc::new(policy),
            blockset,
            skeletonset,
            fetcher,
        })
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn blockset(&self) -> &BlockSet {
        &self.blockset
    }

    /// process a single input. Never panics: the pipeline runs under
    /// `catch_unwind`, so a logic bug degrades to an `internal_error` report
    pub fn process(&self, input: InputSource) -> Outcome {
        let source = input.describe();
        let start = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| self.pipeline(input)));
        let mut outcome = match result {
            Ok(outcome) => outcome,
            Err(_) => Outcome {
                report: error_report(
                    source.clone(),
                    InputStatus::InternalError,
                    "panic in processing pipeline".to_string(),
                ),
                sanitized: None,
            },
        };
        outcome.report.source = source;
        outcome.report.duration_ms = start.elapsed().as_millis() as u64;
        outcome
    }

    /// Process a batch sequentially for now, calling
    /// `emit` with each finished report and its output bytes in input order.
    /// The report's `id` is `input-N` by position.
    pub fn process_batch<F>(&self, inputs: Vec<InputSource>, jobs: usize, mut emit: F) -> RunReport
    where
        F: FnMut(&InputReport, Option<&[u8]>),
    {
        let workers = jobs.max(1);
        let mut report = RunReport::assemble(
            Zoned::now().to_string(),
            self.policy.source.to_string(),
            workers,
            0, // waiting for working pool implementation
            Vec::new(),
        );
        for (index, input) in inputs.into_iter().enumerate() {
            let mut outcome = self.process(input);
            outcome.report.id = format!("input-{index}");
            emit(&outcome.report, outcome.sanitized.as_deref());
            report.push(outcome.report);
        }
        report
    }

    fn pipeline(&self, input: InputSource) -> Outcome {
        let source = input.describe();
        // acquire
        let data = match self.acquire(input.clone()) {
            Ok(data) => data,
            Err((status, cause)) => {
                return Outcome {
                    report: error_report(source, status, cause),
                    sanitized: None,
                };
            }
        };
        // input-bytes budget
        let budget = self.policy.budgets.max_input_bytes;
        if data.len() as u64 > budget {
            return Outcome {
                report: error_report(
                    source,
                    InputStatus::BudgetExceeded,
                    format!("input is {} bytes, budget is {budget}", data.len()),
                ),
                sanitized: None,
            };
        }

        if self.policy.subresources.fetch_subresources {
            //call all subresource fetchers and sanitizers
        }

        let sniff_outcome = crate::engine::sniff::run(
            AcquiredInput::new(input.clone(), data.clone()), //TODO: qua il clone serve per forza?
            self.policy.clone(),
            0,
        );

        let bytes_in = data.len() as u64;
        let output = sniff_outcome.output.unwrap_or_default();
        let status = if sniff_outcome.refused {
            InputStatus::Refused
        } else if sniff_outcome.actions.is_empty() {
            InputStatus::Clean
        } else {
            InputStatus::Sanitised
        };
        Outcome {
            report: InputReport {
                id: "input-0".to_string(),
                source,
                status,
                bytes_in,
                bytes_out: output.len() as u64,
                duration_ms: 0,
                actions: sniff_outcome.actions,
                error: None,
            },
            sanitized: Some(output),
        }
    }

    fn acquire(&self, input: InputSource) -> Result<Vec<u8>, (InputStatus, String)> {
        match input {
            InputSource::Bytes { data, .. } => Ok(data),
            InputSource::File(path) => {
                // Size check via metadata first: a file over budget is refused
                // without reading it into memory (that is the point of the budget).
                let budget = self.policy.budgets.max_input_bytes;
                let meta =
                    fs::metadata(&path).map_err(|e| (InputStatus::IoError, e.to_string()))?;
                if meta.len() > budget {
                    return Err((
                        InputStatus::BudgetExceeded,
                        format!("input is {} bytes, budget is {budget}", meta.len()),
                    ));
                }
                fs::read(&path).map_err(|e| (InputStatus::IoError, e.to_string()))
            }
            InputSource::Url(url) => {
                // only http/https schema are allowed
                if !matches!(url.scheme(), "http" | "https") {
                    return Err((
                        InputStatus::UnsupportedScheme,
                        format!("scheme `{}` is not supported", url.scheme()),
                    ));
                }
                self.fetcher
                    .fetch(&url, &self.policy.fetch)
                    .map(|fetched| fetched.body)
                    .map_err(|e| (InputStatus::FetchError, e.to_string()))
            }
            InputSource::MalformedUrl(s) => Err((
                InputStatus::MalformedUrl,
                format!("url `{}` does not respect WHATWG standards", s),
            )),
        }
    }
}

fn error_report(source: String, status: InputStatus, cause: String) -> InputReport {
    InputReport {
        id: "input-0".to_string(),
        source,
        status,
        bytes_in: 0,
        bytes_out: 0,
        duration_ms: 0,
        actions: Vec::new(),
        error: Some(cause),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fetch::DisabledFetcher;

    fn engine() -> Engine {
        Engine::new(Policy::builtin(), Arc::new(DisabledFetcher)).unwrap()
    }

    fn engine_with_budget(max_input_bytes: u64) -> Engine {
        let mut policy = Policy::builtin();
        policy.budgets.max_input_bytes = max_input_bytes;
        Engine::new(policy, Arc::new(DisabledFetcher)).unwrap()
    }

    fn bytes(data: &[u8]) -> InputSource {
        InputSource::Bytes {
            name: "test-bytes".to_string(),
            data: data.to_vec(),
        }
    }

    #[test]
    fn empty_input_is_clean_with_zero_actions() {
        // 0-byte input processes successfully.
        let outcome = engine().process(bytes(b""));
        assert_eq!(outcome.report.status, InputStatus::Clean);
        assert_eq!(outcome.report.bytes_in, 0);
        assert_eq!(outcome.report.bytes_out, 0);
        assert!(outcome.report.actions.is_empty());
        assert_eq!(outcome.sanitized.as_deref(), Some(&b""[..]));
    }

    #[test]
    fn byte_budget_boundary_is_exact() {
        let engine = engine_with_budget(4);
        assert_eq!(
            engine.process(bytes(b"1234")).report.status,
            InputStatus::Clean
        );
        let over = engine.process(bytes(b"12345"));
        assert_eq!(over.report.status, InputStatus::BudgetExceeded);
        assert!(over.sanitized.is_none());
        assert!(over.report.error.as_deref().unwrap().contains("budget"));
    }

    #[test]
    fn oversized_file_is_refused_without_reading() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.html");
        fs::write(&path, b"123456").unwrap();
        let outcome = engine_with_budget(5).process(InputSource::File(path));
        assert_eq!(outcome.report.status, InputStatus::BudgetExceeded);
    }

    #[test]
    fn missing_file_is_io_error() {
        let outcome = engine().process(InputSource::File("/nonexistent/x.html".into()));
        assert_eq!(outcome.report.status, InputStatus::IoError);
        assert!(outcome.report.error.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_file_is_io_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locked.html");
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::read(&path).is_ok() {
            return;
        }
        let outcome = engine().process(InputSource::File(path));
        assert_eq!(outcome.report.status, InputStatus::IoError);
    }

    #[test]
    fn non_http_scheme_is_rejected_without_fetch() {
        // file:// and friends never reach the fetcher.
        let url = url::Url::parse("file:///etc/passwd").unwrap();
        let outcome = engine().process(InputSource::Url(url));
        assert_eq!(outcome.report.status, InputStatus::UnsupportedScheme);
    }

    #[test]
    fn http_url_with_disabled_fetcher_is_fetch_error() {
        let url = url::Url::parse("http://example.com/").unwrap();
        let outcome = engine().process(InputSource::Url(url));
        assert_eq!(outcome.report.status, InputStatus::FetchError);
        assert!(
            outcome
                .report
                .error
                .as_deref()
                .unwrap()
                .contains("not available")
        );
    }

    #[test]
    fn batch_preserves_order_assigns_ids_and_counts() {
        // ordering (sequential today; the pool must keep this property).
        let engine = engine_with_budget(4);
        let inputs = vec![bytes(b"ok"), bytes(b"toolong"), bytes(b"ok2")];
        let mut emitted = Vec::new();
        let report = engine.process_batch(inputs, 8, |r, out| {
            emitted.push((r.id.clone(), out.is_some()));
        });
        assert_eq!(report.run.workers, 8);
        assert_eq!(report.run.inputs_total, 3);
        assert_eq!(report.run.inputs_ok, 2);
        assert_eq!(report.run.inputs_refused, 1);
        assert_eq!(report.run.cache_hits, 0);
        let ids: Vec<&str> = report.inputs.iter().map(|i| i.id.as_str()).collect();
        assert_eq!(ids, ["input-0", "input-1", "input-2"]);
        assert_eq!(
            emitted,
            [
                ("input-0".to_string(), true),
                ("input-1".to_string(), false),
                ("input-2".to_string(), true),
            ]
        );
        assert_eq!(report.exit_code(), 1); // one refused input --> exit 1
    }

    #[test]
    fn bad_blocklist_is_a_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("bad.txt");
        fs::write(&list, "http://not-a-host/\n").unwrap();
        let mut policy = Policy::builtin();
        policy.urls.blocklists = vec![list];
        assert!(Engine::new(policy, Arc::new(DisabledFetcher)).is_err());
    }

    #[test]
    fn good_blocklist_is_compiled_at_startup() {
        let dir = tempfile::tempdir().unwrap();
        let list = dir.path().join("list.txt");
        fs::write(&list, "0.0.0.0 evil.com\n0.0.0.0 ads.example\n").unwrap();

        let mut policy = Policy::builtin();
        policy.urls.blocklists = vec![list];
        let engine = Engine::new(policy, Arc::new(DisabledFetcher)).unwrap();
        assert!(
            engine
                .blockset()
                .contains(url::Host::parse("sub.evil.com").unwrap())
        );
        assert_eq!(engine.blockset().len(), 2);
    }
}
