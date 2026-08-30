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
//! ## `sub-resources`
//! With the user's opt-in, an HTML input gains one bounded inner loop: the
//! references the HTML stage saw are resolved against the document base, fetched
//! under a joint budget, sanitised by the same pipeline at depth 1, and reported
//! nested under their parent. See [`subresource`].
//!
//! ## Development status
//! ### Completed
//! - acquire, input-bytes budget, panic isolation
//! - pipeline: sniff -> route -> sub-resource loop -> report
//!
//! ### Missing
//! - the worker pool that will replace the sequential loop in
//!   [`Engine::process_batch`] behind the same signature

pub mod route;
pub mod subresource;

use std::fs;
use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::time::{Duration, Instant};

use jiff::Zoned;
use url::Url;

use crate::fetch::Fetcher;
use crate::fetch::guard::{FetchContext, FetchOrigin};
use crate::html;
use crate::input::{InputSource, OutputName};
use crate::policy::protectedset::SkeletonSet;
use crate::policy::{ConfigError, Policy, blockset::BlockSet};
use crate::report::{InputReport, InputStatus, RunCounters, RunReport};
use crate::sniff::{AcquiredInput, sniff_input};
use crate::urlcheck::UrlChecker;
use crate::urlcheck::cache::VerdictCache;

use subresource::{Asset, SubresourceLoop, SubresourceOutcome};

pub struct Engine {
    policy: Arc<Policy>,
    blockset: BlockSet,
    skeletonset: SkeletonSet,
    /// Shared by every worker: read-mostly, so one `RwLock` and no copying.
    verdictcache: VerdictCache,
    fetcher: Arc<dyn Fetcher>,
    /// Which frontend owns the engine.
    origin: FetchOrigin,
}

/// Result of processing one input: the report plus the sanitized bytes when
/// processing produced output (refused/errored inputs have none). The bytes
/// travel with the report because both front-ends need them — the CLI writes
/// them to the output directory, the server returns them inline.
pub struct Outcome {
    pub report: InputReport,
    pub sanitized: Option<Vec<u8>>,
    /// Sanitised sub-resource bodies, each with the path it takes under the
    /// output directory. Empty unless the sub-resource loop ran.
    pub assets: Vec<Asset>,
}

impl Outcome {
    /// An input that produced a report and nothing else.
    fn failed(report: InputReport) -> Outcome {
        Outcome {
            report,
            sanitized: None,
            assets: Vec::new(),
        }
    }
}

struct Acquired {
    data: Vec<u8>,
    url: Option<Url>,
    endpoint: Option<SocketAddr>,
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
            verdictcache: VerdictCache::default(),
            fetcher,
            origin: FetchOrigin::InputCli,
        })
    }

    pub fn with_origin(mut self, origin: FetchOrigin) -> Engine {
        self.origin = origin;
        self
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    pub fn blockset(&self) -> &BlockSet {
        &self.blockset
    }

    /// Process a single input. Never panics: the pipeline runs under
    /// `catch_unwind`, so a logic bug degrades to an `internal_error` report.
    pub fn process(&self, input: InputSource) -> Outcome {
        self.process_indexed(0, input)
    }

    /// Process a batch sequentially for now, calling `emit` with each finished
    /// outcome and its position in the input list. The index is what names the
    /// outputs deterministically once completions stop arriving in order.
    pub fn process_batch<F>(&self, inputs: Vec<InputSource>, jobs: usize, mut emit: F) -> RunReport
    where
        F: FnMut(usize, &Outcome),
    {
        let workers = jobs.max(1);
        let mut report = RunReport::assemble(
            Zoned::now().to_string(),
            self.policy.source.to_string(),
            workers,
            RunCounters {
                fetch_subresources: self.policy.subresources.fetch_subresources,
                ..RunCounters::default()
            },
            Vec::new(),
        );
        for (index, input) in inputs.into_iter().enumerate() {
            let outcome = self.process_indexed(index, input);
            emit(index, &outcome);
            report.push(outcome.report);
        }
        // read once, after every worker is done: the counters order nothing
        report.run.cache_hits = self.verdictcache.hits();
        report.run.resolve_cache_hits = self.fetcher.resolve_cache_hits();
        report
    }

    fn process_indexed(&self, index: usize, input: InputSource) -> Outcome {
        let source = input.describe();
        let start = Instant::now();
        let result = catch_unwind(AssertUnwindSafe(|| self.pipeline(index, input, start)));
        let mut outcome = match result {
            Ok(outcome) => outcome,
            Err(_) => Outcome::failed(error_report(
                source.clone(),
                InputStatus::InternalError,
                "panic in processing pipeline".to_string(),
            )),
        };
        outcome.report.id = format!("input-{index}");
        outcome.report.source = source;
        outcome.report.duration_ms = start.elapsed().as_millis() as u64;
        outcome
    }

    fn pipeline(&self, index: usize, input: InputSource, start: Instant) -> Outcome {
        let source = input.describe();
        // acquire
        let acquired = match self.acquire(&input) {
            Ok(acquired) => acquired,
            Err((status, cause)) => return Outcome::failed(error_report(source, status, cause)),
        };
        // input-bytes budget
        let budget = self.policy.budgets.max_input_bytes;
        if acquired.data.len() as u64 > budget {
            return Outcome::failed(error_report(
                source,
                InputStatus::BudgetExceeded,
                format!("input is {} bytes, budget is {budget}", acquired.data.len()),
            ));
        }

        let bytes_in = acquired.data.len() as u64;
        let Acquired {
            data,
            url,
            endpoint,
        } = acquired;
        // one checker per input: the pipeline and the sub-resource loop share it
        let checker = UrlChecker::new(
            &self.blockset,
            &self.skeletonset,
            &self.verdictcache,
            &self.policy.urls,
        );
        let sniff_outcome = sniff_input(
            AcquiredInput::new(input, data),
            &self.policy.subresources,
            0,
        );
        let sniff_actions = sniff_outcome.actions.clone();
        let sniff_refused = sniff_outcome.refused;
        let routed = route::route(sniff_outcome, &self.policy, &checker, 0);

        // sub-resources, only for a document that survived and only when asked
        let names = OutputName::derive(index, &source);
        let subresources =
            self.fetch_subresources(&routed, &checker, url.as_ref(), endpoint, &names, start);
        let output = match &subresources {
            Some(sub) if !sub.rewrites.is_empty() => {
                html::rewrite_references(&routed.output, &sub.rewrites)
            }
            _ => routed.output,
        };

        let mut actions = sniff_actions;
        actions.extend(routed.actions);
        let refused = sniff_refused || routed.refused;
        let status = if refused {
            InputStatus::Refused
        } else if actions.is_empty() {
            InputStatus::Clean
        } else {
            InputStatus::Sanitised
        };

        let (assets, reports) = match subresources {
            Some(sub) => (sub.assets, Some(sub.reports)),
            None => (Vec::new(), None),
        };
        // a refused input produces a report and nothing else: handing bytes
        // back would let the front-ends write an output file for it
        let sanitized = if refused { None } else { Some(output) };
        Outcome {
            report: InputReport {
                id: format!("input-{index}"),
                source,
                status,
                bytes_in,
                bytes_out: sanitized.as_ref().map_or(0, |out| out.len() as u64),
                duration_ms: 0,
                actions,
                error: None,
                subresources: reports,
            },
            sanitized,
            assets,
        }
    }

    /// Run the sub-resource loop for this input, or say why it did not run.
    /// `Some` (possibly empty) whenever fetching is enabled, so the report can
    /// distinguish "nothing to fetch" from "the feature is off".
    fn fetch_subresources(
        &self,
        routed: &route::RouteOutcome,
        checker: &UrlChecker,
        url: Option<&Url>,
        endpoint: Option<SocketAddr>,
        names: &OutputName,
        start: Instant,
    ) -> Option<SubresourceOutcome> {
        if !self.policy.subresources.fetch_subresources {
            return None;
        }
        if routed.refused {
            return Some(SubresourceOutcome::default());
        }
        let deadline = start + Duration::from_millis(self.policy.budgets.max_time_ms);
        let outcome = SubresourceLoop::new(
            &self.policy,
            self.fetcher.as_ref(),
            checker,
            document_base(url, routed.base.as_deref()),
            endpoint,
            names.asset_dir(),
            deadline,
        )
        .run(&routed.references);
        Some(outcome)
    }

    fn acquire(&self, input: &InputSource) -> Result<Acquired, (InputStatus, String)> {
        match input {
            InputSource::Bytes { data, .. } => Ok(Acquired {
                data: data.clone(),
                url: None,
                endpoint: None,
            }),
            InputSource::File(path) => {
                // Size check via metadata first: a file over budget is refused
                // without reading it into memory (that is the point of the budget).
                let budget = self.policy.budgets.max_input_bytes;
                let meta = fs::metadata(path).map_err(|e| (InputStatus::IoError, e.to_string()))?;
                if meta.len() > budget {
                    return Err((
                        InputStatus::BudgetExceeded,
                        format!("input is {} bytes, budget is {budget}", meta.len()),
                    ));
                }
                let data = fs::read(path).map_err(|e| (InputStatus::IoError, e.to_string()))?;
                Ok(Acquired {
                    data,
                    url: None,
                    endpoint: None,
                })
            }
            InputSource::Url(url) => {
                // only http/https schema are allowed
                if !matches!(url.scheme(), "http" | "https") {
                    return Err((
                        InputStatus::UnsupportedScheme,
                        format!("scheme `{}` is not supported", url.scheme()),
                    ));
                }
                let fetched = self
                    .fetcher
                    .fetch(url, &self.policy.fetch, FetchContext::input(self.origin))
                    .map_err(fetch_failure)?;
                Ok(Acquired {
                    data: fetched.body,
                    url: Some(fetched.final_url),
                    endpoint: fetched.endpoint,
                })
            }
            InputSource::MalformedUrl(s) => Err((
                InputStatus::MalformedUrl,
                format!("url `{s}` does not respect WHATWG standards"),
            )),
        }
    }
}

/// The base a document's references resolve against: its own `<base href>` when
/// it has one, otherwise the URL the document came from.
fn document_base(url: Option<&Url>, declared: Option<&str>) -> Option<Url> {
    match (declared, url) {
        (Some(base), Some(url)) => url.join(base).ok().or_else(|| Some(url.clone())),
        (Some(base), None) => Url::parse(base).ok(),
        (None, url) => url.cloned(),
    }
}

fn fetch_failure(error: crate::fetch::FetchError) -> (InputStatus, String) {
    match error {
        crate::fetch::FetchError::SsrfBlocked { address, rule, .. } => (
            InputStatus::SsrfBlocked,
            format!("{rule} refuses {address}"),
        ),
        other => (InputStatus::FetchError, other.to_string()),
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
        subresources: None,
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
    fn a_refused_input_keeps_its_report_and_loses_its_bytes() {
        // a declared jpeg that is really a png: the sniff mismatch refuses it,
        // and no output must reach the front-ends
        let outcome = engine().process(InputSource::Bytes {
            name: "fake.jpg".to_string(),
            data: vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A],
        });
        assert_eq!(outcome.report.status, InputStatus::Refused);
        assert!(outcome.sanitized.is_none());
        assert_eq!(outcome.report.bytes_out, 0);
        assert!(!outcome.report.actions.is_empty());
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
        let report = engine.process_batch(inputs, 8, |index, outcome| {
            emitted.push((
                index,
                outcome.report.id.clone(),
                outcome.sanitized.is_some(),
            ));
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
                (0, "input-0".to_string(), true),
                (1, "input-1".to_string(), false),
                (2, "input-2".to_string(), true),
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

    // the pipeline with sub-resources

    /// A fetcher that answers every URL with the same body, and remembers what
    /// it was asked for.
    struct RecordingFetcher {
        body: Vec<u8>,
        mime: Option<String>,
        requested: std::sync::Mutex<Vec<String>>,
        contexts: std::sync::Mutex<Vec<FetchContext>>,
    }

    impl RecordingFetcher {
        fn new(body: &[u8], mime: Option<&str>) -> Arc<RecordingFetcher> {
            Arc::new(RecordingFetcher {
                body: body.to_vec(),
                mime: mime.map(String::from),
                requested: std::sync::Mutex::new(Vec::new()),
                contexts: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn requested(&self) -> Vec<String> {
            self.requested.lock().unwrap().clone()
        }

        fn contexts(&self) -> Vec<FetchContext> {
            self.contexts.lock().unwrap().clone()
        }
    }

    impl crate::fetch::Fetcher for RecordingFetcher {
        fn fetch(
            &self,
            url: &Url,
            _policy: &crate::policy::FetchPolicy,
            ctx: FetchContext,
        ) -> Result<crate::fetch::Fetched, crate::fetch::FetchError> {
            self.requested.lock().unwrap().push(url.to_string());
            self.contexts.lock().unwrap().push(ctx);
            Ok(crate::fetch::Fetched {
                final_url: url.clone(),
                declared_mime: self.mime.clone(),
                endpoint: None,
                body: self.body.clone(),
            })
        }
    }

    const PAGE: &[u8] =
        br#"<!DOCTYPE html><base href="http://site.test/"><link rel="stylesheet" href="/a.css">"#;

    fn page() -> InputSource {
        InputSource::Bytes {
            name: "page.html".to_string(),
            data: PAGE.to_vec(),
        }
    }

    fn url_input() -> InputSource {
        InputSource::Url(Url::parse("http://site.test/page.html").unwrap())
    }

    #[test]
    fn an_input_url_is_fetched_as_cli_input_by_default() {
        let fetcher = RecordingFetcher::new(b"", Some("text/plain"));
        let engine = Engine::new(Policy::builtin(), fetcher.clone()).unwrap();
        engine.process(url_input());

        assert_eq!(fetcher.contexts(), [FetchContext::input_cli()]);
    }

    #[test]
    fn a_server_engine_marks_its_input_urls_as_server_input() {
        // the guard scope of `guard_input_urls = server` has no effect unless
        // the origin reaches the fetcher, so this is what makes it real
        let fetcher = RecordingFetcher::new(b"", Some("text/plain"));
        let engine = Engine::new(Policy::builtin(), fetcher.clone())
            .unwrap()
            .with_origin(FetchOrigin::InputServer);
        engine.process(url_input());

        assert_eq!(fetcher.contexts(), [FetchContext::input_server()]);
    }

    #[test]
    fn the_origin_does_not_leak_into_subresource_requests() {
        // a reference read out of a document is always guarded, whichever
        // front-end submitted the parent
        let fetcher = RecordingFetcher::new(b"body{}", Some("text/css"));
        let mut policy = Policy::builtin();
        policy.subresources.fetch_subresources = true;
        let engine = Engine::new(policy, fetcher.clone())
            .unwrap()
            .with_origin(FetchOrigin::InputServer);
        engine.process(page());

        assert_eq!(fetcher.contexts(), [FetchContext::subresource(None)]);
    }

    #[test]
    fn references_are_inspected_but_not_fetched_by_default() {
        let fetcher = RecordingFetcher::new(b"body{}", Some("text/css"));
        let engine = Engine::new(Policy::builtin(), fetcher.clone()).unwrap();
        let outcome = engine.process(page());

        assert!(fetcher.requested().is_empty());
        assert!(outcome.report.subresources.is_none());
        assert!(outcome.assets.is_empty());
    }

    #[test]
    fn opting_in_fetches_reports_and_rewrites() {
        let fetcher = RecordingFetcher::new(b"body{}", Some("text/css"));
        let mut policy = Policy::builtin();
        policy.subresources.fetch_subresources = true;
        let engine = Engine::new(policy, fetcher.clone()).unwrap();
        let outcome = engine.process(page());

        assert_eq!(fetcher.requested(), ["http://site.test/a.css"]);
        let subs = outcome.report.subresources.as_ref().unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].status, InputStatus::Clean);
        assert_eq!(subs[0].depth, 1);

        assert_eq!(outcome.assets.len(), 1);
        assert_eq!(outcome.assets[0].path, "0-page.html.assets/asset-0.css");
        let html = String::from_utf8(outcome.sanitized.unwrap()).unwrap();
        assert!(
            html.contains(r#"href="0-page.html.assets/asset-0.css""#),
            "{html}"
        );
    }

    #[test]
    fn a_page_with_no_references_reports_an_empty_section() {
        let fetcher = RecordingFetcher::new(b"body{}", Some("text/css"));
        let mut policy = Policy::builtin();
        policy.subresources.fetch_subresources = true;
        let engine = Engine::new(policy, fetcher.clone()).unwrap();
        let outcome = engine.process(InputSource::Bytes {
            name: "plain.html".to_string(),
            data: b"<!DOCTYPE html><p>nothing here</p>".to_vec(),
        });

        assert!(fetcher.requested().is_empty());
        assert_eq!(outcome.report.subresources.as_ref().unwrap().len(), 0);
        assert_eq!(outcome.report.status, InputStatus::Clean);
    }

    #[test]
    fn asset_paths_follow_the_name_of_their_parent() {
        let fetcher = RecordingFetcher::new(b"body{}", Some("text/css"));
        let mut policy = Policy::builtin();
        policy.subresources.fetch_subresources = true;
        let engine = Engine::new(policy, fetcher).unwrap();
        let report = engine.process_batch(vec![page(), page()], 1, |index, outcome| {
            assert_eq!(
                outcome.assets[0].path,
                format!("{index}-page.html.assets/asset-0.css")
            );
        });
        assert_eq!(report.run.subresources_fetched, 2);
        assert!(report.run.fetch_subresources);
    }

    #[test]
    fn a_refused_sub_resource_leaves_its_parent_alone() {
        let fetcher = RecordingFetcher::new(b"<!DOCTYPE html><p>not css</p>", Some("text/css"));
        let mut policy = Policy::builtin();
        policy.subresources.fetch_subresources = true;
        let engine = Engine::new(policy, fetcher).unwrap();
        let report = engine.process_batch(vec![page()], 1, |_, _| {});

        let subs = report.inputs[0].subresources.as_ref().unwrap();
        assert_eq!(subs[0].status, InputStatus::Refused);
        assert_eq!(report.run.subresources_refused, 1);
        assert_eq!(report.run.inputs_refused, 0);
        assert_eq!(report.exit_code(), 0);
    }

    #[test]
    fn a_run_without_fetching_says_so_and_counts_nothing() {
        let engine = Engine::new(Policy::builtin(), Arc::new(DisabledFetcher)).unwrap();
        let report = engine.process_batch(vec![page()], 1, |_, _| {});
        assert!(!report.run.fetch_subresources);
        assert_eq!(report.run.subresources_fetched, 0);
        assert_eq!(report.run.ssrf_blocked, 0);
    }

    #[test]
    fn a_blocked_input_url_is_its_own_status() {
        struct BlockingFetcher;
        impl crate::fetch::Fetcher for BlockingFetcher {
            fn fetch(
                &self,
                _url: &Url,
                _policy: &crate::policy::FetchPolicy,
                _ctx: FetchContext,
            ) -> Result<crate::fetch::Fetched, crate::fetch::FetchError> {
                Err(crate::fetch::FetchError::SsrfBlocked {
                    address: "169.254.169.254:80".parse().unwrap(),
                    rule: "ssrf.link_local",
                    hop: 0,
                })
            }
        }
        let engine = Engine::new(Policy::builtin(), Arc::new(BlockingFetcher)).unwrap();
        let outcome = engine.process(InputSource::Url(
            Url::parse("http://metadata.test/").unwrap(),
        ));
        assert_eq!(outcome.report.status, InputStatus::SsrfBlocked);
        assert!(
            outcome
                .report
                .error
                .as_deref()
                .unwrap()
                .contains("ssrf.link_local")
        );
    }

    #[test]
    fn the_base_of_a_url_input_is_the_url_it_came_from() {
        let fetcher = RecordingFetcher::new(
            br#"<!DOCTYPE html><link rel="stylesheet" href="style.css">"#,
            Some("text/html"),
        );
        let mut policy = Policy::builtin();
        policy.subresources.fetch_subresources = true;
        let engine = Engine::new(policy, fetcher.clone()).unwrap();
        engine.process(InputSource::Url(
            Url::parse("http://site.test/dir/page.html").unwrap(),
        ));

        assert_eq!(
            fetcher.requested(),
            [
                "http://site.test/dir/page.html",
                "http://site.test/dir/style.css"
            ]
        );
    }
}
