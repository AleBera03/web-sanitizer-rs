//! The sub-resource loop is a bounded inner cycle that turns the
//! references an HTML input declared into fetched, sanitised, reported assets.
//!
//! The loop belongs to the worker that owns the parent input, and everything it
//! produces is owned there too. Bodies are fetched, sanitised and dropped inside
//! the same stack frame, so nothing is shared and no lifetime crosses a thread.
//!
//! Four limits hold it, and they are joint:
//! - how many requests (`max_requests`)
//! - how many bytes in total (`max_total_bytes`)
//! - how deep (`max_depth`, so a fetched stylesheet's own
//!   references are inspected but never fetched)
//! - the parent's own time budget.
//!
//! De-duplication is by absolute URL, which is what closes the cycle a page
//! referencing itself would otherwise open.
//!
//! Each sub-resource failure carries its own entry, its own status and its own cause.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use url::Url;

use crate::fetch::guard::FetchContext;
use crate::fetch::{FetchError, Fetcher};
use crate::html::Reference;
use crate::policy::{Action, FetchPolicy, Policy, SniffAction, SubresourceType};
use crate::report::{GuardBlock, InputStatus, SanitisationAction, SubresourceReport};
use crate::sniff::{MimeType, SniffOutcome, mime_from_content_type, sniff_bytes};
use crate::urlcheck::{UrlChecker, Verdict};

use super::route::route;

const CATEGORY_SSRF: &str = "ssrf";
/// Depth of everything this loop fetches: the parent sits at 0.
const SUBRESOURCE_DEPTH: u32 = 1;

/// A sanitised sub-resource body, ready to be written next to its parent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    /// Path relative to the output directory, `<N>-<name>.assets/asset-K.ext`,
    /// where the directory shares the stem of the parent's own output file.
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct SubresourceOutcome {
    /// One entry per reference the loop acted on, in document order.
    pub reports: Vec<SubresourceReport>,
    pub assets: Vec<Asset>,
    /// Reference string to local path, for the parent's second pass.
    pub rewrites: HashMap<String, String>,
}

/// What the joint budget has already been spent on.
#[derive(Debug, Default, Clone, Copy)]
struct Spent {
    requests: u32,
    bytes: u64,
}

pub struct SubresourceLoop<'a> {
    policy: &'a Policy,
    fetcher: &'a dyn Fetcher,
    urls: &'a UrlChecker<'a>,
    /// `None` for an input that has no URL of its own, such as a local file, where only references that
    /// are already absolute can name something fetchable.
    base: Option<Url>,
    /// Endpoint of the parent input, for the same-origin exemption.
    parent_endpoint: Option<SocketAddr>,
    /// Directory the assets of this input live in, relative to the output dir.
    asset_dir: String,
    /// The parent's time budget.
    deadline: Instant,
}

impl<'a> SubresourceLoop<'a> {
    pub fn new(
        policy: &'a Policy,
        fetcher: &'a dyn Fetcher,
        urls: &'a UrlChecker<'a>,
        base: Option<Url>,
        parent_endpoint: Option<SocketAddr>,
        asset_dir: String,
        deadline: Instant,
    ) -> SubresourceLoop<'a> {
        SubresourceLoop {
            policy,
            fetcher,
            urls,
            base,
            parent_endpoint,
            asset_dir,
            deadline,
        }
    }

    pub fn run(&self, references: &[Reference]) -> SubresourceOutcome {
        let rules = &self.policy.subresources;
        let mut outcome = SubresourceOutcome::default();
        if !rules.fetch_subresources || rules.max_depth == 0 {
            return outcome;
        }

        let mut seen: HashSet<String> = HashSet::new();
        let mut spent = Spent::default();
        for reference in references {
            // a reference we cannot turn into an absolute http(s) URL is not a request we could make
            let Some(url) = self.absolute(&reference.raw) else {
                continue;
            };
            if !matches!(url.scheme(), "http" | "https") {
                continue;
            }
            if !seen.insert(url.as_str().to_string()) {
                continue;
            }

            let slot = outcome.reports.len();
            let (report, asset) = self.handle(&url, reference, slot, &mut spent);
            if let Some(local) = self.rewrite_target(&report, asset.as_ref()) {
                outcome.rewrites.insert(reference.raw.clone(), local);
            }
            outcome.reports.push(report);
            outcome.assets.extend(asset);
        }
        outcome
    }

    /// One reference, end to end.
    fn handle(
        &self,
        url: &Url,
        reference: &Reference,
        slot: usize,
        spent: &mut Spent,
    ) -> (SubresourceReport, Option<Asset>) {
        let rules = &self.policy.subresources;
        let start = Instant::now();

        // a block-listed or malformed URL is refused without a request
        if let Some(rule) = url_refusal(self.urls.check(url.as_str())) {
            return (self.refused(url, start, rule), None);
        }
        if spent.requests >= rules.max_requests {
            return (
                self.budget_exceeded(url, start, "max_requests reached"),
                None,
            );
        }
        let remaining_bytes = rules.max_total_bytes.saturating_sub(spent.bytes);
        if remaining_bytes == 0 {
            return (
                self.budget_exceeded(url, start, "max_total_bytes reached"),
                None,
            );
        }
        let Some(time_left) = self.time_left() else {
            return (
                self.budget_exceeded(url, start, "parent time budget reached"),
                None,
            );
        };

        spent.requests += 1;
        let fetch_policy = self.fetch_policy(remaining_bytes, time_left);
        let fetched = match self.fetcher.fetch(
            url,
            &fetch_policy,
            FetchContext::subresource(self.parent_endpoint),
        ) {
            Ok(fetched) => fetched,
            Err(error) => return (self.fetch_failed(url, start, error), None),
        };
        spent.bytes += fetched.body.len() as u64;

        let declared = fetched.declared_mime.clone();
        let sniffed = sniff_bytes(&fetched.body);
        let mut report = SubresourceReport {
            final_url: Some(fetched.final_url.to_string()),
            declared_mime: declared.clone(),
            sniffed_mime: sniffed.map(|m| m.label().to_string()),
            bytes_in: fetched.body.len() as u64,
            ..self.entry(url, InputStatus::Clean, start)
        };

        // per-sub-resource budgets apply to each body individually
        if fetched.body.len() as u64 > self.policy.budgets.max_input_bytes {
            report.status = InputStatus::BudgetExceeded;
            report.error = Some("body exceeds max_input_bytes".to_string());
            report.duration_ms = elapsed_ms(start);
            return (report, None);
        }

        // the sniffed type wins over the declaration
        let mut actions = Vec::new();
        if let Some(mismatch) = mime_mismatch(declared.as_deref(), sniffed) {
            actions.push(mismatch);
            if rules.sniff_rule == SniffAction::Reject {
                report.status = InputStatus::Refused;
                report.error = Some("declared and sniffed types disagree".to_string());
                report.actions = actions;
                report.duration_ms = elapsed_ms(start);
                return (report, None);
            }
        }

        let Some(kind) = effective_type(sniffed, reference.kind) else {
            report.status = InputStatus::Refused;
            report.error = Some(format!(
                "sniffed type {} is not a fetchable sub-resource",
                report.sniffed_mime.as_deref().unwrap_or("unknown")
            ));
            report.actions = actions;
            report.duration_ms = elapsed_ms(start);
            return (report, None);
        };
        if !rules.types.contains(&kind) {
            report.status = InputStatus::Refused;
            report.error = Some(format!("type {kind:?} is outside the configured set"));
            report.actions = actions;
            report.duration_ms = elapsed_ms(start);
            return (report, None);
        }

        // re-entry into the pipeline at depth 1. Its own references, if it has
        // any, are inspected by the HTML pass and never fetched
        let routed = route(
            SniffOutcome {
                output: Some(fetched.body),
                mime_type: sniffed,
                actions: Vec::new(),
                refused: false,
            },
            self.policy,
            self.urls,
            SUBRESOURCE_DEPTH,
        );
        actions.extend(routed.actions);

        report.status = if routed.refused {
            InputStatus::Refused
        } else if actions.is_empty() {
            InputStatus::Clean
        } else {
            InputStatus::Sanitised
        };
        report.actions = actions;
        report.duration_ms = elapsed_ms(start);

        if routed.refused {
            report.error = Some("refused while sanitising".to_string());
            return (report, None);
        }
        report.bytes_out = routed.output.len() as u64;
        let asset = Asset {
            path: format!(
                "{}/asset-{slot}.{}",
                self.asset_dir,
                extension(sniffed, kind)
            ),
            bytes: routed.output,
        };
        (report, Some(asset))
    }

    fn absolute(&self, raw: &str) -> Option<Url> {
        let raw = raw.trim();
        if raw.is_empty() || raw.starts_with('#') {
            return None;
        }
        match &self.base {
            Some(base) => base.join(raw).ok(),
            None => Url::parse(raw).ok(),
        }
    }

    /// Where the parent's attribute should point after the loop, if anywhere.
    fn rewrite_target(&self, report: &SubresourceReport, asset: Option<&Asset>) -> Option<String> {
        let rules = &self.policy.subresources;
        if !rules.rewrite_refs {
            return None;
        }
        if let Some(asset) = asset {
            return Some(asset.path.clone());
        }
        let refused = matches!(
            report.status,
            InputStatus::Refused | InputStatus::BudgetExceeded | InputStatus::SsrfBlocked
        );
        if refused && rules.action_refused != Action::Allow {
            return Some(self.urls.rules().placeholder_url.clone());
        }
        None
    }

    /// The client's limits for one sub-resource request: never more than what is
    /// left of the parent's joint byte budget, never longer than its time budget.
    fn fetch_policy(&self, remaining_bytes: u64, time_left: Duration) -> FetchPolicy {
        let fetch = &self.policy.fetch;
        FetchPolicy {
            max_response_bytes: fetch.max_response_bytes.min(remaining_bytes),
            total_timeout_ms: fetch
                .total_timeout_ms
                .min(time_left.as_millis().max(1) as u64),
            ..fetch.clone()
        }
    }

    fn time_left(&self) -> Option<Duration> {
        let left = self.deadline.saturating_duration_since(Instant::now());
        if left.is_zero() { None } else { Some(left) }
    }

    fn entry(&self, url: &Url, status: InputStatus, start: Instant) -> SubresourceReport {
        SubresourceReport {
            url: url.to_string(),
            final_url: None,
            depth: SUBRESOURCE_DEPTH,
            status,
            bytes_in: 0,
            bytes_out: 0,
            duration_ms: elapsed_ms(start),
            declared_mime: None,
            sniffed_mime: None,
            block: None,
            actions: Vec::new(),
            error: None,
        }
    }

    fn refused(&self, url: &Url, start: Instant, cause: &str) -> SubresourceReport {
        SubresourceReport {
            error: Some(cause.to_string()),
            ..self.entry(url, InputStatus::Refused, start)
        }
    }

    fn budget_exceeded(&self, url: &Url, start: Instant, cause: &str) -> SubresourceReport {
        SubresourceReport {
            error: Some(cause.to_string()),
            ..self.entry(url, InputStatus::BudgetExceeded, start)
        }
    }

    /// Map a client failure onto the report, keeping the guard's refusal apart
    /// from ordinary network trouble.
    fn fetch_failed(&self, url: &Url, start: Instant, error: FetchError) -> SubresourceReport {
        match error {
            FetchError::SsrfBlocked { address, rule, hop } => SubresourceReport {
                block: Some(GuardBlock {
                    rule_id: rule.to_string(),
                    category: CATEGORY_SSRF.to_string(),
                    resolved_address: address.to_string(),
                    hop,
                }),
                error: Some(format!("{rule} refuses {address}")),
                ..self.entry(url, InputStatus::SsrfBlocked, start)
            },
            FetchError::BodyTooLarge { cap } => {
                self.budget_exceeded(url, start, &format!("body exceeds {cap} bytes"))
            }
            FetchError::UnsupportedScheme { .. } => SubresourceReport {
                error: Some(error.to_string()),
                ..self.entry(url, InputStatus::UnsupportedScheme, start)
            },
            other => SubresourceReport {
                error: Some(other.to_string()),
                ..self.entry(url, InputStatus::FetchError, start)
            },
        }
    }
}

/// The rule that refuses a URL before any request, if one does.
fn url_refusal(verdict: Verdict) -> Option<&'static str> {
    match verdict {
        Verdict::Blocked => Some("host is on a block-list"),
        Verdict::Homograph => Some("host is a homograph of a protected domain"),
        Verdict::Malformed => Some("url is malformed"),
        Verdict::Clean | Verdict::Idn => None,
    }
}

fn effective_type(sniffed: Option<MimeType>, claimed: SubresourceType) -> Option<SubresourceType> {
    match sniffed {
        None => Some(claimed),
        Some(mime) => subresource_type(mime),
    }
}

/// The policy category a sniffed body falls into, or `None` when the type is
/// one no sub-resource may ever be. This is a decision of the loop, so it
/// lives here and never in the sniffer.
fn subresource_type(mime: MimeType) -> Option<SubresourceType> {
    match mime {
        MimeType::ImageJpeg
        | MimeType::ImagePng
        | MimeType::ImageGif
        | MimeType::ImageWebp
        | MimeType::ImageSvg
        | MimeType::ImageTiff => Some(SubresourceType::Image),
        _ => None,
    }
}

/// Extension of the sanitised copy: from the sniffed type when there is one,
/// otherwise from the class of the reference. Never from the URL, so a
/// reference to `../../etc/passwd` cannot influence an output path.
fn extension(sniffed: Option<MimeType>, kind: SubresourceType) -> &'static str {
    match sniffed {
        Some(mime) => mime.extension(),
        None => match kind {
            SubresourceType::Css => "css",
            SubresourceType::Js => "js",
            SubresourceType::Image => "bin",
        },
    }
}

/// The mismatch action, when a declared `Content-Type` we understand disagrees
/// with the sniffed type. A declaration we do not know is not a disagreement.
fn mime_mismatch(declared: Option<&str>, sniffed: Option<MimeType>) -> Option<SanitisationAction> {
    let declared_mime = mime_from_content_type(declared?)?;
    let sniffed = sniffed?;
    if declared_mime == sniffed {
        return None;
    }
    Some(SanitisationAction {
        rule_id: "sniff.mime_mismatch".to_string(),
        category: "sniff".to_string(),
        location: crate::report::Location {
            line: 0,
            byte_offset: 0,
        },
        original: format!(
            "declared={} sniffed={}",
            declared_mime.label(),
            sniffed.label()
        ),
        action: Action::Rewrite,
        replacement: None,
    })
}

fn elapsed_ms(start: Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    use crate::fetch::Fetched;
    use crate::html::tests_support::no_url_checker;
    use crate::policy::{GuardScope, Policy, SsrfRules};
    use crate::tests_helper::set_from::SetFrom;

    const PNG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    const HTML: &[u8] = b"<!DOCTYPE html><p>hi</p>";

    type Answer = Result<(Vec<u8>, Option<String>), FetchError>;

    struct StubFetcher {
        answers: Mutex<HashMap<String, Answer>>,
        default: Mutex<Option<Answer>>,
        requested: Mutex<Vec<String>>,
        contexts: Mutex<Vec<FetchContext>>,
    }

    impl StubFetcher {
        fn new() -> StubFetcher {
            StubFetcher {
                answers: Mutex::new(HashMap::new()),
                default: Mutex::new(None),
                requested: Mutex::new(Vec::new()),
                contexts: Mutex::new(Vec::new()),
            }
        }

        fn body(self, url: &str, body: &[u8], mime: Option<&str>) -> StubFetcher {
            self.answers
                .lock()
                .unwrap()
                .insert(url.to_string(), Ok((body.to_vec(), mime.map(String::from))));
            self
        }

        fn failure(self, url: &str, error: FetchError) -> StubFetcher {
            self.answers
                .lock()
                .unwrap()
                .insert(url.to_string(), Err(error));
            self
        }

        /// Answer for every URL without an explicit script entry.
        fn otherwise(self, body: &[u8], mime: Option<&str>) -> StubFetcher {
            *self.default.lock().unwrap() = Some(Ok((body.to_vec(), mime.map(String::from))));
            self
        }

        fn requested(&self) -> Vec<String> {
            self.requested.lock().unwrap().clone()
        }
    }

    impl Fetcher for StubFetcher {
        fn fetch(
            &self,
            url: &Url,
            _policy: &FetchPolicy,
            ctx: FetchContext,
        ) -> Result<Fetched, FetchError> {
            self.requested.lock().unwrap().push(url.to_string());
            self.contexts.lock().unwrap().push(ctx);
            let scripted = self.answers.lock().unwrap().get(url.as_str()).cloned();
            let answer = match scripted {
                Some(answer) => answer,
                None => self
                    .default
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or(Err(FetchError::Status { status: 404 })),
            };
            answer.map(|(body, declared_mime)| Fetched {
                final_url: url.clone(),
                declared_mime,
                endpoint: None,
                body,
            })
        }
    }

    fn policy_fetching() -> Policy {
        let mut policy = Policy::builtin();
        policy.subresources.fetch_subresources = true;
        policy.ssrf = SsrfRules {
            guard_input_urls: GuardScope::Server,
            ..SsrfRules::default()
        };
        policy
    }

    fn css(raw: &str) -> Reference {
        Reference {
            raw: raw.to_string(),
            kind: SubresourceType::Css,
        }
    }

    fn image(raw: &str) -> Reference {
        Reference {
            raw: raw.to_string(),
            kind: SubresourceType::Image,
        }
    }

    fn run(policy: &Policy, fetcher: &StubFetcher, references: &[Reference]) -> SubresourceOutcome {
        let checker = no_url_checker();
        SubresourceLoop::new(
            policy,
            fetcher,
            &checker,
            Some(Url::parse("http://parent.test/dir/page.html").unwrap()),
            None,
            "0-page.html.assets".to_string(),
            Instant::now() + Duration::from_secs(30),
        )
        .run(references)
    }

    // the switch itself

    #[test]
    fn nothing_is_fetched_while_the_feature_is_off() {
        // the default policy makes zero requests
        let fetcher = StubFetcher::new().otherwise(b"body{}", Some("text/css"));
        let outcome = run(&Policy::builtin(), &fetcher, &[css("/a.css")]);
        assert!(outcome.reports.is_empty());
        assert!(fetcher.requested().is_empty());
    }

    #[test]
    fn a_zero_depth_policy_fetches_nothing() {
        let mut policy = policy_fetching();
        policy.subresources.max_depth = 0;
        let fetcher = StubFetcher::new().otherwise(b"body{}", Some("text/css"));
        assert!(run(&policy, &fetcher, &[css("/a.css")]).reports.is_empty());
        assert!(fetcher.requested().is_empty());
    }

    // resolution and de-duplication

    #[test]
    fn references_resolve_against_the_document_base() {
        let fetcher = StubFetcher::new().otherwise(b"body{}", Some("text/css"));
        let refs = [css("a.css"), css("/b.css"), css("http://other.test/c.css")];
        run(&policy_fetching(), &fetcher, &refs);
        assert_eq!(
            fetcher.requested(),
            [
                "http://parent.test/dir/a.css",
                "http://parent.test/b.css",
                "http://other.test/c.css"
            ]
        );
    }

    #[test]
    fn the_same_absolute_url_is_fetched_once() {
        let fetcher = StubFetcher::new().otherwise(b"body{}", Some("text/css"));
        let refs = [css("/a.css"), css("a.css"), css("/dir/a.css")];
        let outcome = run(&policy_fetching(), &fetcher, &refs);
        // `/a.css` and `/dir/a.css` are two URLs, `a.css` repeats the second
        assert_eq!(fetcher.requested().len(), 2);
        assert_eq!(outcome.reports.len(), 2);
    }

    #[test]
    fn unfetchable_references_are_skipped_without_a_request() {
        let fetcher = StubFetcher::new().otherwise(b"body{}", Some("text/css"));
        let refs = [
            css("#blocked"),
            css("data:text/css,body{}"),
            css("mailto:a@b.test"),
            css("   "),
        ];
        let outcome = run(&policy_fetching(), &fetcher, &refs);
        assert!(outcome.reports.is_empty());
        assert!(fetcher.requested().is_empty());
    }

    // budgets

    #[test]
    fn the_request_budget_is_exact_at_its_boundary() {
        // exactly `max_requests` fetched, the extra one refused
        let mut policy = policy_fetching();
        policy.subresources.max_requests = 3;
        let fetcher = StubFetcher::new().otherwise(b"body{}", Some("text/css"));
        let refs: Vec<Reference> = (0..5).map(|i| css(&format!("/a{i}.css"))).collect();

        let outcome = run(&policy, &fetcher, &refs);
        assert_eq!(fetcher.requested().len(), 3);
        assert_eq!(outcome.reports.len(), 5);
        assert_eq!(outcome.reports[2].status, InputStatus::Clean);
        for extra in &outcome.reports[3..] {
            assert_eq!(extra.status, InputStatus::BudgetExceeded);
            assert!(extra.error.as_deref().unwrap().contains("max_requests"));
        }
    }

    #[test]
    fn the_byte_budget_stops_the_loop_once_it_is_spent() {
        let mut policy = policy_fetching();
        policy.subresources.max_total_bytes = 10;
        let fetcher = StubFetcher::new().otherwise(&[b'x'; 10], Some("text/css"));
        let refs = [css("/a.css"), css("/b.css")];

        let outcome = run(&policy, &fetcher, &refs);
        assert_eq!(fetcher.requested().len(), 1);
        assert_eq!(outcome.reports[0].status, InputStatus::Clean);
        assert_eq!(outcome.reports[1].status, InputStatus::BudgetExceeded);
        assert!(
            outcome.reports[1]
                .error
                .as_deref()
                .unwrap()
                .contains("max_total_bytes")
        );
    }

    #[test]
    fn an_expired_parent_deadline_stops_every_request() {
        let policy = policy_fetching();
        let fetcher = StubFetcher::new().otherwise(b"body{}", Some("text/css"));
        let checker = no_url_checker();
        let outcome = SubresourceLoop::new(
            &policy,
            &fetcher,
            &checker,
            Some(Url::parse("http://parent.test/").unwrap()),
            None,
            "0-page.html.assets".to_string(),
            Instant::now() - Duration::from_secs(1),
        )
        .run(&[css("/a.css")]);

        assert!(fetcher.requested().is_empty());
        assert_eq!(outcome.reports[0].status, InputStatus::BudgetExceeded);
    }

    #[test]
    fn an_oversized_body_is_a_budget_refusal_of_that_sub_resource_only() {
        let mut policy = policy_fetching();
        policy.budgets.max_input_bytes = 4;
        let fetcher = StubFetcher::new()
            .body("http://parent.test/big.css", &[b'x'; 8], Some("text/css"))
            .body("http://parent.test/ok.css", b"body", Some("text/css"));

        let outcome = run(&policy, &fetcher, &[css("/big.css"), css("/ok.css")]);
        assert_eq!(outcome.reports[0].status, InputStatus::BudgetExceeded);
        assert_eq!(outcome.reports[1].status, InputStatus::Clean);
    }

    // classification before the socket

    #[test]
    fn a_blocklisted_reference_is_refused_without_a_request() {
        let policy = policy_fetching();
        let blockset = crate::policy::blockset::BlockSet::set_from_list(&["0.0.0.0 evil.test"]);
        let skeletons = crate::policy::protectedset::SkeletonSet::default();
        let cache = crate::urlcheck::cache::VerdictCache::default();
        let rules = crate::policy::UrlRules::default();
        let checker = UrlChecker::new(&blockset, &skeletons, &cache, &rules);
        let fetcher = StubFetcher::new().otherwise(b"body{}", Some("text/css"));

        let outcome = SubresourceLoop::new(
            &policy,
            &fetcher,
            &checker,
            Some(Url::parse("http://parent.test/").unwrap()),
            None,
            "0-page.html.assets".to_string(),
            Instant::now() + Duration::from_secs(30),
        )
        .run(&[css("http://evil.test/a.css")]);

        assert!(fetcher.requested().is_empty());
        assert_eq!(outcome.reports[0].status, InputStatus::Refused);
        assert!(
            outcome.reports[0]
                .error
                .as_deref()
                .unwrap()
                .contains("block-list")
        );
    }

    // the guard, seen from the loop

    #[test]
    fn a_guard_refusal_becomes_a_block_entry() {
        // the report names the address and the rule that fired
        let fetcher = StubFetcher::new().failure(
            "http://parent.test/meta",
            FetchError::SsrfBlocked {
                address: "169.254.169.254:80".parse().unwrap(),
                rule: "ssrf.link_local",
                hop: 0,
            },
        );
        let outcome = run(&policy_fetching(), &fetcher, &[image("/meta")]);
        let entry = &outcome.reports[0];
        assert_eq!(entry.status, InputStatus::SsrfBlocked);
        let block = entry.block.as_ref().unwrap();
        assert_eq!(block.rule_id, "ssrf.link_local");
        assert_eq!(block.category, "ssrf");
        assert_eq!(block.resolved_address, "169.254.169.254:80");
        assert_eq!(block.hop, 0);
        assert!(entry.final_url.is_none());
    }

    #[test]
    fn every_sub_resource_request_declares_itself_as_one() {
        // the guard can only apply its scope if the reason is passed along
        let fetcher = StubFetcher::new().otherwise(b"body{}", Some("text/css"));
        run(&policy_fetching(), &fetcher, &[css("/a.css")]);
        let contexts = fetcher.contexts.lock().unwrap();
        assert_eq!(contexts[0], FetchContext::subresource(None));
    }

    // types, sniffing, isolation

    #[test]
    fn a_stylesheet_that_is_really_html_is_refused() {
        // the sniffed type decides, and HTML is not in the set
        let fetcher = StubFetcher::new().body("http://parent.test/a.css", HTML, Some("text/css"));
        let outcome = run(&policy_fetching(), &fetcher, &[css("/a.css")]);
        let entry = &outcome.reports[0];
        assert_eq!(entry.status, InputStatus::Refused);
        assert_eq!(entry.sniffed_mime.as_deref(), Some("text/html"));
        assert_eq!(entry.declared_mime.as_deref(), Some("text/css"));
    }

    #[test]
    fn a_type_outside_the_configured_set_is_refused() {
        let mut policy = policy_fetching();
        policy.subresources.types = vec![SubresourceType::Css];
        let fetcher = StubFetcher::new().body("http://parent.test/a.png", PNG, Some("image/png"));
        let outcome = run(&policy, &fetcher, &[image("/a.png")]);
        assert_eq!(outcome.reports[0].status, InputStatus::Refused);
        assert!(
            outcome.reports[0]
                .error
                .as_deref()
                .unwrap()
                .contains("outside")
        );
    }

    #[test]
    fn a_declared_type_that_contradicts_the_bytes_is_reported() {
        let mut policy = policy_fetching();
        policy.subresources.sniff_rule = SniffAction::Rewrite;
        let fetcher = StubFetcher::new().body("http://parent.test/a.png", PNG, Some("image/gif"));
        let outcome = run(&policy, &fetcher, &[image("/a.png")]);
        let entry = &outcome.reports[0];
        assert_eq!(entry.status, InputStatus::Sanitised);
        assert_eq!(entry.actions[0].rule_id, "sniff.mime_mismatch");
        // the sniffed type wins: the asset is written as a png
        assert!(outcome.assets[0].path.ends_with(".png"));
    }

    #[test]
    fn an_unknown_declaration_is_not_a_mismatch() {
        // `text/css` names no magic-byte type, so it cannot contradict anything
        let fetcher =
            StubFetcher::new().body("http://parent.test/a.css", b"body{}", Some("text/css"));
        let outcome = run(&policy_fetching(), &fetcher, &[css("/a.css")]);
        assert_eq!(outcome.reports[0].status, InputStatus::Clean);
        assert!(outcome.reports[0].actions.is_empty());
    }

    #[test]
    fn failures_are_isolated_one_entry_each() {
        // a timeout, a 404 and a refusal live side by side
        let fetcher = StubFetcher::new()
            .failure(
                "http://parent.test/slow.css",
                FetchError::Timeout {
                    phase: crate::fetch::TimeoutPhase::Read,
                },
            )
            .failure(
                "http://parent.test/missing.css",
                FetchError::Status { status: 404 },
            )
            .body("http://parent.test/ok.css", b"body{}", Some("text/css"));

        let outcome = run(
            &policy_fetching(),
            &fetcher,
            &[css("/slow.css"), css("/missing.css"), css("/ok.css")],
        );
        assert_eq!(outcome.reports[0].status, InputStatus::FetchError);
        assert_eq!(outcome.reports[1].status, InputStatus::FetchError);
        assert_eq!(outcome.reports[2].status, InputStatus::Clean);
        assert!(outcome.reports[1].error.as_deref().unwrap().contains("404"));
    }

    #[test]
    fn a_fetched_html_sub_resource_does_not_pull_its_own_references() {
        // depth 1 is enforced, not assumed
        let nested = br#"<!DOCTYPE html><img src="http://parent.test/deep.png">"#;
        let mut policy = policy_fetching();
        policy.subresources.types = vec![SubresourceType::Image];
        // let the HTML body through the type filter by claiming it is an image
        let fetcher = StubFetcher::new().body("http://parent.test/page2", nested, None);
        run(&policy, &fetcher, &[image("/page2")]);
        assert_eq!(fetcher.requested(), ["http://parent.test/page2"]);
    }

    // output layout and rewriting

    #[test]
    fn assets_are_named_by_slot_and_sniffed_type() {
        let fetcher = StubFetcher::new()
            .body("http://parent.test/a.css", b"body{}", Some("text/css"))
            .body("http://parent.test/b.png", PNG, Some("image/png"));
        let outcome = run(
            &policy_fetching(),
            &fetcher,
            &[css("/a.css"), image("/b.png")],
        );

        assert_eq!(outcome.assets[0].path, "0-page.html.assets/asset-0.css");
        assert_eq!(outcome.assets[1].path, "0-page.html.assets/asset-1.png");
        assert_eq!(outcome.assets[0].bytes, b"body{}");
    }

    #[test]
    fn a_traversal_reference_cannot_reach_the_output_path() {
        let fetcher = StubFetcher::new().otherwise(b"body{}", Some("text/css"));
        let outcome = run(&policy_fetching(), &fetcher, &[css("../../etc/passwd")]);
        assert_eq!(outcome.assets[0].path, "0-page.html.assets/asset-0.css");
    }

    #[test]
    fn the_parent_is_pointed_at_the_local_copies() {
        let fetcher =
            StubFetcher::new().body("http://parent.test/a.css", b"body{}", Some("text/css"));
        let outcome = run(&policy_fetching(), &fetcher, &[css("/a.css")]);
        assert_eq!(
            outcome.rewrites.get("/a.css").map(String::as_str),
            Some("0-page.html.assets/asset-0.css")
        );
    }

    #[test]
    fn a_refused_reference_is_defanged_in_the_parent() {
        let fetcher = StubFetcher::new().body("http://parent.test/a.css", HTML, Some("text/css"));
        let outcome = run(&policy_fetching(), &fetcher, &[css("/a.css")]);
        assert_eq!(
            outcome.rewrites.get("/a.css").map(String::as_str),
            Some("#blocked")
        );
    }

    #[test]
    fn a_network_failure_leaves_the_reference_alone() {
        let fetcher = StubFetcher::new().failure(
            "http://parent.test/a.css",
            FetchError::Status { status: 404 },
        );
        let outcome = run(&policy_fetching(), &fetcher, &[css("/a.css")]);
        assert!(outcome.rewrites.is_empty());
    }

    #[test]
    fn only_images_are_a_fetchable_subresource_type() {
        assert_eq!(
            subresource_type(MimeType::ImagePng),
            Some(SubresourceType::Image)
        );
        assert_eq!(subresource_type(MimeType::TextHtml), None);
        assert_eq!(subresource_type(MimeType::ApplicationPdf), None);
    }

    #[test]
    fn inspect_only_mode_rewrites_nothing() {
        let mut policy = policy_fetching();
        policy.subresources.rewrite_refs = false;
        let fetcher = StubFetcher::new().otherwise(b"body{}", Some("text/css"));
        let outcome = run(&policy, &fetcher, &[css("/a.css")]);
        assert!(outcome.rewrites.is_empty());
        // the asset is still produced and reported
        assert_eq!(outcome.assets.len(), 1);
    }
}
