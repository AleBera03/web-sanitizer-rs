pub mod expect;
pub mod origin;
pub mod sentinel;
pub mod server;

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};

use crate::error::{Result, XtaskError, write};
use crate::paths::Layout;
use crate::table;

use expect::{SECRET, SENTINEL};
use origin::Origin;
use sentinel::Sentinel;
use server::Sanitiser;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    NoFetch,
    Fetch,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Mode::NoFetch => "nofetch",
            Mode::Fetch => "fetch",
        }
    }

    pub fn policy(self) -> &'static str {
        match self {
            Mode::NoFetch => "scenarios/policy-nofetch.toml",
            Mode::Fetch => "scenarios/policy-fetch.toml",
        }
    }

    pub fn parse(text: &str) -> Vec<Mode> {
        match text {
            "nofetch" => vec![Mode::NoFetch],
            "fetch" => vec![Mode::Fetch],
            _ => vec![Mode::NoFetch, Mode::Fetch],
        }
    }
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Suite {
    Origin,
    Local,
}

impl Suite {
    pub const ALL: [Suite; 2] = [Suite::Origin, Suite::Local];

    pub fn label(self) -> &'static str {
        match self {
            Suite::Origin => "origin",
            Suite::Local => "local",
        }
    }

    pub fn title(self) -> &'static str {
        match self {
            Suite::Origin => "evil-origin scenarios",
            Suite::Local => "local scenarios",
        }
    }
}

#[derive(Debug, Deserialize)]
struct ScenarioList {
    scenarios: Vec<Published>,
}


#[derive(Debug, Clone, Deserialize)]
struct Published {
    category: String,
    name: String,
    #[serde(default)]
    path: String,
}

impl Published {
    fn into_scenario(self) -> Scenario {
        Scenario {
            suite: Suite::Origin,
            category: self.category,
            name: self.name,
            path: self.path,
        }
    }
}


#[derive(Debug, Clone)]
pub struct Scenario {
    pub suite: Suite,
    pub category: String,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Deserialize)]
struct ResourceResponse {
    #[serde(default)]
    report: Option<Report>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Report {
    status: String,
    #[serde(default)]
    sniffed_mime: Option<String>,
    #[serde(default)]
    actions: Vec<Action>,
    #[serde(default)]
    subresources: Option<Vec<SubresourceReport>>,
    #[serde(default)]
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Action {
    rule_id: String,
}

#[derive(Debug, Deserialize)]
struct SubresourceReport {
    status: String,
    #[serde(default)]
    block: Option<Block>,
}

#[derive(Debug, Deserialize)]
struct Block {
    #[serde(default)]
    resolved_address: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ScenarioRow {
    pub suite: String,
    pub mode: String,
    pub category: String,
    pub name: String,
    pub http: u16,
    pub status: String,
    pub wall_ms: u128,
    pub rules: String,
    pub sniffed_mime: String,
    pub subresources: String,
    pub blocked_addresses: String,
    pub sentinel_accepted: String,
    pub passed: bool,
    pub reason: String,
}

struct Answer {
    http: u16,
    body: Vec<u8>,
    transport: Option<String>,
}

fn post(endpoint: &str, payload: &[u8], content_type: &str, timeout: Duration) -> Answer {
    let sent = ureq::post(endpoint)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .header("Content-Type", content_type)
        .header("Cookie", &format!("session={SECRET}"))
        .header("Authorization", &format!("Bearer {SECRET}"))
        .send(payload);
    match sent {
        Ok(mut response) => {
            let http = response.status().as_u16();
            let body = response
                .body_mut()
                .with_config()
                .limit(64 * 1024 * 1024)
                .read_to_vec()
                .unwrap_or_default();
            Answer {
                http,
                body,
                transport: None,
            }
        }
        Err(ureq::Error::StatusCode(code)) => Answer {
            http: code,
            body: Vec::new(),
            transport: None,
        },
        Err(error) => Answer {
            http: 0,
            body: Vec::new(),
            transport: Some(error.to_string()),
        },
    }
}

fn load_scenarios(origin: &Origin, timeout: Duration) -> Result<Vec<Scenario>> {
    let url = origin.url("/scenarios");
    let text = ureq::get(&url)
        .config()
        .timeout_global(Some(timeout))
        .build()
        .call()
        .and_then(|mut response| response.body_mut().read_to_string())
        .map_err(|error| {
            XtaskError::Harness(format!("cannot read the scenario list from {url}: {error}"))
        })?;
    let list: ScenarioList = serde_json::from_str(&text).map_err(|source| XtaskError::Json {
        path: std::path::PathBuf::from(&url),
        source,
    })?;
    Ok(list
        .scenarios
        .into_iter()
        .map(Published::into_scenario)
        .collect())
}

fn judge(
    mode: Mode,
    scenario: &Scenario,
    answer: &Answer,
    parsed: &Option<ResourceResponse>,
    wall_ms: u128,
    sentinel: Option<usize>,
) -> (Vec<String>, ScenarioRow) {
    let table_of = expect::table();
    let expectation = table_of.get(scenario.name.as_str());
    let mut reasons = Vec::new();

    if let Some(transport) = &answer.transport {
        reasons.push(format!("transport failure: {transport}"));
    }

    if let Some(message) = parsed.as_ref().and_then(|body| body.error.as_ref()) {
        reasons.push(format!("the server answered with an error: {message}"));
    }
    let report = parsed.as_ref().and_then(|body| body.report.as_ref());
    if let Some(message) = report.and_then(|r| r.error.as_ref()) {
        reasons.push(format!("the report carries an error: {message}"));
    }
    let status = report.map(|r| r.status.clone()).unwrap_or_default();
    let rules: Vec<String> = report
        .map(|r| r.actions.iter().map(|a| a.rule_id.clone()).collect())
        .unwrap_or_default();
    let sniffed = report
        .and_then(|r| r.sniffed_mime.clone())
        .unwrap_or_default();
    let content = parsed
        .as_ref()
        .and_then(|body| body.content.as_ref())
        .and_then(|encoded| BASE64.decode(encoded).ok())
        .unwrap_or_default();
    let lowered = String::from_utf8_lossy(&content).to_lowercase();

    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut blocked = Vec::new();
    if let Some(subresources) = report.and_then(|r| r.subresources.as_ref()) {
        for sub in subresources {
            *counts.entry(sub.status.clone()).or_default() += 1;
            if sub.status == "ssrf_blocked" {
                if let Some(address) = sub.block.as_ref().and_then(|b| b.resolved_address.clone()) {
                    blocked.push(address);
                }
            }
        }
    }

    if let Some(expected) = expectation {
        if !expected.http.contains(&answer.http) {
            reasons.push(format!("http {} not in {:?}", answer.http, expected.http));
        }
        if !status.is_empty() && !expected.status.contains(&status.as_str()) {
            reasons.push(format!("status {status} not in {:?}", expected.status));
        }
        for rule in expected.rules {
            if !rules.iter().any(|fired| fired == rule) {
                reasons.push(format!("rule {rule} did not fire"));
            }
        }
        for marker in expected.forbidden {
            if lowered.contains(&marker.to_lowercase()) {
                reasons.push(format!("{marker:?} survived in the output"));
            }
        }
        if let Some(mime) = expected.sniffed {
            if sniffed != mime {
                reasons.push(format!("sniffed {sniffed:?}, expected {mime:?}"));
            }
        }
        if let Some(limit) = expected.max_wall_ms {
            if wall_ms > limit {
                reasons.push(format!("took {wall_ms} ms, limit is {limit} ms"));
            }
        }

        if mode == Mode::Fetch {
            let fetch_table = expect::fetch_table();
            if let Some(rule) = fetch_table.get(scenario.name.as_str()) {
                let never_requested: usize = ["budget_exceeded", "ssrf_blocked"]
                    .iter()
                    .map(|status| counts.get(*status).copied().unwrap_or_default())
                    .sum();
                let attempted: usize = counts.values().sum::<usize>() - never_requested;
                if let Some(max) = rule.max_attempted {
                    if attempted > max {
                        reasons.push(format!("requested {attempted} sub-resources, cap is {max}"));
                    }
                }
                if let Some(min) = rule.min_budget_exceeded {
                    let seen = counts.get("budget_exceeded").copied().unwrap_or_default();
                    if seen < min {
                        reasons.push(format!("{seen} budget refusals, expected at least {min}"));
                    }
                }
                for wanted in rule.blocked {
                    if counts.get(*wanted).copied().unwrap_or_default() == 0 {
                        reasons.push(format!("no sub-resource ended in {wanted}"));
                    }
                }
                for marker in rule.forbidden {
                    if lowered.contains(&marker.to_lowercase()) {
                        reasons.push(format!("{marker:?} survived in the output"));
                    }
                }
            }
        }
    }

    if let Some(accepted) = sentinel {
        if accepted > 0 {
            reasons.push(format!("the sentinel accepted {accepted} connection(s)"));
        }
    }

    let row = ScenarioRow {
        suite: scenario.suite.label().to_string(),
        mode: mode.label().to_string(),
        category: scenario.category.clone(),
        name: scenario.name.clone(),
        http: answer.http,
        status,
        wall_ms,
        rules: table::words(&rules),
        sniffed_mime: sniffed,
        subresources: counts
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect::<Vec<String>>()
            .join(" "),
        blocked_addresses: table::words(&blocked),
        sentinel_accepted: sentinel.map(|n| n.to_string()).unwrap_or_default(),
        passed: reasons.is_empty(),
        reason: reasons.join("; "),
    };
    (reasons, row)
}

pub struct Options {
    pub origin: String,
    pub port: u16,
    pub timeout: Duration,
    pub boot: Duration,
    pub attach: Option<String>,
    pub skip_setup: bool,
}

pub fn run(layout: &Layout, modes: &[Mode], options: &Options) -> Result<Vec<ScenarioRow>> {
    let origin = Origin::new(&options.origin);
    if !options.skip_setup {
        origin.ensure(layout.root(), options.boot)?;
    }
    let published = load_scenarios(&origin, options.timeout)?;
    println!("{} scenarios published by the origin", published.len());

    let mut rows = Vec::new();
    for suite in Suite::ALL {
        println!("\n===== {} =====", suite.title());
        let first = rows.len();
        for mode in modes {
            let server = match &options.attach {
                Some(base) => Sanitiser::attach(base),
                None => Sanitiser::start(layout.root(), mode.policy(), options.port, options.boot)?,
            };
            println!("\n== {} mode", mode.label());
            match suite {
                Suite::Origin => {
                    run_published(&server, &origin, *mode, &published, options.timeout, &mut rows)
                }
                Suite::Local => run_local(&server, *mode, options.timeout, &mut rows)?,
            }
        }
        report_suite(suite, &rows[first..]);
    }
    Ok(rows)
}

fn run_published(
    server: &Sanitiser,
    origin: &Origin,
    mode: Mode,
    published: &[Scenario],
    timeout: Duration,
    rows: &mut Vec<ScenarioRow>,
) {
    for scenario in published {
        let row = run_one(server, origin, mode, scenario, timeout);
        report_line(&row);
        rows.push(row);
    }
}

fn run_local(
    server: &Sanitiser,
    mode: Mode,
    timeout: Duration,
    rows: &mut Vec<ScenarioRow>,
) -> Result<()> {
    let row = run_sentinel(server, mode, timeout)?;
    report_line(&row);
    rows.push(row);
    Ok(())
}

fn run_one(
    server: &Sanitiser,
    origin: &Origin,
    mode: Mode,
    scenario: &Scenario,
    timeout: Duration,
) -> ScenarioRow {
    let url = origin.url(&scenario.path);
    let payload = serde_json::json!({ "url": url }).to_string();
    let started = Instant::now();
    let answer = post(
        &server.endpoint(),
        payload.as_bytes(),
        "application/json",
        timeout,
    );
    let wall_ms = started.elapsed().as_millis();
    let parsed = serde_json::from_slice::<ResourceResponse>(&answer.body).ok();
    judge(mode, scenario, &answer, &parsed, wall_ms, None).1
}

fn run_sentinel(server: &Sanitiser, mode: Mode, timeout: Duration) -> Result<ScenarioRow> {
    let sentinel = Sentinel::start()?;
    println!("sentinel listening on 127.0.0.1:{}", sentinel.port());
    let page = sentinel.page();
    let scenario = Scenario {
        suite: Suite::Local,
        category: "local".to_string(),
        name: SENTINEL.to_string(),
        path: String::new(),
    };
    let started = Instant::now();
    let answer = post(&server.endpoint(), page.as_bytes(), "text/html", timeout);
    let wall_ms = started.elapsed().as_millis();
    std::thread::sleep(Duration::from_millis(300));
    let parsed = serde_json::from_slice::<ResourceResponse>(&answer.body).ok();
    Ok(judge(
        mode,
        &scenario,
        &answer,
        &parsed,
        wall_ms,
        Some(sentinel.accepted()),
    )
    .1)
}

fn report_suite(suite: Suite, rows: &[ScenarioRow]) {
    let failed = rows.iter().filter(|row| !row.passed).count();
    println!(
        "\n{} — {} of {} runs failed",
        suite.title(),
        failed,
        rows.len()
    );
}

fn report_line(row: &ScenarioRow) {
    println!(
        "{} {:9} {:30} {:>3} {:16} {}",
        match row.passed {
            true => "PASS",
            false => "FAIL",
        },
        row.category,
        row.name,
        row.http,
        row.status,
        row.reason
    );
}

pub fn save(layout: &Layout, rows: &[ScenarioRow]) -> Result<()> {
    table::save(&layout.scenario_file("scenarios.csv"), rows)?;
    let json = serde_json::to_string_pretty(rows).map_err(|source| XtaskError::Json {
        path: layout.scenario_file("scenarios.json"),
        source,
    })?;
    write(&layout.scenario_file("scenarios.json"), json)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scenario(name: &str) -> Scenario {
        Scenario {
            suite: Suite::Origin,
            category: "html".to_string(),
            name: name.to_string(),
            path: format!("/html/{name}"),
        }
    }

    fn local(name: &str) -> Scenario {
        Scenario {
            suite: Suite::Local,
            category: "local".to_string(),
            name: name.to_string(),
            path: String::new(),
        }
    }

    fn answer(http: u16, body: &str) -> Answer {
        Answer {
            http,
            body: body.as_bytes().to_vec(),
            transport: None,
        }
    }

    fn response(status: &str, rules: &[&str], content: &str) -> ResourceResponse {
        let encoded = BASE64.encode(content);
        let actions: Vec<String> = rules
            .iter()
            .map(|rule| format!("{{\"rule_id\":\"{rule}\"}}"))
            .collect();
        let text = format!(
            "{{\"report\":{{\"status\":\"{status}\",\"actions\":[{}]}},\"content\":\"{encoded}\"}}",
            actions.join(",")
        );
        serde_json::from_str(&text).unwrap()
    }

    #[test]
    fn a_scenario_meeting_every_expectation_passes() {
        let parsed = Some(response(
            "sanitised",
            &["html.script.disallowed"],
            "<p>clean",
        ));
        let (judged, row) = judge(
            Mode::NoFetch,
            &scenario("script-tag"),
            &answer(200, ""),
            &parsed,
            5,
            None,
        );
        assert!(judged.is_empty(), "{:?}", judged);
        assert!(row.passed);
        assert_eq!(row.mode, "nofetch");
        assert_eq!(row.suite, "origin");
    }

    #[test]
    fn a_surviving_payload_fails_and_says_which_marker() {
        let parsed = Some(response(
            "sanitised",
            &["html.script.disallowed"],
            "<script>alert(1)</script>",
        ));
        let (judged, _) = judge(
            Mode::NoFetch,
            &scenario("script-tag"),
            &answer(200, ""),
            &parsed,
            5,
            None,
        );
        assert!(!judged.is_empty());
        assert!(judged.iter().any(|r| r.contains("survived")));
    }

    #[test]
    fn a_missing_rule_is_reported_by_name() {
        let parsed = Some(response("sanitised", &[], "<p>clean"));
        let (judged, _) = judge(
            Mode::NoFetch,
            &scenario("script-tag"),
            &answer(200, ""),
            &parsed,
            5,
            None,
        );
        assert!(judged.iter().any(|r| r.contains("html.script.disallowed")));
    }

    #[test]
    fn an_unexpected_http_code_fails() {
        let parsed = Some(response("sanitised", &["html.script.disallowed"], "ok"));
        let (judged, _) = judge(
            Mode::NoFetch,
            &scenario("script-tag"),
            &answer(500, ""),
            &parsed,
            5,
            None,
        );
        assert!(judged.iter().any(|r| r.contains("http 500")));
    }

    #[test]
    fn a_sentinel_that_accepted_a_connection_fails_the_run() {
        let parsed = Some(response("sanitised", &["ssrf.loopback"], "<p>ok"));
        let (judged, row) = judge(
            Mode::Fetch,
            &local(SENTINEL),
            &answer(200, ""),
            &parsed,
            5,
            Some(1),
        );
        assert!(!judged.is_empty());
        assert_eq!(row.sentinel_accepted, "1");
        assert_eq!(row.suite, "local");
        assert!(judged.iter().any(|r| r.contains("sentinel accepted")));
    }

    #[test]
    fn a_transport_failure_is_carried_into_the_reason() {
        let failed = Answer {
            http: 0,
            body: Vec::new(),
            transport: Some("connection refused".to_string()),
        };
        let (judged, _) = judge(
            Mode::NoFetch,
            &scenario("script-tag"),
            &failed,
            &None,
            5,
            None,
        );
        assert!(judged.iter().any(|r| r.contains("connection refused")));
    }

    #[test]
    fn a_scenario_outside_the_table_is_recorded_without_a_verdict_to_fail() {
        let parsed = Some(response("clean", &[], "ok"));
        let (judged, row) = judge(
            Mode::NoFetch,
            &scenario("brand-new-scenario"),
            &answer(200, ""),
            &parsed,
            5,
            None,
        );
        assert!(judged.is_empty());
        assert_eq!(row.name, "brand-new-scenario");
    }

    #[test]
    fn a_deadline_overrun_is_reported() {
        let parsed = Some(response("fetch_error", &[], ""));
        let (judged, _) = judge(
            Mode::NoFetch,
            &Scenario {
                suite: Suite::Origin,
                category: "download".into(),
                name: "slow-drip".into(),
                path: "/download/slow-drip".into(),
            },
            &answer(502, ""),
            &parsed,
            40_000,
            None,
        );
        assert!(judged.iter().any(|r| r.contains("limit is 35000")));
    }

    #[test]
    fn sub_resources_refused_before_connecting_do_not_count_as_requests() {
        let text = "{\"report\":{\"status\":\"sanitised\",\"actions\":[],\"subresources\":[\
                    {\"status\":\"clean\"},{\"status\":\"budget_exceeded\"},\
                    {\"status\":\"budget_exceeded\"},{\"status\":\"ssrf_blocked\"}]}}";
        let parsed: Option<ResourceResponse> = serde_json::from_str(text).ok();
        let (judged, row) = judge(
            Mode::Fetch,
            &Scenario {
                suite: Suite::Origin,
                category: "html".into(),
                name: "recursive-include".into(),
                path: "/html/recursive-include".into(),
            },
            &answer(200, ""),
            &parsed,
            5,
            None,
        );
        assert!(judged.is_empty(), "{:?}", judged);
        assert!(row.subresources.contains("budget_exceeded=2"));
    }

    #[test]
    fn the_origin_corpus_runs_before_the_locally_authored_one() {
        assert_eq!(Suite::ALL, [Suite::Origin, Suite::Local]);
        assert_eq!(Suite::Origin.label(), "origin");
        assert_eq!(Suite::Local.label(), "local");
        assert_ne!(Suite::Origin.title(), Suite::Local.title());
    }

    #[test]
    fn a_published_scenario_belongs_to_the_origin_suite() {
        let list: ScenarioList = serde_json::from_str(
            "{\"scenarios\":[{\"category\":\"html\",\"name\":\"script-tag\",\
             \"path\":\"/html/script-tag\"}]}",
        )
        .unwrap();
        let scenarios: Vec<Scenario> = list
            .scenarios
            .into_iter()
            .map(Published::into_scenario)
            .collect();
        assert_eq!(scenarios[0].suite, Suite::Origin);
        assert_eq!(scenarios[0].path, "/html/script-tag");
    }

    #[test]
    fn modes_parse_into_one_or_both_runs() {
        assert_eq!(Mode::parse("fetch"), vec![Mode::Fetch]);
        assert_eq!(Mode::parse("nofetch"), vec![Mode::NoFetch]);
        assert_eq!(Mode::parse("both").len(), 2);
        assert_eq!(Mode::Fetch.policy(), "scenarios/policy-fetch.toml");
    }
}
