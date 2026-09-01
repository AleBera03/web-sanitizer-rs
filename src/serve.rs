//! # Server front-end
//! Sockets, routing, and the translation between an
//! [`Outcome`] and an HTTP response. No sanitisation logic lives here.
//!
//! The runtime belongs to this module alone. Every submission crosses into the
//! engine through `spawn_blocking`, so the synchronous pipeline keeps running on
//! a thread that is allowed to block and no async code exists below this line.
//!
//! ## What a submission is
//! The body is the input itself, unless the caller declares `application/json`,
//! in which case it names a URL the server fetches through the guarded client.
//! A URL that arrives here is attacker-controlled, so the engine runs with
//! [`FetchOrigin::InputServer`] and `ssrf.guard_input_urls` decides its fate.

use std::error::Error;
use std::net::IpAddr;
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header::CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use url::Url;

use web_sanitizer::fetch::HttpFetcher;
use web_sanitizer::input::InputSource;
use web_sanitizer::policy::{GuardScope, Policy};
use web_sanitizer::report::{InputReport, InputStatus};
use web_sanitizer::{Asset, Engine, FetchOrigin, Outcome};

use crate::args::ServeArgs;
use crate::status_slug;

#[tokio::main]
pub async fn run(policy: Policy, serve_args: &ServeArgs) -> Result<u8, Box<dyn Error>> {
    warn_about_bind(&serve_args.bind, &policy);

    // read before the policy moves into the engine
    let limit = body_limit(policy.budgets.max_input_bytes);
    let fetcher =
        Arc::new(HttpFetcher::new(&policy.fetch, &policy.ssrf).map_err(|e| e.to_string())?);
    let engine = Arc::new(
        Engine::new(policy, fetcher)
            .map_err(|e| e.to_string())?
            .with_origin(FetchOrigin::InputServer),
    );

    let app = Router::new()
        .route("/", get(liveness))
        .route("/health", get(health))
        .route(
            "/v1/resources",
            post(submit).layer(DefaultBodyLimit::max(limit)),
        )
        .with_state(engine);

    let address = address_of(&serve_args.bind, serve_args.port);
    let listener = tokio::net::TcpListener::bind(&address)
        .await
        .map_err(|e| format!("cannot listen on {address}: {e}"))?;
    eprintln!("listening on http://{address}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(|e| format!("server stopped: {e}"))?;
    Ok(0)
}

async fn liveness() -> &'static str {
    "Hi, i'm listening\n"
}

async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

async fn submit(
    State(engine): State<Arc<Engine>>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let input = match input_of(&headers, body) {
        Ok(input) => input,
        Err(detail) => return RequestError::bad_request(detail),
    };
    match tokio::task::spawn_blocking(move || engine.process(input)).await {
        Ok(outcome) => ResourceResponse::of(outcome).into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "processing panicked\n").into_response(),
    }
}

/// What the caller submitted. Raw bytes need no schema, so only the JSON form
/// can be malformed.
fn input_of(headers: &HeaderMap, body: Bytes) -> Result<InputSource, String> {
    if !declares_json(headers) {
        return Ok(InputSource::Bytes {
            name: String::new(),
            data: body.to_vec(),
        });
    }
    let submission: UrlSubmission =
        serde_json::from_slice(&body).map_err(|e| format!("invalid JSON body: {e}"))?;
    Ok(match Url::parse(&submission.url) {
        Ok(url) => InputSource::Url(url),
        Err(_) => InputSource::MalformedUrl(submission.url),
    })
}

fn declares_json(headers: &HeaderMap) -> bool {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .split(';')
                .next()
                .unwrap_or(value)
                .trim()
                .eq_ignore_ascii_case("application/json")
        })
}

fn http_status(status: InputStatus) -> StatusCode {
    match status {
        InputStatus::Sanitised | InputStatus::Clean | InputStatus::Refused => StatusCode::OK,
        InputStatus::BudgetExceeded => StatusCode::PAYLOAD_TOO_LARGE,
        InputStatus::SsrfBlocked => StatusCode::FORBIDDEN,
        InputStatus::FetchError => StatusCode::BAD_GATEWAY,
        InputStatus::UnsupportedScheme | InputStatus::MalformedUrl => StatusCode::BAD_REQUEST,
        InputStatus::IoError | InputStatus::InternalError | InputStatus::SkippedSymlink => {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

fn body_limit(max_input_bytes: u64) -> usize {
    max_input_bytes.min(usize::MAX as u64) as usize
}

fn address_of(bind: &str, port: u16) -> String {
    if bind.contains(':') && !bind.starts_with('[') {
        format!("[{bind}]:{port}")
    } else {
        format!("{bind}:{port}")
    }
}

fn warn_about_bind(bind: &str, policy: &Policy) {
    if is_loopback(bind) {
        return;
    }
    eprintln!(
        "WARNING: bind {bind} accepts requests from other hosts, and server mode has no authentication"
    );
    if policy.ssrf.guard_input_urls == GuardScope::Never {
        eprintln!(
            "WARNING: ssrf.guard_input_urls = never on a non-loopback bind turns this server into an open SSRF proxy"
        );
    }
}

fn is_loopback(bind: &str) -> bool {
    let host = bind.trim_start_matches('[').trim_end_matches(']');
    match host.parse::<IpAddr>() {
        Ok(address) => address.is_loopback(),
        Err(_) => host.eq_ignore_ascii_case("localhost"),
    }
}

/// Stop serving on Ctrl-C so the run ends through the exit-code contract
/// instead of a signal.
async fn shutdown_signal() {
    if tokio::signal::ctrl_c().await.is_err() {
        // no handler could be installed: serve until the process is killed
        std::future::pending::<()>().await;
    }
}

#[derive(Debug, Serialize)]
struct Health {
    status: &'static str,
}

#[derive(Debug, Deserialize)]
struct UrlSubmission {
    url: String,
}

#[derive(Debug, Serialize)]
struct ResourceResponse {
    report: InputReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    assets: Vec<AssetPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct AssetPayload {
    path: String,
    content: String,
}

#[derive(Debug, Serialize)]
struct RequestError {
    error: &'static str,
    detail: String,
}

impl ResourceResponse {
    fn of(outcome: Outcome) -> ResourceResponse {
        let status = outcome.report.status;
        let error = match http_status(status) {
            StatusCode::OK => None,
            _ => Some(status_slug(status)),
        };
        ResourceResponse {
            report: outcome.report,
            content: outcome.sanitized.map(|bytes| BASE64.encode(bytes)),
            assets: outcome.assets.into_iter().map(AssetPayload::of).collect(),
            error,
        }
    }
}

impl IntoResponse for ResourceResponse {
    fn into_response(self) -> Response {
        (http_status(self.report.status), Json(self)).into_response()
    }
}

impl AssetPayload {
    fn of(asset: Asset) -> AssetPayload {
        AssetPayload {
            path: asset.path,
            content: BASE64.encode(asset.bytes),
        }
    }
}

impl RequestError {
    fn bad_request(detail: String) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(RequestError {
                error: "bad_request",
                detail,
            }),
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use web_sanitizer::fetch::{FetchError, Fetched, Fetcher, TimeoutPhase};
    use web_sanitizer::{FetchContext, InputSource};

    fn headers(content_type: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(value) = content_type {
            headers.insert(CONTENT_TYPE, value.parse().unwrap());
        }
        headers
    }

    fn engine_with(fetcher: Arc<dyn Fetcher>) -> Arc<Engine> {
        Arc::new(
            Engine::new(Policy::builtin(), fetcher)
                .unwrap()
                .with_origin(FetchOrigin::InputServer),
        )
    }

    /// The engine's answer to a URL, without a network.
    struct StubFetcher(fn(&Url) -> Result<Fetched, FetchError>);

    impl Fetcher for StubFetcher {
        fn fetch(
            &self,
            url: &Url,
            _policy: &web_sanitizer::policy::FetchPolicy,
            _ctx: FetchContext,
        ) -> Result<Fetched, FetchError> {
            (self.0)(url)
        }
    }

    async fn submitted(
        engine: Arc<Engine>,
        content_type: Option<&str>,
        body: &[u8],
    ) -> (StatusCode, serde_json::Value) {
        let response = submit(
            State(engine),
            headers(content_type),
            Bytes::copy_from_slice(body),
        )
        .await
        .into_response();
        let status = response.status();
        let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        (status, json)
    }

    fn offline() -> Arc<Engine> {
        engine_with(Arc::new(StubFetcher(|_| {
            Err(FetchError::UnsupportedScheme {
                scheme: "unreachable".to_string(),
            })
        })))
    }

    #[test]
    fn a_body_without_a_json_content_type_is_the_input_itself() {
        let input = input_of(&headers(None), Bytes::from_static(b"<p>hi</p>")).unwrap();
        match input {
            InputSource::Bytes { name, data } => {
                assert!(name.is_empty());
                assert_eq!(data, b"<p>hi</p>");
            }
            other => panic!("expected raw bytes, got {other:?}"),
        }
    }

    #[test]
    fn a_json_body_naming_a_url_becomes_a_url_input() {
        let input = input_of(
            &headers(Some("application/json")),
            Bytes::from_static(br#"{"url":"http://localhost:3100/html/script-tag"}"#),
        )
        .unwrap();
        assert_eq!(
            input,
            InputSource::Url(Url::parse("http://localhost:3100/html/script-tag").unwrap())
        );
    }

    #[test]
    fn the_content_type_is_read_without_its_parameters() {
        assert!(declares_json(&headers(Some(
            "application/json; charset=utf-8"
        ))));
        assert!(declares_json(&headers(Some("APPLICATION/JSON"))));
        assert!(!declares_json(&headers(Some("application/json-seq"))));
        assert!(!declares_json(&headers(Some("text/html"))));
        assert!(!declares_json(&headers(None)));
    }

    #[test]
    fn a_url_the_parser_rejects_still_reaches_the_engine() {
        let input = input_of(
            &headers(Some("application/json")),
            Bytes::from_static(br#"{"url":"http://"}"#),
        )
        .unwrap();
        assert_eq!(input, InputSource::MalformedUrl("http://".to_string()));
    }

    #[test]
    fn malformed_json_is_the_callers_error() {
        assert!(input_of(&headers(Some("application/json")), Bytes::from_static(b"{")).is_err());
        assert!(
            input_of(
                &headers(Some("application/json")),
                Bytes::from_static(br#"{"uri":"http://x.test/"}"#)
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn submitted_bytes_come_back_sanitised_and_reported() {
        let (status, body) = submitted(
            offline(),
            None,
            br#"<!DOCTYPE html><p onclick="alert(1)">hi</p>"#,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["report"]["status"], "sanitised");
        assert!(body["error"].is_null());
        let content = BASE64.decode(body["content"].as_str().unwrap()).unwrap();
        let html = String::from_utf8(content).unwrap();
        assert!(!html.contains("onclick"), "{html}");
    }

    #[tokio::test]
    async fn a_clean_input_answers_200_with_no_error_slug() {
        let (status, body) = submitted(offline(), None, b"plain text").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["report"]["status"], "clean");
        assert!(body["error"].is_null());
    }

    #[tokio::test]
    async fn a_refusal_is_a_result_and_keeps_its_200() {
        // entity declarations refuse the input, and the caller gets to read why
        let (status, body) = submitted(
            offline(),
            None,
            br#"<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><lolz>&lol;</lolz>"#,
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["report"]["status"], "refused");
        assert!(body["error"].is_null());
        assert!(body["content"].is_null());
    }

    #[tokio::test]
    async fn malformed_json_answers_400_without_touching_the_engine() {
        let (status, body) = submitted(offline(), Some("application/json"), b"{").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "bad_request");
        assert!(body["report"].is_null());
    }

    #[tokio::test]
    async fn a_malformed_url_answers_400_with_its_report() {
        let (status, body) =
            submitted(offline(), Some("application/json"), br#"{"url":"http://"}"#).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "malformed_url");
        assert_eq!(body["report"]["status"], "malformed_url");
    }

    #[tokio::test]
    async fn a_scheme_outside_http_answers_400_and_is_never_fetched() {
        let engine = engine_with(Arc::new(StubFetcher(|_| panic!("must not fetch"))));
        let (status, body) = submitted(
            engine,
            Some("application/json"),
            br#"{"url":"file:///etc/passwd"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "unsupported_scheme");
    }

    #[tokio::test]
    async fn a_guard_refusal_answers_403() {
        let engine = engine_with(Arc::new(StubFetcher(|_| {
            Err(FetchError::SsrfBlocked {
                address: "169.254.169.254:80".parse().unwrap(),
                rule: "ssrf.link_local",
                hop: 0,
            })
        })));
        let (status, body) = submitted(
            engine,
            Some("application/json"),
            br#"{"url":"http://metadata.test/"}"#,
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(body["error"], "ssrf_blocked");
        assert_eq!(body["report"]["status"], "ssrf_blocked");
        assert!(body["content"].is_null());
    }

    #[tokio::test]
    async fn a_failed_fetch_answers_502() {
        let engine = engine_with(Arc::new(StubFetcher(|_| {
            Err(FetchError::Timeout {
                phase: TimeoutPhase::Read,
            })
        })));
        let (status, body) = submitted(
            engine,
            Some("application/json"),
            br#"{"url":"http://slow.test/"}"#,
        )
        .await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(body["error"], "fetch_error");
    }

    #[tokio::test]
    async fn an_upstream_body_over_the_cap_answers_413() {
        let engine = engine_with(Arc::new(StubFetcher(|_| {
            Err(FetchError::BodyTooLarge {
                cap: 10 * 1024 * 1024,
            })
        })));
        let (status, body) = submitted(
            engine,
            Some("application/json"),
            br#"{"url":"http://huge.test/"}"#,
        )
        .await;

        assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(body["report"]["status"], "budget_exceeded");
        assert_eq!(body["error"], "budget_exceeded");
        assert!(
            body["report"]["error"]
                .as_str()
                .unwrap()
                .contains("10485760")
        );
        assert!(body["content"].is_null());
    }

    #[tokio::test]
    async fn a_timeout_is_still_the_upstreams_fault() {
        let engine = engine_with(Arc::new(StubFetcher(|_| {
            Err(FetchError::Timeout {
                phase: TimeoutPhase::Read,
            })
        })));
        let (status, _) = submitted(
            engine,
            Some("application/json"),
            br#"{"url":"http://slow.test/"}"#,
        )
        .await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn every_status_that_produced_no_output_carries_an_error_code() {
        for status in [
            InputStatus::SsrfBlocked,
            InputStatus::BudgetExceeded,
            InputStatus::FetchError,
            InputStatus::UnsupportedScheme,
            InputStatus::MalformedUrl,
            InputStatus::IoError,
            InputStatus::InternalError,
            InputStatus::SkippedSymlink,
        ] {
            let code = http_status(status);
            assert!(code.is_client_error() || code.is_server_error());
        }
        for status in [
            InputStatus::Clean,
            InputStatus::Sanitised,
            InputStatus::Refused,
        ] {
            assert_eq!(http_status(status), StatusCode::OK);
        }
    }

    #[test]
    fn the_body_cap_follows_the_input_budget() {
        assert_eq!(body_limit(10 * 1024 * 1024), 10 * 1024 * 1024);
        assert_eq!(body_limit(u64::MAX), usize::MAX);
    }

    #[test]
    fn an_ipv6_bind_is_bracketed_before_the_port() {
        assert_eq!(address_of("127.0.0.1", 3000), "127.0.0.1:3000");
        assert_eq!(address_of("::1", 3000), "[::1]:3000");
        assert_eq!(address_of("[::1]", 3000), "[::1]:3000");
    }

    #[test]
    fn only_a_loopback_address_stays_silent() {
        assert!(is_loopback("127.0.0.1"));
        assert!(is_loopback("127.1.2.3"));
        assert!(is_loopback("::1"));
        assert!(is_loopback("[::1]"));
        assert!(is_loopback("localhost"));
        assert!(!is_loopback("0.0.0.0"));
        assert!(!is_loopback("192.168.1.10"));
        // an unresolved name could be anything, so it warns
        assert!(!is_loopback("sanitizer.internal"));
    }
}
