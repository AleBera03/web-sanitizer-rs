//! The fetch seam: the only module in the crate that opens a socket.
//!
//! [`HttpFetcher`] is the `ureq`-based client http/https only,
//! a fixed outgoing header set, redirects followed **by hand** one hop at a
//! time, a response-size cap enforced while streaming, and a total-time deadline that
//! spans the whole redirect chain.
//!
//! The SSRF guard of [`guard`] lives *below* the client, as the resolver the agent
//! was built with, so input URLs, sub-resources and every redirect hop funnel
//! through the same check without any of them having to remember to ask.
//!
//! [`DisabledFetcher`] keeps URL inputs honest (`fetch_error`) where no client is wired.

pub mod guard;

use std::fmt;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use thiserror::Error;
use ureq::http::Response;
use ureq::http::header::{CONTENT_TYPE, HeaderName, LOCATION};
use ureq::unversioned::transport::DefaultConnector;
use ureq::{Body, Timeout};
use url::Url;

use crate::policy::{ConfigError, FetchPolicy, SsrfRules};
use guard::{FetchContext, Guard, GuardedResolver, Scope};

// CONSTANTS
const READ_CHUNK: usize = 8 * 1024;
const REDIRECT_STATUS: &[u16] = &[301, 302, 303, 307, 308];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutPhase {
    Connect,
    Read,
    Total,
}

impl fmt::Display for TimeoutPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TimeoutPhase::Connect => f.write_str("connect"),
            TimeoutPhase::Read => f.write_str("read"),
            TimeoutPhase::Total => f.write_str("total"),
        }
    }
}

#[derive(Error, Debug, Clone, PartialEq)]
pub enum FetchError {
    /// No fetch client configured in this build.
    #[error("fetching is not available in this build")]
    Disabled,

    #[error("scheme `{scheme}` is not fetchable")]
    UnsupportedScheme { scheme: String },

    #[error("fetch_timeout: {phase} exceeded its budget")]
    Timeout { phase: TimeoutPhase },

    #[error("redirect_limit: more than {limit} redirects")]
    RedirectLimit { limit: u32 },

    #[error("invalid redirect target `{location}`: {reason}")]
    BadRedirect { location: String, reason: String },

    #[error("response status {status}")]
    Status { status: u16 },

    #[error("response body exceeds {cap} bytes")]
    BodyTooLarge { cap: u64 },

    #[error("ssrf_blocked: {rule} refuses {address} at hop {hop}")]
    SsrfBlocked {
        address: SocketAddr,
        rule: &'static str,
        hop: u32,
    },

    #[error("transport error: {0}")]
    Transport(String),
}

pub trait Fetcher: Send + Sync {
    /// `ctx` says *why* the request exists, which is what decides whether the
    /// guard applies to it and which parent endpoint it may reuse.
    fn fetch(
        &self,
        url: &Url,
        policy: &FetchPolicy,
        ctx: FetchContext,
    ) -> Result<Fetched, FetchError>;

    /// Resolutions served from the guard's cache, for `run.resolve_cache_hits`.
    /// A client without a guard has none.
    fn resolve_cache_hits(&self) -> u64 {
        0
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Fetched {
    /// URL after redirects — MIME sniffing and reporting use this, not the input URL.
    pub final_url: Url,
    /// `Content-Type` as declared by the server; sniffing may overrule it.
    pub declared_mime: Option<String>,
    /// Vetted address the last hop was made to, carried so a sub-resource of
    /// this document can be compared against it (T-11.5).
    pub endpoint: Option<SocketAddr>,
    pub body: Vec<u8>,
}

/// Fetcher that refuses every request. Placeholder front-end wiring where no
/// network access is wanted (unit tests, `--no-fetch` style builds).
pub struct DisabledFetcher;

impl Fetcher for DisabledFetcher {
    fn fetch(
        &self,
        _url: &Url,
        _policy: &FetchPolicy,
        _ctx: FetchContext,
    ) -> Result<Fetched, FetchError> {
        Err(FetchError::Disabled)
    }
}

pub struct HttpFetcher {
    agent: ureq::Agent,
    guard: Arc<Guard>,
}

impl HttpFetcher {
    /// Build the client and its guard together. There is deliberately no
    /// constructor that produces an unguarded client: the guard's placement is
    /// the design, so it cannot be forgotten at a call site or in a build.
    pub fn new(policy: &FetchPolicy, ssrf: &SsrfRules) -> Result<HttpFetcher, ConfigError> {
        Ok(HttpFetcher::with_guard(policy, Arc::new(Guard::new(ssrf)?)))
    }

    pub fn with_guard(policy: &FetchPolicy, guard: Arc<Guard>) -> HttpFetcher {
        let config = ureq::Agent::config_builder()
            .max_redirects(0)
            // a 3xx must come back as a response
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .user_agent(policy.user_agent.as_str())
            .accept_encoding("identity")
            // an environment proxy would make `ureq` skip the resolver entirely,
            // and with it the guard: egress must stay our own decision (OS-8)
            .proxy(None)
            // a pooled keep-alive connection would also skip the resolver, and
            // `last_endpoint` would come back `None`: the parent's endpoint
            // must survive to ground the same-origin exemption of its
            // sub-resources, so every request resolves anew
            .max_idle_connections(0)
            .build();
        let agent = ureq::Agent::with_parts(
            config,
            DefaultConnector::new(),
            GuardedResolver::new(Arc::clone(&guard)),
        );
        HttpFetcher { agent, guard }
    }

    pub fn guard(&self) -> &Arc<Guard> {
        &self.guard
    }

    /// One hop. Timeouts are applied per request from the policy the caller
    /// passed, so the client has a single source of truth for them.
    fn request_once(
        &self,
        url: &Url,
        policy: &FetchPolicy,
        deadline: Instant,
        hop: u32,
    ) -> Result<Response<Body>, FetchError> {
        let budget = remaining(deadline)?.min(Duration::from_millis(policy.total_timeout_ms));
        self.agent
            .get(url.as_str())
            .config()
            .timeout_connect(Some(Duration::from_millis(policy.connect_timeout_ms)))
            .timeout_recv_response(Some(Duration::from_millis(policy.read_timeout_ms)))
            .timeout_recv_body(Some(Duration::from_millis(policy.read_timeout_ms)))
            .timeout_global(Some(budget))
            .build()
            .call()
            .map_err(|e| map_ureq_error(e, hop))
    }
}

impl Fetcher for HttpFetcher {
    fn fetch(
        &self,
        url: &Url,
        policy: &FetchPolicy,
        ctx: FetchContext,
    ) -> Result<Fetched, FetchError> {
        let deadline = Instant::now() + Duration::from_millis(policy.total_timeout_ms);
        let mut current = url.clone();

        // the scope travels to the resolver on this thread and is restored on
        // the way out, including when a hop fails
        let _scope = guard::enter_scope(Scope {
            guarded: self.guard.applies_to(&ctx),
            parent: ctx.parent_endpoint,
        });

        // one initial request plus at most `redirect_limit` hops
        for hop in 0..=policy.redirect_limit {
            check_scheme(&current)?;
            let response = self.request_once(&current, policy, deadline, hop)?;
            let endpoint = guard::last_endpoint();
            let status = response.status().as_u16();

            match next_hop(status, header(&response, LOCATION).as_deref(), &current)? {
                // T-11.4: the next hop re-enters scheme check and guard, because
                // it is a new request through the same resolver
                Some(next) => current = next,
                None => {
                    check_status(status)?;
                    let declared_mime = header(&response, CONTENT_TYPE);
                    check_declared_length(&response, policy.max_response_bytes)?;
                    let body = read_capped(
                        response.into_body().into_reader(),
                        policy.max_response_bytes,
                        deadline,
                    )?;
                    return Ok(Fetched {
                        final_url: current,
                        declared_mime,
                        endpoint,
                        body,
                    });
                }
            }
        }
        Err(FetchError::RedirectLimit {
            limit: policy.redirect_limit,
        })
    }

    fn resolve_cache_hits(&self) -> u64 {
        self.guard.cache().hits()
    }
}

fn check_scheme(url: &Url) -> Result<(), FetchError> {
    match url.scheme() {
        "http" | "https" => Ok(()),
        other => Err(FetchError::UnsupportedScheme {
            scheme: other.to_string(),
        }),
    }
}

fn check_status(status: u16) -> Result<(), FetchError> {
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(FetchError::Status { status })
    }
}

/// `Some(next)` when the response is a redirect we must follow, `None` when it is
/// the final answer.
fn next_hop(status: u16, location: Option<&str>, current: &Url) -> Result<Option<Url>, FetchError> {
    if !REDIRECT_STATUS.contains(&status) {
        return Ok(None);
    }
    // whitespace-only would otherwise `join` back to the current URL and loop
    let location = location.unwrap_or_default().trim();
    if location.is_empty() {
        return Err(FetchError::BadRedirect {
            location: String::new(),
            reason: "missing or non-ascii `Location` header".to_string(),
        });
    }
    // RFC 3986
    // Location may be relative to the URL of the hop that produced it
    let next = current
        .join(location)
        .map_err(|e| FetchError::BadRedirect {
            location: location.to_string(),
            reason: e.to_string(),
        })?;
    check_scheme(&next).map_err(|e| FetchError::BadRedirect {
        location: next.to_string(),
        reason: e.to_string(),
    })?;
    Ok(Some(next))
}

fn check_declared_length(response: &Response<Body>, cap: u64) -> Result<(), FetchError> {
    match response.body().content_length() {
        Some(len) if len > cap => Err(FetchError::BodyTooLarge { cap }),
        _ => Ok(()),
    }
}

/// Read at most `cap + 1` bytes.
fn read_capped(reader: impl Read, cap: u64, deadline: Instant) -> Result<Vec<u8>, FetchError> {
    let mut limited = reader.take(cap.saturating_add(1));
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; READ_CHUNK];
    loop {
        if Instant::now() >= deadline {
            return Err(FetchError::Timeout {
                phase: TimeoutPhase::Total,
            });
        }
        match limited.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                // the client's own read timeout fires as an io error: report the cause
                if Instant::now() >= deadline {
                    return Err(FetchError::Timeout {
                        phase: TimeoutPhase::Total,
                    });
                }
                return Err(FetchError::Transport(e.to_string()));
            }
        }
    }
    if buf.len() as u64 > cap {
        return Err(FetchError::BodyTooLarge { cap });
    }
    Ok(buf)
}

fn remaining(deadline: Instant) -> Result<Duration, FetchError> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(FetchError::Timeout {
            phase: TimeoutPhase::Total,
        })
    } else {
        Ok(left)
    }
}

fn header(response: &Response<Body>, name: HeaderName) -> Option<String> {
    let value = response.headers().get(name)?.to_str().ok()?.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

/// A refusal comes back from the resolver as an `io::Error` carrying its own
/// payload — the only channel `ureq`'s trait offers — and is unpacked here into
/// the typed error the report needs.
fn map_ureq_error(err: ureq::Error, hop: u32) -> FetchError {
    if let Some(denial) = guard::denial_of(&err) {
        return FetchError::SsrfBlocked {
            address: denial.endpoint(),
            rule: denial.rule,
            hop,
        };
    }
    match err {
        ureq::Error::Timeout(t) => FetchError::Timeout {
            phase: timeout_phase(t),
        },
        ureq::Error::StatusCode(status) => FetchError::Status { status },
        ureq::Error::BodyExceedsLimit(cap) => FetchError::BodyTooLarge { cap },
        other => FetchError::Transport(other.to_string()),
    }
}

fn timeout_phase(timeout: Timeout) -> TimeoutPhase {
    match timeout {
        Timeout::Resolve | Timeout::Connect => TimeoutPhase::Connect,
        Timeout::SendRequest
        | Timeout::SendBody
        | Timeout::Await100
        | Timeout::RecvResponse
        | Timeout::RecvBody => TimeoutPhase::Read,
        _ => TimeoutPhase::Total,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::GuardScope;
    use std::io::{BufRead, BufReader, Cursor, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::Mutex;
    use std::thread;

    // pure helpers

    #[test]
    fn only_http_schemes_are_fetchable() {
        for ok in ["http://a/", "https://a/"] {
            assert!(check_scheme(&Url::parse(ok).unwrap()).is_ok());
        }
        for bad in ["file:///etc/passwd", "ftp://a/", "gopher://a/", "data:,x"] {
            let err = check_scheme(&Url::parse(bad).unwrap()).unwrap_err();
            assert!(matches!(err, FetchError::UnsupportedScheme { .. }), "{bad}");
        }
    }

    #[test]
    fn only_2xx_is_a_final_success() {
        assert!(check_status(200).is_ok());
        assert!(check_status(204).is_ok());
        assert!(check_status(299).is_ok());
        assert_eq!(check_status(404), Err(FetchError::Status { status: 404 }));
        assert_eq!(check_status(500), Err(FetchError::Status { status: 500 }));
        assert_eq!(check_status(199), Err(FetchError::Status { status: 199 }));
    }

    #[test]
    fn non_redirect_status_ends_the_loop() {
        let base = Url::parse("http://host/a/b").unwrap();
        for status in [200, 204, 300, 304, 404, 500] {
            assert_eq!(next_hop(status, Some("/x"), &base), Ok(None), "{status}");
        }
    }

    #[test]
    fn every_redirect_status_is_followed() {
        let base = Url::parse("http://host/a/b").unwrap();
        for status in [301, 302, 303, 307, 308] {
            let next = next_hop(status, Some("/x"), &base).unwrap().unwrap();
            assert_eq!(next.as_str(), "http://host/x", "{status}");
        }
    }

    #[test]
    fn relative_location_resolves_against_the_current_hop() {
        let base = Url::parse("http://host/dir/page.html").unwrap();
        let cases = [
            ("next.html", "http://host/dir/next.html"),
            ("/root.html", "http://host/root.html"),
            ("../up.html", "http://host/up.html"),
            ("//other/x", "http://other/x"),
            ("https://other/x", "https://other/x"),
        ];
        for (location, expected) in cases {
            let next = next_hop(302, Some(location), &base).unwrap().unwrap();
            assert_eq!(next.as_str(), expected, "{location}");
        }
    }

    #[test]
    fn redirect_without_location_is_a_bad_redirect() {
        let base = Url::parse("http://host/").unwrap();
        for location in [None, Some(""), Some("   ")] {
            let err = next_hop(302, location, &base).unwrap_err();
            assert!(
                matches!(err, FetchError::BadRedirect { .. }),
                "{location:?}"
            );
        }
    }

    #[test]
    fn redirect_to_unfetchable_scheme_is_a_bad_redirect() {
        let base = Url::parse("http://host/").unwrap();
        for location in ["file:///etc/passwd", "ftp://host/x", "gopher://host/"] {
            let err = next_hop(302, Some(location), &base).unwrap_err();
            match err {
                FetchError::BadRedirect { reason, .. } => assert!(reason.contains("not fetchable")),
                other => panic!("{location}: {other:?}"),
            }
        }
    }

    #[test]
    fn redirect_to_garbage_is_a_bad_redirect() {
        let base = Url::parse("http://host/").unwrap();
        let err = next_hop(302, Some("http://"), &base).unwrap_err();
        assert!(matches!(err, FetchError::BadRedirect { .. }));
    }

    #[test]
    fn read_capped_boundary_is_exact() {
        let far = Instant::now() + Duration::from_secs(60);
        assert_eq!(
            read_capped(Cursor::new(vec![b'x'; 4]), 4, far),
            Ok(vec![b'x'; 4])
        );
        assert_eq!(
            read_capped(Cursor::new(vec![b'x'; 3]), 4, far),
            Ok(vec![b'x'; 3])
        );
        assert_eq!(
            read_capped(Cursor::new(vec![b'x'; 5]), 4, far),
            Err(FetchError::BodyTooLarge { cap: 4 })
        );
    }

    #[test]
    fn read_capped_accepts_empty_body_and_zero_cap() {
        let far = Instant::now() + Duration::from_secs(60);
        assert_eq!(read_capped(Cursor::new(Vec::new()), 0, far), Ok(Vec::new()));
        assert_eq!(
            read_capped(Cursor::new(vec![b'x']), 0, far),
            Err(FetchError::BodyTooLarge { cap: 0 })
        );
    }

    #[test]
    fn read_capped_stops_at_an_expired_deadline() {
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            read_capped(Cursor::new(vec![b'x'; 8]), 1024, past),
            Err(FetchError::Timeout {
                phase: TimeoutPhase::Total
            })
        );
    }

    #[test]
    fn read_capped_never_buffers_more_than_the_cap_plus_one() {
        // a 1 MiB body against a 16-byte cap must not materialise in memory
        let far = Instant::now() + Duration::from_secs(60);
        let huge = vec![b'x'; 1024 * 1024];
        assert_eq!(
            read_capped(Cursor::new(huge), 16, far),
            Err(FetchError::BodyTooLarge { cap: 16 })
        );
    }

    #[test]
    fn expired_deadline_leaves_no_budget() {
        let past = Instant::now() - Duration::from_secs(1);
        assert_eq!(
            remaining(past),
            Err(FetchError::Timeout {
                phase: TimeoutPhase::Total
            })
        );
        assert!(remaining(Instant::now() + Duration::from_secs(5)).is_ok());
    }

    #[test]
    fn ureq_timeouts_map_onto_our_phases() {
        assert_eq!(timeout_phase(Timeout::Connect), TimeoutPhase::Connect);
        assert_eq!(timeout_phase(Timeout::Resolve), TimeoutPhase::Connect);
        assert_eq!(timeout_phase(Timeout::RecvBody), TimeoutPhase::Read);
        assert_eq!(timeout_phase(Timeout::RecvResponse), TimeoutPhase::Read);
        assert_eq!(timeout_phase(Timeout::Global), TimeoutPhase::Total);
        assert_eq!(timeout_phase(Timeout::PerCall), TimeoutPhase::Total);
    }

    #[test]
    fn timeout_phase_is_printable_in_the_error() {
        let err = FetchError::Timeout {
            phase: TimeoutPhase::Read,
        };
        assert_eq!(err.to_string(), "fetch_timeout: read exceeded its budget");
    }

    #[test]
    fn disabled_fetcher_refuses_everything() {
        let url = Url::parse("http://example.com/").unwrap();
        let err = DisabledFetcher
            .fetch(&url, &FetchPolicy::default(), FetchContext::input_cli())
            .unwrap_err();
        assert_eq!(err, FetchError::Disabled);
    }

    // scripted origin server

    /// One scripted answer per accepted connection. Every reply closes the
    /// connection, so one hop == one connection == one recorded request.
    enum Reply {
        Raw(Vec<u8>),
        Drip { gap: Duration },
    }

    struct TestServer {
        base: Url,
        requests: Arc<Mutex<Vec<String>>>,
    }

    impl TestServer {
        fn start(script: Vec<Reply>) -> TestServer {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let log = Arc::clone(&requests);
            thread::spawn(move || {
                for reply in script {
                    match listener.accept() {
                        Ok((stream, _)) => serve(stream, reply, &log),
                        Err(_) => break,
                    }
                }
            });
            TestServer {
                base: Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap(),
                requests,
            }
        }

        fn url(&self, path: &str) -> Url {
            self.base.join(path).unwrap()
        }

        /// Request heads seen so far, in order.
        fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    fn serve(mut stream: TcpStream, reply: Reply, log: &Arc<Mutex<Vec<String>>>) {
        log.lock().unwrap().push(read_head(&stream));
        match reply {
            Reply::Raw(bytes) => {
                let _ = stream.write_all(&bytes);
                let _ = stream.flush();
            }
            Reply::Drip { gap } => {
                let head = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\
                             Content-Length: 100000\r\nConnection: close\r\n\r\n";
                let _ = stream.write_all(head);
                let _ = stream.flush();
                while stream.write_all(b"x").is_ok() && stream.flush().is_ok() {
                    thread::sleep(gap);
                }
            }
        }
        let _ = stream.shutdown(Shutdown::Both);
    }

    fn read_head(stream: &TcpStream) -> String {
        let mut reader = BufReader::new(stream);
        let mut head = String::new();
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) if line == "\r\n" => break,
                Ok(_) => head.push_str(&line),
                Err(_) => break,
            }
        }
        head
    }

    fn reply(status: u16, headers: &[(&str, &str)], body: &[u8]) -> Reply {
        let mut head = format!(
            "HTTP/1.1 {status} X\r\nConnection: close\r\nContent-Length: {}\r\n",
            body.len()
        );
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str("\r\n");
        let mut bytes = head.into_bytes();
        bytes.extend_from_slice(body);
        Reply::Raw(bytes)
    }

    fn ok_body(mime: &str, body: &[u8]) -> Reply {
        reply(200, &[("Content-Type", mime)], body)
    }

    fn redirect_to(status: u16, location: &str) -> Reply {
        reply(status, &[("Location", location)], b"")
    }

    /// Close-delimited body: no `Content-Length`, so only the streaming cap can stop it.
    fn unsized_body(body: &[u8]) -> Reply {
        let mut bytes =
            b"HTTP/1.1 200 X\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n".to_vec();
        bytes.extend_from_slice(body);
        Reply::Raw(bytes)
    }

    fn policy() -> FetchPolicy {
        FetchPolicy {
            connect_timeout_ms: 2_000,
            read_timeout_ms: 2_000,
            total_timeout_ms: 5_000,
            ..FetchPolicy::default()
        }
    }

    /// The client under the *default* SSRF policy. The transport tests below
    /// talk to a loopback server as `InputCli`, which the default scope
    /// (`server`) leaves unguarded — that is T-11.7, not a test loophole.
    fn client(policy: &FetchPolicy) -> HttpFetcher {
        HttpFetcher::new(policy, &SsrfRules::default()).expect("default ssrf policy compiles")
    }

    // the client against that server

    #[test]
    fn fetches_body_status_and_declared_mime() {
        let server = TestServer::start(vec![ok_body("text/html; charset=utf-8", b"<h1>hi</h1>")]);
        let policy = policy();
        let fetched = client(&policy)
            .fetch(
                &server.url("/page.html"),
                &policy,
                FetchContext::input_cli(),
            )
            .unwrap();

        assert_eq!(fetched.body, b"<h1>hi</h1>");
        assert_eq!(
            fetched.declared_mime.as_deref(),
            Some("text/html; charset=utf-8")
        );
        assert_eq!(fetched.final_url, server.url("/page.html"));
    }

    #[test]
    fn empty_body_is_a_success_not_an_error() {
        let server = TestServer::start(vec![ok_body("text/html", b"")]);
        let policy = policy();
        let fetched = client(&policy)
            .fetch(&server.url("/empty"), &policy, FetchContext::input_cli())
            .unwrap();
        assert!(fetched.body.is_empty());
    }

    #[test]
    fn missing_content_type_is_reported_as_none() {
        let server = TestServer::start(vec![reply(200, &[], b"x")]);
        let policy = policy();
        let fetched = client(&policy)
            .fetch(&server.url("/x"), &policy, FetchContext::input_cli())
            .unwrap();
        assert_eq!(fetched.declared_mime, None);
    }

    #[test]
    fn redirect_chain_is_followed_and_final_url_wins() {
        let server = TestServer::start(vec![
            redirect_to(302, "/second"),
            redirect_to(301, "/third"),
            ok_body("text/plain", b"done"),
        ]);
        let policy = policy();
        let fetched = client(&policy)
            .fetch(&server.url("/first"), &policy, FetchContext::input_cli())
            .unwrap();

        assert_eq!(fetched.body, b"done");
        // reporting and sniffing must use the URL we ended on, not the one we asked for
        assert_eq!(fetched.final_url, server.url("/third"));
        let paths: Vec<String> = server
            .requests()
            .iter()
            .map(|head| head.lines().next().unwrap_or_default().to_string())
            .collect();
        assert_eq!(
            paths,
            [
                "GET /first HTTP/1.1",
                "GET /second HTTP/1.1",
                "GET /third HTTP/1.1"
            ]
        );
    }

    #[test]
    fn redirect_limit_stops_the_chain_at_the_configured_hop() {
        // limit 2 == 1 initial request + 2 hops == 3 requests, then refuse
        let server = TestServer::start(vec![
            redirect_to(302, "/b"),
            redirect_to(302, "/c"),
            redirect_to(302, "/d"),
            ok_body("text/plain", b"never reached"),
        ]);
        let mut policy = policy();
        policy.redirect_limit = 2;

        let err = client(&policy)
            .fetch(&server.url("/a"), &policy, FetchContext::input_cli())
            .unwrap_err();
        assert_eq!(err, FetchError::RedirectLimit { limit: 2 });
        assert_eq!(server.requests().len(), 3);
    }

    #[test]
    fn redirect_loop_terminates() {
        let server = TestServer::start(vec![
            redirect_to(302, "/loop"),
            redirect_to(302, "/loop"),
            redirect_to(302, "/loop"),
        ]);
        let mut policy = policy();
        policy.redirect_limit = 2;
        let err = client(&policy)
            .fetch(&server.url("/loop"), &policy, FetchContext::input_cli())
            .unwrap_err();
        assert_eq!(err, FetchError::RedirectLimit { limit: 2 });
    }

    #[test]
    fn redirect_to_file_scheme_is_refused_at_the_hop() {
        // the redirect laundering shape: http in, file:// out
        let server = TestServer::start(vec![redirect_to(302, "file:///etc/passwd")]);
        let policy = policy();
        let err = client(&policy)
            .fetch(&server.url("/a"), &policy, FetchContext::input_cli())
            .unwrap_err();
        match err {
            FetchError::BadRedirect { location, reason } => {
                assert!(location.starts_with("file:"));
                assert!(reason.contains("not fetchable"));
            }
            other => panic!("{other:?}"),
        }
        // refused *before* the next connection
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn redirect_without_location_header_is_refused() {
        let server = TestServer::start(vec![reply(302, &[], b"")]);
        let policy = policy();
        let err = client(&policy)
            .fetch(&server.url("/a"), &policy, FetchContext::input_cli())
            .unwrap_err();
        assert!(matches!(err, FetchError::BadRedirect { .. }));
    }

    #[test]
    fn error_status_is_classified_not_swallowed() {
        for status in [400u16, 403, 404, 500, 503] {
            let server = TestServer::start(vec![reply(status, &[], b"error page")]);
            let policy = policy();
            let err = client(&policy)
                .fetch(&server.url("/a"), &policy, FetchContext::input_cli())
                .unwrap_err();
            assert_eq!(err, FetchError::Status { status });
        }
    }

    #[test]
    fn declared_oversize_body_is_refused_before_download() {
        let server = TestServer::start(vec![ok_body("text/plain", &[b'x'; 64])]);
        let mut policy = policy();
        policy.max_response_bytes = 16;
        let err = client(&policy)
            .fetch(&server.url("/big"), &policy, FetchContext::input_cli())
            .unwrap_err();
        assert_eq!(err, FetchError::BodyTooLarge { cap: 16 });
    }

    #[test]
    fn undeclared_oversize_body_is_refused_while_streaming() {
        // no Content-Length to trust: the cap has to hold on the wire
        let server = TestServer::start(vec![unsized_body(&[b'x'; 64])]);
        let mut policy = policy();
        policy.max_response_bytes = 16;
        let err = client(&policy)
            .fetch(&server.url("/big"), &policy, FetchContext::input_cli())
            .unwrap_err();
        assert_eq!(err, FetchError::BodyTooLarge { cap: 16 });
    }

    #[test]
    fn body_exactly_at_the_cap_is_accepted() {
        let server = TestServer::start(vec![ok_body("text/plain", &[b'x'; 16])]);
        let mut policy = policy();
        policy.max_response_bytes = 16;
        let fetched = client(&policy)
            .fetch(&server.url("/exact"), &policy, FetchContext::input_cli())
            .unwrap();
        assert_eq!(fetched.body.len(), 16);
    }

    #[test]
    fn slow_drip_server_hits_the_total_budget() {
        let server = TestServer::start(vec![Reply::Drip {
            gap: Duration::from_millis(40),
        }]);
        let mut policy = policy();
        policy.total_timeout_ms = 400;
        policy.read_timeout_ms = 400;

        let start = Instant::now();
        let err = client(&policy)
            .fetch(&server.url("/drip"), &policy, FetchContext::input_cli())
            .unwrap_err();
        assert!(
            matches!(err, FetchError::Timeout { .. }),
            "expected a timeout, got {err:?}"
        );
        // the budget is an upper bound, generously checked to stay CI-stable
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn unfetchable_scheme_never_reaches_the_socket() {
        let server = TestServer::start(vec![ok_body("text/plain", b"unreachable")]);
        let policy = policy();
        let mut url = server.url("/x");
        url.set_scheme("ftp").ok();

        let err = client(&policy)
            .fetch(&url, &policy, FetchContext::input_cli())
            .unwrap_err();
        assert!(matches!(err, FetchError::UnsupportedScheme { .. }));
        assert!(server.requests().is_empty());
    }

    /// the outgoing header set is fixed and carries nothing about the user.
    #[test]
    fn outgoing_headers_are_the_documented_fixed_set() {
        let server = TestServer::start(vec![ok_body("text/plain", b"ok")]);
        let policy = policy();
        client(&policy)
            .fetch(
                &server.url("/echo-headers"),
                &policy,
                FetchContext::input_cli(),
            )
            .unwrap();

        let head = server.requests().remove(0);
        let names: Vec<String> = head
            .lines()
            .skip(1) // request line
            .filter_map(|line| line.split(':').next())
            .map(|name| name.trim().to_ascii_lowercase())
            .filter(|name| !name.is_empty())
            .collect();

        for name in &names {
            assert!(
                ["host", "user-agent", "accept", "accept-encoding"].contains(&name.as_str()),
                "unexpected outgoing header `{name}` in:\n{head}"
            );
        }
        for forbidden in [
            "cookie",
            "authorization",
            "referer",
            "from",
            "x-forwarded-for",
        ] {
            assert!(!names.iter().any(|n| n == forbidden), "leaked {forbidden}");
        }
        assert!(head.contains(&policy.user_agent));
        // identity: the size cap must apply to what actually crossed the wire
        assert!(
            head.to_ascii_lowercase()
                .contains("accept-encoding: identity")
        );
    }

    #[test]
    fn redirect_hops_carry_no_referer_from_the_previous_hop() {
        let server = TestServer::start(vec![
            redirect_to(302, "/second"),
            ok_body("text/plain", b"done"),
        ]);
        let policy = policy();
        client(&policy)
            .fetch(&server.url("/first"), &policy, FetchContext::input_cli())
            .unwrap();

        let second = server.requests().remove(1).to_ascii_lowercase();
        assert!(!second.contains("referer"), "{second}");
    }

    #[test]
    fn connection_refused_is_a_transport_error() {
        // an address nobody listens on: bind, read the port, drop the listener
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let policy = policy();
        let url = Url::parse(&format!("http://127.0.0.1:{port}/")).unwrap();
        let err = client(&policy)
            .fetch(&url, &policy, FetchContext::input_cli())
            .unwrap_err();
        assert!(
            matches!(err, FetchError::Transport(_) | FetchError::Timeout { .. }),
            "{err:?}"
        );
    }

    // the guard, from inside the client

    fn guarded_client(policy: &FetchPolicy, rules: SsrfRules) -> HttpFetcher {
        HttpFetcher::new(policy, &rules).expect("ssrf policy compiles")
    }

    /// SC-1b: the measurement is not a line in a report, it is that no packet
    /// left the process. The scripted server counts accepted connections.
    #[test]
    fn a_subresource_to_loopback_never_reaches_the_socket() {
        let server = TestServer::start(vec![ok_body("text/css", b"body{}")]);
        let policy = policy();
        let err = guarded_client(&policy, SsrfRules::default())
            .fetch(
                &server.url("/style.css"),
                &policy,
                FetchContext::subresource(None),
            )
            .unwrap_err();

        match err {
            FetchError::SsrfBlocked { address, rule, hop } => {
                assert_eq!(rule, "ssrf.loopback");
                assert_eq!(address.ip().to_string(), "127.0.0.1");
                assert_eq!(hop, 0);
            }
            other => panic!("{other:?}"),
        }
        assert!(server.requests().is_empty(), "a connection was accepted");
    }

    #[test]
    fn the_same_origin_exemption_makes_the_loopback_harness_usable() {
        // the parent's own endpoint is reachable for its sub-resources
        let server = TestServer::start(vec![ok_body("text/css", b"body{}")]);
        let policy = policy();
        let parent = server
            .base
            .socket_addrs(|| None)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();

        let fetched = guarded_client(&policy, SsrfRules::default())
            .fetch(
                &server.url("/style.css"),
                &policy,
                FetchContext::subresource(Some(parent)),
            )
            .unwrap();
        assert_eq!(fetched.body, b"body{}");
        assert_eq!(fetched.endpoint, Some(parent));
    }

    #[test]
    fn a_neighbouring_port_of_the_parent_stays_refused() {
        let server = TestServer::start(vec![ok_body("text/css", b"body{}")]);
        let policy = policy();
        let mut parent = server
            .base
            .socket_addrs(|| None)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        // same host, different port: a different endpoint, no new reach granted
        parent.set_port(parent.port().wrapping_add(1));

        let err = guarded_client(&policy, SsrfRules::default())
            .fetch(
                &server.url("/style.css"),
                &policy,
                FetchContext::subresource(Some(parent)),
            )
            .unwrap_err();
        assert!(matches!(err, FetchError::SsrfBlocked { .. }), "{err:?}");
        assert!(server.requests().is_empty());
    }

    #[test]
    fn a_redirect_into_a_forbidden_address_is_refused_at_that_hop() {
        // T-11.4: redirect laundering. The public hop answers, the next one is
        // the metadata endpoint and never gets a connection.
        let server = TestServer::start(vec![
            redirect_to(302, "http://169.254.169.254/latest/meta-data/"),
            ok_body("text/plain", b"never reached"),
        ]);
        let policy = policy();
        let rules = SsrfRules {
            // the first hop is loopback in this test, so exempt it explicitly
            allow_hosts: vec!["127.0.0.1".to_string()],
            ..SsrfRules::default()
        };
        let err = guarded_client(&policy, rules)
            .fetch(
                &server.url("/first"),
                &policy,
                FetchContext::subresource(None),
            )
            .unwrap_err();

        match err {
            FetchError::SsrfBlocked { address, rule, hop } => {
                assert_eq!(rule, "ssrf.link_local");
                assert_eq!(address.to_string(), "169.254.169.254:80");
                assert_eq!(hop, 1); // refused at the second request, not the first
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(server.requests().len(), 1);
    }

    #[test]
    fn an_input_url_follows_the_configured_scope() {
        // T-11.7: the same loopback URL, guarded or not depending on who asked
        let server = TestServer::start(vec![ok_body("text/html", b"<p>hi</p>")]);
        let policy = policy();
        let rules = SsrfRules {
            guard_input_urls: GuardScope::Always,
            ..SsrfRules::default()
        };
        let err = guarded_client(&policy, rules)
            .fetch(&server.url("/page"), &policy, FetchContext::input_cli())
            .unwrap_err();
        assert!(matches!(err, FetchError::SsrfBlocked { .. }), "{err:?}");
        assert!(server.requests().is_empty());

        // and with the default scope the same CLI input is the user's own intent
        let fetched = guarded_client(&policy, SsrfRules::default())
            .fetch(&server.url("/page"), &policy, FetchContext::input_cli())
            .unwrap();
        assert_eq!(fetched.body, b"<p>hi</p>");
    }

    #[test]
    fn a_server_input_url_is_guarded_by_default() {
        let server = TestServer::start(vec![ok_body("text/html", b"<p>hi</p>")]);
        let policy = policy();
        let err = guarded_client(&policy, SsrfRules::default())
            .fetch(&server.url("/page"), &policy, FetchContext::input_server())
            .unwrap_err();
        assert!(matches!(err, FetchError::SsrfBlocked { .. }), "{err:?}");
        assert!(server.requests().is_empty());
    }

    #[test]
    fn the_scope_does_not_leak_into_the_next_request() {
        // the RAII guard restores the previous scope even after a refusal
        let server = TestServer::start(vec![ok_body("text/html", b"<p>hi</p>")]);
        let policy = policy();
        let fetcher = guarded_client(&policy, SsrfRules::default());
        assert!(
            fetcher
                .fetch(&server.url("/a"), &policy, FetchContext::subresource(None))
                .is_err()
        );
        assert_eq!(guard::current_scope(), guard::Scope::default());
        // the unguarded CLI request that follows still works
        assert!(
            fetcher
                .fetch(&server.url("/a"), &policy, FetchContext::input_cli())
                .is_ok()
        );
    }
}
