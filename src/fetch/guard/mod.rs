//! The SSRF guard. It checks every address a request resolves to,
//! and refuses the connection if any of them is forbidden.
//!
//! Three layers, from pure to impure:
//! - [`table`] classifies an address
//! - [`resolver`] turns a name into addresses behind an injectable trait
//! - [`cache`] remembers verdicts with deny/allow asymmetry
//! - [`GuardedResolver`] composes them and is handed to `ureq` through `Agent::with_parts`

pub mod cache;
pub mod resolver;
pub mod table;

use std::cell::Cell;
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use ureq::config::Config;
use ureq::http::Uri;
use ureq::unversioned::resolver::{ResolvedSocketAddrs, Resolver};
use ureq::unversioned::transport::NextTimeout;

use crate::policy::{ConfigError, GuardScope, SsrfRules};

use cache::{ResolveCache, ResolveVerdict};
use resolver::{NameResolver, SystemResolver};
use table::{AllowList, CATEGORY_SSRF, IpDenyTable};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchOrigin {
    /// A URL the user typed.
    InputCli,
    /// A URL that arrived in a request body from a possibly untrusted caller.
    InputServer,
    /// A reference read out of an untrusted document.
    Subresource,
}

/// The caller's half of the guard decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FetchContext {
    pub origin: FetchOrigin,
    /// Endpoint of the parent input, for the same-origin exemption.
    pub parent_endpoint: Option<SocketAddr>,
}

impl FetchContext {
    pub fn input_cli() -> FetchContext {
        FetchContext {
            origin: FetchOrigin::InputCli,
            parent_endpoint: None,
        }
    }

    pub fn input_server() -> FetchContext {
        FetchContext {
            origin: FetchOrigin::InputServer,
            parent_endpoint: None,
        }
    }

    pub fn subresource(parent_endpoint: Option<SocketAddr>) -> FetchContext {
        FetchContext {
            origin: FetchOrigin::Subresource,
            parent_endpoint,
        }
    }
}

/// A refusal, carried inside `io::Error` because that is the only channel
/// `ureq`'s resolver trait offers. The fetcher downcasts it back into a typed
/// error so the report can name the address and the rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsrfDenied {
    pub addr: IpAddr,
    pub port: u16,
    pub rule: &'static str,
}

impl SsrfDenied {
    pub fn endpoint(&self) -> SocketAddr {
        SocketAddr::new(self.addr, self.port)
    }

    pub fn category(&self) -> &'static str {
        CATEGORY_SSRF
    }
}

impl fmt::Display for SsrfDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} refuses {}", self.rule, self.endpoint())
    }
}

impl std::error::Error for SsrfDenied {}

/// Everything the guard needs. Compiled once at start-up and immutable.
pub struct Guard {
    table: IpDenyTable,
    allow: AllowList,
    rules: SsrfRules,
    cache: ResolveCache,
    names: Arc<dyn NameResolver>,
}

impl Guard {
    /// Compile the policy. A malformed CIDR is a config error (exit 2) before
    /// any input is touched.
    pub fn new(rules: &SsrfRules) -> Result<Guard, ConfigError> {
        Guard::with_resolver(rules, Arc::new(SystemResolver))
    }


    pub fn with_resolver(
        rules: &SsrfRules,
        names: Arc<dyn NameResolver>,
    ) -> Result<Guard, ConfigError> {
        Ok(Guard {
            table: IpDenyTable::compile(rules)?,
            allow: AllowList::compile(rules)?,
            rules: rules.clone(),
            cache: ResolveCache::default(),
            names,
        })
    }

    pub fn rules(&self) -> &SsrfRules {
        &self.rules
    }

    pub fn cache(&self) -> &ResolveCache {
        &self.cache
    }

    pub fn applies_to(&self, ctx: &FetchContext) -> bool {
        match ctx.origin {
            FetchOrigin::Subresource => true,
            FetchOrigin::InputCli => self.rules.guard_input_urls == GuardScope::Always,
            FetchOrigin::InputServer => matches!(
                self.rules.guard_input_urls,
                GuardScope::Always | GuardScope::Server
            ),
        }
    }

    fn decide(&self, host: &str, port: u16, scope: Scope) -> Result<Vec<SocketAddr>, GuardError> {
        // an allow-listed name never reaches the table (T-11.6)
        if self.allow.allows_host(host) {
            return self.lookup(host, port);
        }

        let literal = parse_literal(host);
        let ttl = Duration::from_millis(self.rules.allow_ttl_ms);
        if literal.is_none()
            && scope.guarded
            && let Some(verdict) = self.cache.get(host, port, ttl)
        {
            return match verdict {
                ResolveVerdict::Allowed { addrs } => Ok(addrs),
                ResolveVerdict::Denied { addr, rule } => {
                    Err(GuardError::Denied(SsrfDenied { addr, port, rule }))
                }
            };
        }

        let addrs = match literal {
            Some(ip) => vec![SocketAddr::new(ip, port)],
            None => self.lookup(host, port)?,
        };
        if !scope.guarded {
            return Ok(addrs);
        }


        let mut exempted = false;
        for candidate in &addrs {
            if self.exempt(*candidate, scope) {
                exempted = true;
                continue;
            }
            if let Some(rule) = self.table.classify(candidate.ip()) {
                let denial = SsrfDenied {
                    addr: candidate.ip(),
                    port: candidate.port(),
                    rule,
                };
                if literal.is_none() {
                    self.cache.insert(
                        host,
                        port,
                        ResolveVerdict::Denied {
                            addr: candidate.ip(),
                            rule,
                        },
                    );
                }
                return Err(GuardError::Denied(denial));
            }
        }
        if literal.is_none() && !exempted {
            self.cache.insert(
                host,
                port,
                ResolveVerdict::Allowed {
                    addrs: addrs.clone(),
                },
            );
        }
        Ok(addrs)
    }

    /// Addresses that stay reachable although the table forbids them.
    fn exempt(&self, candidate: SocketAddr, scope: Scope) -> bool {
        if self.allow.allows_addr(candidate.ip()) {
            return true;
        }
        self.rules.same_origin_exemption && scope.parent == Some(candidate)
    }

    fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, GuardError> {
        let addrs = self.names.lookup(host, port).map_err(GuardError::Lookup)?;
        if addrs.is_empty() {
            // an empty answer is a failure
            return Err(GuardError::NoAddress);
        }
        Ok(addrs)
    }
}

/// Failure modes of one guarded resolution.
#[derive(Debug)]
enum GuardError {
    Denied(SsrfDenied),
    Lookup(io::Error),
    NoAddress,
}

/// What the guard was told about the request currently running on this thread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scope {
    pub guarded: bool,
    pub parent: Option<SocketAddr>,
}

impl Default for Scope {
    fn default() -> Scope {
        Scope {
            guarded: true,
            parent: None,
        }
    }
}

thread_local! {
    static SCOPE: Cell<Scope> = Cell::new(Scope::default());
    static LAST_ENDPOINT: Cell<Option<SocketAddr>> = const { Cell::new(None) };
}

/// Scope of the request being made, restored when the guard is dropped.
///
/// A thread-local is correct here because `ureq` is synchronous and resolves on
/// the very thread that called it — verified in its `run.rs`, where the resolver
/// runs inline before the connector chain. The alternative, one agent per input,
/// would build a connection pool per document.
pub struct ScopeGuard {
    previous: Scope,
}

impl Drop for ScopeGuard {
    fn drop(&mut self) {
        SCOPE.with(|s| s.set(self.previous));
    }
}

/// Enter `scope` for as long as the returned guard lives.
pub fn enter_scope(scope: Scope) -> ScopeGuard {
    let previous = SCOPE.with(|s| s.replace(scope));
    LAST_ENDPOINT.with(|e| e.set(None));
    ScopeGuard { previous }
}

pub fn current_scope() -> Scope {
    SCOPE.with(|s| s.get())
}

/// First vetted address of the last resolution on this thread — the endpoint
/// the connector attempts first, and therefore the parent endpoint a
/// sub-resource is compared against.
pub fn last_endpoint() -> Option<SocketAddr> {
    LAST_ENDPOINT.with(|e| e.get())
}

/// The `ureq` seam. One per agent, shared by every request that agent makes.
#[derive(Debug)]
pub struct GuardedResolver {
    guard: Arc<Guard>,
}

impl GuardedResolver {
    pub fn new(guard: Arc<Guard>) -> GuardedResolver {
        GuardedResolver { guard }
    }
}

impl fmt::Debug for Guard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Guard")
            .field("guard_input_urls", &self.rules.guard_input_urls)
            .finish()
    }
}

impl Resolver for GuardedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        _config: &Config,
        _timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let host = uri
            .host()
            .ok_or_else(|| ureq::Error::BadUri("missing host".to_string()))?;
        let port = uri
            .port_u16()
            .or_else(|| default_port(uri.scheme_str()))
            .ok_or_else(|| ureq::Error::BadUri("missing port".to_string()))?;

        let vetted = self
            .guard
            .decide(host, port, current_scope())
            .map_err(|e| match e {
                GuardError::Denied(denial) => {
                    ureq::Error::Io(io::Error::new(io::ErrorKind::PermissionDenied, denial))
                }
                GuardError::Lookup(e) => ureq::Error::Io(e),
                GuardError::NoAddress => ureq::Error::HostNotFound,
            })?;

        LAST_ENDPOINT.with(|e| e.set(vetted.first().copied()));
        let mut addrs = self.empty();
        for addr in vetted.iter().take(16) {
            addrs.push(*addr);
        }
        Ok(addrs)
    }
}

/// The refusal inside a `ureq` error, when there is one.
pub fn denial_of(error: &ureq::Error) -> Option<SsrfDenied> {
    match error {
        ureq::Error::Io(e) => e.get_ref()?.downcast_ref::<SsrfDenied>().cloned(),
        _ => None,
    }
}

fn parse_literal(host: &str) -> Option<IpAddr> {
    host.trim_matches(['[', ']']).parse().ok()
}

fn default_port(scheme: Option<&str>) -> Option<u16> {
    match scheme {
        Some("http") => Some(80),
        Some("https") => Some(443),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::resolver::scripted::ScriptedResolver;
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("test address parses")
    }

    fn guard_with(
        rules: SsrfRules,
        answers: Vec<Vec<SocketAddr>>,
    ) -> (Arc<Guard>, Arc<ScriptedResolver>) {
        let names = Arc::new(ScriptedResolver::new(answers));
        let guard = Guard::with_resolver(&rules, names.clone()).unwrap();
        (Arc::new(guard), names)
    }

    fn guarded() -> Scope {
        Scope {
            guarded: true,
            parent: None,
        }
    }

    fn denial(result: Result<Vec<SocketAddr>, GuardError>) -> SsrfDenied {
        match result {
            Err(GuardError::Denied(d)) => d,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    // the decision itself

    #[test]
    fn a_public_answer_is_allowed_and_returned_verbatim() {
        let (guard, names) = guard_with(
            SsrfRules::default(),
            vec![vec![addr("93.184.216.34:80"), addr("93.184.216.35:80")]],
        );
        let vetted = guard.decide("example.com", 80, guarded()).unwrap();
        assert_eq!(vetted, [addr("93.184.216.34:80"), addr("93.184.216.35:80")]);
        assert_eq!(names.calls(), 1);
    }

    #[test]
    fn a_private_answer_from_a_public_name_is_refused() {
        // the malicious-DNS-record branch: nothing about the name is suspicious
        let (guard, _) = guard_with(SsrfRules::default(), vec![vec![addr("127.0.0.1:80")]]);
        let denied = denial(guard.decide("internal.attacker.com", 80, guarded()));
        assert_eq!(denied.rule, "ssrf.loopback");
        assert_eq!(denied.endpoint(), addr("127.0.0.1:80"));
    }

    #[test]
    fn a_mixed_answer_is_refused_as_a_whole() {
        // keeping the good address would let the attacker choose the target
        let (guard, _) = guard_with(
            SsrfRules::default(),
            vec![vec![addr("93.184.216.34:80"), addr("10.0.0.5:80")]],
        );
        let denied = denial(guard.decide("split.test", 80, guarded()));
        assert_eq!(denied.rule, "ssrf.private");
    }

    #[test]
    fn an_empty_answer_is_a_failure_not_a_pass() {
        let (guard, _) = guard_with(SsrfRules::default(), vec![vec![]]);
        assert!(matches!(
            guard.decide("void.test", 80, guarded()),
            Err(GuardError::NoAddress)
        ));
    }

    #[test]
    fn ip_literals_are_classified_without_any_lookup() {
        // no name, no resolution, no cache probe
        let (guard, names) = guard_with(SsrfRules::default(), vec![vec![addr("93.184.216.34:80")]]);
        for (host, rule) in [
            ("127.0.0.1", "ssrf.loopback"),
            ("169.254.169.254", "ssrf.link_local"),
            ("10.0.0.5", "ssrf.private"),
            ("[::1]", "ssrf.loopback"),
            ("[::ffff:127.0.0.1]", "ssrf.loopback"),
        ] {
            let denied = denial(guard.decide(host, 80, guarded()));
            assert_eq!(denied.rule, rule, "{host}");
        }
        assert_eq!(
            guard.decide("93.184.216.34", 80, guarded()).unwrap().len(),
            1
        );
        assert_eq!(names.calls(), 0);
    }

    // rebinding and caching

    #[test]
    fn a_vetted_answer_is_never_re_resolved_within_the_ttl() {
        // the second answer is the rebinding attempt and is never asked for
        let (guard, names) = guard_with(
            SsrfRules::default(),
            vec![vec![addr("93.184.216.34:80")], vec![addr("127.0.0.1:80")]],
        );
        let first = guard.decide("rebind.test", 80, guarded()).unwrap();
        let second = guard.decide("rebind.test", 80, guarded()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first, [addr("93.184.216.34:80")]);
        assert_eq!(names.calls(), 1);
    }

    #[test]
    fn a_deny_is_sticky_for_the_run() {
        // re-resolving a refused name could only produce an allow
        let (guard, names) = guard_with(
            SsrfRules::default(),
            vec![vec![addr("127.0.0.1:80")], vec![addr("93.184.216.34:80")]],
        );
        assert_eq!(
            denial(guard.decide("flip.test", 80, guarded())).rule,
            "ssrf.loopback"
        );
        assert_eq!(
            denial(guard.decide("flip.test", 80, guarded())).rule,
            "ssrf.loopback"
        );
        assert_eq!(names.calls(), 1);
        assert_eq!(guard.cache().hits(), 1);
    }

    #[test]
    fn a_zero_ttl_re_resolves_every_time() {
        let rules = SsrfRules {
            allow_ttl_ms: 0,
            ..SsrfRules::default()
        };
        let (guard, names) = guard_with(
            rules,
            vec![vec![addr("93.184.216.34:80")], vec![addr("127.0.0.1:80")]],
        );
        assert!(guard.decide("h.test", 80, guarded()).is_ok());
        // the world changed and this time we see it
        assert_eq!(
            denial(guard.decide("h.test", 80, guarded())).rule,
            "ssrf.loopback"
        );
        assert_eq!(names.calls(), 2);
    }

    // scope and exemptions

    #[test]
    fn the_same_origin_exemption_is_endpoint_exact() {
        // same host and port is reachable, a neighbouring port is not
        let (guard, _) = guard_with(SsrfRules::default(), vec![vec![addr("127.0.0.1:3100")]]);
        let parent = Some(addr("127.0.0.1:3100"));
        let scope = Scope {
            guarded: true,
            parent,
        };
        assert!(guard.decide("127.0.0.1", 3100, scope).is_ok());
        assert_eq!(
            denial(guard.decide("127.0.0.1", 8080, scope)).rule,
            "ssrf.loopback"
        );
        // and without a parent the same reference is refused
        assert_eq!(
            denial(guard.decide("127.0.0.1", 3100, guarded())).rule,
            "ssrf.loopback"
        );
    }

    #[test]
    fn the_same_origin_exemption_can_be_switched_off() {
        let rules = SsrfRules {
            same_origin_exemption: false,
            ..SsrfRules::default()
        };
        let (guard, _) = guard_with(rules, vec![vec![addr("127.0.0.1:3100")]]);
        let scope = Scope {
            guarded: true,
            parent: Some(addr("127.0.0.1:3100")),
        };
        assert_eq!(
            denial(guard.decide("127.0.0.1", 3100, scope)).rule,
            "ssrf.loopback"
        );
    }

    #[test]
    fn an_exempted_allow_is_not_cached_for_other_parents() {
        let (guard, _) = guard_with(SsrfRules::default(), vec![vec![addr("127.0.0.1:3100")]]);
        let scope = Scope {
            guarded: true,
            parent: Some(addr("127.0.0.1:3100")),
        };
        assert!(guard.decide("harness.test", 3100, scope).is_ok());
        // another input, no parent: the exemption must not have leaked
        assert_eq!(
            denial(guard.decide("harness.test", 3100, guarded())).rule,
            "ssrf.loopback"
        );
    }

    #[test]
    fn an_allow_listed_host_bypasses_the_table() {
        // T-11.6, the intranet-mirror escape hatch
        let rules = SsrfRules {
            allow_hosts: vec!["intranet.local".to_string()],
            ..SsrfRules::default()
        };
        let (guard, _) = guard_with(rules, vec![vec![addr("10.1.2.3:80")]]);
        assert!(guard.decide("intranet.local", 80, guarded()).is_ok());
        assert_eq!(
            denial(guard.decide("other.local", 80, guarded())).rule,
            "ssrf.private"
        );
    }

    #[test]
    fn an_allow_listed_network_bypasses_the_table() {
        let rules = SsrfRules {
            allow_hosts: vec!["10.1.0.0/16".to_string()],
            ..SsrfRules::default()
        };
        let (guard, _) = guard_with(rules, vec![vec![addr("10.1.2.3:80")]]);
        assert!(guard.decide("mirror.test", 80, guarded()).is_ok());
        assert!(guard.decide("10.1.2.3", 80, guarded()).is_ok());
        assert_eq!(
            denial(guard.decide("10.2.2.3", 80, guarded())).rule,
            "ssrf.private"
        );
    }

    #[test]
    fn an_unguarded_scope_resolves_and_allows() {
        // a CLI input URL under `guard_input_urls = never` is the user's
        // own target, and it still resolves exactly once
        let (guard, names) = guard_with(SsrfRules::default(), vec![vec![addr("127.0.0.1:8080")]]);
        let scope = Scope {
            guarded: false,
            parent: None,
        };
        assert_eq!(
            guard.decide("localhost", 8080, scope).unwrap(),
            [addr("127.0.0.1:8080")]
        );
        assert_eq!(names.calls(), 1);
    }

    // scope plumbing

    #[test]
    fn guard_scope_decides_which_origins_are_guarded() {
        let subresource = FetchContext::subresource(None);
        for (scope, cli, server) in [
            (GuardScope::Never, false, false),
            (GuardScope::Server, false, true),
            (GuardScope::Always, true, true),
        ] {
            let rules = SsrfRules {
                guard_input_urls: scope,
                ..SsrfRules::default()
            };
            let guard = Guard::new(&rules).unwrap();
            assert_eq!(
                guard.applies_to(&FetchContext::input_cli()),
                cli,
                "{scope:?}"
            );
            assert_eq!(
                guard.applies_to(&FetchContext::input_server()),
                server,
                "{scope:?}"
            );
            // a document-controlled URL is guarded under every scope
            assert!(guard.applies_to(&subresource), "{scope:?}");
        }
    }

    #[test]
    fn no_scope_leaves_a_document_controlled_url_unguarded() {
        // the narrowest setting still guards everything a document asked for
        let rules = SsrfRules {
            guard_input_urls: GuardScope::Never,
            ..SsrfRules::default()
        };
        let guard = Guard::new(&rules).unwrap();
        assert!(guard.applies_to(&FetchContext::subresource(None)));
    }

    #[test]
    fn the_thread_scope_is_restored_on_exit() {
        assert_eq!(current_scope(), Scope::default());
        {
            let _outer = enter_scope(Scope {
                guarded: false,
                parent: None,
            });
            assert!(!current_scope().guarded);
            {
                let _inner = enter_scope(Scope {
                    guarded: true,
                    parent: Some(addr("127.0.0.1:3100")),
                });
                assert_eq!(current_scope().parent, Some(addr("127.0.0.1:3100")));
            }
            assert!(!current_scope().guarded);
        }
        // fail closed once nobody declared a scope
        assert_eq!(current_scope(), Scope::default());
    }

    #[test]
    fn a_refusal_survives_the_trip_through_io_error() {
        let denied = SsrfDenied {
            addr: "169.254.169.254".parse().unwrap(),
            port: 80,
            rule: "ssrf.link_local",
        };
        let error = ureq::Error::Io(io::Error::new(
            io::ErrorKind::PermissionDenied,
            denied.clone(),
        ));
        assert_eq!(denial_of(&error), Some(denied));
        assert_eq!(denial_of(&ureq::Error::HostNotFound), None);
        assert_eq!(denial_of(&ureq::Error::Io(io::Error::other("plain"))), None);
    }

    #[test]
    fn default_ports_come_from_the_scheme() {
        assert_eq!(default_port(Some("http")), Some(80));
        assert_eq!(default_port(Some("https")), Some(443));
        assert_eq!(default_port(Some("ftp")), None);
        assert_eq!(default_port(None), None);
    }
}
