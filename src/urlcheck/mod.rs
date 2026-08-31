//! URL and link inspection.
//!
//! One [`UrlChecker`] classifies a single URL string into a [`Verdict`]; the
//! HTML pass (`crate::html`) walks the URL-bearing attributes, calls
//! [`UrlChecker::check`] on each, and maps the verdict to the policy action.
//! The checker itself is pure classification, it never mutates a document and
//! never dereferences a URL (protection from SSRF).
//!
//! Questions in priority order:
//!
//! |Label|Question|
//! |---|---|
//! | `Malformed` | control chars / CR-LF / invalid absolute URL |
//! | `Blocked` | host on a configured block-list (suffix, punycode) |
//! | `Homograph` | Unicode host confusable with a protected domain |
//! | `Internal` | IP literal in a network nobody should be sent to |
//! | `UserInfo` | credentials in the authority, hiding the real host |
//! | `Idn` | otherwise an `xn--` IDN host, re-emitted in its ascii form |
//! | `Clean` | none of the above (incl. relative refs, routable IPs) |
//!
//! A verdict also carries the form the HTML pass should emit. The checker
//! parses a URL to decide, so keeping the original text in the document leaves
//! a reader free to resolve it to a different host than the one just cleared.
//! Whenever the text and the parse disagree on the authority, the verdict
//! carries the serialised URL and the attribute is rewritten to it.
//!
//! The [`BlockSet`] and [`SkeletonSet`] are *borrowed*: it is owned by the engine and shared, so the
//! worker pool hands every worker the same compiled lists without copying it.

pub mod cache;
use cache::VerdictCache;
use std::net::IpAddr;
use std::sync::LazyLock;

use url::{Host, ParseError, Position, Url};

use crate::netaddr::IpDenyTable;
use crate::policy::UrlRules;
use crate::policy::blockset::BlockSet;
use crate::policy::protectedset::SkeletonSet;

/// Synthetic base for resolving protocol-relative (`//host/path`) references.
/// Only the resolved authority is ever read, so the placeholder scheme and the
/// `.invalid` host guarantee the base itself can never match a real block-list
/// or protected-domain entry.
static PROTOCOL_RELATIVE_BASE: LazyLock<Url> =
    LazyLock::new(|| Url::parse("https://web-sanitizer.invalid/").expect("valid base URL"));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Label {
    Clean,
    Idn,
    Blocked,
    Homograph,
    Malformed,
    UserInfo,
    Internal(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    pub label: Label,
    pub canonical: Option<String>,
}

impl Verdict {
    /// A verdict that leaves the attribute text as it was written.
    pub fn plain(label: Label) -> Verdict {
        Verdict {
            label,
            canonical: None,
        }
    }

    /// A verdict carrying the text to emit in place of the original.
    pub fn rewritten(label: Label, canonical: String) -> Verdict {
        Verdict {
            label,
            canonical: Some(canonical),
        }
    }
}

pub struct UrlChecker<'a> {
    blockset: &'a BlockSet,
    skeletons: &'a SkeletonSet,
    addresses: &'a IpDenyTable,
    verdictcache: &'a VerdictCache,
    rules: &'a UrlRules,
}

impl<'a> UrlChecker<'a> {
    /// Build a checker over a borrowed block-list and URL policies.
    pub fn new(
        blockset: &'a BlockSet,
        skeletons: &'a SkeletonSet,
        addresses: &'a IpDenyTable,
        verdictcache: &'a VerdictCache,
        rules: &'a UrlRules,
    ) -> UrlChecker<'a> {
        UrlChecker {
            blockset,
            skeletons,
            addresses,
            verdictcache,
            rules,
        }
    }

    /// The URL policy this checker enforces — the HTML pass reads
    /// `action_blocked` / `action_homograph` / `placeholder_url` from here.
    pub fn rules(&self) -> &UrlRules {
        self.rules
    }

    /// Classify one attribute value. Never dereferences or mutates anything.
    ///
    /// Memoised: classification is a pure function of `raw`, so every verdict
    /// is cached, not only the ones on the fall-through path.
    pub fn check(&self, raw: &str) -> Verdict {
        if let Some(verdict) = self.verdictcache.get(raw) {
            return verdict;
        }

        let verdict = self.classify(raw);
        self.verdictcache.insert(raw.to_string(), verdict.clone());
        verdict
    }

    /// The classification itself, cache-free. Kept apart from [`Self::check`]
    /// so an early `return` leaves the verdict for the caller to memoise.
    fn classify(&self, raw: &str) -> Verdict {
        if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Verdict::plain(Label::Malformed);
        }

        let mut protocol_relative = false;
        let url = match Url::parse(raw) {
            Ok(url) => url,
            // protocol relative integration
            Err(ParseError::RelativeUrlWithoutBase) if raw.trim_start().starts_with("//") => {
                protocol_relative = true;
                match PROTOCOL_RELATIVE_BASE.join(raw) {
                    Ok(url) => url,
                    Err(_) => return Verdict::plain(Label::Malformed),
                }
            }
            Err(ParseError::RelativeUrlWithoutBase) => return Verdict::plain(Label::Clean),
            Err(_) => return Verdict::plain(Label::Malformed),
        };

        // schemeless-host cases (`mailto:`, `data:`, `tel:`) carry no host
        // engine will notice bad schemes
        let Some(host) = url.host() else {
            return Verdict::plain(Label::Clean);
        };

        if self.blockset.contains(host.to_owned()) {
            return Verdict::plain(Label::Blocked);
        }

        // homograph / IDN reporting only make sense for domain hosts: the
        // `Host` variant carries that distinction, so IP literals never reach
        // the punycode path
        let idn = match host {
            Host::Domain(ascii) => {
                // Decode punycode to the Unicode the user would actually see.
                let (unicode, _) = idna::domain_to_unicode(ascii);
                if self.skeletons.confusable_with(&unicode) {
                    return Verdict::plain(Label::Homograph);
                }
                is_idn(ascii)
            }
            Host::Ipv4(v4) => match self.addresses.classify(IpAddr::V4(v4)) {
                Some(rule) => return Verdict::plain(Label::Internal(rule)),
                None => false,
            },
            Host::Ipv6(v6) => match self.addresses.classify(IpAddr::V6(v6)) {
                Some(rule) => return Verdict::plain(Label::Internal(rule)),
                None => false,
            },
        };

        // credentials make a link read as a host it never reaches, and a
        // sanitised document has no use for them
        if !url.username().is_empty() || url.password().is_some() {
            let mut stripped = url.clone();
            let _ = stripped.set_username("");
            let _ = stripped.set_password(None);
            return Verdict::rewritten(Label::UserInfo, serialise(&stripped, protocol_relative));
        }

        let label = if idn { Label::Idn } else { Label::Clean };

        match written_authority(raw) {
            Some(written) if written.eq_ignore_ascii_case(url.authority()) => Verdict::plain(label),
            _ => Verdict::rewritten(label, serialise(&url, protocol_relative)),
        }
    }
}

/// True when any label of an ASCII host is a punycode (`xn--`) label.
fn is_idn(ascii_host: &str) -> bool {
    ascii_host
        .split('.')
        .any(|label| label.len() >= 4 && label.as_bytes()[..4].eq_ignore_ascii_case(b"xn--"))
}

fn written_authority(raw: &str) -> Option<&str> {
    let raw = raw.trim();
    let start = raw.find("//")?;
    if raw[..start].contains(['/', '?', '#']) {
        return None;
    }
    let rest = &raw[start + 2..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    Some(&rest[..end])
}

fn serialise(url: &Url, protocol_relative: bool) -> String {
    if protocol_relative {
        format!("//{}{}", url.authority(), &url[Position::BeforePath..])
    } else {
        url.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::SsrfRules;
    use crate::tests_helper::set_from::SetFrom;

    fn rules(protected: &[&str]) -> UrlRules {
        UrlRules {
            protected_domains: protected.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    static BUILTIN_ADDRESSES: LazyLock<IpDenyTable> = LazyLock::new(IpDenyTable::builtin);

    fn checker<'a>(
        blockset: &'a BlockSet,
        skeletons: &'a SkeletonSet,
        verdictcache: &'a VerdictCache,
        rules: &'a UrlRules,
    ) -> UrlChecker<'a> {
        // leak-free: rules is cloned into the checker, so the temporary is fine
        UrlChecker::new(blockset, skeletons, &BUILTIN_ADDRESSES, verdictcache, rules)
    }

    // Block lists

    #[test]
    fn host_on_blocklist_is_blocked() {
        let bs = BlockSet::set_from_list(&["0.0.0.0 evil.com"]);
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(c.check("http://evil.com/x"), Verdict::plain(Label::Blocked));
        // parent-domain suffix + case-insensitive.
        assert_eq!(
            c.check("https://a.b.EVIL.com/p?q=1"),
            Verdict::plain(Label::Blocked)
        );
        // label boundary, not substring.
        assert_eq!(c.check("http://notevil.com/"), Verdict::plain(Label::Clean));
    }

    #[test]
    fn protocol_relative_host_is_extracted_and_checked() {
        // `//host/path` carries an authority but no scheme; it still names a
        // host the browser resolves against the page scheme
        let bs = BlockSet::set_from_list(&["0.0.0.0 evil.com"]);
        let protected = &["paypal.com"];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(c.check("//evil.com/path"), Verdict::plain(Label::Blocked)); // blocklisted host
        assert_eq!(c.check("//a.b.evil.com/x"), Verdict::plain(Label::Blocked)); // suffix walk
        assert_eq!(
            c.check("//p\u{0430}ypal.com/"),
            Verdict::plain(Label::Homograph)
        ); // homograph host
        assert_eq!(c.check("//example.com/ok"), Verdict::plain(Label::Clean)); // benign host
    }

    #[test]
    fn malformed_protocol_relative_is_neutralised() {
        // A nested host/split, bad port, or empty authority in a protocol-
        // relative reference fails resolution and must not slip through as Clean.
        let bs = BlockSet::set_from_list(&["0.0.0.0 evil.com"]);
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(
            c.check("//example.com\u{FF20}evil.com/"),
            Verdict::plain(Label::Malformed)
        ); // nested ＠
        assert_eq!(
            c.check("//evil.com:99999/"),
            Verdict::plain(Label::Malformed)
        ); // invalid port
        assert_eq!(c.check("///path"), Verdict::plain(Label::Malformed)); // empty authority
        assert_eq!(c.check("//"), Verdict::plain(Label::Malformed));
    }

    #[test]
    fn punycode_blocklist_entry_matches_the_idn_host() {
        // The list carries the ASCII/punycode form of `münchen.de` — the only
        // form `Host` ever produces — so both spellings of the URL block.
        let bs = BlockSet::set_from_list(&["0.0.0.0 xn--mnchen-3ya.de"]);
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(
            c.check("http://xn--mnchen-3ya.de/"),
            Verdict::plain(Label::Blocked)
        );
        assert_eq!(
            c.check("http://m\u{00fc}nchen.de/"),
            Verdict::plain(Label::Blocked)
        );
    }

    // Homograph + IDN

    #[test]
    fn cyrillic_homograph_of_protected_domain_is_flagged() {
        let bs = BlockSet::default();
        let protected = &["paypal.com"];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        // `pаypal.com` with a Cyrillic а (U+0430) → punycode host, confusable.
        let spoof = "http://p\u{0430}ypal.com/login";
        assert_eq!(c.check(spoof), Verdict::plain(Label::Homograph));
    }

    #[test]
    fn confusable_subdomain_is_flagged_against_registrable_domain() {
        let bs = BlockSet::default();
        let protected = &["paypal.com"];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        let spoof = "http://login.p\u{0430}ypal.com/";
        assert_eq!(c.check(spoof), Verdict::plain(Label::Homograph));
    }

    #[test]
    fn genuine_protected_domain_is_not_a_homograph() {
        let bs = BlockSet::default();
        let protected = &["paypal.com"];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(c.check("https://paypal.com/"), Verdict::plain(Label::Clean));
        assert_eq!(
            c.check("https://login.paypal.com/"),
            Verdict::plain(Label::Clean)
        );
    }

    #[test]
    fn plain_idn_without_protected_match_is_reported_as_idn() {
        let bs = BlockSet::default();
        let protected = &[]; // no protected domains
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(
            c.check("http://m\u{00fc}nchen.de/"),
            Verdict::rewritten(Label::Idn, "http://xn--mnchen-3ya.de/".to_string())
        );
        assert_eq!(
            c.check("http://xn--mnchen-3ya.de/"),
            Verdict::plain(Label::Idn)
        );
    }

    #[test]
    fn block_list_takes_priority_over_homograph() {
        // Derive the punycode of the spoof host so the block-list entry is
        // exactly what `check` sees — no hand-computed xn-- to get wrong.
        let ascii = idna::domain_to_ascii("p\u{0430}ypal.com").unwrap();
        let entry = format!("0.0.0.0 {ascii}");
        let bs = BlockSet::set_from_list(&[entry.as_str()]);
        let protected = &["paypal.com"];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(
            c.check("http://p\u{0430}ypal.com/"),
            Verdict::plain(Label::Blocked)
        );
    }

    // malformed / host-split

    #[test]
    fn embedded_control_chars_are_malformed() {
        let bs = BlockSet::default();
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(
            c.check("http://exa\r\nmple.com/"),
            Verdict::plain(Label::Malformed)
        );
        assert_eq!(
            c.check("http://exa\tmple.com/"),
            Verdict::plain(Label::Malformed)
        );
        assert_eq!(
            c.check("http://example.com/\u{0000}"),
            Verdict::plain(Label::Malformed)
        );
    }

    #[test]
    fn unicode_normalisation_host_split_is_malformed() {
        let bs = BlockSet::default();
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(
            c.check("http://example.com\u{FF20}evil.com/"),
            Verdict::plain(Label::Malformed)
        ); // ＠
        assert_eq!(
            c.check("http://evil.com\u{FF0F}path"),
            Verdict::plain(Label::Malformed)
        ); //         ／
        assert_eq!(
            c.check("http://exa mple.com/"),
            Verdict::plain(Label::Malformed)
        ); // raw space in host
    }

    #[test]
    fn broken_absolute_urls_are_malformed_not_clean() {
        // An absolute-looking URL that fails to parse is default-denied, not
        // waved through as if it were a relative reference — closing the
        // `Err(_) => Clean` hole that let host/split payloads pass verbatim.
        let bs = BlockSet::default();
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(
            c.check("http://example.com:99999/"),
            Verdict::plain(Label::Malformed)
        ); // InvalidPort
        assert_eq!(
            c.check("http://999.999.999.999/"),
            Verdict::plain(Label::Malformed)
        ); //   InvalidIpv4Address
        assert_eq!(c.check("http://[::1/"), Verdict::plain(Label::Malformed)); //              InvalidIpv6Address
    }

    // Clean verdict / benign

    #[test]
    fn relative_and_hostless_urls_are_clean() {
        let bs = BlockSet::set_from_list(&["0.0.0.0 evil.com"]);
        let protected = &["paypal.com"];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(c.check("/relative/path"), Verdict::plain(Label::Clean));
        assert_eq!(c.check("#anchor"), Verdict::plain(Label::Clean));
        assert_eq!(c.check("page.html"), Verdict::plain(Label::Clean));
        assert_eq!(c.check("?q=1"), Verdict::plain(Label::Clean));
        assert_eq!(c.check("../up/two"), Verdict::plain(Label::Clean));
        assert_eq!(c.check("foo/bar"), Verdict::plain(Label::Clean));
        assert_eq!(c.check("mailto:a@b.com"), Verdict::plain(Label::Clean));
        assert_eq!(
            c.check("https://example.com/"),
            Verdict::plain(Label::Clean)
        );
    }

    // memoisation

    #[test]
    fn every_verdict_is_memoised_not_only_the_clean_one() {
        // each raw string is classified once, whatever the verdict: the second
        // pass must be served entirely by the cache
        let bs = BlockSet::set_from_list(&["0.0.0.0 evil.com"]);
        let protected = &["paypal.com"];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);

        let cases = [
            ("http://evil.com/", Verdict::plain(Label::Blocked)),
            (
                "http://p\u{0430}ypal.com/",
                Verdict::plain(Label::Homograph),
            ),
            (
                "http://m\u{00fc}nchen.de/",
                Verdict::rewritten(Label::Idn, "http://xn--mnchen-3ya.de/".to_string()),
            ),
            ("http://exa\r\nmple.com/", Verdict::plain(Label::Malformed)),
            (
                "http://example.com:99999/",
                Verdict::plain(Label::Malformed),
            ),
            ("/relative/path", Verdict::plain(Label::Clean)),
            ("https://example.com/", Verdict::plain(Label::Clean)),
        ];

        for (raw, expected) in &cases {
            assert_eq!(&c.check(raw), expected);
        }
        // all misses so far: distinct urls, none seen before
        assert_eq!(verdicache.hit_rate(), 0.0);

        for (raw, expected) in &cases {
            assert_eq!(&c.check(raw), expected);
        }
        // one hit per miss
        assert!((verdicache.hit_rate() - 0.5).abs() < f64::EPSILON);
    }

    #[test]
    fn a_cached_verdict_short_circuits_classification() {
        // the lookup happens before any parsing: a pre-seeded entry wins over
        // the block-list, which is what makes the cache observable at all
        let bs = BlockSet::set_from_list(&["0.0.0.0 evil.com"]);
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);

        verdicache.insert("http://evil.com/".to_string(), Verdict::plain(Label::Clean));
        assert_eq!(c.check("http://evil.com/"), Verdict::plain(Label::Clean));
        // a sibling url is untouched and still classified
        assert_eq!(
            c.check("http://evil.com/other"),
            Verdict::plain(Label::Blocked)
        );
    }

    #[test]
    fn the_cache_is_keyed_on_the_raw_value_not_the_host() {
        // two spellings of one host are two entries, and both must reach the
        // same verdict on their own
        let bs = BlockSet::set_from_list(&["0.0.0.0 evil.com"]);
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);

        assert_eq!(c.check("http://evil.com/"), Verdict::plain(Label::Blocked));
        assert_eq!(c.check("http://EVIL.com/"), Verdict::plain(Label::Blocked));
        assert_eq!(c.check("//evil.com/"), Verdict::plain(Label::Blocked));
        // three misses, no hit
        assert_eq!(verdicache.hit_rate(), 0.0);
    }

    #[test]
    fn ip_host_is_neither_idn_or_homograph() {
        // `Host::Ipv4`/`Host::Ipv6` skip the punycode path entirely, so the
        // bracketed IPv6 form is never mistaken for a domain label.
        let bs = BlockSet::default();
        let protected = &["paypal.com"];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        // routable literals: no punycode path, and no address rule either
        assert_eq!(
            c.check("http://93.184.216.34/"),
            Verdict::plain(Label::Clean)
        );
        assert_eq!(
            c.check("http://[2606:2800:220:1:248:1893:25c8:1946]/"),
            Verdict::plain(Label::Clean)
        );
    }

    // internal addresses

    #[test]
    fn a_link_to_an_unreachable_network_is_named_by_its_rule() {
        // the same table the fetch guard consults, so the report reads the
        // same on both paths
        let bs = BlockSet::default();
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);

        let cases = [
            (
                "http://169.254.169.254/latest/meta-data/",
                "ssrf.link_local",
            ),
            ("http://10.0.0.1/internal", "ssrf.private"),
            ("http://192.168.1.1/", "ssrf.private"),
            ("http://127.0.0.1:8080/", "ssrf.loopback"),
            ("http://0.0.0.0/", "ssrf.unspecified"),
            ("http://[::1]/", "ssrf.loopback"),
            ("http://[fd00:ec2::254]/", "ssrf.unique_local"),
            ("http://203.0.113.9/", "ssrf.documentation"),
        ];
        for (raw, rule) in cases {
            assert_eq!(c.check(raw), Verdict::plain(Label::Internal(rule)), "{raw}");
        }
    }

    #[test]
    fn an_ipv6_wrapper_around_a_private_address_is_unwrapped() {
        // deciding on the wrapper would classify by syntax, which is the
        // mistake the address table exists to avoid
        let bs = BlockSet::default();
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);

        assert_eq!(
            c.check("http://[::ffff:10.0.0.1]/"),
            Verdict::plain(Label::Internal("ssrf.private"))
        );
        assert_eq!(
            c.check("http://[2002:a00:1::]/"),
            Verdict::plain(Label::Internal("ssrf.private"))
        );
    }

    #[test]
    fn a_name_is_never_resolved_to_reach_a_verdict() {
        let bs = BlockSet::default();
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);

        assert_eq!(
            c.check("http://metadata.example.test/"),
            Verdict::plain(Label::Clean)
        );
        assert_eq!(
            c.check("http://169.254.169.254.example.test/"),
            Verdict::plain(Label::Clean)
        );
    }

    #[test]
    fn a_unicode_host_is_re_emitted_as_punycode() {
        let bs = BlockSet::default();
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);

        let cases = [
            (
                "http://www.\u{0430}\u{0440}\u{0440}\u{04CF}\u{0435}.com/login",
                "http://www.xn--80ak6aa92e.com/login",
            ),
            ("http://\u{0261}oogle.com", "http://xn--oogle-qmc.com/"),
            ("http://\u{0440}aypal.com", "http://xn--aypal-uye.com/"),
        ];
        for (raw, ascii) in cases {
            assert_eq!(
                c.check(raw),
                Verdict::rewritten(Label::Idn, ascii.to_string()),
                "{raw}"
            );
        }
    }

    #[test]
    fn a_homograph_of_a_protected_domain_still_outranks_the_idn_report() {
        let bs = BlockSet::default();
        let protected = &["paypal.com"];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(
            c.check("http://p\u{0430}ypal.com/login"),
            Verdict::plain(Label::Homograph)
        );
    }

    #[test]
    fn a_block_list_entry_cannot_shadow_the_address_table() {
        let bs = BlockSet::set_from_list(&["0.0.0.0 10.0.0.1"]);
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(
            c.check("http://10.0.0.1/"),
            Verdict::plain(Label::Internal("ssrf.private"))
        );
    }

    #[test]
    fn a_policy_added_network_reaches_the_emit_path_too() {
        let ssrf = SsrfRules {
            deny_extra: vec!["198.18.0.0/15".to_string()],
            ..Default::default()
        };
        let addresses = IpDenyTable::compile(&ssrf).unwrap();
        let bs = BlockSet::default();
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = UrlChecker::new(&bs, &skeletons, &addresses, &verdicache, &rules);
        assert_eq!(
            c.check("http://198.18.0.7/"),
            Verdict::plain(Label::Internal("ssrf.benchmarking"))
        );
    }

    // canonical form

    fn plain_checker<'a>(
        bs: &'a BlockSet,
        skeletons: &'a SkeletonSet,
        verdicache: &'a VerdictCache,
        rules: &'a UrlRules,
    ) -> UrlChecker<'a> {
        checker(bs, skeletons, verdicache, rules)
    }

    #[test]
    fn a_url_the_text_spells_differently_is_re_emitted_as_parsed() {
        // the parser resolves all three correctly. Leaving the original text in
        // the document is what lets a reader downstream reach another host
        let bs = BlockSet::default();
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = plain_checker(&bs, &skeletons, &verdicache, &rules);

        // fullwidth full stop is a label separator after IDNA mapping
        assert_eq!(
            c.check("http://169.254.169.254\u{FF0E}example.com/"),
            Verdict::rewritten(
                Label::Clean,
                "http://169.254.169.254.example.com/".to_string()
            )
        );
        // percent-encoded dot, decoded by host parsing
        assert_eq!(
            c.check("http://169.254.169.254%2Eexample.com/"),
            Verdict::rewritten(
                Label::Clean,
                "http://169.254.169.254.example.com/".to_string()
            )
        );
        // a backslash ends the authority, so `@other.test` belongs to the path
        assert_eq!(
            c.check("http://trusted.example.com\\@other.test/"),
            Verdict::rewritten(
                Label::Clean,
                "http://trusted.example.com/@other.test/".to_string()
            )
        );
        // a default port carries no meaning and disappears on serialisation
        assert_eq!(
            c.check("http://example.com:80/x"),
            Verdict::rewritten(Label::Clean, "http://example.com/x".to_string())
        );
    }

    #[test]
    fn credentials_are_stripped_from_the_emitted_url() {
        let bs = BlockSet::set_from_list(&["0.0.0.0 evil.com"]);
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = plain_checker(&bs, &skeletons, &verdicache, &rules);

        assert_eq!(
            c.check("http://trusted.example.com@other.test/"),
            Verdict::rewritten(Label::UserInfo, "http://other.test/".to_string())
        );
        assert_eq!(
            c.check("https://user:pass@other.test/x?q=1"),
            Verdict::rewritten(Label::UserInfo, "https://other.test/x?q=1".to_string())
        );
        // the block-list already decides on the real host, so it wins
        assert_eq!(
            c.check("http://trusted.example.com@evil.com/"),
            Verdict::plain(Label::Blocked)
        );
    }

    #[test]
    fn a_rewritten_protocol_relative_reference_keeps_its_shape() {
        // the synthetic base is an implementation detail and must never reach
        // the document
        let bs = BlockSet::default();
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = plain_checker(&bs, &skeletons, &verdicache, &rules);

        assert_eq!(
            c.check("//example\u{FF0E}com/x"),
            Verdict::rewritten(Label::Clean, "//example.com/x".to_string())
        );
        assert_eq!(
            c.check("//user@example.com/x"),
            Verdict::rewritten(Label::UserInfo, "//example.com/x".to_string())
        );
    }

    #[test]
    fn an_ordinary_url_is_left_exactly_as_written() {
        // normalisation must not fire on every link of every page: only a
        // disagreement about the authority earns a rewrite
        let bs = BlockSet::default();
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = plain_checker(&bs, &skeletons, &verdicache, &rules);

        assert_eq!(c.check("http://example.com"), Verdict::plain(Label::Clean));
        assert_eq!(c.check("http://EXAMPLE.com/"), Verdict::plain(Label::Clean));
        assert_eq!(
            c.check("https://example.com/a/b?q=1#f"),
            Verdict::plain(Label::Clean)
        );
        assert_eq!(
            c.check("https://example.com:8443/x"),
            Verdict::plain(Label::Clean)
        );
        assert_eq!(c.check("//example.com/x"), Verdict::plain(Label::Clean));
    }

    #[test]
    fn the_canonical_form_is_a_fixed_point() {
        let bs = BlockSet::default();
        let protected = &[];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = plain_checker(&bs, &skeletons, &verdicache, &rules);

        let cases = [
            "http://169.254.169.254\u{FF0E}example.com/",
            "http://169.254.169.254%2Eexample.com/",
            "http://trusted.example.com\\@other.test/",
            "http://example.com:80/x",
            "http://trusted.example.com@other.test/",
            "//example\u{FF0E}com/x",
            "//user@example.com/x",
        ];
        for raw in cases {
            let canonical = c.check(raw).canonical.expect("case rewrites");
            assert_eq!(c.check(&canonical), Verdict::plain(Label::Clean));
        }
    }
}
