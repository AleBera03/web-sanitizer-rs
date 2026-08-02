//! URL and link inspection.
//!
//! One [`UrlChecker`] classifies a single URL string into a [`Verdict`]; the
//! HTML pass (`crate::html`) walks the URL-bearing attributes, calls
//! [`UrlChecker::check`] on each, and maps the verdict to the policy action.
//! The checker itself is pure classification, it never mutates a document and
//! never dereferences a URL (protection from SSRF).
//!
//! Three orthogonal questions, in priority order:
//!
//! |Verdict|Question|
//! |---|---|
//! | `Malformed` | control chars / CR-LF / invalid absolute URL |
//! | `Blocked` | host on a configured block-list (suffix, punycode) |
//! | `Homograph` | Unicode host confusable with a protected domain |
//! | `Idn` | otherwise an `xn--` IDN host (report-only) |
//! | `Clean` | none of the above (incl. relative refs, IPs) |
//!
//! The [`BlockSet`] and [`SkeletonSet`] are *borrowed*: it is owned by the engine and shared, so the
//! worker pool hands every worker the same compiled lists without copying it.

pub mod cache;
use cache::VerdictCache;

use std::sync::LazyLock;

use url::{Host, ParseError, Url};

use crate::policy::UrlRules;
use crate::policy::blockset::BlockSet;
use crate::policy::protectedset::SkeletonSet;

/// Synthetic base for resolving protocol-relative (`//host/path`) references.
/// Only the resolved authority is ever read, so the placeholder scheme and the
/// `.invalid` host guarantee the base itself can never match a real block-list
/// or protected-domain entry.
static PROTOCOL_RELATIVE_BASE: LazyLock<Url> =
    LazyLock::new(|| Url::parse("https://web-sanitizer.invalid/").expect("valid base URL"));

/// Classification of one URL. Only `Blocked`/`Homograph`/`Malformed` are
/// actionable; `Idn` is report-only and `Clean` leaves the attribute untouched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Idn,
    Blocked,
    Homograph,
    Malformed,
}

pub struct UrlChecker<'a> {
    blockset: &'a BlockSet,
    skeletons: &'a SkeletonSet,
    verdictcache: &'a VerdictCache,
    rules: &'a UrlRules,
}

impl<'a> UrlChecker<'a> {
    /// Build a checker over a borrowed block-list and URL policies.
    pub fn new(
        blockset: &'a BlockSet,
        skeletons: &'a SkeletonSet,
        verdictcache: &'a VerdictCache,
        rules: &'a UrlRules,
    ) -> UrlChecker<'a> {
        UrlChecker {
            blockset,
            skeletons,
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
        self.verdictcache.insert(raw.to_string(), verdict);
        verdict
    }

    /// The classification itself, cache-free. Kept apart from [`Self::check`]
    /// so an early `return` leaves the verdict for the caller to memoise.
    fn classify(&self, raw: &str) -> Verdict {
        if raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Verdict::Malformed;
        }

        let url = match Url::parse(raw) {
            Ok(url) => url,
            // protocol relative integration
            Err(ParseError::RelativeUrlWithoutBase) if raw.trim_start().starts_with("//") => {
                match PROTOCOL_RELATIVE_BASE.join(raw) {
                    Ok(url) => url,
                    Err(_) => return Verdict::Malformed,
                }
            }
            Err(ParseError::RelativeUrlWithoutBase) => return Verdict::Clean,
            Err(_) => return Verdict::Malformed,
        };

        // schemeless-host cases (`mailto:`, `data:`, `tel:`) carry no host
        // engine will notice bad schemes
        let Some(host) = url.host() else {
            return Verdict::Clean;
        };

        if self.blockset.contains(host.to_owned()) {
            return Verdict::Blocked;
        }

        // homograph / IDN reporting only make sense for domain hosts: the
        // `Host` variant carries that distinction, so IP literals never reach
        // the punycode path
        if let Host::Domain(ascii) = host {
            // Decode punycode to the Unicode the user would actually see.
            let (unicode, _) = idna::domain_to_unicode(ascii);
            if self.skeletons.confusable_with(&unicode) {
                return Verdict::Homograph;
            }
            if is_idn(ascii) {
                return Verdict::Idn;
            }
        }

        Verdict::Clean
    }
}

/// True when any label of an ASCII host is a punycode (`xn--`) label.
fn is_idn(ascii_host: &str) -> bool {
    ascii_host
        .split('.')
        .any(|label| label.len() >= 4 && label.as_bytes()[..4].eq_ignore_ascii_case(b"xn--"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_helper::set_from::SetFrom;

    fn rules(protected: &[&str]) -> UrlRules {
        UrlRules {
            protected_domains: protected.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    fn checker<'a>(
        blockset: &'a BlockSet,
        skeletons: &'a SkeletonSet,
        verdictcache: &'a VerdictCache,
        rules: &'a UrlRules,
    ) -> UrlChecker<'a> {
        // leak-free: rules is cloned into the checker, so the temporary is fine
        UrlChecker::new(blockset, skeletons, verdictcache, rules)
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
        assert_eq!(c.check("http://evil.com/x"), Verdict::Blocked);
        // parent-domain suffix + case-insensitive.
        assert_eq!(c.check("https://a.b.EVIL.com/p?q=1"), Verdict::Blocked);
        // label boundary, not substring.
        assert_eq!(c.check("http://notevil.com/"), Verdict::Clean);
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
        assert_eq!(c.check("//evil.com/path"), Verdict::Blocked); // blocklisted host
        assert_eq!(c.check("//a.b.evil.com/x"), Verdict::Blocked); // suffix walk
        assert_eq!(c.check("//p\u{0430}ypal.com/"), Verdict::Homograph); // homograph host
        assert_eq!(c.check("//example.com/ok"), Verdict::Clean); // benign host
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
            Verdict::Malformed
        ); // nested ＠
        assert_eq!(c.check("//evil.com:99999/"), Verdict::Malformed); // invalid port
        assert_eq!(c.check("///path"), Verdict::Malformed); // empty authority
        assert_eq!(c.check("//"), Verdict::Malformed);
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
        assert_eq!(c.check("http://xn--mnchen-3ya.de/"), Verdict::Blocked);
        assert_eq!(c.check("http://m\u{00fc}nchen.de/"), Verdict::Blocked);
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
        assert_eq!(c.check(spoof), Verdict::Homograph);
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
        assert_eq!(c.check(spoof), Verdict::Homograph);
    }

    #[test]
    fn genuine_protected_domain_is_not_a_homograph() {
        let bs = BlockSet::default();
        let protected = &["paypal.com"];
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        assert_eq!(c.check("https://paypal.com/"), Verdict::Clean);
        assert_eq!(c.check("https://login.paypal.com/"), Verdict::Clean);
    }

    #[test]
    fn plain_idn_without_protected_match_is_reported_as_idn() {
        let bs = BlockSet::default();
        let protected = &[]; // no protected domains
        let skeletons = SkeletonSet::set_from_list(protected);
        let verdicache = VerdictCache::default();
        let rules = rules(protected);
        let c = checker(&bs, &skeletons, &verdicache, &rules);
        // münchen.de: a legitimate IDN, not confusable with anything protected.
        assert_eq!(c.check("http://m\u{00fc}nchen.de/"), Verdict::Idn);
        assert_eq!(c.check("http://xn--mnchen-3ya.de/"), Verdict::Idn);
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
        assert_eq!(c.check("http://p\u{0430}ypal.com/"), Verdict::Blocked);
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
        assert_eq!(c.check("http://exa\r\nmple.com/"), Verdict::Malformed);
        assert_eq!(c.check("http://exa\tmple.com/"), Verdict::Malformed);
        assert_eq!(c.check("http://example.com/\u{0000}"), Verdict::Malformed);
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
            Verdict::Malformed
        ); // ＠
        assert_eq!(c.check("http://evil.com\u{FF0F}path"), Verdict::Malformed); //         ／
        assert_eq!(c.check("http://exa mple.com/"), Verdict::Malformed); // raw space in host
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
        assert_eq!(c.check("http://example.com:99999/"), Verdict::Malformed); // InvalidPort
        assert_eq!(c.check("http://999.999.999.999/"), Verdict::Malformed); //   InvalidIpv4Address
        assert_eq!(c.check("http://[::1/"), Verdict::Malformed); //              InvalidIpv6Address
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
        assert_eq!(c.check("/relative/path"), Verdict::Clean);
        assert_eq!(c.check("#anchor"), Verdict::Clean);
        assert_eq!(c.check("page.html"), Verdict::Clean);
        assert_eq!(c.check("?q=1"), Verdict::Clean);
        assert_eq!(c.check("../up/two"), Verdict::Clean);
        assert_eq!(c.check("foo/bar"), Verdict::Clean);
        assert_eq!(c.check("mailto:a@b.com"), Verdict::Clean);
        assert_eq!(c.check("https://example.com/"), Verdict::Clean);
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
            ("http://evil.com/", Verdict::Blocked),
            ("http://p\u{0430}ypal.com/", Verdict::Homograph),
            ("http://m\u{00fc}nchen.de/", Verdict::Idn),
            ("http://exa\r\nmple.com/", Verdict::Malformed),
            ("http://example.com:99999/", Verdict::Malformed),
            ("/relative/path", Verdict::Clean),
            ("https://example.com/", Verdict::Clean),
        ];

        for (raw, expected) in cases {
            assert_eq!(c.check(raw), expected);
        }
        // all misses so far: distinct urls, none seen before
        assert_eq!(verdicache.hit_rate(), 0.0);

        for (raw, expected) in cases {
            assert_eq!(c.check(raw), expected);
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

        verdicache.insert("http://evil.com/".to_string(), Verdict::Clean);
        assert_eq!(c.check("http://evil.com/"), Verdict::Clean);
        // a sibling url is untouched and still classified
        assert_eq!(c.check("http://evil.com/other"), Verdict::Blocked);
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

        assert_eq!(c.check("http://evil.com/"), Verdict::Blocked);
        assert_eq!(c.check("http://EVIL.com/"), Verdict::Blocked);
        assert_eq!(c.check("//evil.com/"), Verdict::Blocked);
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
        assert_eq!(c.check("http://203.0.113.9/"), Verdict::Clean);
        assert_eq!(c.check("http://[2001:db8::1]/"), Verdict::Clean);
    }
}
