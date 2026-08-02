use std::collections::HashMap;

use url::Host;

use crate::policy::ConfigError;

/// UTS#39 basic-confusable skeletons of the policy's protected domains.
///
/// A skeleton maps every character to its confusable prototype, so two strings
/// that are visually confusable share a skeleton. We index protected domains by
/// skeleton; a candidate host is confusable iff, at some parent-label suffix,
/// its skeleton hits an entry whose domain it is not literally equal to (the
/// real domain must not flag itself).
#[derive(Debug, Default)]
pub struct SkeletonSet {
    /// skeleton(protected domain) -> the protected domain (lowercased Unicode).
    by_skeleton: HashMap<String, String>,
}

impl SkeletonSet {
    pub fn build(protected: Vec<&str>) -> Result<SkeletonSet, ConfigError> {
        let mut by_skeleton = HashMap::new();
        for domain in protected {
            if domain.is_empty() {
                continue;
            }
            // check if domain is host-parsable
            Host::parse(domain).map_err(|e| ConfigError::Parse { path: None, message: e.to_string() })?;
            let (unicode, _) = idna::domain_to_unicode(domain);
            let norm = unicode.to_lowercase();
            if norm.is_empty() {
                continue;
            }
            by_skeleton.insert(skeleton_of(&norm), norm);
        }
        Ok(SkeletonSet { by_skeleton })
    }

    /// True if `host` (Unicode, any case) is confusable with a protected domain
    /// it is not literally equal to. Walks parent labels so a confusable
    /// sub-domain (`login.pаypal.com`) is caught against `paypal.com`.
    pub fn confusable_with(&self, host: &str) -> bool {
        if self.by_skeleton.is_empty() {
            return false;
        }
        let host = host.to_lowercase();
        let mut candidate = host.as_str();
        loop {
            if let Some(protected) = self.by_skeleton.get(&skeleton_of(candidate)) {
                // a skeleton hit on the genuine domain is not a homograph
                return candidate != protected;
            }
            match candidate.split_once('.') {
                Some((_, parent)) => candidate = parent,
                None => return false,
            }
        }
    }
}

/// UTS#39 basic-confusable skeleton of `s` (all confusables mapped to their
/// prototype). Isolated so the crate dependency lives in exactly one place.
fn skeleton_of(s: &str) -> String {
    unicode_security::skeleton(s).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_helper::set_from::SetFrom;

    /// The host reaching [`SkeletonSet::confusable_with`] is always the decoded
    /// Unicode form, exactly like `UrlChecker` produces it from `Host::Domain`.
    fn decoded(host: &str) -> String {
        let (unicode, _) = idna::domain_to_unicode(host);
        unicode
    }

    // genuine domains

    #[test]
    fn a_protected_domain_is_not_confusable_with_itself() {
        let set = SkeletonSet::set_from_list(&["paypal.com"]);
        assert!(!set.confusable_with("paypal.com"));
        assert!(!set.confusable_with("login.paypal.com"));
        assert!(!set.confusable_with("a.b.paypal.com"));
    }

    #[test]
    fn an_unrelated_host_is_not_confusable() {
        let set = SkeletonSet::set_from_list(&["paypal.com"]);
        assert!(!set.confusable_with("example.com"));
        assert!(!set.confusable_with("com"));
        assert!(!set.confusable_with(""));
    }

    // homographs

    #[test]
    fn a_cyrillic_lookalike_is_confusable() {
        // `pаypal.com` with a Cyrillic а (U+0430): same skeleton, different host
        let set = SkeletonSet::set_from_list(&["paypal.com"]);
        assert!(set.confusable_with("p\u{0430}ypal.com"));
    }

    #[test]
    fn a_confusable_label_is_caught_under_a_subdomain() {
        // the full host has no match; the parent-label walk finds the spoof
        let set = SkeletonSet::set_from_list(&["paypal.com"]);
        assert!(set.confusable_with("login.p\u{0430}ypal.com"));
        assert!(set.confusable_with("a.b.p\u{0430}ypal.com"));
    }

    #[test]
    fn confusables_need_no_unicode_at_all() {
        // `rn` is the UTS#39 prototype of `m`: a pure-ASCII homograph
        let set = SkeletonSet::set_from_list(&["microsoft.com"]);
        assert!(set.confusable_with("rnicrosoft.com"));
    }

    #[test]
    fn matching_is_case_insensitive_on_both_alphabets() {
        // `PАYPAL.COM` carries an upper-case Cyrillic А (U+0410)
        let set = SkeletonSet::set_from_list(&["PayPal.com"]);
        assert!(set.confusable_with("P\u{0410}YPAL.COM"));
        assert!(!set.confusable_with("PAYPAL.COM"));
    }

    #[test]
    fn the_walk_goes_up_the_labels_not_down() {
        // `pаypal.com.attacker.net` is a phishing shape, but its confusable
        // label is a *prefix*: only suffixes are registrable, so no match
        let set = SkeletonSet::set_from_list(&["paypal.com"]);
        assert!(!set.confusable_with("p\u{0430}ypal.com.attacker.net"));
    }

    // IDN protected entries

    #[test]
    fn an_idn_entry_indexes_the_same_whichever_way_it_is_spelled() {
        // both spellings decode to `münchen.de`, so both index one skeleton;
        // `rnünchen.de` is its confusable (m -> rn)
        for spelling in ["m\u{00fc}nchen.de", "xn--mnchen-3ya.de"] {
            let set = SkeletonSet::set_from_list(&[spelling]);
            assert!(set.confusable_with(&decoded("xn--rnnchen-o2a.de")));
            assert!(!set.confusable_with("m\u{00fc}nchen.de"));
        }
    }

    #[test]
    fn the_punycode_form_of_a_host_would_never_match() {
        // guards the decode contract: skeletons of the two forms disagree, so
        // a caller passing the raw `xn--` host silently loses every homograph
        let set = SkeletonSet::set_from_list(&["paypal.com"]);
        let ascii = idna::domain_to_ascii("p\u{0430}ypal.com").unwrap();
        assert!(!set.confusable_with(&ascii));
        assert!(set.confusable_with(&decoded(&ascii)));
    }

    // build

    #[test]
    fn an_empty_set_never_flags_anything() {
        let set = SkeletonSet::default();
        assert!(!set.confusable_with("p\u{0430}ypal.com"));
        assert!(!SkeletonSet::set_from_list(&[]).confusable_with("p\u{0430}ypal.com"));
    }

    #[test]
    fn every_entry_is_indexed_independently() {
        let set = SkeletonSet::set_from_list(&["paypal.com", "microsoft.com"]);
        assert!(set.confusable_with("p\u{0430}ypal.com"));
        assert!(set.confusable_with("rnicrosoft.com"));
        assert!(!set.confusable_with("example.com"));
    }

    #[test]
    fn an_empty_entry_is_skipped_not_indexed() {
        let set = SkeletonSet::set_from_list(&["", "paypal.com"]);
        assert!(!set.confusable_with(""));
        assert!(set.confusable_with("p\u{0430}ypal.com"));
    }

    #[test]
    fn undecodable_punycode_fails_the_build() {
        for bad in ["xn--", "xn--a", "xn--0.pt"] {
            assert!(matches!(
                SkeletonSet::build(vec![bad]),
                Err(ConfigError::Parse { .. })
            ));
        }
    }

    #[test]
    fn two_entries_sharing_a_skeleton_collapse_to_the_last_one() {
        // documents the current last-wins `insert`: the surviving entry becomes
        // the reference, so the one it displaced now reads as a spoof
        let set = SkeletonSet::set_from_list(&["paypal.com", "p\u{0430}ypal.com"]);
        assert!(set.confusable_with("paypal.com"));
        assert!(!set.confusable_with("p\u{0430}ypal.com"));
    }
}
