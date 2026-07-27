use std::collections::HashMap;

use crate::policy::ParseError;

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

    pub fn build(protected: &[&str]) -> Result<SkeletonSet, ParseError> {
        let mut by_skeleton = HashMap::new();
        for domain in protected {
            // index on the Unicode form (lowercased), because `confusable_with`
            // is queried with the decoded Unicode host (`domain_to_unicode`).
            // Indexing on the punycode ASCII form instead would make skeletons
            // of the two sides disagree for IDN protected domains. We still run
            // `domain_to_ascii` first as a validation gate (rejects malformed
            // domains at build time), then discard its ASCII output
            idna::domain_to_ascii(domain).map_err(|e| ParseError::Idna { source: e })?;
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
                // A skeleton hit on the genuine domain is not a homograph.
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


// TODO: test implementation