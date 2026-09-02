use std::sync::LazyLock;

use crate::html::sanitize_html;
use crate::netaddr::IpDenyTable;
use crate::policy::protectedset::SkeletonSet;
use crate::policy::{HtmlRules, UrlRules, blockset::BlockSet};
use crate::report::SanitisationAction;
use crate::urlcheck::UrlChecker;
use crate::urlcheck::cache::VerdictCache;

static EMPTY_BLOCKSET: LazyLock<BlockSet> = LazyLock::new(BlockSet::default);
static EMPTY_SKELETONSET: LazyLock<SkeletonSet> = LazyLock::new(SkeletonSet::default);
static BUILTIN_ADDRESSES: LazyLock<IpDenyTable> = LazyLock::new(IpDenyTable::builtin);
static DEFAULT_VERDICTCACHE: LazyLock<VerdictCache> = LazyLock::new(VerdictCache::default);
static NEUTRAL_URL_RULES: LazyLock<UrlRules> = LazyLock::new(UrlRules::default);

/// Detection-only pass: uses maximally restrictive rules (no allow-lists),
/// so any script/handler/dangerous-scheme construct is flagged regardless
/// of the caller's actual policy
pub fn svg_has_active_content(data: &[u8]) -> Vec<SanitisationAction> {
    let rules = HtmlRules::default();
    let checker = UrlChecker::new(
        &EMPTY_BLOCKSET,
        &EMPTY_SKELETONSET,
        &BUILTIN_ADDRESSES,
        &DEFAULT_VERDICTCACHE,
        &NEUTRAL_URL_RULES,
    );

    sanitize_html(data, &rules, &checker)
        .actions
        .into_iter()
        .filter(|a| a.category == "xss")
        .collect()
}

pub fn sanitize_svg(data: &[u8]) -> Vec<u8> {
    let rules = HtmlRules::default();
    let checker = UrlChecker::new(
        &EMPTY_BLOCKSET,
        &EMPTY_SKELETONSET,
        &BUILTIN_ADDRESSES,
        &DEFAULT_VERDICTCACHE,
        &NEUTRAL_URL_RULES,
    );
    sanitize_html(data, &rules, &checker).output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_svg_produces_no_actions() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><circle r="5"/></svg>"#;
        assert!(svg_has_active_content(svg).is_empty());
    }

    #[test]
    fn svg_with_inline_script_is_detected() {
        let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
        let actions = svg_has_active_content(svg);
        assert!(!actions.is_empty());
        assert!(actions.iter().all(|a| a.category == "xss"));
    }

    #[test]
    fn svg_with_event_handler_is_detected() {
        let svg = br#"<svg onload="alert(1)" xmlns="http://www.w3.org/2000/svg"></svg>"#;
        let actions = svg_has_active_content(svg);
        assert!(!actions.is_empty());
    }
}
