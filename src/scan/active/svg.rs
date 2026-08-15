use std::sync::LazyLock;

use crate::html::sanitize_html;
use crate::policy::protectedset::SkeletonSet;
use crate::policy::{HtmlRules, UrlRules, blockset::BlockSet};
use crate::report::SanitisationAction;
use crate::urlcheck::UrlChecker;
use crate::urlcheck::cache::VerdictCache;

static EMPTY_BLOCKSET: LazyLock<BlockSet> = LazyLock::new(BlockSet::default);
static EMPTY_SKELETONSET: LazyLock<SkeletonSet> = LazyLock::new(SkeletonSet::default);
static DEFAULT_VERDICTCACHE: LazyLock<VerdictCache> = LazyLock::new(VerdictCache::default);
static NEUTRAL_URL_RULES: LazyLock<UrlRules> = LazyLock::new(UrlRules::default);

/// Detection-only pass: uses maximally restrictive rules (no allow-lists),
/// so any script/handler/dangerous-scheme construct is flagged regardless
/// of the caller's actual policy. Presence, not policy decision.
pub fn svg_has_active_content(data: &[u8]) -> Vec<SanitisationAction> {
    let rules = HtmlRules::default();
    let checker = UrlChecker::new(
        &EMPTY_BLOCKSET,
        &EMPTY_SKELETONSET,
        &DEFAULT_VERDICTCACHE,
        &NEUTRAL_URL_RULES,
    );

    sanitize_html(data, &rules, &checker)
        .actions
        .into_iter()
        .filter(|a| a.category == "xss")
        .collect()
}
