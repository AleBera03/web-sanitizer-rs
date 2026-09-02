//! Declarative (configuration file based) sanitisation policy.
//!
//! A built-in default policy is compiled in; `--policy <path>` loads a TOML
//! file that overrides it section by section. Unknown keys are a hard error:
//! a typoed policy that silently does nothing is worse than a crash, so we
//! fail fast with exit code 2

pub mod blockset;
pub mod protectedset;

use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// What to do when a rule fires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Remove,
    Placeholder,
    Rewrite,
    Refuse,
    Allow,
}

/// Where a policy came from, for the report's `run.policy` field.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum PolicySource {
    #[default]
    Builtin,
    File(PathBuf),
}

impl fmt::Display for PolicySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PolicySource::Builtin => f.write_str("builtin"),
            PolicySource::File(p) => write!(f, "{}", p.display()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub html: HtmlRules,
    pub urls: UrlRules,
    pub budgets: Budgets,
    pub fetch: FetchPolicy,
    pub input: InputRules,
    pub subresources: SubresourcesRules,
    pub ssrf: SsrfRules,
    #[serde(skip)]
    pub source: PolicySource,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HtmlRules {
    /// Origins allowed for `<script src>`; everything else fires `action_script`.
    pub script_allowlist: Vec<String>,
    /// Origins allowed for `<iframe>`/`<object>`/`<embed>` targets.
    pub frame_origin_allowlist: Vec<String>,
    pub action_script: Action,
    pub action_event_handler: Action,
    pub action_dangerous_scheme: Action,
    pub action_frame: Action,
    pub action_meta_refresh: Action,
    pub placeholder_frame: String,
}

impl Default for HtmlRules {
    fn default() -> Self {
        HtmlRules {
            script_allowlist: Vec::new(),
            frame_origin_allowlist: Vec::new(),
            action_script: Action::Remove,
            action_event_handler: Action::Remove,
            action_dangerous_scheme: Action::Rewrite,
            action_frame: Action::Placeholder,
            action_meta_refresh: Action::Remove,
            placeholder_frame: "<div class=\"sanitized-placeholder\"></div>".to_string(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct UrlRules {
    /// Hosts-style block-list files, loaded and compiled at engine start.
    pub blocklists: Vec<PathBuf>,
    /// Domains checked for homograph confusables.
    pub protected_domains: Vec<String>,
    pub action_blocked: Action,
    pub action_homograph: Action,
    pub action_userinfo: Action,
    pub action_internal: Action,
    pub action_idn: Action,
    pub placeholder_url: String,
}

impl Default for UrlRules {
    fn default() -> Self {
        UrlRules {
            blocklists: Vec::new(),
            protected_domains: Vec::new(),
            action_blocked: Action::Rewrite,
            action_homograph: Action::Rewrite,
            action_userinfo: Action::Rewrite,
            action_internal: Action::Rewrite,
            action_idn: Action::Rewrite,
            placeholder_url: "#blocked".to_string(),
        }
    }
}

/// Per-input resource budgets. Exceeding any budget aborts that
/// input with `budget_exceeded`; the batch continues.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Budgets {
    pub max_input_bytes: u64,
    pub max_time_ms: u64,
    pub max_decompress_ratio: u32,
    pub max_entity_expansions: u32,
    pub max_image_pixels: u64,
}

impl Default for Budgets {
    fn default() -> Self {
        Budgets {
            max_input_bytes: 10 * 1024 * 1024,
            max_time_ms: 10_000,
            max_decompress_ratio: 10,
            max_entity_expansions: 1_000,
            max_image_pixels: 50_000_000,
        }
    }
}

/// Fetch-client limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FetchPolicy {
    pub connect_timeout_ms: u64,
    pub read_timeout_ms: u64,
    pub total_timeout_ms: u64,
    pub redirect_limit: u32,
    pub max_response_bytes: u64,
    pub user_agent: String,
}

impl Default for FetchPolicy {
    fn default() -> Self {
        FetchPolicy {
            connect_timeout_ms: 5_000,
            read_timeout_ms: 5_000,
            total_timeout_ms: 30_000,
            redirect_limit: 5,
            max_response_bytes: 10 * 1024 * 1024,
            user_agent: concat!("web-sanitizer/", env!("CARGO_PKG_VERSION")).to_string(),
        }
    }
}

/// Input-gathering configuration ("configurable set" of extensions).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct InputRules {
    /// File extensions picked up by directory walks, lowercase, no dot.
    pub extensions: Vec<String>,
}

impl Default for InputRules {
    fn default() -> Self {
        InputRules {
            extensions: vec!["html".to_string(), "htm".to_string()],
        }
    }
}

/// Sniff actions for subresources
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SniffAction {
    /// Reject subresources that do not match declared MIME type
    Reject,
    /// Replace extension of subresources that do not match declared MIME type
    Rewrite,
}

/// Active content actions for subresources
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActiveContentAction {
    /// Reject subresources that contain active content
    Reject,
    /// Flag subresources that contain active content, but do not reject them
    Allow,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ZipBudgets {
    pub max_compression_ratio: f64,
    pub max_total_uncompressed_bytes: u64,
    pub max_entry_count: u32,
}

impl Default for ZipBudgets {
    fn default() -> Self {
        ZipBudgets {
            max_compression_ratio: 100.0,
            max_total_uncompressed_bytes: 1024 * 1024 * 1024,
            max_entry_count: 10_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct XmlBudgets {
    pub max_entity_depth: u32,
    pub max_expanded_size: u64,
    pub max_entity_count: u32,
}

impl Default for XmlBudgets {
    fn default() -> Self {
        XmlBudgets {
            max_entity_depth: 20,
            max_expanded_size: 10 * 1024 * 1024,
            max_entity_count: 10_000,
        }
    }
}

/// Rules for subresources that might be prone to DOS attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DosDetectedAction {
    /// Reject subresources that contain DOS risks
    Reject,
    /// Truncates subresources that contain DOS risks if possible
    Truncate,
}

/// Kinds of reference the sub-resource loop is allowed to fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubresourceType {
    Css,
    Js,
    Image,
}

/// Subresources handling rules. Fetching is off by default: the
/// project brief calls it optional, and optional means the user asks for it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]

pub struct SubresourcesRules {
    pub fetch_subresources: bool,
    /// Zero disables the loop entirely. Any other value fetches at depth 1
    /// only: a fetched sub-resource has its own references inspected, never
    /// followed.
    pub max_depth: u32,
    /// Requests per parent input.
    pub max_requests: u32,
    /// Bytes summed over every sub-resource of one parent input.
    pub max_total_bytes: u64,
    pub types: Vec<SubresourceType>,
    pub sniff_rule: SniffAction,
    pub active_content_rule: ActiveContentAction,
    pub zip_budget: ZipBudgets,
    pub xml_budget: XmlBudgets,
    pub dos_risk_rule: DosDetectedAction,
    /// Point the sanitised parent at the local sanitised copies.
    pub rewrite_refs: bool,
    /// What happens to the reference of a sub-resource that was refused.
    pub action_refused: Action,
}

impl Default for SubresourcesRules {
    fn default() -> Self {
        SubresourcesRules {
            fetch_subresources: false,
            max_depth: 1,
            max_requests: 32,
            max_total_bytes: 50 * 1024 * 1024,
            types: vec![
                SubresourceType::Css,
                SubresourceType::Js,
                SubresourceType::Image,
            ],
            sniff_rule: SniffAction::Reject,
            active_content_rule: ActiveContentAction::Reject,
            zip_budget: ZipBudgets::default(),
            xml_budget: XmlBudgets::default(),
            dos_risk_rule: DosDetectedAction::Reject,
            rewrite_refs: true,
            action_refused: Action::Rewrite,
        }
    }
}

/// Which requests the SSRF guard applies to when the URL is the *input* rather
/// than something a document asked for (spec T-11.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuardScope {
    /// The user's own URL is never second-guessed.
    Never,
    /// Guarded only in server mode, where the URL arrives from a caller.
    Server,
    Always,
}

/// SSRF guard configuration. The guard itself is always on;
/// what stays configurable is its scope over input URLs and the narrow
/// exemptions below.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SsrfRules {
    pub guard_input_urls: GuardScope,
    /// A sub-resource served by the parent's own endpoint stays reachable.
    pub same_origin_exemption: bool,
    /// Hosts or CIDRs that bypass the deny table; compiled at engine start.
    pub allow_hosts: Vec<String>,
    /// Site-specific CIDRs added to the built-in deny table.
    pub deny_extra: Vec<String>,
    /// Freshness of a positive resolve verdict. Denies never expire.
    pub allow_ttl_ms: u64,
}

impl Default for SsrfRules {
    fn default() -> Self {
        SsrfRules {
            guard_input_urls: GuardScope::Server,
            same_origin_exemption: true,
            allow_hosts: Vec::new(),
            deny_extra: Vec::new(),
            allow_ttl_ms: 30_000,
        }
    }
}

fn fmt_path(path: &Option<PathBuf>) -> String {
    match path {
        Some(p) => p.display().to_string(),
        None => "".to_string(),
    }
}

fn fmt_line(line: &Option<usize>) -> String {
    match line {
        Some(l) => format!(":{l}"),
        None => String::new(),
    }
}

#[derive(Error, Debug)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Io { path: PathBuf, source: io::Error },

    #[error("invalid policy{}: {message}", fmt_path(path))]
    Parse {
        path: Option<PathBuf>,
        message: String,
    },

    #[error("invalid block-list {path} {}: {message}", fmt_line(line))]
    Blocklist {
        path: PathBuf,
        line: Option<usize>,
        message: String,
    },

    #[error("invalid ssrf.{field} entry `{entry}`: {message}")]
    Ssrf {
        field: &'static str,
        entry: String,
        message: String,
    },
}

impl Policy {
    /// The compiled-in default policy.
    pub fn builtin() -> Policy {
        Policy::default()
    }

    /// Load a policy from a TOML file. Missing sections fall back to the
    /// builtin defaults; unknown keys are rejected.
    pub fn load(path: &Path) -> Result<Policy, ConfigError> {
        let text = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let mut policy: Policy = toml::from_str(&text).map_err(|e| ConfigError::Parse {
            path: Some(path.to_path_buf()),
            message: e.to_string(),
        })?;
        policy.source = PolicySource::File(path.to_path_buf());
        Ok(policy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_defaults_match_spec_tc8() {
        let p = Policy::builtin();
        assert_eq!(p.budgets.max_input_bytes, 10 * 1024 * 1024);
        assert_eq!(p.budgets.max_time_ms, 10_000);
        assert_eq!(p.budgets.max_decompress_ratio, 10);
        assert_eq!(p.budgets.max_entity_expansions, 1_000);
        assert_eq!(p.budgets.max_image_pixels, 50_000_000);
        assert_eq!(p.fetch.redirect_limit, 5);
        assert_eq!(p.fetch.connect_timeout_ms, 5_000);
        assert_eq!(p.fetch.read_timeout_ms, 5_000);
        assert_eq!(p.fetch.total_timeout_ms, 30_000);
        assert_eq!(p.urls.placeholder_url, "#blocked");
        assert_eq!(p.input.extensions, ["html", "htm"]);
        assert_eq!(p.source, PolicySource::Builtin);
    }

    #[test]
    fn subresource_and_ssrf_defaults_match_spec_tc10_tc11() {
        let p = Policy::builtin();
        assert!(!p.subresources.fetch_subresources); // opt-in, never assumed
        assert_eq!(p.subresources.max_depth, 1);
        assert_eq!(p.subresources.max_requests, 32);
        assert_eq!(p.subresources.max_total_bytes, 50 * 1024 * 1024);
        assert_eq!(
            p.subresources.types,
            [
                SubresourceType::Css,
                SubresourceType::Js,
                SubresourceType::Image
            ]
        );
        assert!(p.subresources.rewrite_refs);
        assert_eq!(p.subresources.action_refused, Action::Rewrite);

        assert_eq!(p.ssrf.guard_input_urls, GuardScope::Server);
        assert!(p.ssrf.same_origin_exemption);
        assert_eq!(p.ssrf.allow_ttl_ms, 30_000);
        assert!(p.ssrf.allow_hosts.is_empty());
        assert!(p.ssrf.deny_extra.is_empty());
    }

    #[test]
    fn ssrf_section_is_configurable_from_toml() {
        let p: Policy = toml::from_str(
            r#"
            [ssrf]
            guard_input_urls = "always"
            allow_hosts = ["intranet.local", "10.1.0.0/16"]
            allow_ttl_ms = 1000

            [subresources]
            fetch_subresources = true
            types = ["css"]
            "#,
        )
        .unwrap();
        assert_eq!(p.ssrf.guard_input_urls, GuardScope::Always);
        assert_eq!(p.ssrf.allow_hosts, ["intranet.local", "10.1.0.0/16"]);
        assert_eq!(p.ssrf.allow_ttl_ms, 1_000);
        assert!(p.subresources.fetch_subresources);
        assert_eq!(p.subresources.types, [SubresourceType::Css]);
        // untouched keys keep their defaults
        assert_eq!(p.subresources.max_requests, 32);
        assert!(p.ssrf.same_origin_exemption);
    }

    #[test]
    fn unknown_guard_scope_is_rejected() {
        assert!(toml::from_str::<Policy>("[ssrf]\nguard_input_urls = \"sometimes\"\n").is_err());
    }

    #[test]
    fn partial_toml_overrides_only_named_keys() {
        let p: Policy = toml::from_str(
            r#"
            [budgets]
            max_input_bytes = 42

            [html]
            action_script = "refuse"
            "#,
        )
        .unwrap();
        assert_eq!(p.budgets.max_input_bytes, 42);
        assert_eq!(p.budgets.max_time_ms, 10_000); // untouched default
        assert_eq!(p.html.action_script, Action::Refuse);
        assert_eq!(p.html.action_frame, Action::Placeholder); // untouched default
    }

    #[test]
    fn unknown_key_is_rejected() {
        // error by "bytez" rather than "bytes"
        let err = toml::from_str::<Policy>("[budgets]\nmax_input_bytez = 1\n").unwrap_err();
        assert!(err.to_string().contains("max_input_bytez"));
    }

    #[test]
    fn bad_action_value_is_rejected() {
        // obliterate does not exist
        assert!(toml::from_str::<Policy>("[html]\naction_script = \"obliterate\"\n").is_err());
    }

    #[test]
    fn load_missing_file_is_io_error() {
        let err = Policy::load(Path::new("/nonexistent/policy.toml")).unwrap_err();
        assert!(matches!(err, ConfigError::Io { .. }));
    }

    #[test]
    fn load_sets_source_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.toml");
        fs::write(&path, "[budgets]\nmax_time_ms = 5\n").unwrap();
        let p = Policy::load(&path).unwrap();
        assert_eq!(p.source, PolicySource::File(path));
        assert_eq!(p.budgets.max_time_ms, 5);
    }
}
