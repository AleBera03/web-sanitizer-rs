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

/// What to do when a rule fires (spec TC-9).
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
    /// Replacement value when a URL action is `rewrite`
    pub placeholder_url: String,
}

impl Default for UrlRules {
    fn default() -> Self {
        UrlRules {
            blocklists: Vec::new(),
            protected_domains: Vec::new(),
            action_blocked: Action::Rewrite,
            action_homograph: Action::Rewrite,
            placeholder_url: "#blocked".to_string(),
        }
    }
}

/// Per-input resource budgets (spec TC-8). Exceeding any budget aborts that
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

/// Subresources handling rules
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SubresourcesRules {
    pub fetch_subresources: bool,
    pub sniff_rule: SniffAction,
    pub active_content_rule: ActiveContentAction,
}

impl Default for SubresourcesRules {
    fn default() -> Self {
        SubresourcesRules {
            fetch_subresources: false,
            sniff_rule: SniffAction::Reject,
            active_content_rule: ActiveContentAction::Reject,
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
