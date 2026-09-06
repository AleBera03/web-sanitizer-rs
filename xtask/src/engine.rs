use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use web_sanitizer::Engine;
use web_sanitizer::fetch::HttpFetcher;
use web_sanitizer::input::InputSource;
use web_sanitizer::policy::Policy;
use web_sanitizer::report::InputStatus;

use crate::error::{Result, XtaskError};

pub const BUILTIN: &str = "builtin";

pub fn policy(root: &Path, name: &str) -> Result<Policy> {
    match name {
        BUILTIN => Ok(Policy::builtin()),
        relative => {
            let path = root.join(relative);
            let mut policy =
                Policy::load(&path).map_err(|source| XtaskError::Policy { path, source })?;
            for list in policy.urls.blocklists.iter_mut() {
                if list.is_relative() {
                    *list = root.join(&*list);
                }
            }
            Ok(policy)
        }
    }
}

pub fn declared_fetching(root: &Path, name: &str) -> Result<crate::paths::Fetching> {
    let policy = self::policy(root, name)?;
    Ok(match policy.subresources.fetch_subresources {
        true => crate::paths::Fetching::On,
        false => crate::paths::Fetching::Off,
    })
}

pub fn engine(policy: Policy) -> Result<Engine> {
    let fetcher = Arc::new(
        HttpFetcher::new(&policy.fetch, &policy.ssrf).map_err(|source| XtaskError::Policy {
            path: std::path::PathBuf::from("<fetch client>"),
            source,
        })?,
    );
    Engine::new(policy, fetcher).map_err(|source| XtaskError::Policy {
        path: std::path::PathBuf::from("<engine>"),
        source,
    })
}

pub struct Processed {
    pub status: InputStatus,
    pub rules: Vec<String>,
    pub output: Option<Vec<u8>>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub elapsed: Duration,
}

impl Processed {
    pub fn status_label(&self) -> String {
        serde_json::to_value(self.status)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_else(|| "unknown".to_string())
    }

    pub fn fired(&self, rule: &str) -> bool {
        self.rules.iter().any(|fired| fired == rule)
    }

    /// Rules that fired and are not accounted for by the given list.
    pub fn beyond(&self, justified: &[String]) -> Vec<String> {
        let mut extra: Vec<String> = self
            .rules
            .iter()
            .filter(|rule| !justified.contains(rule))
            .cloned()
            .collect();
        extra.sort();
        extra.dedup();
        extra
    }

    pub fn distinct_rules(&self) -> Vec<String> {
        let mut rules = self.rules.clone();
        rules.sort();
        rules.dedup();
        rules
    }
}

pub fn process(engine: &Engine, path: &Path) -> Processed {
    let started = Instant::now();
    let outcome = engine.process(InputSource::File(path.to_path_buf()));
    let elapsed = started.elapsed();
    let report = outcome.report;
    Processed {
        status: report.status,
        rules: report
            .actions
            .iter()
            .map(|action| action.rule_id.clone())
            .collect(),
        bytes_in: report.bytes_in,
        bytes_out: report.bytes_out,
        output: outcome.sanitized,
        elapsed,
    }
}

pub fn process_source(engine: &Engine, source: InputSource) -> Processed {
    let started = Instant::now();
    let outcome = engine.process(source);
    let elapsed = started.elapsed();
    let report = outcome.report;
    Processed {
        status: report.status,
        rules: report
            .actions
            .iter()
            .map(|action| action.rule_id.clone())
            .collect(),
        bytes_in: report.bytes_in,
        bytes_out: report.bytes_out,
        output: outcome.sanitized,
        elapsed,
    }
}

pub fn process_bytes(engine: &Engine, name: &str, data: Vec<u8>) -> Processed {
    let started = Instant::now();
    let outcome = engine.process(InputSource::Bytes {
        name: name.to_string(),
        data,
    });
    let elapsed = started.elapsed();
    let report = outcome.report;
    Processed {
        status: report.status,
        rules: report
            .actions
            .iter()
            .map(|action| action.rule_id.clone())
            .collect(),
        bytes_in: report.bytes_in,
        bytes_out: report.bytes_out,
        output: outcome.sanitized,
        elapsed,
    }
}

/// Case-insensitive search over the output, which may be any byte string.
pub fn output_contains(output: Option<&Vec<u8>>, marker: &str) -> bool {
    match output {
        None => false,
        Some(bytes) => String::from_utf8_lossy(bytes)
            .to_lowercase()
            .contains(&marker.to_lowercase()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Layout;

    #[test]
    fn the_builtin_name_loads_without_touching_the_disk() {
        let layout = Layout::discover();
        let loaded = policy(layout.root(), BUILTIN).unwrap();
        assert_eq!(
            loaded.source.to_string(),
            Policy::builtin().source.to_string()
        );
    }

    #[test]
    fn a_relative_name_loads_the_corpus_policy() {
        let layout = Layout::discover();
        let loaded = policy(layout.root(), "corpus/policy-fetch.toml").unwrap();
        assert!(!loaded.urls.protected_domains.is_empty());
    }

    #[test]
    fn block_list_paths_are_anchored_to_the_repository_rather_than_the_caller() {
        let layout = Layout::discover();
        let loaded = policy(layout.root(), "corpus/policy-fetch.toml").unwrap();
        for list in &loaded.urls.blocklists {
            assert!(list.is_absolute(), "{} stayed relative", list.display());
            assert!(list.is_file(), "{} does not resolve", list.display());
        }
    }

    #[test]
    fn a_policy_file_states_its_own_fetching_mode() {
        let layout = Layout::discover();
        assert_eq!(
            declared_fetching(layout.root(), "corpus/policy-fetch.toml").unwrap(),
            crate::paths::Fetching::On
        );
        assert_eq!(
            declared_fetching(layout.root(), "corpus/policy-nofetch.toml").unwrap(),
            crate::paths::Fetching::Off
        );
        assert_eq!(
            declared_fetching(layout.root(), "corpus/permissive.toml").unwrap(),
            crate::paths::Fetching::Off
        );
    }

    #[test]
    fn a_missing_policy_names_the_file_it_looked_for() {
        let layout = Layout::discover();
        let error = policy(layout.root(), "corpus/absent.toml").unwrap_err();
        assert!(error.to_string().contains("absent.toml"));
    }

    #[test]
    fn a_script_page_is_sanitised_and_reports_its_rule() {
        let layout = Layout::discover();
        let engine = engine(policy(layout.root(), BUILTIN).unwrap()).unwrap();
        let done = process_bytes(
            &engine,
            "t.html",
            b"<!DOCTYPE html><html><body><script>alert(1)</script></body></html>".to_vec(),
        );
        assert_eq!(done.status_label(), "sanitised");
        assert!(done.fired("html.script.disallowed"));
        assert!(!output_contains(done.output.as_ref(), "<script"));
    }

    #[test]
    fn a_plain_page_stays_clean_and_fires_nothing() {
        let layout = Layout::discover();
        let engine = engine(policy(layout.root(), BUILTIN).unwrap()).unwrap();
        let done = process_bytes(
            &engine,
            "t.html",
            b"<!DOCTYPE html><html><body><p>hello</p></body></html>".to_vec(),
        );
        assert_eq!(done.status_label(), "clean");
        assert!(done.rules.is_empty());
        assert!(output_contains(done.output.as_ref(), "hello"));
    }

    #[test]
    fn beyond_lists_only_the_rules_the_ground_truth_does_not_cover() {
        let done = Processed {
            status: InputStatus::Sanitised,
            rules: vec!["a".into(), "b".into(), "b".into(), "c".into()],
            output: None,
            bytes_in: 0,
            bytes_out: 0,
            elapsed: Duration::ZERO,
        };
        assert_eq!(done.beyond(&["a".to_string()]), vec!["b", "c"]);
        assert_eq!(done.distinct_rules(), vec!["a", "b", "c"]);
    }

    #[test]
    fn a_marker_search_ignores_case_and_survives_binary_output() {
        let bytes = vec![
            0x89, b'P', b'N', b'G', b'<', b'S', b'c', b'R', b'i', b'p', b't',
        ];
        assert!(output_contains(Some(&bytes), "<script"));
        assert!(!output_contains(None, "<script"));
    }
}
