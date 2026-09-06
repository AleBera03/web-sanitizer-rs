use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Result, XtaskError, read_to_string};
use crate::paths::Fetching;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SampleSet {
    Benign,
    Malicious,
}

impl SampleSet {
    pub fn label(self) -> &'static str {
        match self {
            SampleSet::Benign => "benign",
            SampleSet::Malicious => "malicious",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Corpus {
    pub benign_dir: String,
    pub malicious_dir: String,
    pub policy_nofetch: String,
    pub policy_fetch: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Sample {
    pub name: String,
    pub set: SampleSet,
    pub category: String,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub licence: Option<String>,
    #[serde(default)]
    pub carries: Option<String>,
    #[serde(default)]
    pub threat: Option<String>,
    pub status: Vec<String>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub forbidden_rules: Vec<String>,
    #[serde(default)]
    pub forbidden: Vec<String>,
    #[serde(default)]
    pub preserved: Vec<String>,
    #[serde(default)]
    pub output: Option<bool>,
    #[serde(default)]
    pub max_duration_ms: Option<u64>,
    #[serde(default)]
    pub fetch: Option<FetchExpectation>,
}

// what fetching adds for this sample. Absent means the no-fetch expectations
// hold unchanged once sub-resources are being requested.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct FetchExpectation {
    #[serde(default)]
    pub status: Vec<String>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub allowed: Vec<String>,
    #[serde(default)]
    pub forbidden: Vec<String>,
    #[serde(default)]
    #[allow(dead_code)]
    pub max_subresources: Option<usize>,
}

impl Sample {
    pub fn expects_output(&self) -> bool {
        self.output.unwrap_or(true)
    }

    /// Rules whose firing is accounted for by the ground truth. Anything
    /// outside this set is an unexpected action on that sample.
    pub fn justified(&self) -> Vec<String> {
        let mut all = self.rules.clone();
        all.extend(self.allowed.iter().cloned());
        all
    }

    pub fn describes(&self) -> &str {
        self.threat
            .as_deref()
            .or(self.carries.as_deref())
            .unwrap_or("")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GroundTruth {
    pub corpus: Corpus,
    #[serde(rename = "sample")]
    pub samples: Vec<Sample>,
}

impl GroundTruth {
    pub fn load(path: &Path) -> Result<GroundTruth> {
        let text = read_to_string(path)?;
        toml::from_str(&text).map_err(|source| XtaskError::Toml {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn of(&self, set: SampleSet) -> Vec<&Sample> {
        self.samples.iter().filter(|s| s.set == set).collect()
    }

    pub fn find(&self, set: SampleSet, name: &str) -> Result<&Sample> {
        self.samples
            .iter()
            .find(|s| s.set == set && s.name == name)
            .ok_or_else(|| XtaskError::UnknownSample {
                name: name.to_string(),
            })
    }

    // the statuses and rules that hold for one sample in one fetching mode
    pub fn expectation(sample: &Sample, fetching: bool) -> (Vec<String>, Vec<String>, Vec<String>, Vec<String>) {
        let extra = match fetching {
            true => sample.fetch.clone().unwrap_or_default(),
            false => FetchExpectation::default(),
        };
        let status = match extra.status.is_empty() {
            true => sample.status.clone(),
            false => extra.status,
        };
        let mut rules = sample.rules.clone();
        rules.extend(extra.rules);
        let mut justified = sample.justified();
        justified.extend(extra.allowed);
        let mut forbidden = sample.forbidden.clone();
        forbidden.extend(extra.forbidden);
        (status, rules, justified, forbidden)
    }

    // fetching is a property of the policy, so each mode names its own file
    pub fn policy(&self, fetching: Fetching) -> &str {
        match fetching {
            Fetching::Off => &self.corpus.policy_nofetch,
            Fetching::On => &self.corpus.policy_fetch,
        }
    }

    pub fn default_policies(&self) -> [&str; 2] {
        [&self.corpus.policy_nofetch, &self.corpus.policy_fetch]
    }

    pub fn directory(&self, set: SampleSet) -> &str {
        match set {
            SampleSet::Benign => &self.corpus.benign_dir,
            SampleSet::Malicious => &self.corpus.malicious_dir,
        }
    }

    /// Every sample named by the ground truth must exist on disk, and every
    /// file in either directory must be named by the ground truth.
    pub fn agree_with_disk(&self, root: &Path, extra: &[&str]) -> Result<()> {
        for set in [SampleSet::Benign, SampleSet::Malicious] {
            let dir = root.join(self.directory(set));
            for sample in self.of(set) {
                if !dir.join(&sample.name).exists() {
                    return Err(XtaskError::MissingSample {
                        name: sample.name.clone(),
                        dir: dir.clone(),
                    });
                }
            }
            let entries = std::fs::read_dir(&dir).map_err(|source| XtaskError::Read {
                path: dir.clone(),
                source,
            })?;
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if entry.path().is_file() && !extra.contains(&name.as_str()) {
                    self.find(set, &name)?;
                }
            }
        }
        Ok(())
    }

    pub fn paths(&self, root: &Path, set: SampleSet) -> Vec<(PathBuf, &Sample)> {
        let dir = root.join(self.directory(set));
        let mut found: Vec<(PathBuf, &Sample)> = self
            .of(set)
            .into_iter()
            .map(|sample| (dir.join(&sample.name), sample))
            .collect();
        found.sort_by(|a, b| a.0.cmp(&b.0));
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Layout;

    fn truth() -> GroundTruth {
        GroundTruth::load(&Layout::discover().ground_truth()).unwrap()
    }

    #[test]
    fn the_checked_in_ground_truth_parses() {
        let truth = truth();
        assert!(truth.samples.len() >= 40);
        assert_eq!(truth.corpus.benign_dir, "corpus/benign");
        assert_eq!(truth.policy(Fetching::Off), "corpus/policy-nofetch.toml");
        assert_eq!(truth.policy(Fetching::On), "corpus/policy-fetch.toml");
    }

    #[test]
    fn the_benign_set_meets_the_twenty_page_floor() {
        assert!(truth().of(SampleSet::Benign).len() >= 20);
    }

    #[test]
    fn every_malicious_sample_states_a_threat() {
        for sample in truth().of(SampleSet::Malicious) {
            assert!(
                sample.threat.is_some(),
                "{} has no threat description",
                sample.name
            );
        }
    }

    #[test]
    fn every_benign_sample_states_where_it_came_from() {
        for sample in truth().of(SampleSet::Benign) {
            assert!(sample.licence.is_some(), "{} has no licence", sample.name);
            if sample.name.ends_with(".html") {
                assert!(sample.source.is_some(), "{} has no source", sample.name);
            }
        }
    }

    #[test]
    fn every_malicious_sample_is_the_twin_of_a_benign_one() {
        let truth = truth();
        for sample in truth.of(SampleSet::Malicious) {
            assert!(
                truth.find(SampleSet::Benign, &sample.name).is_ok(),
                "{} has no benign original",
                sample.name
            );
        }
    }

    #[test]
    fn a_benign_sample_never_requires_a_rule_to_fire() {
        for sample in truth().of(SampleSet::Benign) {
            assert!(
                sample.rules.is_empty(),
                "{} demands a detection but is benign",
                sample.name
            );
        }
    }

    #[test]
    fn every_malicious_sample_requires_a_rule_or_says_why_not() {
        for sample in truth().of(SampleSet::Malicious) {
            let unruled = matches!(
                sample.category.as_str(),
                "robustness" | "dos" | "mime-confusion" | "xss"
            );
            assert!(
                !sample.rules.is_empty() || unruled,
                "{} requires no rule and is not a robustness case",
                sample.name
            );
        }
    }

    #[test]
    fn names_are_unique_within_a_set() {
        let truth = truth();
        for set in [SampleSet::Benign, SampleSet::Malicious] {
            let mut names: Vec<&str> = truth.of(set).iter().map(|s| s.name.as_str()).collect();
            names.sort();
            let count = names.len();
            names.dedup();
            assert_eq!(names.len(), count, "duplicate name in {}", set.label());
        }
    }

    #[test]
    fn the_ground_truth_and_the_directories_agree() {
        let layout = Layout::discover();
        truth()
            .agree_with_disk(layout.root(), &["blocklist.txt"])
            .unwrap();
    }

    #[test]
    fn justified_merges_required_and_allowed_rules() {
        let sample = Sample {
            name: "x".into(),
            set: SampleSet::Malicious,
            category: "xss".into(),
            source: None,
            licence: None,
            carries: None,
            threat: Some("t".into()),
            status: vec!["sanitised".into()],
            rules: vec!["a".into()],
            allowed: vec!["b".into()],
            forbidden_rules: Vec::new(),
            forbidden: Vec::new(),
            preserved: Vec::new(),
            output: None,
            max_duration_ms: None,
            fetch: None,
        };
        assert_eq!(sample.justified(), vec!["a".to_string(), "b".to_string()]);
        assert!(sample.expects_output());
    }

    #[test]
    fn an_unknown_name_is_an_error_that_names_it() {
        let error = truth().find(SampleSet::Malicious, "not-in-the-corpus.html").unwrap_err();
        assert!(error.to_string().contains("not-in-the-corpus.html"));
    }
}
