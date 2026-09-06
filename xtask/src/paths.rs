use std::path::{Path, PathBuf};

use crate::truth::SampleSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetching {
    Off,
    On,
}

impl Fetching {
    pub const ALL: [Fetching; 2] = [Fetching::Off, Fetching::On];

    pub fn label(self) -> &'static str {
        match self {
            Fetching::Off => "no-fetch",
            Fetching::On => "fetch",
        }
    }

    pub fn enabled(self) -> bool {
        self == Fetching::On
    }

    pub fn parse(text: &str) -> Vec<Fetching> {
        match text {
            "off" | "no-fetch" | "nofetch" => vec![Fetching::Off],
            "on" | "fetch" => vec![Fetching::On],
            _ => Fetching::ALL.to_vec(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Section {
    Benign,
    Malicious,
    Scenarios,
    Compare,
}

impl Section {
    pub fn label(self) -> &'static str {
        match self {
            Section::Benign => "benign",
            Section::Malicious => "malicious",
            Section::Scenarios => "scenarios",
            Section::Compare => "compare",
        }
    }
}

/// Where one run's charts live inside its set: the two the ground truth names
/// are known by their fetching mode, everything else by its own name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RunKind {
    NoFetch,
    Fetch,
    Custom(String),
}

impl RunKind {
    pub fn folder(&self) -> PathBuf {
        match self {
            RunKind::NoFetch => PathBuf::from("no-fetch"),
            RunKind::Fetch => PathBuf::from("fetch"),
            RunKind::Custom(slug) => PathBuf::from("custom").join(slug),
        }
    }

    pub fn fetching(&self) -> Option<Fetching> {
        match self {
            RunKind::NoFetch => Some(Fetching::Off),
            RunKind::Fetch => Some(Fetching::On),
            RunKind::Custom(_) => None,
        }
    }
}

pub fn policy_slug(name: &str) -> String {
    Path::new(name)
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .filter(|stem| !stem.is_empty())
        .unwrap_or_else(|| name.to_string())
}

pub struct Layout {
    root: PathBuf,
}

impl Layout {
    pub fn discover() -> Layout {
        let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| manifest.clone());
        Layout { root }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn join(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    pub fn ground_truth(&self) -> PathBuf {
        self.join("corpus/ground-truth.toml")
    }

    pub fn results(&self) -> PathBuf {
        self.join("eval/results")
    }

    pub fn plots(&self) -> PathBuf {
        self.join("eval/plots")
    }

    pub fn result_file(&self, name: &str) -> PathBuf {
        self.results().join(name)
    }

    pub fn set_dir(&self, set: SampleSet) -> PathBuf {
        self.results().join(set.label())
    }

    pub fn run_dir(&self, set: SampleSet, policy: &str) -> PathBuf {
        self.set_dir(set).join(policy_slug(policy))
    }

    pub fn run_file(&self, set: SampleSet, policy: &str, name: &str) -> PathBuf {
        self.run_dir(set, policy).join(name)
    }

    pub fn scenario_dir(&self) -> PathBuf {
        self.results().join(Section::Scenarios.label())
    }

    pub fn scenario_file(&self, name: &str) -> PathBuf {
        self.scenario_dir().join(name)
    }

    pub fn plot_dir(&self, section: Section) -> PathBuf {
        self.plots().join(section.label())
    }

    pub fn plot_file(&self, section: Section, name: &str) -> PathBuf {
        self.plot_dir(section).join(name)
    }

    // eval/plots/<set>/<no-fetch|fetch|custom/<slug>>
    pub fn run_plot_dir(&self, set: SampleSet, kind: &RunKind) -> PathBuf {
        self.plots().join(set.label()).join(kind.folder())
    }

    // eval/plots/<set>/compare/<plot>
    pub fn compare_plot_dir(&self, set: SampleSet, plot: &str) -> PathBuf {
        self.plots().join(set.label()).join("compare").join(plot)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_is_the_workspace_and_holds_the_corpus() {
        let layout = Layout::discover();
        assert!(layout.join("Cargo.toml").is_file());
        assert!(layout.join("corpus").is_dir());
    }

    #[test]
    fn results_and_plots_sit_under_eval() {
        let layout = Layout::discover();
        assert!(layout.results().ends_with("eval/results"));
        assert!(layout.plots().ends_with("eval/plots"));
        assert!(layout.result_file("a.csv").ends_with("eval/results/a.csv"));
    }

    #[test]
    fn the_ground_truth_is_where_the_corpus_expects_it() {
        let layout = Layout::discover();
        assert!(layout.ground_truth().is_file());
    }

    #[test]
    fn a_run_writes_under_its_set_and_then_its_policy() {
        let layout = Layout::discover();
        let path = layout.run_file(SampleSet::Benign, "corpus/policy-fetch.toml", "latency.csv");
        assert!(
            path.ends_with("eval/results/benign/policy-fetch/latency.csv"),
            "{}",
            path.display()
        );
        let custom = layout.run_dir(SampleSet::Malicious, "corpus/permissive.toml");
        assert!(
            custom.ends_with("eval/results/malicious/permissive"),
            "{}",
            custom.display()
        );
    }

    #[test]
    fn a_policy_name_becomes_a_single_directory_component() {
        assert_eq!(policy_slug("builtin"), "builtin");
        assert_eq!(policy_slug("corpus/policy-fetch.toml"), "policy-fetch");
        assert_eq!(policy_slug("corpus/permissive.toml"), "permissive");
        assert_eq!(policy_slug("scenarios/policy-fetch.toml"), "policy-fetch");
    }

    #[test]
    fn scenarios_and_charts_have_their_own_sections() {
        let layout = Layout::discover();
        assert!(layout.scenario_file("scenarios.csv").ends_with("eval/results/scenarios/scenarios.csv"));
        assert!(
            layout
                .plot_file(Section::Compare, "latency-vs-size.png")
                .ends_with("eval/plots/compare/latency-vs-size.png")
        );
        assert!(
            layout
                .run_plot_dir(SampleSet::Benign, &RunKind::Fetch)
                .ends_with("eval/plots/benign/fetch")
        );
        assert!(
            layout
                .run_plot_dir(SampleSet::Benign, &RunKind::Custom("permissive".into()))
                .ends_with("eval/plots/benign/custom/permissive")
        );
        assert!(
            layout
                .compare_plot_dir(SampleSet::Malicious, "latency")
                .ends_with("eval/plots/malicious/compare/latency")
        );
    }

    #[test]
    fn a_fetch_mode_parses_from_the_command_line() {
        assert_eq!(Fetching::parse("on"), vec![Fetching::On]);
        assert_eq!(Fetching::parse("off"), vec![Fetching::Off]);
        assert_eq!(Fetching::parse("both").len(), 2);
        assert!(!Fetching::Off.enabled());
    }
}
