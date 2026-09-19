use crate::error::{Result, write};
use crate::paths::Layout;
use crate::truth::{GroundTruth, Sample, SampleSet};

fn escape(text: &str) -> String {
    text.replace('|', "\\|")
}

fn code_list(values: &[String]) -> String {
    match values.is_empty() {
        true => "&mdash;".to_string(),
        false => values
            .iter()
            .map(|value| format!("`{}`", escape(value)))
            .collect::<Vec<String>>()
            .join(", "),
    }
}

fn benign_table(truth: &GroundTruth) -> String {
    let mut text = String::from(
        "| Page | Origin | Licence | What it carries | Rules allowed to fire |\n|---|---|---|---|---|\n",
    );
    for sample in truth.of(SampleSet::Benign) {
        text.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            escape(&sample.name),
            origin_cell(sample),
            escape(
                sample
                    .licence
                    .as_deref()
                    .unwrap_or("authored for this project")
            ),
            escape(sample.carries.as_deref().unwrap_or("")),
            code_list(&sample.allowed),
        ));
    }
    text
}

fn origin_cell(sample: &Sample) -> String {
    match sample.source.as_deref() {
        Some(url) => {
            let host = url
                .split("://")
                .nth(1)
                .and_then(|rest| rest.split('/').next())
                .unwrap_or(url);
            format!("[{}]({url})", escape(host))
        }
        None => "authored".to_string(),
    }
}

fn malicious_table(truth: &GroundTruth) -> String {
    let mut text = String::from(
        "| Sample | Category | Threat | Expected status | Rules that must fire |\n|---|---|---|---|---|\n",
    );
    let mut samples = truth.of(SampleSet::Malicious);
    samples.sort_by(|a, b| a.category.cmp(&b.category).then(a.name.cmp(&b.name)));
    for sample in samples {
        text.push_str(&format!(
            "| `{}` | {} | {} | {} | {} |\n",
            escape(&sample.name),
            escape(&sample.category),
            escape(sample.describes()),
            code_list(&sample.status),
            code_list(&sample.rules),
        ));
    }
    text
}

pub fn render(truth: &GroundTruth) -> String {
    let benign = truth.of(SampleSet::Benign).len();
    let malicious = truth.of(SampleSet::Malicious).len();
    format!(
        "# Corpus ground truth\n\n\
         Generated from `corpus/ground-truth.toml` by `cargo xtask ground-truth`. \
         Edit the TOML file, never this page.\n\n\
         The corpus holds {benign} benign inputs and {malicious} malicious samples. \
         Most benign pages are real documents retrieved from the public web and stored \
         unmodified, so they carry whatever their publishers put there, including scripts and \
         embeds; the remaining benign inputs are well-formed files of the other types the \
         sanitiser accepts, authored here. A rule firing on a construct an input genuinely \
         contains is a true positive, which is why each benign entry lists the rules its \
         content justifies, and a rule outside that list counts as a false positive. \
         Each malicious sample carries the name of a benign input and is that same document \
         with one threat injected, so the two sets compare like with like.\n\n\
         ## Benign set\n\n{}\n## Malicious set\n\n{}",
        benign_table(truth),
        malicious_table(truth),
    )
}

pub fn save(layout: &Layout, truth: &GroundTruth) -> Result<std::path::PathBuf> {
    let path = layout.result_file("ground-truth.md");
    write(&path, render(truth))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Layout;

    fn truth() -> GroundTruth {
        GroundTruth::load(&Layout::discover().ground_truth()).unwrap()
    }

    #[test]
    fn the_page_names_both_sets_and_their_sizes() {
        let text = render(&truth());
        assert!(text.contains("## Benign set"));
        assert!(text.contains("## Malicious set"));
        assert!(text.contains("benign inputs and"));
    }

    #[test]
    fn every_sample_appears_as_a_row() {
        let truth = truth();
        let text = render(&truth);
        for sample in &truth.samples {
            assert!(text.contains(&sample.name), "{} is missing", sample.name);
        }
    }

    #[test]
    fn a_pipe_in_a_description_cannot_break_the_table() {
        assert_eq!(escape("a|b"), "a\\|b");
    }

    #[test]
    fn an_empty_rule_list_renders_as_a_dash() {
        assert_eq!(code_list(&[]), "&mdash;");
        assert_eq!(code_list(&["a".into()]), "`a`");
    }

    fn page(source: Option<&str>) -> Sample {
        Sample {
            name: "a.html".into(),
            set: SampleSet::Benign,
            category: "reference".into(),
            source: source.map(str::to_string),
            licence: None,
            carries: None,
            threat: None,
            status: vec!["clean".into()],
            rules: Vec::new(),
            allowed: Vec::new(),
            forbidden_rules: Vec::new(),
            forbidden: Vec::new(),
            preserved: Vec::new(),
            output: None,
            max_duration_ms: None,
            fetch: None,
        }
    }

    #[test]
    fn the_origin_column_links_the_host_to_the_page() {
        let cell = origin_cell(&page(Some("https://example.com/a/b")));
        assert_eq!(cell, "[example.com](https://example.com/a/b)");
    }

    #[test]
    fn a_sample_without_a_source_is_marked_authored() {
        assert_eq!(origin_cell(&page(None)), "authored");
    }
}
