use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::engine::{self, Processed};
use crate::error::{Result, XtaskError, read};
use crate::paths::{Fetching, Layout, policy_slug};
use crate::served::Origin;
use crate::table;
use crate::truth::{GroundTruth, Sample, SampleSet};

#[derive(Debug, Clone, Copy)]
pub struct Run<'a> {
    pub set: SampleSet,
    pub policy: &'a str,
    pub fetching: Fetching,
}

impl Run<'_> {
    pub fn label(&self) -> String {
        format!(
            "{} / {} ({})",
            self.set.label(),
            policy_slug(self.policy),
            self.fetching.label()
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Detected,
    Mislabelled,
    Missed,
    Leaked,
    Clean,
    FalsePositive,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Detected => "detected",
            Verdict::Mislabelled => "mislabelled",
            Verdict::Missed => "missed",
            Verdict::Leaked => "leaked",
            Verdict::Clean => "clean",
            Verdict::FalsePositive => "false_positive",
        }
    }

    fn is_failure(self) -> bool {
        matches!(
            self,
            Verdict::Missed | Verdict::Leaked | Verdict::FalsePositive | Verdict::Mislabelled
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct SampleRow {
    pub set: String,
    pub fetching: String,
    pub category: String,
    pub name: String,
    pub policy: String,
    pub status: String,
    pub status_expected: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub duration_us: u128,
    pub fired: String,
    pub missing: String,
    pub unexpected: String,
    pub leaked: String,
    pub lost: String,
    pub verdict: String,
}

#[derive(Serialize, Deserialize)]
pub struct RuleRow {
    pub rule: String,
    pub expected: usize,
    pub fired: usize,
    pub true_positive: usize,
    pub false_negative: usize,
    pub false_positive: usize,
    pub precision: String,
    pub recall: String,
}

#[derive(Serialize, Deserialize)]
pub struct SummaryRow {
    pub metric: String,
    pub set: String,
    pub numerator: usize,
    pub denominator: usize,
    pub rate: String,
}

/// One sample measured against its ground-truth entry.
struct Measured {
    sample_name: String,
    category: String,
    set: SampleSet,
    status: String,
    status_ok: bool,
    missing: Vec<String>,
    unexpected: Vec<String>,
    leaked: Vec<String>,
    lost: Vec<String>,
    fired: Vec<String>,
    expected_rules: Vec<String>,
    output_ok: bool,
    duration_us: u128,
    bytes_in: u64,
    bytes_out: u64,
}

impl Measured {
    fn neutralised(&self) -> bool {
        self.status_ok && self.output_ok && self.leaked.is_empty()
    }

    fn rules_named(&self) -> bool {
        self.missing.is_empty()
    }

    fn verdict(&self) -> Verdict {
        match self.set {
            SampleSet::Malicious => match (self.neutralised(), self.rules_named()) {
                (true, true) => Verdict::Detected,
                (true, false) => Verdict::Mislabelled,
                (false, _) if !self.leaked.is_empty() => Verdict::Leaked,
                (false, _) => Verdict::Missed,
            },
            SampleSet::Benign => match self.unexpected.is_empty() && self.lost.is_empty() {
                true => Verdict::Clean,
                false => Verdict::FalsePositive,
            },
        }
    }
}

fn measure(sample: &Sample, done: &Processed, fetching: bool) -> Measured {
    let (accepted_status, required, justified, forbidden) =
        GroundTruth::expectation(sample, fetching);
    let status = done.status_label();
    let status_ok = accepted_status.contains(&status);
    let missing: Vec<String> = required
        .iter()
        .filter(|rule| !done.fired(rule))
        .cloned()
        .collect();
    let mut unexpected = done.beyond(&justified);
    for rule in &sample.forbidden_rules {
        if done.fired(rule) && !unexpected.contains(rule) {
            unexpected.push(rule.clone());
        }
    }
    let leaked: Vec<String> = forbidden
        .iter()
        .filter(|marker| engine::output_contains(done.output.as_ref(), marker))
        .cloned()
        .collect();
    let lost: Vec<String> = sample
        .preserved
        .iter()
        .filter(|marker| !engine::output_contains(done.output.as_ref(), marker))
        .cloned()
        .collect();
    let output_ok = done.output.is_some() == sample.expects_output();
    if let Some(limit) = sample.max_duration_ms {
        let taken = done.elapsed.as_millis();
        if taken > limit as u128 {
            unexpected.push(format!("took {taken} ms, budget is {limit} ms"));
        }
    }

    Measured {
        sample_name: sample.name.clone(),
        category: sample.category.clone(),
        set: sample.set,
        status,
        status_ok,
        missing,
        unexpected,
        leaked,
        lost,
        fired: done.distinct_rules(),
        expected_rules: required,
        output_ok,
        duration_us: done.elapsed.as_micros(),
        bytes_in: done.bytes_in,
        bytes_out: done.bytes_out,
    }
}

fn row(measured: &Measured, sample: &Sample, policy: &str, fetching: Fetching) -> SampleRow {
    SampleRow {
        set: measured.set.label().to_string(),
        fetching: fetching.label().to_string(),
        category: measured.category.clone(),
        name: measured.sample_name.clone(),
        policy: policy.to_string(),
        status: measured.status.clone(),
        status_expected: table::words(&sample.status),
        bytes_in: measured.bytes_in,
        bytes_out: measured.bytes_out,
        duration_us: measured.duration_us,
        fired: table::words(&measured.fired),
        missing: table::words(&measured.missing),
        unexpected: table::words(&measured.unexpected),
        leaked: table::words(&measured.leaked),
        lost: table::words(&measured.lost),
        verdict: measured.verdict().label().to_string(),
    }
}

#[derive(Default)]
struct RuleCounts {
    expected: usize,
    fired: usize,
    true_positive: usize,
    false_negative: usize,
    false_positive: usize,
}

fn confusion(measured: &[Measured]) -> Vec<RuleRow> {
    let mut counts: BTreeMap<String, RuleCounts> = BTreeMap::new();
    for item in measured {
        for rule in &item.expected_rules {
            let entry = counts.entry(rule.clone()).or_default();
            entry.expected += 1;
            match item.fired.contains(rule) {
                true => entry.true_positive += 1,
                false => entry.false_negative += 1,
            }
        }
        for rule in &item.fired {
            counts.entry(rule.clone()).or_default().fired += 1;
        }
        if item.set == SampleSet::Benign {
            for rule in &item.unexpected {
                counts.entry(rule.clone()).or_default().false_positive += 1;
            }
        }
    }
    counts
        .into_iter()
        .map(|(rule, count)| RuleRow {
            rule,
            expected: count.expected,
            fired: count.fired,
            true_positive: count.true_positive,
            false_negative: count.false_negative,
            false_positive: count.false_positive,
            precision: ratio(
                count.true_positive,
                count.true_positive + count.false_positive,
            ),
            recall: ratio(
                count.true_positive,
                count.true_positive + count.false_negative,
            ),
        })
        .collect()
}

fn ratio(numerator: usize, denominator: usize) -> String {
    match denominator {
        0 => "n/a".to_string(),
        _ => format!("{:.4}", numerator as f64 / denominator as f64),
    }
}

fn percentage(numerator: usize, denominator: usize) -> String {
    match denominator {
        0 => "n/a".to_string(),
        _ => format!("{:.2}", 100.0 * numerator as f64 / denominator as f64),
    }
}

pub struct Outcome {
    pub samples: Vec<SampleRow>,
    pub rules: Vec<RuleRow>,
    pub summary: Vec<SummaryRow>,
    pub failures: usize,
}

pub fn run(layout: &Layout, truth: &GroundTruth, run: Run) -> Result<Outcome> {
    truth.agree_with_disk(layout.root(), &["blocklist.txt"])?;

    let mut policy = engine::policy(layout.root(), run.policy)?;
    policy.subresources.fetch_subresources = run.fetching.enabled();
    let engine = engine::engine(policy)?;
    let origin = match run.fetching.enabled() {
        true => Some(Origin::start()),
        false => None,
    };

    let mut rows = Vec::new();
    let mut measured = Vec::new();
    for (path, sample) in truth.paths(layout.root(), run.set) {
        let done = match &origin {
            Some(origin) => {
                let data = read(&path)?;
                engine::process_source(&engine, origin.publish(&sample.name, &data))
            }
            None => engine::process(&engine, &path),
        };
        let item = measure(sample, &done, run.fetching.enabled());
        rows.push(row(&item, sample, run.policy, run.fetching));
        measured.push(item);
    }

    let rules = confusion(&measured);
    let failures = measured
        .iter()
        .filter(|item| item.verdict().is_failure())
        .count();
    let summary = summarise(run.set, &measured);

    Ok(Outcome {
        samples: rows,
        rules,
        summary,
        failures,
    })
}

fn summarise(set: SampleSet, measured: &[Measured]) -> Vec<SummaryRow> {
    let label = set.label().to_string();
    let total = measured.len();
    let mut summary = match set {
        SampleSet::Malicious => {
            let neutralised = measured.iter().filter(|m| m.neutralised()).count();
            let named = measured.iter().filter(|m| m.rules_named()).count();
            let leaked = measured
                .iter()
                .filter(|m| m.verdict() == Verdict::Leaked)
                .count();
            vec![
                SummaryRow {
                    metric: "detection_rate".to_string(),
                    set: label.clone(),
                    numerator: neutralised,
                    denominator: total,
                    rate: percentage(neutralised, total),
                },
                SummaryRow {
                    metric: "rule_accuracy".to_string(),
                    set: label.clone(),
                    numerator: named,
                    denominator: total,
                    rate: percentage(named, total),
                },
                SummaryRow {
                    metric: "leak_rate".to_string(),
                    set: label.clone(),
                    numerator: leaked,
                    denominator: total,
                    rate: percentage(leaked, total),
                },
                SummaryRow {
                    metric: "false_negative_rate".to_string(),
                    set: label.clone(),
                    numerator: total - neutralised,
                    denominator: total,
                    rate: percentage(total - neutralised, total),
                },
            ]
        }
        SampleSet::Benign => {
            let false_positives = measured
                .iter()
                .filter(|m| m.verdict() == Verdict::FalsePositive)
                .count();
            vec![SummaryRow {
                metric: "false_positive_rate".to_string(),
                set: label.clone(),
                numerator: false_positives,
                denominator: total,
                rate: percentage(false_positives, total),
            }]
        }
    };

    let mut categories: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for item in measured {
        let entry = categories.entry(item.category.as_str()).or_insert((0, 0));
        entry.1 += 1;
        let held = match set {
            SampleSet::Malicious => item.neutralised(),
            SampleSet::Benign => item.verdict() == Verdict::Clean,
        };
        if held {
            entry.0 += 1;
        }
    }
    // the per-category metric is named for what it counts in each set
    let prefix = match set {
        SampleSet::Malicious => "detection_rate",
        SampleSet::Benign => "clean_rate",
    };
    for (category, (held, total)) in categories {
        summary.push(SummaryRow {
            metric: format!("{prefix}.{category}"),
            set: label.clone(),
            numerator: held,
            denominator: total,
            rate: percentage(held, total),
        });
    }
    summary
}

pub fn report(
    layout: &Layout,
    run: Run,
    outcome: &Outcome,
    strict: bool,
) -> Result<std::path::PathBuf> {
    let dir = layout.run_dir(run.set, run.policy);
    table::save(&dir.join("correctness.csv"), &outcome.samples)?;
    if !outcome.rules.is_empty() {
        table::save(&dir.join("rules.csv"), &outcome.rules)?;
    }
    table::save(&dir.join("summary.csv"), &outcome.summary)?;

    for row in &outcome.summary {
        if !row.metric.contains('.') {
            println!(
                "  {:24} {:>4} / {:<4} {:>7}%",
                row.metric, row.numerator, row.denominator, row.rate
            );
        }
    }
    for row in &outcome.samples {
        if matches!(
            row.verdict.as_str(),
            "missed" | "leaked" | "false_positive" | "mislabelled" | "modified"
        ) {
            println!(
                "  {:14} {:34} status={:<14} missing=[{}] unexpected=[{}] leaked=[{}] lost=[{}]",
                row.verdict,
                row.name,
                row.status,
                row.missing,
                row.unexpected,
                row.leaked,
                row.lost
            );
        }
    }

    match strict && outcome.failures > 0 {
        true => Err(XtaskError::Violations {
            measured: outcome.failures,
        }),
        false => Ok(dir),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::truth::SampleSet;
    use std::time::Duration;
    use web_sanitizer::report::InputStatus;

    fn sample(rules: &[&str], allowed: &[&str], forbidden: &[&str]) -> Sample {
        Sample {
            name: "s.html".into(),
            set: SampleSet::Malicious,
            category: "xss".into(),
            source: None,
            licence: None,
            carries: None,
            threat: Some("t".into()),
            status: vec!["sanitised".into()],
            rules: rules.iter().map(|r| r.to_string()).collect(),
            allowed: allowed.iter().map(|r| r.to_string()).collect(),
            forbidden_rules: Vec::new(),
            forbidden: forbidden.iter().map(|r| r.to_string()).collect(),
            preserved: Vec::new(),
            output: None,
            max_duration_ms: None,
            fetch: None,
        }
    }

    fn processed(status: InputStatus, rules: &[&str], output: Option<&str>) -> Processed {
        Processed {
            status,
            rules: rules.iter().map(|r| r.to_string()).collect(),
            output: output.map(|o| o.as_bytes().to_vec()),
            bytes_in: 10,
            bytes_out: output.map_or(0, |o| o.len() as u64),
            elapsed: Duration::from_micros(5),
        }
    }

    #[test]
    fn a_malicious_sample_with_its_rule_and_no_leak_is_detected() {
        let sample = sample(&["html.script.disallowed"], &[], &["<script"]);
        let done = processed(
            InputStatus::Sanitised,
            &["html.script.disallowed"],
            Some("<p>ok"),
        );
        assert_eq!(measure(&sample, &done, false).verdict(), Verdict::Detected);
    }

    #[test]
    fn a_rule_that_never_fired_is_a_miss() {
        let sample = sample(&["html.script.disallowed"], &[], &[]);
        let done = processed(InputStatus::Clean, &[], Some("<script>"));
        let measured = measure(&sample, &done, false);
        assert_eq!(measured.verdict(), Verdict::Missed);
        assert_eq!(measured.missing, vec!["html.script.disallowed"]);
    }

    #[test]
    fn a_rule_that_fired_while_the_payload_survived_is_a_leak() {
        let sample = sample(&["html.script.disallowed"], &[], &["<script"]);
        let done = processed(
            InputStatus::Sanitised,
            &["html.script.disallowed"],
            Some("still <SCRIPT> here"),
        );
        let measured = measure(&sample, &done, false);
        assert_eq!(measured.verdict(), Verdict::Leaked);
        assert_eq!(measured.leaked, vec!["<script"]);
    }

    #[test]
    fn a_status_outside_the_accepted_list_is_a_miss() {
        let sample = sample(&[], &[], &[]);
        let done = processed(InputStatus::Clean, &[], Some("x"));
        assert_eq!(measure(&sample, &done, false).verdict(), Verdict::Missed);
    }

    #[test]
    fn a_benign_page_firing_only_allowed_rules_stays_clean() {
        let mut sample = sample(&[], &["html.script.disallowed"], &[]);
        sample.set = SampleSet::Benign;
        sample.status = vec!["sanitised".into()];
        let done = processed(
            InputStatus::Sanitised,
            &["html.script.disallowed"],
            Some("x"),
        );
        assert_eq!(measure(&sample, &done, false).verdict(), Verdict::Clean);
    }

    #[test]
    fn a_benign_page_firing_an_unlisted_rule_is_a_false_positive() {
        let mut sample = sample(&[], &["html.script.disallowed"], &[]);
        sample.set = SampleSet::Benign;
        sample.status = vec!["sanitised".into()];
        let done = processed(
            InputStatus::Sanitised,
            &["html.script.disallowed", "url.homograph"],
            Some("x"),
        );
        let measured = measure(&sample, &done, false);
        assert_eq!(measured.verdict(), Verdict::FalsePositive);
        assert_eq!(measured.unexpected, vec!["url.homograph"]);
    }

    #[test]
    fn a_benign_page_that_lost_a_preserved_marker_is_a_false_positive() {
        let mut sample = sample(&[], &[], &[]);
        sample.set = SampleSet::Benign;
        sample.preserved = vec!["&lt;script".into()];
        let done = processed(InputStatus::Sanitised, &[], Some("nothing left"));
        assert_eq!(
            measure(&sample, &done, false).verdict(),
            Verdict::FalsePositive
        );
    }

    #[test]
    fn a_missing_output_where_one_was_expected_is_a_miss() {
        let sample = sample(&[], &[], &[]);
        let done = processed(InputStatus::Sanitised, &[], None);
        assert_eq!(measure(&sample, &done, false).verdict(), Verdict::Missed);
    }

    #[test]
    fn a_spurious_firing_counts_against_a_rule_only_on_a_benign_page() {
        let mut benign = sample(&[], &[], &[]);
        benign.set = SampleSet::Benign;
        benign.status = vec!["sanitised".into()];
        let on_benign = measure(
            &benign,
            &processed(InputStatus::Sanitised, &["url.homograph"], Some("x")),
            false,
        );
        let on_malicious = measure(
            &sample(&[], &[], &[]),
            &processed(InputStatus::Sanitised, &["url.homograph"], Some("x")),
            false,
        );
        let rows = confusion(&[on_benign, on_malicious]);
        let rule = rows.iter().find(|r| r.rule == "url.homograph").unwrap();
        assert_eq!(rule.false_positive, 1, "only the benign page counts");
        assert_eq!(rule.fired, 2);
    }

    #[test]
    fn the_confusion_table_counts_hits_misses_and_spurious_firings() {
        let hit = measure(
            &sample(&["a"], &[], &[]),
            &processed(InputStatus::Sanitised, &["a"], Some("x")),
            false,
        );
        let miss = measure(
            &sample(&["a"], &[], &[]),
            &processed(InputStatus::Sanitised, &[], Some("x")),
            false,
        );
        let mut benign = sample(&[], &[], &[]);
        benign.set = SampleSet::Benign;
        let spurious = measure(
            &benign,
            &processed(InputStatus::Sanitised, &["b"], Some("x")),
            false,
        );
        let rows = confusion(&[hit, miss, spurious]);
        let a = rows.iter().find(|r| r.rule == "a").unwrap();
        assert_eq!((a.expected, a.true_positive, a.false_negative), (2, 1, 1));
        assert_eq!(a.recall, "0.5000");
        let b = rows.iter().find(|r| r.rule == "b").unwrap();
        assert_eq!((b.false_positive, b.fired), (1, 1));
        assert_eq!(b.precision, "0.0000");
    }

    #[test]
    fn rates_of_an_empty_set_are_reported_as_not_available() {
        assert_eq!(ratio(0, 0), "n/a");
        assert_eq!(percentage(0, 0), "n/a");
        assert_eq!(percentage(1, 4), "25.00");
    }
}
