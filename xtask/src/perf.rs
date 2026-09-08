use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use web_sanitizer::sniff::{AcquiredInput, sniff_input};

use crate::engine::{self};
use crate::error::{Result, XtaskError, read};
use crate::paths::{Fetching, Layout, policy_slug};
use crate::progress::Progress;
use crate::served::Origin;
use crate::table;
use crate::truth::{GroundTruth, SampleSet};

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

#[derive(Serialize, Deserialize)]
pub struct LatencyRow {
    pub set: String,
    pub fetching: String,
    pub name: String,
    pub bytes: u64,
    pub repeats: usize,
    pub median_us: u128,
    pub best_us: u128,
    pub worst_us: u128,
    pub us_per_kib: String,
}

#[derive(Serialize, Deserialize)]
pub struct PhaseRow {
    pub set: String,
    pub fetching: String,
    pub name: String,
    pub bytes: u64,
    pub read_us: u128,
    pub sniff_us: u128,
    pub rewrite_us: u128,
    pub total_us: u128,
    pub sniff_share: String,
}

#[derive(Serialize, Deserialize)]
pub struct MemoryRow {
    pub set: String,
    pub fetching: String,
    pub name: String,
    pub bytes: u64,
    pub peak_rss_kib: u64,
    pub baseline_kib: u64,
    pub growth_kib: u64,
    pub bytes_per_input_byte: String,
}

fn median(values: &mut [u128]) -> u128 {
    values.sort_unstable();
    match values.len() {
        0 => 0,
        n => values[n / 2],
    }
}

fn per_kib(duration_us: u128, bytes: u64) -> String {
    match bytes {
        0 => "n/a".to_string(),
        _ => format!("{:.3}", duration_us as f64 / (bytes as f64 / 1024.0)),
    }
}

fn share(part: u128, whole: u128) -> String {
    match whole {
        0 => "n/a".to_string(),
        _ => format!("{:.3}", part as f64 / whole as f64),
    }
}

// fetching is a policy switch, so the run owns the policy it measures under
fn policy_of(layout: &Layout, run: Run) -> Result<web_sanitizer::policy::Policy> {
    let mut policy = engine::policy(layout.root(), run.policy)?;
    policy.subresources.fetch_subresources = run.fetching.enabled();
    Ok(policy)
}

fn inputs(layout: &Layout, truth: &GroundTruth, set: SampleSet) -> Vec<(PathBuf, String)> {
    truth
        .paths(layout.root(), set)
        .into_iter()
        .map(|(path, sample)| (path, sample.name.clone()))
        .collect()
}

pub fn latency(
    layout: &Layout,
    truth: &GroundTruth,
    run: Run,
    repeats: usize,
) -> Result<(Vec<LatencyRow>, Progress)> {
    let engine = engine::engine(policy_of(layout, run)?)?;
    let origin = match run.fetching.enabled() {
        true => Some(Origin::start()),
        false => None,
    };
    let listing = inputs(layout, truth, run.set);
    let mut progress = Progress::start(&run.label(), listing.len());
    let mut rows = Vec::new();
    for (path, name) in listing {
        progress.tick(&name);
        let data = read(&path)?;
        let source = origin.as_ref().map(|origin| origin.publish(&name, &data));
        let mut samples = Vec::with_capacity(repeats);
        for _ in 0..repeats {
            let done = match &source {
                Some(source) => engine::process_source(&engine, source.clone()),
                None => engine::process_bytes(&engine, &name, data.clone()),
            };
            samples.push(done.elapsed.as_micros());
        }
        let best = *samples.iter().min().unwrap_or(&0);
        let worst = *samples.iter().max().unwrap_or(&0);
        let middle = median(&mut samples);
        rows.push(LatencyRow {
            set: run.set.label().to_string(),
            fetching: run.fetching.label().to_string(),
            name,
            bytes: data.len() as u64,
            repeats,
            median_us: middle,
            best_us: best,
            worst_us: worst,
            us_per_kib: per_kib(middle, data.len() as u64),
        });
    }
    rows.sort_by_key(|row| row.bytes);
    Ok((rows, progress))
}

pub fn phases(
    layout: &Layout,
    truth: &GroundTruth,
    run: Run,
    repeats: usize,
) -> Result<(Vec<PhaseRow>, Progress)> {
    let policy = policy_of(layout, run)?;
    let engine = engine::engine(policy.clone())?;
    let origin = match run.fetching.enabled() {
        true => Some(Origin::start()),
        false => None,
    };
    let listing = inputs(layout, truth, run.set);
    let mut progress = Progress::start(&run.label(), listing.len());
    let mut rows = Vec::new();
    for (path, name) in listing {
        progress.tick(&name);
        let data = read(&path)?;
        let source = origin.as_ref().map(|origin| origin.publish(&name, &data));
        let mut read_us = Vec::new();
        let mut sniff_us = Vec::new();
        let mut total_us = Vec::new();
        for _ in 0..repeats {
            let started = Instant::now();
            let bytes = read(&path)?;
            read_us.push(started.elapsed().as_micros());

            let started = Instant::now();
            let acquired = AcquiredInput::new(
                web_sanitizer::input::InputSource::File(path.clone()),
                bytes,
            );
            let _ = sniff_input(acquired, &policy.subresources, 0);
            sniff_us.push(started.elapsed().as_micros());

            let done = match &source {
                Some(source) => engine::process_source(&engine, source.clone()),
                None => engine::process_bytes(&engine, &name, data.clone()),
            };
            total_us.push(done.elapsed.as_micros());
        }
        let read_median = median(&mut read_us);
        let sniff_median = median(&mut sniff_us);
        let total_median = median(&mut total_us);
        rows.push(PhaseRow {
            set: run.set.label().to_string(),
            fetching: run.fetching.label().to_string(),
            name,
            bytes: data.len() as u64,
            read_us: read_median,
            sniff_us: sniff_median,
            rewrite_us: total_median.saturating_sub(sniff_median),
            total_us: total_median,
            sniff_share: share(sniff_median, total_median),
        });
    }
    rows.sort_by_key(|row| row.bytes);
    Ok((rows, progress))
}


#[cfg(target_os = "linux")]
fn peak_rss_kib() -> u64 {
    // VmHWM is already KiB.
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|text| {
            text.lines()
                .find(|line| line.starts_with("VmHWM:"))
                .and_then(|line| {
                    line.split_whitespace()
                        .nth(1)
                        .and_then(|value| value.parse::<u64>().ok())
                })
        })
        .unwrap_or(0)
}

#[cfg(target_os = "macos")]
fn peak_rss_kib() -> u64 {
    // ru_maxrss counts bytes on macOS, unlike the KiB every other unix reports.
    let mut usage = std::mem::MaybeUninit::<libc::rusage>::uninit();
    match unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) } {
        0 => (unsafe { usage.assume_init() }.ru_maxrss as u64) / 1024,
        _ => 0,
    }
}

#[cfg(windows)]
fn peak_rss_kib() -> u64 {
    use windows_sys::Win32::System::ProcessStatus::{
        GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    // PeakWorkingSetSize counts bytes
    // the call wants the struct size in cb.
    let mut counters = PROCESS_MEMORY_COUNTERS {
        cb: size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
        ..Default::default()
    };
    let read = unsafe { GetProcessMemoryInfo(GetCurrentProcess(), &mut counters, counters.cb) };
    match read {
        0 => 0,
        _ => (counters.PeakWorkingSetSize as u64) / 1024,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn peak_rss_kib() -> u64 {
    0
}

pub fn probe(layout: &Layout, file: &Path, policy_name: &str, fetching: bool) -> Result<()> {
    let baseline = peak_rss_kib();
    let mut policy = engine::policy(layout.root(), policy_name)?;
    policy.subresources.fetch_subresources = fetching;
    let engine = engine::engine(policy)?;
    let done = match fetching {
        true => {
            let origin = Origin::start();
            let name = file
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let data = read(file)?;
            engine::process_source(&engine, origin.publish(&name, &data))
        }
        false => engine::process(&engine, file),
    };
    let peak = peak_rss_kib();
    println!(
        "{{\"peak_rss_kib\":{},\"baseline_kib\":{},\"bytes_in\":{},\"status\":\"{}\"}}",
        peak,
        baseline,
        done.bytes_in,
        done.status_label()
    );
    Ok(())
}

pub fn memory(
    layout: &Layout,
    truth: &GroundTruth,
    run: Run,
) -> Result<(Vec<MemoryRow>, Progress)> {
    let executable = std::env::current_exe().map_err(|source| XtaskError::Read {
        path: PathBuf::from("<current executable>"),
        source,
    })?;
    let listing = inputs(layout, truth, run.set);
    let mut progress = Progress::start(&run.label(), listing.len());
    let mut rows = Vec::new();
    for (path, name) in listing {
        progress.tick(&name);
        let mut command = std::process::Command::new(&executable);
        command
            .arg("memory-probe")
            .arg("--file")
            .arg(&path)
            .arg("--policy")
            .arg(run.policy);
        if run.fetching.enabled() {
            command.arg("--fetch");
        }
        let output = command
            .current_dir(layout.root())
            .output()
            .map_err(|source| XtaskError::Read {
                path: executable.clone(),
                source,
            })?;
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let probe: ProbeResult =
            serde_json::from_str(&text).map_err(|source| XtaskError::Json {
                path: path.clone(),
                source,
            })?;
        let growth = probe.peak_rss_kib.saturating_sub(probe.baseline_kib);
        rows.push(MemoryRow {
            set: run.set.label().to_string(),
            fetching: run.fetching.label().to_string(),
            name,
            bytes: probe.bytes_in,
            peak_rss_kib: probe.peak_rss_kib,
            baseline_kib: probe.baseline_kib,
            growth_kib: growth,
            bytes_per_input_byte: match probe.bytes_in {
                0 => "n/a".to_string(),
                bytes => format!("{:.3}", (growth * 1024) as f64 / bytes as f64),
            },
        });
    }
    rows.sort_by_key(|row| row.bytes);
    Ok((rows, progress))
}

#[derive(Deserialize)]
struct ProbeResult {
    peak_rss_kib: u64,
    baseline_kib: u64,
    bytes_in: u64,
}

fn run_file(layout: &Layout, run: Run, name: &str) -> PathBuf {
    layout.run_file(run.set, run.policy, name)
}

pub fn save_latency(layout: &Layout, run: Run, rows: &[LatencyRow]) -> Result<PathBuf> {
    let path = run_file(layout, run, "latency.csv");
    table::save(&path, rows)?;
    Ok(path)
}

pub fn save_phases(layout: &Layout, run: Run, rows: &[PhaseRow]) -> Result<PathBuf> {
    let path = run_file(layout, run, "phases.csv");
    table::save(&path, rows)?;
    Ok(path)
}

pub fn save_memory(layout: &Layout, run: Run, rows: &[MemoryRow]) -> Result<PathBuf> {
    let path = run_file(layout, run, "memory.csv");
    table::save(&path, rows)?;
    Ok(path)
}

pub fn machine_notes() -> Vec<String> {
    let mut notes = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/proc/cpuinfo") {
        if let Some(line) = text.lines().find(|line| line.starts_with("model name")) {
            notes.push(line.trim().to_string());
        }
        notes.push(format!(
            "logical cpus: {}",
            text.lines().filter(|l| l.starts_with("processor")).count()
        ));
    }
    if let Ok(text) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(line) = text.lines().find(|line| line.starts_with("MemTotal")) {
            notes.push(line.trim().to_string());
        }
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Layout;
    use crate::truth::GroundTruth;

    fn truth() -> GroundTruth {
        GroundTruth::load(&Layout::discover().ground_truth()).unwrap()
    }

    #[test]
    fn the_median_of_an_odd_run_is_the_middle_value() {
        let mut values = vec![5, 1, 3];
        assert_eq!(median(&mut values), 3);
    }

    #[test]
    fn the_median_of_an_empty_run_is_zero_rather_than_a_panic() {
        assert_eq!(median(&mut []), 0);
    }

    #[test]
    fn a_rate_per_kibibyte_divides_by_the_input_size() {
        assert_eq!(per_kib(1024, 1024), "1024.000");
        assert_eq!(per_kib(512, 1024), "512.000");
        assert_eq!(per_kib(1000, 2048), "500.000");
        assert_eq!(per_kib(10, 0), "n/a");
    }

    #[test]
    fn a_share_of_zero_total_is_reported_as_not_available() {
        assert_eq!(share(1, 0), "n/a");
        assert_eq!(share(1, 4), "0.250");
    }

    #[test]
    fn the_high_water_mark_is_readable_and_positive_on_this_platform() {
        assert!(peak_rss_kib() > 0);
    }

    #[test]
    fn latency_covers_every_sample_and_orders_by_size() {
        let layout = Layout::discover();
        let truth = truth();
        let run = Run {
            set: SampleSet::Benign,
            policy: truth.policy(Fetching::Off),
            fetching: Fetching::Off,
        };
        let (rows, _) = latency(&layout, &truth, run, 1).unwrap();
        assert_eq!(rows.len(), truth.of(SampleSet::Benign).len());
        assert!(rows.iter().all(|row| row.fetching == "no-fetch"));
        assert!(rows.windows(2).all(|pair| pair[0].bytes <= pair[1].bytes));
    }

    #[test]
    fn phases_split_the_total_into_parts_that_do_not_exceed_it() {
        let layout = Layout::discover();
        let truth = truth();
        let run = Run {
            set: SampleSet::Malicious,
            policy: truth.policy(Fetching::Off),
            fetching: Fetching::Off,
        };
        let (rows, _) = phases(&layout, &truth, run, 1).unwrap();
        for row in &rows {
            assert_eq!(
                row.rewrite_us + row.sniff_us,
                row.total_us.max(row.sniff_us)
            );
        }
    }

    #[test]
    fn the_input_listing_covers_one_set_at_a_time() {
        let layout = Layout::discover();
        let truth = truth();
        let benign = inputs(&layout, &truth, SampleSet::Benign);
        let malicious = inputs(&layout, &truth, SampleSet::Malicious);
        assert_eq!(benign.len(), truth.of(SampleSet::Benign).len());
        assert_eq!(malicious.len(), truth.of(SampleSet::Malicious).len());
        assert!(benign.iter().all(|(path, _)| path.exists()));
    }
}
