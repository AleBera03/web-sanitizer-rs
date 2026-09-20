use std::path::{Path, PathBuf};

use charming::component::{Axis, Grid, Legend, Title};
use charming::datatype::{CompositeValue, DataPoint};
use charming::element::{
    AxisLabel, AxisType, Color, ItemStyle, Label, LabelPosition, LineStyle, LineStyleType,
    SymbolSize,
};
use charming::renderer::image_renderer::ImageFormat;
use charming::series::{Bar, Line, Scatter};
use charming::{Chart, ImageRenderer};
use serde::{Deserialize, Serialize};

use crate::correctness::{SampleRow, SummaryRow};
use crate::error::{Result, XtaskError, read_to_string};
use crate::paths::{Fetching, Layout, RunKind, Section, policy_slug};
use crate::perf::{LatencyRow, MemoryRow, PhaseRow};
use crate::scenarios::ScenarioRow;
use crate::table;
use crate::truth::{GroundTruth, SampleSet};

const SURFACE: &str = "#fcfcfb";
const INK: &str = "#0b0b0b";
const SERIES: [&str; 3] = ["#2a78d6", "#eb6834", "#1baf7a"];
const GUIDE: &str = "#8a8a85";
const WIDTH: u32 = 1000;
const HEIGHT: u32 = 560;

fn point(x: f64, y: f64) -> DataPoint {
    DataPoint::from(CompositeValue::from(vec![
        CompositeValue::from(x),
        CompositeValue::from(y),
    ]))
}

fn title(text: &str, subtext: &str) -> Title {
    Title::new().text(text).subtext(subtext).left("center")
}

fn canvas() -> Chart {
    canvas_with(Grid::new().left("11%").right("9%").top("20%").bottom("13%"))
}

fn canvas_with(grid: Grid) -> Chart {
    Chart::new()
        .background_color(Color::Value(SURFACE.to_string()))
        .grid(grid)
}

fn value_axis(name: &str, logarithmic: bool) -> Axis {
    let kind = match logarithmic {
        true => AxisType::Log,
        false => AxisType::Value,
    };
    Axis::new().type_(kind).name(name).scale(true)
}

fn render_sized(chart: Chart, path: &Path, height: u32) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|source| XtaskError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let mut renderer = ImageRenderer::new(WIDTH, height);
    renderer
        .save_format(ImageFormat::Png, &chart, path)
        .map_err(|source| XtaskError::Chart {
            path: path.to_path_buf(),
            source,
        })
}

fn render(chart: Chart, path: &Path) -> Result<()> {
    render_sized(chart, path, HEIGHT)
}

fn series_colour(index: usize) -> ItemStyle {
    ItemStyle::new().color(Color::Value(SERIES[index % SERIES.len()].to_string()))
}

fn rows<T: serde::de::DeserializeOwned>(path: &Path) -> Option<Vec<T>> {
    match path.is_file() {
        true => table::load(path).ok(),
        false => None,
    }
}

fn words(cell: &str) -> usize {
    cell.split_whitespace().count()
}

pub struct Run {
    pub set: SampleSet,
    pub slug: String,
    pub kind: RunKind,
    dir: PathBuf,
}

impl Run {
    fn table<T: serde::de::DeserializeOwned>(&self, name: &str) -> Option<Vec<T>> {
        rows(&self.dir.join(name))
    }

    fn conditions(&self) -> String {
        match self.kind.fetching() {
            Some(Fetching::Off) => format!("{}, fetching off", self.slug),
            Some(Fetching::On) => format!("{}, fetching on", self.slug),
            None => format!("{}, its own fetching mode", self.slug),
        }
    }

    fn criterion_id(&self) -> Option<String> {
        let mode = self.kind.fetching()?;
        Some(format!("{}-{}", self.set.label(), mode.label()))
    }
}

pub fn discover(layout: &Layout, truth: &GroundTruth) -> Vec<Run> {
    let [nofetch, fetch] = truth.default_policies();
    let (nofetch, fetch) = (policy_slug(nofetch), policy_slug(fetch));
    let mut found = Vec::new();
    for set in [SampleSet::Benign, SampleSet::Malicious] {
        let Ok(entries) = std::fs::read_dir(layout.set_dir(set)) else {
            continue;
        };
        let mut runs: Vec<Run> = entries
            .flatten()
            .filter(|entry| entry.path().is_dir())
            .map(|entry| {
                let slug = entry.file_name().to_string_lossy().into_owned();
                let kind = match slug.as_str() {
                    s if s == nofetch => RunKind::NoFetch,
                    s if s == fetch => RunKind::Fetch,
                    _ => RunKind::Custom(slug.clone()),
                };
                Run {
                    set,
                    slug,
                    kind,
                    dir: entry.path(),
                }
            })
            .collect();
        runs.sort_by_key(|run| match run.kind {
            RunKind::NoFetch => (0, run.slug.clone()),
            RunKind::Fetch => (1, run.slug.clone()),
            RunKind::Custom(_) => (2, run.slug.clone()),
        });
        found.extend(runs);
    }
    found
}

// one run

pub fn latency(layout: &Layout, run: &Run) -> Result<Option<PathBuf>> {
    let Some(rows) = run.table::<LatencyRow>("latency.csv") else {
        return Ok(None);
    };
    let data: Vec<DataPoint> = rows
        .iter()
        .filter(|row| row.bytes > 0 && row.median_us > 0)
        .map(|row| point(row.bytes as f64, row.median_us as f64))
        .collect();
    if data.is_empty() {
        return Ok(None);
    }
    let chart = canvas()
        .title(title(
            "Per-input latency against input size",
            &format!(
                "one worker, median of the repeats, both axes logarithmic \u{2014} {}",
                run.conditions()
            ),
        ))
        .legend(Legend::new().top("9%"))
        .x_axis(value_axis("input bytes", true))
        .y_axis(value_axis("microseconds", true))
        .series(
            Scatter::new()
                .name(run.set.label())
                .symbol_size(SymbolSize::Number(9.0))
                .item_style(series_colour(0))
                .data(data),
        );
    let path = layout
        .run_plot_dir(run.set, &run.kind)
        .join("latency-vs-size.png");
    render(chart, &path)?;
    Ok(Some(path))
}

pub fn memory(layout: &Layout, run: &Run) -> Result<Option<PathBuf>> {
    let Some(rows) = run.table::<MemoryRow>("memory.csv") else {
        return Ok(None);
    };
    let data: Vec<DataPoint> = rows
        .iter()
        .filter(|row| row.bytes > 0)
        .map(|row| point(row.bytes as f64, row.peak_rss_kib as f64))
        .collect();
    if data.is_empty() {
        return Ok(None);
    }
    let chart = canvas()
        .title(title(
            "Peak resident set against input size",
            &format!(
                "one process per input, high-water mark read from the kernel \u{2014} {}",
                run.conditions()
            ),
        ))
        .legend(Legend::new().top("9%"))
        .x_axis(value_axis("input bytes", true))
        .y_axis(value_axis("peak RSS, KiB", false))
        .series(
            Scatter::new()
                .name(run.set.label())
                .symbol_size(SymbolSize::Number(9.0))
                .item_style(series_colour(0))
                .data(data),
        );
    let path = layout
        .run_plot_dir(run.set, &run.kind)
        .join("memory-vs-size.png");
    render(chart, &path)?;
    Ok(Some(path))
}

fn per_kib(row: &PhaseRow) -> (f64, f64, f64) {
    let kib = (row.bytes as f64 / 1024.0).max(1.0 / 1024.0);
    (
        row.read_us as f64 / kib,
        row.sniff_us as f64 / kib,
        row.rewrite_us as f64 / kib,
    )
}

pub fn phases(layout: &Layout, run: &Run) -> Result<Option<PathBuf>> {
    let Some(rows) = run.table::<PhaseRow>("phases.csv") else {
        return Ok(None);
    };
    let mut buckets: Vec<(String, f64, f64, f64)> = rows
        .iter()
        .filter(|row| row.bytes > 0)
        .map(|row| {
            let (read, sniff, rewrite) = per_kib(row);
            (row.name.clone(), read, sniff, rewrite)
        })
        .collect();
    if buckets.is_empty() {
        return Ok(None);
    }

    buckets.sort_by(|a, b| a.3.partial_cmp(&b.3).unwrap_or(std::cmp::Ordering::Equal));

    let labels: Vec<String> = buckets.iter().map(|b| b.0.clone()).collect();
    let height = (24 * labels.len().max(6)) as u32 + 170;
    let mut chart = canvas_with(Grid::new().left("30%").right("8%").top("110").bottom("50"))
        .title(title(
            "Where the time goes, per kibibyte of input",
            &format!(
                "every input of the set, split into pipeline phases \u{2014} {}",
                run.conditions()
            ),
        ))
        .legend(Legend::new().top("75"))
        .x_axis(value_axis("us per KiB", false))
        .y_axis(Axis::new().type_(AxisType::Category).data(labels));

    for (index, name) in ["read", "sniff", "rewrite"].iter().enumerate() {
        let data: Vec<DataPoint> = buckets
            .iter()
            .map(|bucket| {
                DataPoint::from(match index {
                    0 => bucket.1,
                    1 => bucket.2,
                    _ => bucket.3,
                })
            })
            .collect();
        chart = chart.series(
            Bar::new()
                .name(*name)
                .stack("phase")
                .item_style(series_colour(index))
                .data(data),
        );
    }
    let path = layout
        .run_plot_dir(run.set, &run.kind)
        .join("phase-breakdown.png");
    render_sized(chart, &path, height)?;
    Ok(Some(path))
}

fn rate_naming(set: SampleSet) -> (&'static str, &'static str, &'static str, &'static str) {
    match set {
        SampleSet::Benign => (
            "False positives per page",
            "rules that fired on legitimate content, and content the sanitiser lost",
            "false-positive-rate.png",
            "false-positives",
        ),
        SampleSet::Malicious => (
            "False negatives per page",
            "required rules that stayed silent, and payloads that survived",
            "false-negative-rate.png",
            "false-negatives",
        ),
    }
}

fn counted(rows: &[SampleRow], set: SampleSet) -> Vec<(String, usize)> {
    let mut out: Vec<(String, usize)> = rows
        .iter()
        .map(|row| {
            let (a, b) = match set {
                SampleSet::Benign => (&row.unexpected, &row.lost),
                SampleSet::Malicious => (&row.missing, &row.leaked),
            };
            (row.name.clone(), words(a) + words(b))
        })
        .collect();
    out.sort_by(|a, b| a.1.cmp(&b.1).then(b.0.cmp(&a.0)));
    out
}

pub fn rates(layout: &Layout, run: &Run) -> Result<Option<PathBuf>> {
    let Some(rows) = run.table::<SampleRow>("correctness.csv") else {
        return Ok(None);
    };
    let counted = counted(&rows, run.set);
    if counted.is_empty() {
        return Ok(None);
    }
    let (heading, subtext, file, _) = rate_naming(run.set);
    let total: usize = counted.iter().map(|(_, count)| count).sum();
    let pages = counted.iter().filter(|(_, count)| *count > 0).count();
    let labels: Vec<String> = counted.iter().map(|(name, _)| name.clone()).collect();
    let data: Vec<DataPoint> = counted
        .iter()
        .map(|(_, count)| DataPoint::from(*count as f64))
        .collect();

    let height = (24 * labels.len().max(6)) as u32 + 150;
    let chart = canvas_with(Grid::new().left("30%").right("10%").top("95").bottom("50"))
        .title(title(
            heading,
            &format!(
                "{subtext} \u{2014} {total} across {pages} of {} inputs \u{2014} {}",
                labels.len(),
                run.conditions()
            ),
        ))
        .x_axis(value_axis("count", false))
        .y_axis(Axis::new().type_(AxisType::Category).data(labels))
        .series(
            Bar::new()
                .name("count")
                .item_style(series_colour(1))
                .label(
                    Label::new()
                        .show(true)
                        .position(LabelPosition::Right)
                        .color(Color::Value(INK.to_string()))
                        .font_size(11.0),
                )
                .data(data),
        );
    let path = layout.run_plot_dir(run.set, &run.kind).join(file);
    render_sized(chart, &path, height)?;
    Ok(Some(path))
}

pub fn detection(layout: &Layout, run: &Run) -> Result<Option<PathBuf>> {
    if run.set != SampleSet::Malicious {
        return Ok(None);
    }
    let Some(rows) = run.table::<SummaryRow>("summary.csv") else {
        return Ok(None);
    };
    let categories: Vec<&SummaryRow> = rows
        .iter()
        .filter(|row| row.metric.starts_with("detection_rate."))
        .collect();
    if categories.is_empty() {
        return Ok(None);
    }
    let labels: Vec<String> = categories
        .iter()
        .map(|row| {
            let name = row.metric.trim_start_matches("detection_rate.").to_string();
            format!("{name}\n{}/{}", row.numerator, row.denominator)
        })
        .collect();
    let values: Vec<DataPoint> = categories
        .iter()
        .map(|row| DataPoint::from(row.rate.parse::<f64>().unwrap_or_default()))
        .collect();

    let chart = canvas()
        .title(title(
            "Threats neutralised by category",
            &format!(
                "share of the malicious samples whose payload did not survive \u{2014} {}",
                run.conditions()
            ),
        ))
        .x_axis(
            Axis::new()
                .type_(AxisType::Category)
                .axis_label(AxisLabel::new().interval(0).font_size(11.0))
                .data(labels),
        )
        .y_axis(
            Axis::new()
                .type_(AxisType::Value)
                .name("percent")
                .min(0)
                .max(100),
        )
        .series(
            Bar::new()
                .name("neutralised")
                .item_style(series_colour(0))
                .label(
                    Label::new()
                        .show(true)
                        .position(LabelPosition::Top)
                        .color(Color::Value(INK.to_string()))
                        .font_size(12.0),
                )
                .data(values),
        );
    let path = layout
        .run_plot_dir(run.set, &run.kind)
        .join("detection-by-category.png");
    render(chart, &path)?;
    Ok(Some(path))
}

// criterion

#[derive(Deserialize)]
struct Estimate {
    mean: Mean,
}

// criterion records the batch's own size, so the rate is read back from the
// benchmark rather than from a constant this crate would have to keep in step
#[derive(Deserialize)]
struct Benchmark {
    throughput: Option<Throughput>,
}

#[derive(Deserialize)]
struct Throughput {
    #[serde(rename = "Bytes")]
    bytes: Option<f64>,
}

#[derive(Deserialize)]
struct Mean {
    point_estimate: f64,
}

fn criterion_workers(layout: &Layout, id: &str) -> Vec<u32> {
    let dir = layout.join(&format!("target/criterion/throughput/{id}"));
    let mut workers: Vec<u32> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .collect();
    workers.sort_unstable();
    workers
}

fn criterion_bytes(layout: &Layout, id: &str, workers: u32) -> Option<f64> {
    let path = layout.join(&format!(
        "target/criterion/throughput/{id}/{workers}/new/benchmark.json"
    ));
    let text = read_to_string(&path).ok()?;
    let benchmark: Benchmark = serde_json::from_str(&text).ok()?;
    benchmark.throughput?.bytes
}

fn criterion_seconds(layout: &Layout, id: &str, workers: u32) -> Option<f64> {
    let path = layout.join(&format!(
        "target/criterion/throughput/{id}/{workers}/new/estimates.json"
    ));
    let text = read_to_string(&path).ok()?;
    let estimate: Estimate = serde_json::from_str(&text).ok()?;
    Some(estimate.mean.point_estimate / 1e9)
}

#[derive(Serialize)]
pub struct ScalingRow {
    pub set: String,
    pub fetching: String,
    pub workers: u32,
    pub batch_seconds: f64,
    pub mib_per_second: f64,
    pub speedup: f64,
    pub efficiency: f64,
}

fn speedups(layout: &Layout, id: &str) -> Vec<(u32, f64, f64)> {
    let workers = criterion_workers(layout, id);
    let mut base = None;
    let mut out = Vec::new();
    for count in workers {
        let Some(seconds) = criterion_seconds(layout, id, count) else {
            continue;
        };
        let first = *base.get_or_insert(seconds);
        out.push((count, seconds, first / seconds));
    }
    out
}

pub fn scaling(layout: &Layout, run: &Run) -> Result<Option<PathBuf>> {
    let Some(id) = run.criterion_id() else {
        return Ok(None);
    };
    let readings = speedups(layout, &id);
    if readings.is_empty() {
        return Ok(None);
    }
    let labels: Vec<String> = readings.iter().map(|(w, _, _)| w.to_string()).collect();
    let data: Vec<DataPoint> = readings
        .iter()
        .map(|(_, _, speedup)| DataPoint::from(*speedup))
        .collect();
    let ideal: Vec<DataPoint> = readings
        .iter()
        .map(|(w, _, _)| DataPoint::from(*w as f64))
        .collect();

    let chart = canvas()
        .title(title(
            "Speed-up against worker count",
            &format!("one batch of the set \u{2014} {}", run.conditions()),
        ))
        .legend(Legend::new().top("9%"))
        .x_axis(
            Axis::new()
                .type_(AxisType::Category)
                .name("workers")
                .data(labels),
        )
        .y_axis(value_axis("speed-up", false))
        .series(
            Line::new()
                .name(run.slug.clone())
                .symbol_size(SymbolSize::Number(9.0))
                .item_style(series_colour(0))
                .line_style(LineStyle::new().width(2.0))
                .data(data),
        )
        .series(
            Line::new()
                .name("ideal")
                .show_symbol(false)
                .line_style(
                    LineStyle::new()
                        .color(Color::Value(GUIDE.to_string()))
                        .type_(LineStyleType::Dashed)
                        .width(2.0),
                )
                .data(ideal),
        );
    let path = layout
        .run_plot_dir(run.set, &run.kind)
        .join("scaling-speedup.png");
    render(chart, &path)?;
    Ok(Some(path))
}

fn scaling_table(layout: &Layout, runs: &[&Run]) -> Vec<ScalingRow> {
    let mut table = Vec::new();
    for run in runs {
        let Some(id) = run.criterion_id() else {
            continue;
        };
        for (workers, seconds, speedup) in speedups(layout, &id) {
            table.push(ScalingRow {
                set: run.set.label().to_string(),
                fetching: run
                    .kind
                    .fetching()
                    .map(|f| f.label().to_string())
                    .unwrap_or_default(),
                workers,
                batch_seconds: (seconds * 10_000.0).round() / 10_000.0,
                mib_per_second: criterion_bytes(layout, &id, workers)
                    .map(|bytes| ((bytes / seconds / (1024.0 * 1024.0)) * 10.0).round() / 10.0)
                    .unwrap_or_default(),
                speedup: (speedup * 1000.0).round() / 1000.0,
                efficiency: ((speedup / workers as f64) * 1000.0).round() / 1000.0,
            });
        }
    }
    table
}

// two runs

fn pair_file(layout: &Layout, set: SampleSet, plot: &str, a: &Run, b: &Run) -> PathBuf {
    layout
        .compare_plot_dir(set, plot)
        .join(format!("{}-vs-{}.png", a.slug, b.slug))
}

// what a scatter comparison is called and how its y axis reads
struct PairPlot {
    plot: &'static str,
    heading: &'static str,
    subtext: &'static str,
    y_axis: &'static str,
    logarithmic: bool,
}

fn scatter_pair(
    layout: &Layout,
    a: &Run,
    b: &Run,
    spec: PairPlot,
    values: impl Fn(&Run) -> Option<Vec<(f64, f64)>>,
) -> Result<Option<PathBuf>> {
    let (Some(first), Some(second)) = (values(a), values(b)) else {
        return Ok(None);
    };
    if first.is_empty() || second.is_empty() {
        return Ok(None);
    }
    let mut chart = canvas()
        .title(title(
            spec.heading,
            &format!("{} \u{2014} {} against {}", spec.subtext, a.slug, b.slug),
        ))
        .legend(Legend::new().top("9%"))
        .x_axis(value_axis("input bytes", true))
        .y_axis(value_axis(spec.y_axis, spec.logarithmic));
    for (index, (run, data)) in [(a, first), (b, second)].into_iter().enumerate() {
        chart = chart.series(
            Scatter::new()
                .name(run.slug.clone())
                .symbol_size(SymbolSize::Number(9.0))
                .item_style(series_colour(index))
                .data(
                    data.into_iter()
                        .map(|(x, y)| point(x, y))
                        .collect::<Vec<DataPoint>>(),
                ),
        );
    }
    let path = pair_file(layout, a.set, spec.plot, a, b);
    render(chart, &path)?;
    Ok(Some(path))
}

pub fn compare_latency(layout: &Layout, a: &Run, b: &Run) -> Result<Option<PathBuf>> {
    scatter_pair(
        layout,
        a,
        b,
        PairPlot {
            plot: "latency",
            heading: "Per-input latency against input size",
            subtext: "one worker, median of the repeats, both axes logarithmic",
            y_axis: "microseconds",
            logarithmic: true,
        },
        |run| {
            run.table::<LatencyRow>("latency.csv").map(|rows| {
                rows.iter()
                    .filter(|row| row.bytes > 0 && row.median_us > 0)
                    .map(|row| (row.bytes as f64, row.median_us as f64))
                    .collect()
            })
        },
    )
}

pub fn compare_memory(layout: &Layout, a: &Run, b: &Run) -> Result<Option<PathBuf>> {
    scatter_pair(
        layout,
        a,
        b,
        PairPlot {
            plot: "memory",
            heading: "Peak resident set against input size",
            subtext: "one process per input, high-water mark read from the kernel",
            y_axis: "peak RSS, KiB",
            logarithmic: false,
        },
        |run| {
            run.table::<MemoryRow>("memory.csv").map(|rows| {
                rows.iter()
                    .filter(|row| row.bytes > 0)
                    .map(|row| (row.bytes as f64, row.peak_rss_kib as f64))
                    .collect()
            })
        },
    )
}

pub fn compare_phases(layout: &Layout, a: &Run, b: &Run) -> Result<Option<PathBuf>> {
    scatter_pair(
        layout,
        a,
        b,
        PairPlot {
            plot: "phases",
            heading: "Total pipeline cost per kibibyte",
            subtext: "read, sniff and rewrite summed, divided by the input size",
            y_axis: "us per KiB",
            logarithmic: true,
        },
        |run| {
            run.table::<PhaseRow>("phases.csv").map(|rows| {
                rows.iter()
                    .filter(|row| row.bytes > 0 && row.total_us > 0)
                    .map(|row| {
                        let kib = (row.bytes as f64 / 1024.0).max(1.0 / 1024.0);
                        (row.bytes as f64, row.total_us as f64 / kib)
                    })
                    .collect()
            })
        },
    )
}

pub fn compare_rates(layout: &Layout, a: &Run, b: &Run) -> Result<Option<PathBuf>> {
    let (Some(first), Some(second)) = (
        a.table::<SampleRow>("correctness.csv"),
        b.table::<SampleRow>("correctness.csv"),
    ) else {
        return Ok(None);
    };
    let left = counted(&first, a.set);
    let right = counted(&second, b.set);
    if left.is_empty() || right.is_empty() {
        return Ok(None);
    }

    let lookup = |rows: &[(String, usize)], name: &str| -> usize {
        rows.iter()
            .find(|(other, _)| other == name)
            .map(|(_, count)| *count)
            .unwrap_or_default()
    };
    let mut names: Vec<String> = left.iter().map(|(name, _)| name.clone()).collect();
    names.sort_by(|x, y| {
        let worse = |name: &str| lookup(&left, name).max(lookup(&right, name));
        worse(x).cmp(&worse(y)).then(y.cmp(x))
    });

    let (heading, subtext, _, plot) = rate_naming(a.set);
    let height = (26 * names.len().max(6)) as u32 + 170;
    let mut chart = canvas_with(Grid::new().left("30%").right("10%").top("110").bottom("50"))
        .title(title(
            heading,
            &format!("{subtext} \u{2014} {} against {}", a.slug, b.slug),
        ))
        .legend(Legend::new().top("75"))
        .x_axis(value_axis("count", false))
        .y_axis(Axis::new().type_(AxisType::Category).data(names.clone()));
    for (index, (run, rows)) in [(a, &left), (b, &right)].into_iter().enumerate() {
        let data: Vec<DataPoint> = names
            .iter()
            .map(|name| DataPoint::from(lookup(rows, name) as f64))
            .collect();
        chart = chart.series(
            Bar::new()
                .name(run.slug.clone())
                .item_style(series_colour(index))
                .data(data),
        );
    }
    let path = pair_file(layout, a.set, plot, a, b);
    render_sized(chart, &path, height)?;
    Ok(Some(path))
}

pub fn compare_scaling(layout: &Layout, a: &Run, b: &Run) -> Result<Option<PathBuf>> {
    let (Some(first), Some(second)) = (a.criterion_id(), b.criterion_id()) else {
        return Ok(None);
    };
    let (left, right) = (speedups(layout, &first), speedups(layout, &second));
    if left.is_empty() || right.is_empty() {
        return Ok(None);
    }
    let labels: Vec<String> = left.iter().map(|(w, _, _)| w.to_string()).collect();
    let mut chart = canvas()
        .title(title(
            "Speed-up against worker count",
            &format!(
                "one batch of the set \u{2014} {} against {}",
                a.slug, b.slug
            ),
        ))
        .legend(Legend::new().top("9%"))
        .x_axis(
            Axis::new()
                .type_(AxisType::Category)
                .name("workers")
                .data(labels),
        )
        .y_axis(value_axis("speed-up", false));
    for (index, (run, readings)) in [(a, &left), (b, &right)].into_iter().enumerate() {
        chart = chart.series(
            Line::new()
                .name(run.slug.clone())
                .symbol_size(SymbolSize::Number(9.0))
                .item_style(series_colour(index))
                .line_style(LineStyle::new().width(2.0))
                .data(
                    readings
                        .iter()
                        .map(|(_, _, speedup)| DataPoint::from(*speedup))
                        .collect::<Vec<DataPoint>>(),
                ),
        );
    }
    chart = chart.series(
        Line::new()
            .name("ideal")
            .show_symbol(false)
            .line_style(
                LineStyle::new()
                    .color(Color::Value(GUIDE.to_string()))
                    .type_(LineStyleType::Dashed)
                    .width(2.0),
            )
            .data(
                left.iter()
                    .map(|(w, _, _)| DataPoint::from(*w as f64))
                    .collect::<Vec<DataPoint>>(),
            ),
    );
    let path = pair_file(layout, a.set, "scaling-speedup", a, b);
    render(chart, &path)?;
    Ok(Some(path))
}

// the rest

pub fn scenarios(layout: &Layout) -> Result<Option<PathBuf>> {
    let source = layout.scenario_file("scenarios.csv");
    let Some(rows) = rows::<ScenarioRow>(&source) else {
        return Ok(None);
    };
    let mut names: Vec<String> = Vec::new();
    for row in &rows {
        if !names.contains(&row.name) {
            names.push(row.name.clone());
        }
    }
    let reading = |name: &str, mode: &str| -> Option<f64> {
        rows.iter()
            .find(|row| row.name == name && row.mode == mode)
            .map(|row| row.wall_ms as f64)
    };
    names.sort_by(|a, b| {
        reading(b, "fetch")
            .unwrap_or_default()
            .partial_cmp(&reading(a, "fetch").unwrap_or_default())
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    names.truncate(20);
    names.reverse();
    if names.is_empty() {
        return Ok(None);
    }

    let height = (26 * names.len().max(6)) as u32 + 170;
    let mut chart = canvas_with(Grid::new().left("30%").right("8%").top("110").bottom("50"))
        .title(title(
            "Scenario wall time with and without fetching",
            "one submission per scenario, the twenty slowest under fetching",
        ))
        .legend(Legend::new().top("75"))
        .x_axis(value_axis("milliseconds", false))
        .y_axis(Axis::new().type_(AxisType::Category).data(names.clone()));

    for (index, mode) in ["nofetch", "fetch"].iter().enumerate() {
        let data: Vec<DataPoint> = names
            .iter()
            .map(|name| DataPoint::from(reading(name, mode).unwrap_or_default()))
            .collect();
        chart = chart.series(
            Bar::new()
                .name(*mode)
                .item_style(series_colour(index))
                .data(data),
        );
    }
    let path = layout.plot_file(Section::Scenarios, "fetch-vs-no-fetch.png");
    render_sized(chart, &path, height)?;
    Ok(Some(path))
}

pub fn sets_side_by_side(layout: &Layout, runs: &[Run]) -> Result<Option<PathBuf>> {
    let pick = |set: SampleSet| {
        runs.iter()
            .find(|run| run.set == set && run.kind == RunKind::NoFetch)
    };
    let (Some(benign), Some(malicious)) = (pick(SampleSet::Benign), pick(SampleSet::Malicious))
    else {
        return Ok(None);
    };
    let mut chart = canvas()
        .title(title(
            "Per-input latency against input size",
            "the same documents, benign against malicious, fetching off",
        ))
        .legend(Legend::new().top("9%"))
        .x_axis(value_axis("input bytes", true))
        .y_axis(value_axis("microseconds", true));
    let mut any = false;
    for (index, run) in [benign, malicious].into_iter().enumerate() {
        let Some(rows) = run.table::<LatencyRow>("latency.csv") else {
            continue;
        };
        any = true;
        chart = chart.series(
            Scatter::new()
                .name(run.set.label())
                .symbol_size(SymbolSize::Number(9.0))
                .item_style(series_colour(index))
                .data(
                    rows.iter()
                        .filter(|row| row.bytes > 0 && row.median_us > 0)
                        .map(|row| point(row.bytes as f64, row.median_us as f64))
                        .collect::<Vec<DataPoint>>(),
                ),
        );
    }
    if !any {
        return Ok(None);
    }
    let path = layout.plot_file(Section::Compare, "latency-vs-size.png");
    render(chart, &path)?;
    Ok(Some(path))
}

pub fn machine(layout: &Layout) -> Result<PathBuf> {
    let path = layout.result_file("machine.txt");
    crate::error::write(&path, crate::perf::machine_notes().join("\n") + "\n")?;
    Ok(path)
}

pub fn all(layout: &Layout, truth: &GroundTruth) -> Result<Vec<PathBuf>> {
    let runs = discover(layout, truth);
    let mut written = vec![machine(layout)?];

    for run in &runs {
        for produced in [
            latency(layout, run)?,
            phases(layout, run)?,
            memory(layout, run)?,
            rates(layout, run)?,
            detection(layout, run)?,
            scaling(layout, run)?,
        ]
        .into_iter()
        .flatten()
        {
            written.push(produced);
        }
    }

    for set in [SampleSet::Benign, SampleSet::Malicious] {
        let of_set: Vec<&Run> = runs.iter().filter(|run| run.set == set).collect();
        let table = scaling_table(layout, &of_set);
        if !table.is_empty() {
            let path = layout.set_dir(set).join("scaling.csv");
            table::save(&path, &table)?;
            written.push(path);
        }
        for (index, a) in of_set.iter().enumerate() {
            for b in of_set.iter().skip(index + 1) {
                for produced in [
                    compare_latency(layout, a, b)?,
                    compare_phases(layout, a, b)?,
                    compare_memory(layout, a, b)?,
                    compare_rates(layout, a, b)?,
                    compare_scaling(layout, a, b)?,
                ]
                .into_iter()
                .flatten()
                {
                    written.push(produced);
                }
            }
        }
    }

    for produced in [scenarios(layout)?, sets_side_by_side(layout, &runs)?]
        .into_iter()
        .flatten()
    {
        written.push(produced);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(set: SampleSet, slug: &str, kind: RunKind) -> Run {
        Run {
            set,
            slug: slug.to_string(),
            kind,
            dir: PathBuf::from("/nonexistent"),
        }
    }

    #[test]
    fn a_pair_becomes_a_two_dimensional_point() {
        let rendered = serde_json::to_string(&point(2.0, 5.0)).unwrap();
        assert!(
            rendered.contains('2') && rendered.contains('5'),
            "{rendered}"
        );
    }

    #[test]
    fn the_palette_holds_three_validated_slots() {
        assert_eq!(SERIES.len(), 3);
        for colour in SERIES {
            assert!(colour.starts_with('#') && colour.len() == 7);
        }
    }

    #[test]
    fn series_colours_wrap_rather_than_panic_past_the_palette() {
        let style = serde_json::to_string(&series_colour(7)).unwrap();
        assert!(style.contains(SERIES[1]), "{style}");
    }

    #[test]
    fn a_logarithmic_axis_asks_for_the_log_type() {
        let axis = serde_json::to_string(&value_axis("x", true)).unwrap();
        assert!(axis.contains("log"), "{axis}");
        let linear = serde_json::to_string(&value_axis("x", false)).unwrap();
        assert!(linear.contains("value"), "{linear}");
    }

    #[test]
    fn a_cell_of_rule_names_counts_its_entries() {
        assert_eq!(words(""), 0);
        assert_eq!(words("html.script.disallowed"), 1);
        assert_eq!(words("url.blocklist url.idn"), 2);
    }

    #[test]
    fn rows_and_bars_come_from_the_same_ordering() {
        let rows = vec![
            SampleRow {
                set: "malicious".into(),
                fetching: "no-fetch".into(),
                category: "xss".into(),
                name: "alpha.html".into(),
                policy: "p".into(),
                status: "sanitised".into(),
                status_expected: "sanitised".into(),
                bytes_in: 1,
                bytes_out: 1,
                duration_us: 1,
                fired: String::new(),
                missing: "a b".into(),
                unexpected: String::new(),
                leaked: String::new(),
                lost: String::new(),
                verdict: "leaked".into(),
            },
            SampleRow {
                name: "zeta.html".into(),
                missing: String::new(),
                ..sample_like()
            },
        ];
        let counted = counted(&rows, SampleSet::Malicious);
        assert_eq!(counted[0], ("zeta.html".to_string(), 0));
        assert_eq!(counted[1], ("alpha.html".to_string(), 2));
    }

    fn sample_like() -> SampleRow {
        SampleRow {
            set: "malicious".into(),
            fetching: "no-fetch".into(),
            category: "xss".into(),
            name: "x.html".into(),
            policy: "p".into(),
            status: "sanitised".into(),
            status_expected: "sanitised".into(),
            bytes_in: 1,
            bytes_out: 1,
            duration_us: 1,
            fired: String::new(),
            missing: String::new(),
            unexpected: String::new(),
            leaked: String::new(),
            lost: String::new(),
            verdict: "detected".into(),
        }
    }

    #[test]
    fn a_benign_count_reads_the_columns_that_mean_a_false_positive() {
        let rows = vec![SampleRow {
            set: "benign".into(),
            name: "page.html".into(),
            unexpected: "url.idn".into(),
            lost: "heading".into(),
            ..sample_like()
        }];
        assert_eq!(counted(&rows, SampleSet::Benign)[0].1, 2);
        assert_eq!(counted(&rows, SampleSet::Malicious)[0].1, 0);
    }

    #[test]
    fn a_run_states_the_conditions_it_was_measured_under() {
        assert!(
            run(SampleSet::Benign, "policy-nofetch", RunKind::NoFetch)
                .conditions()
                .ends_with("fetching off")
        );
        assert!(
            run(SampleSet::Benign, "policy-fetch", RunKind::Fetch)
                .conditions()
                .ends_with("fetching on")
        );
        assert!(
            run(
                SampleSet::Benign,
                "permissive",
                RunKind::Custom("permissive".into())
            )
            .conditions()
            .contains("its own fetching mode")
        );
    }

    #[test]
    fn only_the_named_pair_has_a_benchmark_to_read() {
        assert_eq!(
            run(SampleSet::Malicious, "policy-fetch", RunKind::Fetch).criterion_id(),
            Some("malicious-fetch".to_string())
        );
        assert!(
            run(
                SampleSet::Benign,
                "permissive",
                RunKind::Custom("permissive".into())
            )
            .criterion_id()
            .is_none()
        );
    }

    #[test]
    fn a_missing_criterion_run_yields_no_reading() {
        let layout = Layout::discover();
        assert!(criterion_seconds(&layout, "no-such-id", 3).is_none());
        assert!(criterion_workers(&layout, "no-such-id").is_empty());
    }

    #[test]
    fn a_pair_is_named_for_both_of_its_runs() {
        let layout = Layout::discover();
        let a = run(SampleSet::Benign, "policy-nofetch", RunKind::NoFetch);
        let b = run(
            SampleSet::Benign,
            "permissive",
            RunKind::Custom("permissive".into()),
        );
        let path = pair_file(&layout, SampleSet::Benign, "latency", &a, &b);
        assert!(
            path.ends_with("eval/plots/benign/compare/latency/policy-nofetch-vs-permissive.png"),
            "{}",
            path.display()
        );
    }

    #[test]
    fn a_run_with_no_tables_draws_nothing_rather_than_failing() {
        let layout = Layout::discover();
        let missing = run(
            SampleSet::Benign,
            "absent",
            RunKind::Custom("absent".into()),
        );
        assert!(latency(&layout, &missing).unwrap().is_none());
        assert!(phases(&layout, &missing).unwrap().is_none());
        assert!(memory(&layout, &missing).unwrap().is_none());
        assert!(rates(&layout, &missing).unwrap().is_none());
        assert!(detection(&layout, &missing).unwrap().is_none());
        assert!(scaling(&layout, &missing).unwrap().is_none());
    }

    #[test]
    fn discovery_names_the_ground_truth_pair_by_their_mode() {
        let layout = Layout::discover();
        let truth = GroundTruth::load(&layout.ground_truth()).unwrap();
        for found in discover(&layout, &truth) {
            match found.slug.as_str() {
                "policy-nofetch" => assert_eq!(found.kind, RunKind::NoFetch),
                "policy-fetch" => assert_eq!(found.kind, RunKind::Fetch),
                other => assert_eq!(found.kind, RunKind::Custom(other.to_string())),
            }
        }
    }

    #[test]
    fn a_chart_renders_to_a_png_file() {
        let path = std::env::temp_dir().join("xtask-plot-test/chart.png");
        let _ = std::fs::remove_file(&path);
        let chart = canvas()
            .title(title("t", "s"))
            .x_axis(Axis::new().type_(AxisType::Category).data(vec!["a", "b"]))
            .y_axis(value_axis("y", false))
            .series(Bar::new().name("s").data(vec![1, 2]));
        render(chart, &path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert!(bytes.starts_with(&[0x89, b'P', b'N', b'G']), "not a png");
    }
}
