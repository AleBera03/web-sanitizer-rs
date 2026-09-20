use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use url::Url;
use web_sanitizer::Engine;
use web_sanitizer::fetch::HttpFetcher;
use web_sanitizer::fixture::{FixtureServer, Resource};
use web_sanitizer::input::InputSource;
use web_sanitizer::policy::Policy;

const WORKERS: [usize; 6] = [1, 2, 4, 6, 8, 12];
/// The batch is whole passes over the set, so every input is processed the same
/// number of times and no document is weighted more than another.
const CYCLES: usize = 3;
const LATENCY: Duration = Duration::from_millis(2);
const MAX_INPUT_BYTES: u64 = 512 * 1024;
const MAX_REQUESTS: u32 = 8;

const ONE_PIXEL_PNG: [u8; 69] = [
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48, 0x44, 0x52,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
    0xde, 0x00, 0x00, 0x00, 0x0c, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0x00,
    0x00, 0x03, 0x01, 0x01, 0x00, 0xc9, 0xfe, 0x92, 0xef, 0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4e,
    0x44, 0xae, 0x42, 0x60, 0x82,
];

/// Inputs above the cap are left out so one enormous document does not decide
/// the batch time on its own.
fn corpus(set: &str) -> Vec<(String, Vec<u8>)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!("corpus/{set}"));
    let mut inputs: Vec<(String, Vec<u8>)> = fs::read_dir(&dir)
        .unwrap_or_else(|_| panic!("corpus/{set} exists"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .filter(|p| p.file_name().is_some_and(|n| n != "blocklist.txt"))
        .filter(|p| {
            fs::metadata(p)
                .map(|m| m.len() <= MAX_INPUT_BYTES)
                .unwrap_or(false)
        })
        .map(|p| {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            (name, fs::read(&p).unwrap())
        })
        .collect();
    inputs.sort();
    assert!(!inputs.is_empty(), "corpus/{set} is empty");
    inputs
}

fn engine(policy: Policy) -> Engine {
    let fetcher = Arc::new(HttpFetcher::new(&policy.fetch, &policy.ssrf).unwrap());
    Engine::new(policy, fetcher).unwrap()
}

fn content_type(name: &str) -> &'static str {
    match name.rsplit('.').next().unwrap_or("") {
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "text/javascript",
        "svg" => "image/svg+xml",
        "xml" => "application/xml",
        "png" => "image/png",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        _ => "application/octet-stream",
    }
}

fn bytes_batch(inputs: &[(String, Vec<u8>)]) -> Vec<InputSource> {
    (0..inputs.len() * CYCLES)
        .map(|k| {
            let (name, data) = &inputs[k % inputs.len()];
            InputSource::Bytes {
                name: format!("{k}-{name}"),
                data: data.clone(),
            }
        })
        .collect()
}

fn by_extension(path: &str) -> Option<Resource> {
    let clean = path.split('?').next().unwrap_or(path);
    match clean.rsplit('.').next().unwrap_or("") {
        "css" => Some(Resource::new(
            "text/css",
            b"body { margin: 0; color: #333; }\n".to_vec(),
        )),
        _ => Some(Resource::new("image/png", ONE_PIXEL_PNG.to_vec())),
    }
}

// every absolute reference is pointed back at the fixture, so a fetching run
// measures the sanitiser against a known latency rather than the open web
fn served_batch(server: &FixtureServer, inputs: &[(String, Vec<u8>)]) -> Vec<InputSource> {
    let base = server.url("/r/");
    (0..inputs.len() * CYCLES)
        .map(|k| {
            let (name, data) = &inputs[k % inputs.len()];
            let kind = content_type(name);
            let body = match kind == "text/html" {
                true => {
                    let page = String::from_utf8_lossy(data)
                        .replace("https://", "\u{0}")
                        .replace("http://", "\u{0}")
                        .replace('\u{0}', &base);
                    let refs = format!(
                        "<link rel=\"stylesheet\" href=\"/s/{k}.css\"><img src=\"/i/{k}.png\" alt=\"\">"
                    );
                    match page.contains("<body>") {
                        true => page.replacen("<body>", &format!("<body>{refs}"), 1),
                        false => format!("{refs}{page}"),
                    }
                    .into_bytes()
                }
                false => data.clone(),
            };
            let path = format!("/p/{k}-{name}");
            server.route(&path, Resource::new(kind, body));
            InputSource::Url(Url::parse(&server.url(&path)).unwrap())
        })
        .collect()
}

fn throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.sample_size(10);
    group.warm_up_time(Duration::from_secs(2));
    group.measurement_time(Duration::from_secs(8));

    let server = FixtureServer::start(LATENCY);
    server.fallback(by_extension);

    for set in ["benign", "malicious"] {
        let inputs = corpus(set);
        let total_bytes: u64 = bytes_batch(&inputs)
            .iter()
            .map(|i| match i {
                InputSource::Bytes { data, .. } => data.len() as u64,
                _ => 0,
            })
            .sum();
        group.throughput(Throughput::Bytes(total_bytes));

        let local = engine(Policy::builtin());
        for &jobs in &WORKERS {
            let id = BenchmarkId::new(format!("{set}-no-fetch"), jobs);
            group.bench_with_input(id, &jobs, |b, &jobs| {
                b.iter_batched(
                    || bytes_batch(&inputs),
                    |batch| local.process_batch(batch, jobs, |_, _| {}),
                    criterion::BatchSize::LargeInput,
                )
            });
        }

        let mut policy = Policy::builtin();
        policy.subresources.fetch_subresources = true;
        policy.subresources.max_requests = MAX_REQUESTS;
        let fetching = engine(policy);
        for &jobs in &WORKERS {
            let id = BenchmarkId::new(format!("{set}-fetch"), jobs);
            group.bench_with_input(id, &jobs, |b, &jobs| {
                b.iter_batched(
                    || served_batch(&server, &inputs),
                    |batch| fetching.process_batch(batch, jobs, |_, _| {}),
                    criterion::BatchSize::LargeInput,
                )
            });
        }
    }
    group.finish();
}

criterion_group!(benches, throughput);
criterion_main!(benches);
