//! CLI front-end: parse args, load config, call the library, write outputs.
//! No sanitisation logic lives here

mod args;

use std::fs;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use std::error::Error;

use web_sanitizer::Engine;
use web_sanitizer::fetch::HttpFetcher;
use web_sanitizer::input::{self, OutputName};
use web_sanitizer::policy::Policy;
use web_sanitizer::report::{InputReport, InputStatus};

// CONSTANT
/// Exit code for configuration/usage errors
const EXIT_CONFIG: u8 = 2;

fn main() -> ExitCode {
    let args = args::Args::parse();
    match run(args) {
        Ok(code) => ExitCode::from(code),
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(EXIT_CONFIG)
        }
    }
}

fn run(args: args::Args) -> Result<u8, Box<dyn Error>> {
    let mut policy = match &args.policy {
        Some(path) => Policy::load(path).map_err(|e| e.to_string())?,
        None => Policy::builtin(),
    };
    args.override_policy(&mut policy);
    warn_about_posture(&policy);

    let gathered = input::gather(
        &args.inputs,
        args.input_list.as_deref(),
        &policy.input.extensions,
    )
    .map_err(|e| e.to_string())?;
    if gathered.inputs.is_empty() && gathered.skipped_symlinks.is_empty() {
        return Err("no inputs (pass files, directories, URLs, or --input-list)".into());
    }

    // unwritable output directory is detected before processing starts
    prepare_out_dir(&args.out)?;

    // the fetch client is built from the policy that is about to be moved into
    // the engine, guard included: there is no unguarded client to build
    let fetcher =
        Arc::new(HttpFetcher::new(&policy.fetch, &policy.ssrf).map_err(|e| e.to_string())?);
    let engine = Engine::new(policy, fetcher).map_err(|e| e.to_string())?;

    let mut write_failures = 0usize;
    let verbose = args.verbose;
    let out_dir = args.out.clone();
    let mut report = engine.process_batch(gathered.inputs, args.jobs, |index, outcome| {
        if verbose > 0 {
            log_input(&outcome.report, verbose);
        }
        if let Some(bytes) = outcome.sanitized.as_deref() {
            let path = out_dir.join(OutputName::derive(index, &outcome.report.source).file());
            if let Err(e) = fs::write(&path, bytes) {
                eprintln!("error: cannot write {}: {e}", path.display());
                write_failures += 1;
            }
        }
        // sub-resource bodies live in their parent's own directory, which the
        // engine named from the same stem, under names it derived from the
        // sniffed type
        for asset in &outcome.assets {
            let path = out_dir.join(&asset.path);
            let written = path
                .parent()
                .map(fs::create_dir_all)
                .unwrap_or(Ok(()))
                .and_then(|()| fs::write(&path, &asset.bytes));
            if let Err(e) = written {
                eprintln!("error: cannot write {}: {e}", path.display());
                write_failures += 1;
            }
        }
    });

    // symlinks the walker refused, appended as skipped_symlink reports
    for path in gathered.skipped_symlinks {
        let id = format!("input-{}", report.inputs.len());
        if verbose > 0 {
            eprintln!("skipped_symlink {} (escapes tree root)", path.display());
        }
        report.push(InputReport {
            id,
            source: path.display().to_string(),
            status: InputStatus::SkippedSymlink,
            bytes_in: 0,
            bytes_out: 0,
            duration_ms: 0,
            actions: Vec::new(),
            error: Some("symlink resolves outside the tree root".to_string()),
            subresources: None,
        });
    }

    let json = serde_json::to_string_pretty(&report)
        .map_err(|e| format!("cannot serialise report: {e}"))?;
    let report_path = args.out.join("report.json");
    fs::write(&report_path, &json)
        .map_err(|e| format!("cannot write {}: {e}", report_path.display()))?;
    println!("{json}");

    if write_failures > 0 {
        // The environment brokes mid-run (disk full, permissions changed):
        // same class as an unwritable output dir
        return Err(format!("{write_failures} sanitised output(s) could not be written").into());
    }
    Ok(report.exit_code() as u8)
}

/// State the protection posture on stderr before anything runs. The guard is
/// always on, so what is left to warn about are the narrow exemptions a policy
/// file can open.
fn warn_about_posture(policy: &Policy) {
    if !policy.ssrf.allow_hosts.is_empty() {
        eprintln!(
            "warning: {} host(s) bypass the SSRF deny table via ssrf.allow_hosts",
            policy.ssrf.allow_hosts.len()
        );
    }
}

fn prepare_out_dir(out: &Path) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    // check with probe file writability of out_dir
    let probe = out.join(".write-probe");
    fs::write(&probe, b"")
        .map_err(|e| format!("output directory {} is not writable: {e}", out.display()))?;
    let _ = fs::remove_file(&probe);
    Ok(())
}

fn log_input(report: &InputReport, verbose: u8) {
    let status = serde_json::to_value(report.status)
        .ok()
        .and_then(|v| v.as_str().map(String::from))
        .unwrap_or_default();
    match &report.error {
        Some(cause) => eprintln!("{status} {} — {cause}", report.source),
        None => eprintln!(
            "{status} {} ({} -> {} bytes, {} ms, {} action(s))",
            report.source,
            report.bytes_in,
            report.bytes_out,
            report.duration_ms,
            report.actions.len()
        ),
    }
    for action in &report.actions {
        eprint!(
            "  {} {} at line {} offset {}",
            action.rule_id,
            serde_json::to_value(action.action)
                .ok()
                .and_then(|v| v.as_str().map(String::from))
                .unwrap_or_default(),
            action.location.line,
            action.location.byte_offset
        );
        if verbose > 1 {
            eprint!(": {:?}", action.original);
        }
        eprintln!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_output_directory_is_created_and_left_clean() {
        let parent = tempfile::tempdir().unwrap();
        let out = parent.path().join("nested/out");
        prepare_out_dir(&out).unwrap();
        assert!(out.is_dir());
        // the probe must not survive the check that used it
        assert_eq!(fs::read_dir(&out).unwrap().count(), 0);
    }

    #[test]
    fn an_output_path_that_cannot_be_a_directory_fails_before_processing() {
        // EC-5: the run stops at configuration time, not halfway through a batch
        let dir = tempfile::tempdir().unwrap();
        let occupied = dir.path().join("file");
        fs::write(&occupied, b"").unwrap();
        assert!(prepare_out_dir(&occupied).is_err());
    }
}
