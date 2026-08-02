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
use web_sanitizer::fetch::DisabledFetcher;
use web_sanitizer::input;
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
    let policy = match &args.policy {
        Some(path) => Policy::load(path).map_err(|e| e.to_string())?,
        None => Policy::builtin(),
    };

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

    let engine = Engine::new(policy, Arc::new(DisabledFetcher)).map_err(|e| e.to_string())?;

    let mut output_index = 0usize;
    let mut write_failures = 0usize;
    let verbose = args.verbose;
    let out_dir = args.out.clone();
    let mut report = engine.process_batch(gathered.inputs, args.jobs, |input_report, sanitised| {
        if verbose > 0 {
            log_input(input_report, verbose);
        }
        if let Some(bytes) = sanitised {
            match output_name(output_index, &input_report.source) {
                Ok(o) => {
                    let pathfile = Path::new(&o);
                    let path = out_dir.join(pathfile);
                    if let Err(e) = fs::write(&path, bytes) {
                        eprintln!("error: cannot write {}: {e}", path.display());
                        write_failures += 1;
                    }
                }
                Err(e) => {
                    eprintln!("{}", e);
                    write_failures += 1;
                }
            }
        }
        output_index += 1;
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

fn prepare_out_dir(out: &Path) -> Result<(), String> {
    fs::create_dir_all(out).map_err(|e| format!("cannot create {}: {e}", out.display()))?;
    // check with probe file writability of out_dir
    let probe = out.join(".write-probe");
    fs::write(&probe, b"")
        .map_err(|e| format!("output directory {} is not writable: {e}", out.display()))?;
    let _ = fs::remove_file(&probe);
    Ok(())
}

/// Output file name: _input index_ + _name derived from the sanitised input name_.
/// The index prefix aims to do not confuse same named-files between different dirs.
fn output_name(index: usize, source: &str) -> Result<String, String> {
    let base = Path::new(source)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .ok_or_else(|| "impossible retrieve a filename/extension".to_string())?;
    let safe: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect();
    Ok(format!("{index}-{safe}"))
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
    fn output_names_are_indexed_and_sanitised() {
        assert_eq!(output_name(3, "/tmp/dir/page.html").unwrap(), "3-page.html");
        assert_eq!(
            output_name(0, "http://example.com/a/b.html").unwrap(),
            "0-b.html"
        );
        assert_eq!(output_name(1, "we ird$.html").unwrap(), "1-we_ird_.html");
        // A bare-host URL falls back to the host as the name.
        assert_eq!(
            output_name(2, "http://example.com/").unwrap(),
            "2-example.com"
        );
    }
}
