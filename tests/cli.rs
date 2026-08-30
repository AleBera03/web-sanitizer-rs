//! End-to-end tests: run the actual binary and assert exit-code
//! contract, output files, and report JSON shape.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn run(args: &[&str], cwd: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_wsrs")) // wsrs name of binary
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("binary runs")
}

fn report_json(out_dir: &Path) -> serde_json::Value {
    let text = fs::read_to_string(out_dir.join("report.json")).expect("report.json exists");
    serde_json::from_str(&text).expect("report.json is valid JSON")
}

#[test]
fn no_subcommand_is_usage_error_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let output = run(&[], dir.path());
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Usage"));
}

#[test]
fn no_inputs_is_usage_error_exit_2() {
    let dir = tempfile::tempdir().unwrap();
    let output = run(&["scan"], dir.path());
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("no inputs"));
}

#[test]
fn benign_file_exits_0_writes_output_and_report() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("page.html"), "<p>hello</p>").unwrap();

    let output = run(&["scan", "page.html", "--out", "result"], dir.path());
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let sanitised = dir.path().join("result/0-page.html");
    assert_eq!(fs::read_to_string(sanitised).unwrap(), "<p>hello</p>");

    let report = report_json(&dir.path().join("result"));
    assert_eq!(report["run"]["policy"], "builtin");
    assert_eq!(report["run"]["inputs_total"], 1);
    assert_eq!(report["run"]["inputs_ok"], 1);
    assert_eq!(report["inputs"][0]["status"], "clean");
    assert_eq!(report["inputs"][0]["bytes_in"], 12);

    let stdout: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout is the report JSON");
    assert_eq!(stdout, report);
}

#[test]
fn budget_refusal_exits_1_and_batch_continues() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("policy.toml"),
        "[budgets]\nmax_input_bytes = 4\n",
    )
    .unwrap();
    fs::write(dir.path().join("ok.html"), "1234").unwrap(); // exactly at budget
    fs::write(dir.path().join("big.html"), "12345").unwrap(); // one byte over

    let output = run(
        &[
            "--policy",
            "policy.toml",
            "scan",
            "big.html",
            "ok.html",
            "--out",
            "result",
        ],
        dir.path(),
    );
    assert_eq!(output.status.code(), Some(1));

    let report = report_json(&dir.path().join("result"));
    assert_eq!(report["run"]["inputs_total"], 2);
    assert_eq!(report["run"]["inputs_refused"], 1);
    assert_eq!(report["run"]["inputs_ok"], 1);
    assert_eq!(report["inputs"][0]["status"], "budget_exceeded");
    assert_eq!(report["inputs"][1]["status"], "clean");
    // Refused input produced no output file; the ok one did.
    assert!(!dir.path().join("result/0-big.html").exists());
    assert!(dir.path().join("result/1-ok.html").exists());
}

#[test]
fn bad_policy_file_exits_2() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("policy.toml"),
        "[budgets]\nmax_input_bytez = 1\n",
    )
    .unwrap();
    fs::write(dir.path().join("page.html"), "x").unwrap();

    let output = run(
        &["--policy", "policy.toml", "scan", "page.html"],
        dir.path(),
    );
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("policy"));
}

#[test]
fn unsupported_scheme_is_reported_not_fetched() {
    let dir = tempfile::tempdir().unwrap();
    let output = run(
        &["scan", "ftp://example.com/x", "--out", "result"],
        dir.path(),
    );
    // errored != refused, so the exit code is 0
    // the batch completed, but one input failed
    assert_eq!(output.status.code(), Some(0));

    let report = report_json(&dir.path().join("result"));
    assert_eq!(report["inputs"][0]["status"], "unsupported_scheme");
    assert_eq!(report["run"]["inputs_errored"], 1);
}

#[cfg(unix)]
#[test]
fn escaping_symlink_appears_as_skipped_symlink_report() {
    let outside = tempfile::tempdir().unwrap();
    fs::write(outside.path().join("secret.html"), "x").unwrap();

    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    fs::create_dir(&tree).unwrap();
    fs::write(tree.join("ok.html"), "<p>ok</p>").unwrap();
    std::os::unix::fs::symlink(outside.path().join("secret.html"), tree.join("leak.html")).unwrap();

    let output = run(&["scan", "tree", "--out", "result"], dir.path());
    assert_eq!(output.status.code(), Some(0));

    let report = report_json(&dir.path().join("result"));
    assert_eq!(report["run"]["inputs_total"], 2);
    let statuses: Vec<&str> = report["inputs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["status"].as_str().unwrap())
        .collect();
    assert!(statuses.contains(&"clean"));
    assert!(statuses.contains(&"skipped_symlink"));
}

#[cfg(unix)]
#[test]
fn unwritable_out_dir_exits_2_before_processing() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("page.html"), "x").unwrap();
    let locked = dir.path().join("locked");
    fs::create_dir(&locked).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o555)).unwrap();
    if fs::write(locked.join("probe"), b"").is_ok() {
        return; // running as root: permissions are not enforced, nothing to test
    }

    let output = run(&["scan", "page.html", "--out", "locked"], dir.path());
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("not writable"));
}
