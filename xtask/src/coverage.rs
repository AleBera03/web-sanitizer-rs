use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use crate::error::{Result, XtaskError};
use crate::paths::Layout;

pub const IMAGE: &str = "xd009642/tarpaulin:latest";
pub const MOUNT: &str = "/volume";
pub const REPORT: &str = "tarpaulin-report.html";
const CARGO_HOME: &str = "/volume/target/coverage/cargo";
const TARGET_DIR: &str = "/volume/target/coverage/build";

pub struct Run {
    pub image: String,
    pub local: bool,
    pub extra: Vec<String>,
}

pub fn run(layout: &Layout, run: &Run) -> Result<PathBuf> {
    let root = layout.root();
    let report = layout.coverage().join(REPORT);
    let started = SystemTime::now();
    let outcome = match run.local {
        true => spawn("cargo", &tarpaulin_args(&run.extra), root),
        false => spawn("docker", &docker_args(root, run), root),
    };
    match outcome {
        Ok(()) => Ok(report),
        // a failing test stops tarpaulin short of a clean exit, yet the lines it
        // did trace are already on disk and worth naming
        Err(error) => {
            if written_since(&report, started) {
                println!(
                    "\nthe run ended badly, its report is at {}",
                    report.display()
                );
            }
            Err(error)
        }
    }
}

fn written_since(report: &Path, moment: SystemTime) -> bool {
    std::fs::metadata(report)
        .and_then(|meta| meta.modified())
        .map(|written| written >= moment)
        .unwrap_or(false)
}

fn tarpaulin_args(extra: &[String]) -> Vec<String> {
    let mut args = vec!["tarpaulin".to_string()];
    args.extend(extra.iter().cloned());
    args
}

fn docker_args(root: &Path, run: &Run) -> Vec<String> {
    let mut args = vec![
        "run".to_string(),
        "--rm".to_string(),
        "--security-opt".to_string(),
        "seccomp=unconfined".to_string(),
        "-v".to_string(),
        format!("{}:{MOUNT}", root.display()),
        "-w".to_string(),
        MOUNT.to_string(),
        "-e".to_string(),
        format!("CARGO_HOME={CARGO_HOME}"),
        "-e".to_string(),
        format!("CARGO_TARGET_DIR={TARGET_DIR}"),
    ];
    if let Some(owner) = owner_of(root) {
        args.push("--user".to_string());
        args.push(owner);
    }
    args.push(run.image.clone());
    args.push("cargo".to_string());
    args.extend(tarpaulin_args(&run.extra));
    args
}

#[cfg(unix)]
fn owner_of(root: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;

    let meta = std::fs::metadata(root).ok()?;
    Some(format!("{}:{}", meta.uid(), meta.gid()))
}

#[cfg(not(unix))]
fn owner_of(_root: &Path) -> Option<String> {
    None
}

fn spawn(program: &str, args: &[String], root: &Path) -> Result<()> {
    println!("{program} {}", args.join(" "));
    let status = Command::new(program)
        .args(args)
        .current_dir(root)
        .status()
        .map_err(|source| XtaskError::Read {
            path: PathBuf::from(program),
            source,
        })?;
    match status.success() {
        true => Ok(()),
        false => Err(XtaskError::Harness(format!(
            "{program} {} failed with {status}",
            args.join(" ")
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(local: bool, extra: &[&str]) -> Run {
        Run {
            image: IMAGE.to_string(),
            local,
            extra: extra.iter().map(|arg| arg.to_string()).collect(),
        }
    }

    #[test]
    fn the_host_run_is_just_cargo_tarpaulin() {
        assert_eq!(tarpaulin_args(&[]), vec!["tarpaulin".to_string()]);
    }

    #[test]
    fn extra_arguments_reach_tarpaulin_unchanged() {
        let args = tarpaulin_args(&["--out".to_string(), "Lcov".to_string()]);
        assert_eq!(args, vec!["tarpaulin", "--out", "Lcov"]);
    }

    #[test]
    fn the_container_mounts_the_root_and_works_inside_it() {
        let args = docker_args(Path::new("/home/user/project"), &sample(false, &[]));
        let line = args.join(" ");
        assert!(line.contains(&format!("/home/user/project:{MOUNT}")));
        assert!(line.contains(&format!("-w {MOUNT}")));
        assert!(line.ends_with("cargo tarpaulin"));
    }

    #[test]
    fn the_container_relaxes_seccomp_for_ptrace() {
        let args = docker_args(Path::new("/project"), &sample(false, &[]));
        assert!(args.join(" ").contains("--security-opt seccomp=unconfined"));
    }

    #[test]
    fn cargo_caches_and_artefacts_stay_inside_the_mount() {
        let args = docker_args(Path::new("/project"), &sample(false, &[]));
        let line = args.join(" ");
        assert!(line.contains(&format!("CARGO_HOME={CARGO_HOME}")));
        assert!(line.contains(&format!("CARGO_TARGET_DIR={TARGET_DIR}")));
    }

    #[test]
    fn the_image_comes_before_the_command_it_runs() {
        let mut run = sample(false, &[]);
        run.image = "local/tarpaulin".to_string();
        let args = docker_args(Path::new("/project"), &run);
        let image = args
            .iter()
            .position(|arg| arg == "local/tarpaulin")
            .unwrap();
        let cargo = args.iter().position(|arg| arg == "cargo").unwrap();
        assert!(image < cargo);
    }

    #[test]
    fn extra_arguments_survive_the_container_wrapping() {
        let args = docker_args(Path::new("/project"), &sample(false, &["--engine", "llvm"]));
        assert!(args.join(" ").ends_with("cargo tarpaulin --engine llvm"));
    }

    #[cfg(unix)]
    #[test]
    fn a_unix_run_carries_the_owner_of_the_tree() {
        let dir = std::env::temp_dir();
        let owner = owner_of(&dir).unwrap();
        assert!(owner.contains(':'));
        assert!(owner.split(':').all(|part| part.parse::<u32>().is_ok()));
    }

    #[test]
    fn a_report_older_than_the_run_is_not_this_runs_work() {
        let path = std::env::temp_dir().join("xtask-coverage-report.html");
        std::fs::write(&path, "old").unwrap();
        let started = SystemTime::now() + std::time::Duration::from_secs(60);
        assert!(!written_since(&path, started));
        assert!(written_since(&path, SystemTime::UNIX_EPOCH));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_report_that_was_never_written_counts_as_missing() {
        let missing = Path::new("/nonexistent/coverage/tarpaulin-report.html");
        assert!(!written_since(missing, SystemTime::UNIX_EPOCH));
    }

    #[test]
    fn a_path_that_does_not_exist_has_no_owner_to_borrow() {
        assert!(owner_of(Path::new("/nonexistent/coverage/root")).is_none());
    }
}
