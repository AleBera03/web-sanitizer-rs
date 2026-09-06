use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use crate::error::{Result, XtaskError};

pub const IMAGE: &str = "evil-origin";
pub const CONTAINER: &str = "evil-origin";
pub const RELEASE_URL: &str = "https://github.com/AleBera03/web-sanitizer-rs/releases/download/evil-origin-v1/evil-origin.zip";

pub struct Origin {
    base: String,
}

impl Origin {
    pub fn new(base: &str) -> Origin {
        Origin {
            base: base.trim_end_matches('/').to_string(),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base, path)
    }

    pub fn listening(&self) -> bool {
        reachable(&self.url("/scenarios"))
    }

    pub fn ensure(&self, root: &Path, boot: Duration) -> Result<()> {
        if self.listening() {
            println!("evil-origin already listening on {}", self.base);
            return Ok(());
        }
        if !image_present()? {
            let tarball = root.join("scenarios/evil-origin.tar");
            if !tarball.is_file() {
                return Err(XtaskError::Harness(format!(
                    "{} is missing; download {RELEASE_URL} and unpack evil-origin.tar into scenarios/",
                    tarball.display()
                )));
            }
            println!("loading the {IMAGE} image");
            run_docker(&["load", "-i", &tarball.to_string_lossy()])?;
        }
        let _ = run_docker(&["container", "rm", "-f", CONTAINER]);
        println!("starting the {CONTAINER} container");
        run_docker(&["run", "-d", "-p", "3100:3100", "--name", CONTAINER, IMAGE])?;
        wait_until(&self.url("/scenarios"), boot, "evil-origin")
    }
}

fn image_present() -> Result<bool> {
    let found = Command::new("docker")
        .args(["image", "inspect", IMAGE])
        .output()
        .map_err(|source| XtaskError::Read {
            path: PathBuf::from("docker"),
            source,
        })?;
    Ok(found.status.success())
}

fn run_docker(args: &[&str]) -> Result<()> {
    let done = Command::new("docker")
        .args(args)
        .output()
        .map_err(|source| XtaskError::Read {
            path: PathBuf::from("docker"),
            source,
        })?;
    match done.status.success() {
        true => Ok(()),
        false => Err(XtaskError::Harness(format!(
            "docker {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&done.stderr).trim()
        ))),
    }
}

pub fn reachable(url: &str) -> bool {
    ureq::get(url)
        .config()
        .timeout_global(Some(Duration::from_secs(2)))
        .build()
        .call()
        .is_ok()
}

pub fn wait_until(url: &str, limit: Duration, label: &str) -> Result<()> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if reachable(url) {
            return Ok(());
        }
        print!(".");
        let _ = std::io::stdout().flush();
        std::thread::sleep(Duration::from_millis(400));
    }
    Err(XtaskError::Harness(format!(
        "{label} did not answer at {url} within {:?}",
        limit
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_base_url_loses_its_trailing_slash() {
        let origin = Origin::new("http://localhost:3100/");
        assert_eq!(origin.url("/scenarios"), "http://localhost:3100/scenarios");
    }

    #[test]
    fn a_port_nobody_listens_on_is_not_reachable() {
        assert!(!reachable("http://127.0.0.1:1/nothing"));
    }

    #[test]
    fn waiting_for_a_dead_address_reports_the_label_and_the_url() {
        let error = wait_until(
            "http://127.0.0.1:1/nothing",
            Duration::from_millis(600),
            "fixture",
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(text.contains("fixture") && text.contains("127.0.0.1:1"));
    }
}
