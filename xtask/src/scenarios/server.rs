use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::error::{Result, XtaskError};

use super::origin::{reachable, wait_until};

pub struct Sanitiser {
    base: String,
    child: Option<Child>,
}

impl Sanitiser {
    pub fn base(&self) -> &str {
        &self.base
    }

    pub fn endpoint(&self) -> String {
        format!("{}/v1/resources", self.base())
    }

    fn health(base: &str) -> String {
        format!("{base}/health")
    }

    pub fn attach(base: &str) -> Sanitiser {
        Sanitiser {
            base: base.trim_end_matches('/').to_string(),
            child: None,
        }
    }

    pub fn start(root: &Path, policy: &str, port: u16, boot: Duration) -> Result<Sanitiser> {
        let base = format!("http://127.0.0.1:{port}");
        if reachable(&Sanitiser::health(&base)) {
            return Err(XtaskError::Harness(format!(
                "something already listens on {base}; stop it or pass another port"
            )));
        }
        let binary = root.join("target/release/wsrs");
        if !binary.is_file() {
            return Err(XtaskError::Harness(format!(
                "{} is missing; run cargo build --release first",
                binary.display()
            )));
        }
        println!("starting the sanitiser on {base} with {policy}");
        let child = Command::new(&binary)
            .arg("--policy")
            .arg(policy)
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .current_dir(root)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|source| XtaskError::Read {
                path: binary.clone(),
                source,
            })?;

        let server = Sanitiser {
            base,
            child: Some(child),
        };
        wait_until(&Sanitiser::health(&server.base), boot, "sanitiser")?;
        println!();
        Ok(server)
    }
}

impl Drop for Sanitiser {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::Layout;

    #[test]
    fn an_attached_server_owns_no_child_and_kills_nothing_on_drop() {
        let server = Sanitiser::attach("http://127.0.0.1:3000/");
        assert_eq!(server.base(), "http://127.0.0.1:3000");
        assert_eq!(server.endpoint(), "http://127.0.0.1:3000/v1/resources");
        assert!(server.child.is_none());
    }

    #[test]
    fn the_health_url_hangs_off_the_base() {
        assert_eq!(
            Sanitiser::health("http://127.0.0.1:3000"),
            "http://127.0.0.1:3000/health"
        );
    }

    #[test]
    fn starting_without_a_release_binary_says_so() {
        let missing = Layout::discover().join("target/nonexistent-root");
        let error = match Sanitiser::start(&missing, "builtin", 3999, Duration::from_millis(10)) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("a missing binary must not start a server"),
        };
        assert!(error.contains("cargo build --release"), "{error}");
    }
}
