//! CLI surface (bin-only module). Server flags (`--serve`, `--port`,
//! `--bind`) are missing rn.

use std::path::PathBuf;
use std::thread;

use clap::{Args as Arguments, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "web-sanitizer",
    version,
    about = "Sanitise untrusted web content and report every action taken"
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,

    /// Policy TOML file; omit to use the built-in default policy.
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Worker threads for batch processing.
    #[arg(long, value_name = "N", default_value_t = default_jobs())]
    pub jobs: usize,

    /// Human-readable progress on stderr; repeat (-vv) to include fragments.
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Fetch the sub-resources an HTML input references (off by default).
    #[arg(long)]
    pub fetch_subresources: bool,

    /// Requests per input while fetching sub-resources.
    #[arg(long, value_name = "N")]
    pub subresource_max_requests: Option<u32>,

    /// Bytes summed over all sub-resources of one input.
    #[arg(long, value_name = "BYTES")]
    pub subresource_max_bytes: Option<u64>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Process files, directories, or URLs from the command line.
    Scan(ScanArgs),
    /// Run an HTTP server accepting sanitisation requests.
    Serve(ServeArgs),
}

#[derive(Debug, Arguments)]
pub struct ScanArgs {
    /// Files, directories, or http(s) URLs to process.
    pub inputs: Vec<String>,
    /// File with one input (path, directory, or URL) per line; `#` comments.
    #[arg(long, value_name = "FILE")]
    pub input_list: Option<PathBuf>,
    /// Output directory for sanitised files and report.json.
    #[arg(long, value_name = "DIR", default_value = "out")]
    pub out: PathBuf,
}

#[derive(Debug, Arguments)]
pub struct ServeArgs {
    #[arg(long, default_value = "127.0.0.1")]
    pub bind: String,
    #[arg(long, default_value_t = 3000)]
    pub port: u16,
}

impl Args {
    /// Apply the flags that override policy values.
    pub fn override_policy(&self, policy: &mut web_sanitizer::Policy) {
        if self.fetch_subresources {
            policy.subresources.fetch_subresources = true;
        }
        if let Some(max) = self.subresource_max_requests {
            policy.subresources.max_requests = max;
        }
        if let Some(max) = self.subresource_max_bytes {
            policy.subresources.max_total_bytes = max;
        }
    }
}

fn default_jobs() -> usize {
    thread::available_parallelism().map_or(1, |n| n.get())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_and_overrides_parse() {
        let args = Args::parse_from(["web-sanitizer", "scan", "a.html", "b.html"]);

        if let Command::Scan(scan_args) = args.command {
            assert_eq!(scan_args.inputs, ["a.html", "b.html"]);
            assert_eq!(scan_args.out, PathBuf::from("out"));
            assert!(args.jobs >= 1);
            assert_eq!(args.verbose, 0);

            let args = Args::parse_from([
                "web-sanitizer",
                "--input-list",
                "list.txt",
                "--policy",
                "p.toml",
                "--jobs",
                "4",
                "--out",
                "result",
                "-vv",
            ]);
            assert_eq!(scan_args.input_list, Some(PathBuf::from("list.txt")));
            assert_eq!(args.policy, Some(PathBuf::from("p.toml")));
            assert_eq!(args.jobs, 4);
            assert_eq!(scan_args.out, PathBuf::from("result"));
            assert_eq!(args.verbose, 2);
        }
    }

    #[test]
    fn the_safe_state_needs_no_flag() {
        let args = Args::parse_from(["web-sanitizer", "a.html"]);
        assert!(!args.fetch_subresources);
        let mut policy = web_sanitizer::Policy::builtin();
        args.override_policy(&mut policy);
        assert!(!policy.subresources.fetch_subresources);
    }

    #[test]
    fn flags_override_the_policy_file() {
        let args = Args::parse_from([
            "web-sanitizer",
            "a.html",
            "--fetch-subresources",
            "--subresource-max-requests",
            "4",
            "--subresource-max-bytes",
            "1024",
        ]);
        let mut policy = web_sanitizer::Policy::builtin();
        args.override_policy(&mut policy);
        assert!(policy.subresources.fetch_subresources);
        assert_eq!(policy.subresources.max_requests, 4);
        assert_eq!(policy.subresources.max_total_bytes, 1024);
    }
}
