//! CLI surface (bin-only module). Server flags (`--serve`, `--port`,
//! `--bind`) are missing rn.

use std::path::PathBuf;
use std::thread;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "web-sanitizer",
    version,
    about = "Sanitise untrusted web content and report every action taken"
)]
pub struct Args {
    /// Files, directories, or http(s) URLs to process.
    pub inputs: Vec<String>,

    /// File with one input (path, directory, or URL) per line; `#` comments.
    #[arg(long, value_name = "FILE")]
    pub input_list: Option<PathBuf>,

    /// Policy TOML file; omit to use the built-in default policy.
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Worker threads for batch processing.
    #[arg(long, value_name = "N", default_value_t = default_jobs())]
    pub jobs: usize,

    /// Output directory for sanitised files and report.json.
    #[arg(long, value_name = "DIR", default_value = "out")]
    pub out: PathBuf,

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
        let args = Args::parse_from(["web-sanitizer", "a.html", "b.html"]);
        assert_eq!(args.inputs, ["a.html", "b.html"]);
        assert_eq!(args.out, PathBuf::from("out"));
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
        assert_eq!(args.input_list, Some(PathBuf::from("list.txt")));
        assert_eq!(args.policy, Some(PathBuf::from("p.toml")));
        assert_eq!(args.jobs, 4);
        assert_eq!(args.out, PathBuf::from("result"));
        assert_eq!(args.verbose, 2);
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
