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
    pub fn override_policy(&self, policy: &mut web_sanitizer::Policy) {
        if self.fetch_subresources {
            policy.subresources.fetch_subresources = true;
        }
    }
}

fn default_jobs() -> usize {
    thread::available_parallelism().map_or(1, |n| n.get())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_of(command: Command) -> ScanArgs {
        match command {
            Command::Scan(scan_args) => scan_args,
            other => panic!("expected the scan subcommand, got {other:?}"),
        }
    }

    #[test]
    fn scan_defaults_parse() {
        let args = Args::parse_from(["web-sanitizer", "scan", "a.html", "b.html"]);
        assert!(args.policy.is_none());
        assert!(args.jobs >= 1);
        assert_eq!(args.verbose, 0);

        let scan_args = scan_of(args.command);
        assert_eq!(scan_args.inputs, ["a.html", "b.html"]);
        assert_eq!(scan_args.out, PathBuf::from("out"));
        assert!(scan_args.input_list.is_none());
    }

    #[test]
    fn engine_flags_come_before_the_subcommand() {
        let args = Args::parse_from([
            "web-sanitizer",
            "-vv",
            "--jobs",
            "4",
            "--policy",
            "p.toml",
            "scan",
            "--input-list",
            "list.txt",
            "--out",
            "result",
        ]);
        assert_eq!(args.policy, Some(PathBuf::from("p.toml")));
        assert_eq!(args.jobs, 4);
        assert_eq!(args.verbose, 2);

        let scan_args = scan_of(args.command);
        assert_eq!(scan_args.input_list, Some(PathBuf::from("list.txt")));
        assert_eq!(scan_args.out, PathBuf::from("result"));
        assert!(scan_args.inputs.is_empty());
    }

    #[test]
    fn an_engine_flag_after_the_subcommand_is_rejected() {
        assert!(Args::try_parse_from(["web-sanitizer", "scan", "a.html", "--jobs", "4"]).is_err());
    }

    #[test]
    fn serve_binds_loopback_on_port_3000_by_default() {
        let args = Args::parse_from(["web-sanitizer", "serve"]);
        match args.command {
            Command::Serve(serve_args) => {
                assert_eq!(serve_args.bind, "127.0.0.1");
                assert_eq!(serve_args.port, 3000);
            }
            other => panic!("expected the serve subcommand, got {other:?}"),
        }
    }

    #[test]
    fn serve_accepts_an_explicit_address() {
        let args = Args::parse_from([
            "web-sanitizer",
            "serve",
            "--bind",
            "0.0.0.0",
            "--port",
            "8080",
        ]);
        match args.command {
            Command::Serve(serve_args) => {
                assert_eq!(serve_args.bind, "0.0.0.0");
                assert_eq!(serve_args.port, 8080);
            }
            other => panic!("expected the serve subcommand, got {other:?}"),
        }
    }

    #[test]
    fn the_safe_state_needs_no_flag() {
        let args = Args::parse_from(["web-sanitizer", "scan", "a.html"]);
        assert!(!args.fetch_subresources);
        let mut policy = web_sanitizer::Policy::builtin();
        args.override_policy(&mut policy);
        assert!(!policy.subresources.fetch_subresources);
    }

    #[test]
    fn the_fetch_flag_turns_fetching_on() {
        let args = Args::parse_from(["web-sanitizer", "--fetch-subresources", "scan", "a.html"]);
        let mut policy = web_sanitizer::Policy::builtin();
        args.override_policy(&mut policy);
        assert!(policy.subresources.fetch_subresources);
    }
}
