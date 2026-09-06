mod correctness;
mod coverage;
mod document;
mod engine;
mod error;
mod paths;
mod perf;
mod plots;
mod progress;
mod scenarios;
mod served;
mod table;
mod truth;

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

use error::Result;
use paths::{Fetching, Layout};
use truth::{GroundTruth, SampleSet};

#[derive(Parser)]
#[command(name = "xtask", about = "Evaluation tasks for the web sanitiser")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Clone)]
struct CorpusArgs {
    /// Which corpus set to run: benign, malicious or both
    #[arg(long, short, default_value = "both")]
    set: String,
    /// Policy to run under. Omit for the pair the ground truth names. A policy
    /// states its own fetching mode, so this cannot be combined with --fetch
    #[arg(long, short, conflicts_with = "fetch")]
    policy: Option<String>,
    /// Sub-resource fetching: off, on or both. Only meaningful for the policies
    /// the ground truth names, one per mode
    #[arg(long, short, default_value = "both")]
    fetch: String,
}

impl CorpusArgs {
    fn sets(&self) -> Vec<SampleSet> {
        match self.set.as_str() {
            "benign" => vec![SampleSet::Benign],
            "malicious" => vec![SampleSet::Malicious],
            _ => vec![SampleSet::Benign, SampleSet::Malicious],
        }
    }

    fn modes(&self, layout: &Layout) -> Result<Vec<Fetching>> {
        match &self.policy {
            None => Ok(Fetching::parse(&self.fetch)),
            Some(named) => Ok(vec![engine::declared_fetching(layout.root(), named)?]),
        }
    }

    // each fetching mode has its own policy file, unless one was named
    fn policy_for(&self, truth: &GroundTruth, fetching: Fetching) -> String {
        self.policy
            .clone()
            .unwrap_or_else(|| truth.policy(fetching).to_string())
    }
}

#[derive(Subcommand)]
enum Command {
    /// Render the ground truth as a table for the report
    GroundTruth,
    /// Measure detection and false-positive rates against the ground truth
    Correctness {
        /// Exit non-zero when a sample does not match the ground truth
        #[arg(long, short)]
        strict: bool,
        #[command(flatten)]
        corpus: CorpusArgs,
    },
    /// Per-input latency against input size
    Latency {
        #[arg(long, short, default_value_t = 5)]
        repeats: usize,
        #[command(flatten)]
        corpus: CorpusArgs,
    },
    /// Split each input into its read, sniff and rewrite phases
    Phases {
        #[arg(long, short, default_value_t = 5)]
        repeats: usize,
        #[command(flatten)]
        corpus: CorpusArgs,
    },
    /// Peak resident set per input, one process per measurement
    Memory {
        #[command(flatten)]
        corpus: CorpusArgs,
    },
    /// Run every evil-origin scenario against the server, fetching off and on
    Scenarios {
        #[arg(long, short, default_value = "both")]
        mode: String,
        #[arg(long, short, default_value = "http://localhost:3100")]
        origin: String,
        #[arg(long, short, default_value_t = 3000)]
        port: u16,
        #[arg(long, short, default_value_t = 45)]
        timeout: u64,
        #[arg(long, short, default_value_t = 300)]
        boot_timeout: u64,
        /// Use a sanitiser already listening at this base URL
        #[arg(long, short)]
        attach: Option<String>,
        /// Assume the evil origin is already running
        #[arg(long, short)]
        no_setup: bool,
    },
    /// Line coverage over the test suite, inside a container by default
    Coverage {
        /// Run tarpaulin straight on this machine instead of in a container
        #[arg(long, short)]
        local: bool,
        /// Image carrying cargo-tarpaulin
        #[arg(long, short, default_value = coverage::IMAGE)]
        image: String,
        /// Anything after -- goes to cargo tarpaulin as it stands
        #[arg(last = true)]
        args: Vec<String>,
    },
    /// Draw every chart the results support. Takes no options: it reads
    /// eval/results and works out what can be drawn
    Plots,
    /// Process one input and report its peak resident set
    MemoryProbe {
        #[arg(long, short)]
        file: PathBuf,
        #[arg(long, short)]
        policy: String,
        #[arg(long, short)]
        fetch: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = dispatch(cli) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    let layout = Layout::discover();
    let truth = GroundTruth::load(&layout.ground_truth())?;
    match cli.command {
        Command::GroundTruth => {
            let path = document::save(&layout, &truth)?;
            println!(
                "{} samples written to {}",
                truth.samples.len(),
                path.display()
            );
            Ok(())
        }
        Command::Correctness { strict, corpus } => {
            let mut failures = 0;
            for set in corpus.sets() {
                for fetching in corpus.modes(&layout)? {
                    let policy = corpus.policy_for(&truth, fetching);
                    let run = correctness::Run {
                        set,
                        policy: &policy,
                        fetching,
                    };
                    println!("\n{}", run.label());
                    let outcome = correctness::run(&layout, &truth, run)?;
                    failures += outcome.failures;
                    correctness::report(&layout, run, &outcome, false)?;
                }
            }
            println!("\n{failures} sample(s) did not match the ground truth");
            println!("tables under {}", layout.results().display());
            match strict && failures > 0 {
                true => Err(error::XtaskError::Violations { measured: failures }),
                false => Ok(()),
            }
        }
        Command::Latency { repeats, corpus } => {
            for set in corpus.sets() {
                for fetching in corpus.modes(&layout)? {
                    let policy = corpus.policy_for(&truth, fetching);
                    let run = perf::Run {
                        set,
                        policy: &policy,
                        fetching,
                    };
                    let (rows, progress) = perf::latency(&layout, &truth, run, repeats)?;
                    let path = perf::save_latency(&layout, run, &rows)?;
                    progress.finish(&path);
                }
            }
            Ok(())
        }
        Command::Phases { repeats, corpus } => {
            for set in corpus.sets() {
                for fetching in corpus.modes(&layout)? {
                    let policy = corpus.policy_for(&truth, fetching);
                    let run = perf::Run {
                        set,
                        policy: &policy,
                        fetching,
                    };
                    let (rows, progress) = perf::phases(&layout, &truth, run, repeats)?;
                    let path = perf::save_phases(&layout, run, &rows)?;
                    progress.finish(&path);
                }
            }
            Ok(())
        }
        Command::Memory { corpus } => {
            for set in corpus.sets() {
                for fetching in corpus.modes(&layout)? {
                    let policy = corpus.policy_for(&truth, fetching);
                    let run = perf::Run {
                        set,
                        policy: &policy,
                        fetching,
                    };
                    let (rows, progress) = perf::memory(&layout, &truth, run)?;
                    let path = perf::save_memory(&layout, run, &rows)?;
                    progress.finish(&path);
                }
            }
            Ok(())
        }
        Command::Scenarios {
            mode,
            origin,
            port,
            timeout,
            boot_timeout,
            attach,
            no_setup,
        } => {
            let options = scenarios::Options {
                origin,
                port,
                timeout: std::time::Duration::from_secs(timeout),
                boot: std::time::Duration::from_secs(boot_timeout),
                attach,
                skip_setup: no_setup,
            };
            let rows = scenarios::run(&layout, &scenarios::Mode::parse(&mode), &options)?;
            scenarios::save(&layout, &rows)?;
            let failed = rows.iter().filter(|row| !row.passed).count();
            println!("\n{} of {} scenario runs failed", failed, rows.len());
            match failed {
                0 => Ok(()),
                measured => Err(error::XtaskError::Violations { measured }),
            }
        }
        Command::Coverage { local, image, args } => {
            let run = coverage::Run {
                image,
                local,
                extra: args,
            };
            let report = coverage::run(&layout, &run)?;
            println!("\nreport at {}", report.display());
            Ok(())
        }
        Command::Plots => {
            let written = plots::all(&layout, &truth)?;
            for path in &written {
                println!("{}", path.display());
            }
            println!(
                "{} file(s) under {}",
                written.len(),
                layout.plots().display()
            );
            Ok(())
        }
        Command::MemoryProbe {
            file,
            policy,
            fetch,
        } => perf::probe(&layout, &file, &policy, fetch),
    }
}
