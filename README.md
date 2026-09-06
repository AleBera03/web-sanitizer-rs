# Rust Web Sanitizer

## Development

The project uses [just](https://github.com/casey/just#Installation). Installing it using `cargo` is recommend

```
cargo install just
```


```
[docs]
just docgen         Produce docs from comments within .rs files of project

[final-report]
just book-deps      Install via cargo dependencies for build final report pdf
just book-build     Build the book from mdbook and mdbook-pdf

[test]
load-image          Load docker image from .tar file
run-image           Run container
serve               Run wsrs command with --serve option

[coverage]
coverage            Line coverage with tarpaulin, in a container by default

[eval]
ground-truth        Render corpus/ground-truth.toml as a table for the report
correctness         Detection rate, false-positive rate and the rule confusion table
scenarios           Run every evil-origin scenario, fetching off and on
latency             Per-input latency against input size
phases              Split each input into read, sniff and rewrite
memory              Peak resident set per input, one process each
bench               Throughput against worker count, fetching off and on
plots               Draw every chart under eval/plots
evaluate            Everything above except the benchmark
```

### Corpus

`corpus/benign` holds real pages retrieved from the public web and stored unmodified,
so they carry whatever their publishers put there, scripts and embeds included.
`corpus/malicious` holds samples written for this project, one per technique.
`corpus/ground-truth.toml` documents every sample: where it came from, what it carries,
the outcome it must produce and the byte patterns that must not survive.

A rule firing on something a benign page genuinely contains is a true positive, so each
benign entry lists the rules its own content justifies. Anything outside that list counts
as a false positive.

### Evaluation

Every step is a subcommand of the `xtask` crate, which links the library directly and
writes CSV rows under `eval/results` and charts under `eval/plots`:

```
cargo xtask correctness   # detection and false positives against the ground truth
cargo xtask latency       # latency against input size
cargo xtask phases        # where the time goes inside one input
cargo xtask memory        # peak resident set, one process per input
cargo xtask scenarios     # the evil-origin harness, needs docker
cargo bench --bench throughput
cargo xtask plots
```

`cargo xtask scenarios` starts the evil-origin container and the sanitiser itself, runs
every published scenario in both fetching modes, and stops what it started.

### Test a scenario

`just scenarios` runs every scenario the origin publishes. For the options type

```
cargo xtask scenarios --help
```

For example, to save report in a json file
```
just scenarios --out /scenarios/out
```

### Coverage

`just coverage` measures line coverage with [tarpaulin](https://github.com/xd009642/tarpaulin)
inside a container, so the only thing the machine needs is docker.

```
just coverage
```

The run mounts the repository at `/volume`, keeps cargo's cache and its build artefacts
under `target/coverage` so the host build stays untouched, and drops the container to the
owner of the tree so the report is readable afterwards. `tarpaulin.toml` holds the settings:
a summary on the terminal and an HTML report at `eval/coverage/tarpaulin-report.html`.

Anything after `--` reaches tarpaulin options:

```
just coverage -- --out Lcov          # another report format
just coverage -- --fail-under 70     # non-zero exit below the threshold
```

With tarpaulin already installed on the machine, `--local` skips docker and runs it directly.
That path only works where tarpaulin does, x86-64 Linux for the default ptrace engine.

```
cargo install --locked cargo-tarpaulin
just coverage --local
```
