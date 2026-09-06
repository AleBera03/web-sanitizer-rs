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
