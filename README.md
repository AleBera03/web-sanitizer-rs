# Rust Web Sanitizer

## Development

### Dependencies
- rust dev environment via [rustup](https://rust-lang.org/tools/install/)
- [docker](https://docs.docker.com/get-started/get-docker/)

The project uses [just](https://github.com/casey/just#Installation). Installing it using `cargo` is recommend

```
cargo install just --locked
```


```
[docs]
just docgen         Produce docs from comments within .rs files of project

[final-report]
just book-deps      Install via cargo dependencies for build final report pdf
just book-build     Build the book from mdbook and mdbook-pdf

[test]
just load-image          Load docker image from .tar file
just run-image           Run container
just serve               Run wsrs command with --serve option

[coverage]
just coverage            Line coverage with tarpaulin, in a container by default

[eval]
just ground-truth        Render corpus/ground-truth.toml as a table for the report
just correctness         Detection rate, false-positive rate and the rule confusion table
just scenarios           Run every evil-origin scenario, fetching off and on
just latency             Per-input latency against input size
just phases              Split each input into read, sniff and rewrite
just memory              Peak resident set per input, one process each
just bench               Throughput against worker count, fetching off and on
just plots               Draw every chart under eval/plots
just evaluate            Everything above except the benchmark
```

To modify deployment methods it is possible to use [cargo-dist](https://github.com/axodotdev/cargo-dist). Install it with
```
cargo install cargo-dist --locked
```
and edit `dist-workspace.toml`

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
cargo xtask scenarios     # the evil-origin harness
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

### Docker on Windows

On Windows the scenario suite can run around 3.3 seconds per HTTP connection, so a redirect chain pays it once per hop and
`triple-hop-to-script-html` alone takes 13 seconds. Time is spent waiting on a TCP connect that never completes.

Three things line up to produce it:

1. `localhost` resolves to `::1` before `127.0.0.1` on Windows.
2. With `networkingMode=mirrored` in `%USERPROFILE%\.wslconfig`, Docker Desktop claims a
   published port on both address families but services only IPv4. A connect to
   `[::1]:<published port>` is black-holed rather than refused, so the client waits for a
   timeout instead of failing over at once. Publishing the port as `127.0.0.1:3100:3100`
   does not help, and an explicit `[::1]:3100:3100` is ignored.
3. `ureq` tries the resolved addresses in sequence, splitting the connect budget
   geometrically. With two addresses the first gets `connect_timeout_ms * 1.0/1.5`, so the
   default 5000 ms spends 3333 ms on the unreachable `::1` before trying `127.0.0.1`.

**The fix is to leave `networkingMode` unset**, which selects NAT mode and forwards IPv6
loopback correctly. Remove the line from `%USERPROFILE%\.wslconfig`, then:

```
wsl --shutdown
```

and start Docker Desktop again.

With that out of the way the suite is dominated by the two `slow-drip` runs, which are slow
on purpose to exercise the read timeout; every other scenario lands in 10-20 ms.

Mirrored mode is worth having for other reasons, such as reaching Windows host services from WSL,
and some VPN setups. So if you need it, `scenarios/policy-fetch.toml` and
`policy-nofetch.toml` set `connect_timeout_ms = 450` as a safety net.

Linux and macOS are unaffected.

### Coverage

`just coverage` measures line coverage with [tarpaulin](https://github.com/xd009642/tarpaulin)
inside a container.

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

### Deployment

This project share compiled binaries via Github Releases.

Before any PRs on main publish a new tag

```
git commit -am "release: x.x.x"
git tag "vx.x.x"
git push
git push --tags
```

Then, the `cargo-dist` generated CI workflow starts a new job which compiles against several platforms and saves them on releases page.
