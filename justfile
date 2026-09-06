[windows]
set shell := ["powershell.exe", "-NoLogo", "-NoProfile", "-Command"]

[group("docs")]
docgen: # see doc/gen after launched command
    cargo doc --target-dir doc/gen

[group("final-report")]
book-deps:
    cargo install mdbook mdbook-pdf mdbook-mermaid

[group("final-report")]
book-build:
    mdbook build final_report

[group("test")]
serve:
    cargo run -- --policy scenarios/policy.toml serve --port 3000

[group("test")]
load-image:
    docker load -i scenarios/evil-origin.tar

[group("test")]
run-image:
    -docker container rm -f evil-origin
    docker run -d -p 3100:3100 --name evil-origin evil-origin

[group("eval")]
scenarios *ARGS:
    cargo xtask scenarios {{ARGS}}

[group("eval")]
ground-truth:
    cargo xtask ground-truth

[group("eval")]
correctness *ARGS:
    cargo xtask correctness {{ARGS}}

[group("eval")]
latency *ARGS:
    cargo xtask latency {{ARGS}}

[group("eval")]
phases *ARGS:
    cargo xtask phases {{ARGS}}

[group("eval")]
memory *ARGS:
    cargo xtask memory {{ARGS}}

[group("eval")]
plots:
    cargo xtask plots

[group("eval")]
evaluate: ground-truth correctness latency phases memory plots

[group("coverage")]
coverage *ARGS:
    cargo xtask coverage {{ARGS}}

[group("eval")]
bench *ARGS:
    cargo bench --bench throughput {{ARGS}}