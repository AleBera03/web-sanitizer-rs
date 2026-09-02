import 'doc/spec/ignore.just'

[group("docs")]
docgen: # see doc/gen after launched command
    rustdoc --target-dir doc/gen

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

[group("test")]
scenarios *ARGS:
    python3 scenarios/run_scenarios.py {{ARGS}}