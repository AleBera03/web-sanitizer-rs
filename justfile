import 'doc/spec/ignore.just'

[group("docs")]
docgen: # see doc/gen after launched command
    rustdoc --lib --target-dir doc/gen

[group("final-report")]
book-deps:
    cargo install mdbook mdbook-pdf mdbook-mermaid

[group("final-report")]
book-build:
    mdbook build final_report
