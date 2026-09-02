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
scenarios           Run python script that run all 28 scenarios
```

### Test a scenario

The `just scenarios` command run all 28 scenarios. If you want to see options type

```
just scenarios --help
```

For example, to save report in a json file
```
just scenarios --out /scenarios/out
```
