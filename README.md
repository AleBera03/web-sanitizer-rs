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
test                Sample test against an arbitrary scenario
```

### Test a scenario

> [!IMPORTANT]  
> Before proceed, remember to unzip multipart compressed evil-origin within `scripts` by extracting `...part1.rar`.

If you want to test a scenario run these commands:

- on terminal (A) run
```
just run-image
```

- then open a new terminal (B)
```
just serve
```
press Ctrl+C in order to stop server.

- finally, run test
```
just test
```

By default, scenario in `test` is `http://localhost:3100/html/script-tag`.
