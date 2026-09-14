# Final Report - Introduction

## 1.1 Context

`web-sanitizer-rs` (binary name `wsrs`) is a command-line and library tool for sanitising untrusted web content: HTML documents, the sub-resources they reference, and a handful of adjacent formats (SVG, XML, PDF, TIFF, ZIP, images, audio and video).
The tool takes files, directories, or `http(s)` URLs as input (through API), runs each one through a fixed pipeline, with multiple threads if more than one file is present (and multi threading is possible), and returns both the sanitised bytes and a structured JSON report describing exactly which rules fired, where, and why.

The main goal of this project is to provide a basic but efficient defence against common malicious attacks, including dangerous html constructs, suspicious URLs, sub-resource manipulation, and other.
Each file is thouroughly sniffed to find the real contents, and enforces customizable rules for each file type.

## 1.2 Goals of this report

This report documents the design and implementation of `web-sanitizer-rs`, covering:

- the **requirements** the system was built to satisfy, both
  - functional (what it sanitises, and how)
  - non-functional (safety, performance, operability);
- the **architectural decisions** behind the acquire → sniff → route → sanitise → report pipeline, and why the codebase is split the way it is;
- a focused discussion of the **Rust systems-programming** aspects: concurrency model, use of lifetimes, error-handling discipline, and (deliberate) avoidance of `unsafe`;
- an **experimental evaluation** based on the project's test suite and performance benchmarks;
- a **critical assessment** of the current limitations of the system and of the extensions that could be implemented.
