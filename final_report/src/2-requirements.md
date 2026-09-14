# Requirements Analysis

## 2.1 Problem statement

When interacting with web content, a user can be at risk of coming into contact with malicious code. `web-sanitizer-rs` must be the first defence against possible attacks, thus the requirements revolve around these risks:

1. **Active content smuggled through a passive format.**
    Scripts, event handlers, dangerous URL schemes, or auto-refreshing frames embedded in HTML; entity-expansion attacks embedded in XML/SVG; polyglot files that are valid under more than one parser.
2. **Resource-exhaustion attacks.**
    Zip bombs, deeply nested archives, oversized images, and decompression-ratio attacks that trade a small input for an unbounded amount of work.
3. **Network-side abuse of the sanitiser itself.**
    If the tool is allowed to fetch a document's sub-resources, a malicious document can try to reach internal infrastructure — e.g. **SSRF** (Server-Side Request Forgery).

## 2.2 Functional requirements

<!--Derived from the CLI surface (`src/args.rs`), the pipeline documentation in
`src/engine/mod.rs`, and the policy schema in `src/policy/mod.rs`: -->

| # | Requirement |
| --- | --- |
| F1 | Accept files, directories, `--input-list` files, and `http(s)` URLs as input, and process them as an ordered batch. |
| F2 | Determine the real content type of every input by inspecting its bytes (magic numbers, structural markers), never by trusting a declared `Content-Type` or file extension alone. |
| F3 | For HTML: remove or rewrite `<script>` tags, inline `on*` event-handler attributes, `javascript:`/`data:` URLs, disallowed `<iframe>`/`<object>`/`<embed>` elements, and `<meta http-equiv="refresh">` redirects, each recorded as a distinct, independently configurable rule. |
| F4 | For URL-bearing attributes (`href`, `src`, `action`, `formaction`, `data`, `poster`): check the host against a configurable block-list and against a set of "protected" domains for homograph/IDN spoofing. |
| F4b | Detect and neutralise URL-confusion classes: raw IP literal that resolves into a disallowed network (private/link-local/loopback/benchmarking ranges), and credentials embedded in the URL authority used to hide the real host. |
| F5 | For XML/SVG: bound entity expansion to defend against billion-laughs-style attacks. |
| F6 | For compressed/archive inputs (gzip, zip/OOXML): bound the decompression ratio and re-sniff the inflated content recursively, under a depth cap. |
| F7 | Optionally fetch the sub-resources an HTML document references, sanitise them with the same pipeline, and embed them next to the sanitised parent — under a joint budget (request count, byte count, depth) and never past depth 1. |
| F8 | Guard every outbound fetch (input URLs and sub-resource URLs) against SSRF: resolve the hostname, check every resolved address against a deny table of private/link-local/loopback ranges, and refuse the connection if any of them match. |
| F9 | Defend against connection-level slow-drip (Slowloris-style) DoS on outbound fetches, not just against an overall time cap. |
| F10 | Produce a structured JSON report for every run: one entry per input, the status it ended in (`Clean`, `Sanitized`, `Refused`, `BudgetExceeded`, `SsrfBlocked`, `FetchError`, ...), and the exact list of actions taken, each with a rule ID, a category, and a source location. |
| F11 | Run under a configurable worker pool for batch throughput, preserving deterministic output naming regardless of completion order. |
| F12 | Load sanitisation policy from a TOML file that overrides a compiled-in default section by section, and fail fast (exit code 2) on unknown keys rather than silently ignoring a typo. |

## 2.3 Non-functional requirements

| # | Requirement |
| --- | --- |
| N1 | **Fail closed, not open.** A pipeline bug must degrade to a refusal, never to passing unsanitised bytes through. |
| N2 | **Bounded resource usage per input**, independent of what the input claims about itself. |
| N3 | **No unbounded recursion.** Gzip/zip re-entry into `route` and the sub-resource loop both carry explicit depth caps. |
| N4 | **The sanitiser must not become an SSRF vector.** Every socket the process opens — for an input URL or a sub-resource — must pass the same address-level check. |
| N5 | **Auditability.** Every transformation must be individually traceable: rule ID, category, before/after fragment, and byte/line location. |
| N6 | **Configuration errors are caught before any input is processed**, not discovered mid-batch. |
| N7 | **Throughput under batch workloads.** Many inputs must be processed concurrently without input-level state leaking across workers. |
| N8 | **Determinism of on-disk output naming**, independent of which worker finishes first. |

## 2.4 Explicit non-requirements

As per requested, these "non-requirements" are a limit to what is in the scope of the project:

- It is **not a general antivirus/content-scanning engine**: it inspects headers and structural risk indicators, not payload semantics.
- It **does not execute scripts in a sandbox**: it merely identifies them and enforces a predetermined action.
