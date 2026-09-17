# Critical Assessment: Limitations and Possible Extensions

This chapter's goal is to point out possible weaknesses or limitations of the sanitiser, and also explain possible extensions that could be developed.

## 6.1 The zip-bomb check trusts declared metadata, not verified decompression

`src/scan/dos/zip/mod.rs` does not depend on a ZIP-handling crate. It hand-parses the End-Of-Central-Directory record and walks the central directory entries directly, reading each entry's *declared* `compressed_size` and `uncompressed_size` fields.
`ZipBudgets`'s `max_compression_ratio`, `max_total_uncompressed_bytes`, `max_entry_count` are therefore checked against what the archive's central directory *says* about itself, not against bytes actually produced by inflating it.

This introduces a weakness in case the declared sizes are understated. An attacker with the ability to modify the archive could trick the sanitiser into letting the zip through, despite it carrying malicious content.
Closing this weakness would mean either adopting a streaming-decompression crate that can enforce a ratio cap against bytes actually produced, or cross-checking a sample of entries' true inflated size against their declared size before trusting the metadata for the rest of the archive.

## 6.2 MIME-type coverage is deliberately limited to widespread formats

The `MimeType` enum lists several formats that are recognised by file extension and by declared `Content-Type` string, but that **do not have a magic-number byte-sniffing rule**: the project's test suite exercises byte-level detection for most of the widespread formats, but there is no equivalent test for, as an example, a RIFF/WEBP FourCC or for the OLE2/Compound File Binary signature that legacy `.doc`/`.xls`/`.ppt` files use, or even EMF.

This decision was made to not widen too much the scope of the sanitiser, and keep the focus on the more common vectors of attacks.

## 6.3 Sub-resource policy is uniform across types, not per-type

`SubresourcesRules` applies `sniff_rule`, `active_content_rule`, and `dos_risk_rule` as single, global settings across every fetched sub-resource type.
This generalization does not allow for certain types of sub-resources to be allowed while others are refused, as the rules are enforced uniformly across all types.

Extending the policy to handle each sub-resource type differently would increase the effectiveness of the sanitiser, allowing the user to customize subresource handling more in depth. In the current version of the sanitiser this wasn't done both for time reasons and because it was deemed out of scope.

## 6.4 Active-content rewriting is safe and linear for only four formats

`scan/active/mod.rs`'s `rewrite_if_possible` has a real, format-specific byte-rewriting path for exactly four types, PDF, TIFF, SVG, and CSS, rewriting is applied only when a format-specific rewrite exists, otherwise passes the original bytes through unchanged.
For every other type where active content is *detected* (JavaScript, ZIP/OOXML documents carrying a VBA macro project, XML with an XXE-style construct), there is no corresponding rewrite, under a policy of `ActiveContentAction::Allow`, the detection is recorded as a `SanitisationAction`, but the bytes that pass through are unchanged. Only `ActiveContentAction::Reject` actually stops the content from reaching the output for these types.

The reason is: PDF, TIFF, and SVG admit a linear, well-bounded way to strip the dangerous construct without disturbing the rest of the file's structure, and CSS is tokenizable cleanly enough for the same treatment.
Office formats with macros are a different problem: a `.docx`/`.xlsx`/ `.pptx` file is a container whose internal structure is considerably more interdependent than an image or a stylesheet, and surgically removing active content risks leaving the rest of the archive in a state that no longer opens correctly in the target application.
Due to the way more complex action of rewriting in these other formats, we preferred directly refusing active content where rewriting proved too difficult and risked corrupting the file.

## 6.5 A development-environment limitation: Docker networking on Windows

This one is not a limitation of the sanitiser itself but of running its evaluation tooling on Windows, and it is documented in the README in some detail.
On Windows, the scenario suite can take roughly 3.3 seconds per HTTP connection, enough that a redirect chain pays that cost once per hop, and the `triple-hop-to-script-html` scenario alone takes 13 seconds.
Three things combine to produce it:

1. `localhost` resolves to `::1` (IPv6) before `127.0.0.1` (IPv4) on Windows.
2. With Docker Desktop's `networkingMode=mirrored` set, a published port is claimed on both address families but only actually served over IPv4, and a connection attempt to `[::1]:<port>` is silently black-holed rather than refused, so the client waits out a full connect timeout instead of failing over immediately.
3. `ureq` tries resolved addresses in sequence and splits its connect budget geometrically across them, with two candidate addresses, the dead `::1` consumes roughly two-thirds of the configured `connect_timeout_ms` before the client moves on to the working `127.0.0.1` address.

The documented fix is to leave `networkingMode` unset in `%USERPROFILE%\.wslconfig` rather than to change anything in the sanitiser or its policy. As a safety net, it's also recommended to additionally set a short `connect_timeout_ms = 450`.
Linux and macOS are unaffected.

## 6.6 Possible extensions

Two extensions have been discussed:

1. **Package-manager distribution.**
  The project already has a `cargo-dist`-based release pipeline that builds platform-specific archives for five targets and publishes them to GitHub Releases automatically on a version tag, but `dist-workspace.toml`'s `installers` list is currently empty, so what ships is a set of raw `.tar.gz`/`.zip` archives a user must fetch and unpack by hand.
  Publishing to `apt` and Homebrew would make the tool installable the way most comparable CLI security tools are, without requiring a Rust toolchain on the user's machine.
2. **A reusable GitHub Action for CI-scanner embedding.**
  The original specification frames one use case as embedding into CI scanners, and the tool's CLI/library split already supports that use case mechanically, but there is currently no published, reusable GitHub Action wrapping it.
  Packaging the CLI as a composite or Docker-based Action would let another project's CI pipeline run this sanitiser as a scanning step without building it themselves.
