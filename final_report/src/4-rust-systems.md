# Rust System-Programming Aspects

This chapter talks about the concurrency model, use of lifetimes, error-handling discipline, and the project's stance on `unsafe`.

## 4.1 Concurrency model

`web-sanitizer-rs` uses a **thread-pool-with-channels** model for batch processing, built directly on `std::thread` and `std::sync::mpsc`.

Each input's processing is CPU/IO-bound in short, independent bursts (parse, sanitise, maybe one bounded round of sub-fetches).

### 4.1.1 The worker pool

`Engine::process_batch` (`src/engine/mod.rs`) sets up two channels: a job channel `(usize, InputSource)` and a result channel `(usize, Outcome)`, and spawns `jobs.max(1)` OS threads, each looping on:

```rust
loop {
    let job = { let guard = job_rx.lock().unwrap(); guard.recv() };
    let (index, input) = match job { Ok(pair) => pair, Err(_) => break };
    let outcome = engine.process_indexed(index, input);
    let _ = res_tx.send((index, outcome));
}
```

Three choices are important:

- **The receiving end of the job channel is behind `Arc<Mutex<Receiver>>`.**
  `mpsc::Receiver` is not `Sync`, so it cannot be shared directly across threads; wrapping it in a `Mutex` turns many workers pulling from one queue into a correct work-stealing queue.
  Since `recv()` blocks and each job is comparatively large-grained, the lock is held only for the instant of receiving a job, not during the work itself.
- **The engine is wrapped in `Arc<Engine>` and cloned per worker.**
  `Engine` itself is `#[derive(Clone)]` over fields that are all `Arc<...>` (`policy`, `blockset`, `skeletonset`, `verdictcache`, and a `dyn Fetcher` behind an `Arc`), so cloning it is cheap and every worker sees the same compiled policy and the same caches without any data being copied per thread.
- **Index-tagged results restore order deterministically.**
  Because workers finish in whatever order the work happens to take, the result channel carries `(index, Outcome)` pairs, and `process_batch` uses the index to name output files and to place each report in its original position.
  This is what makes the tool's on-disk output deterministic across runs even though the *scheduling* is not.

### 4.1.2 Shared, lock-guarded caches

Two caches are shared across the whole worker pool: the URL-verdict cache (`urlcheck::cache::VerdictCache`) and the DNS-resolution verdict cache (`fetch::guard::cache::ResolveCache`):

```rust
pub struct VerdictCache {
    table: RwLock<HashMap<String, Entry>>,
    hits: AtomicU64,
    misses: AtomicU64,
    clock: AtomicU64,
    max_entries: usize,
    evict_sample_rate: usize,
}
pub struct ResolveCache {
    table: RwLock<HashMap<String, Entry>>,
    hits: AtomicU64,
    misses: AtomicU64,
    clock: AtomicU64,
    max_entries: usize,
    evict_sample_rate: usize,
}
```

This is a piece of concurrent-data-structure design:

- **`RwLock<HashMap<...>>`** lets any number of workers read a cached verdict concurrently (`read()`), while a write (inserting a new verdict, or evicting) takes the exclusive lock only for the duration of the mutation.
  Given that verdict lookups usually outnumber insertions, this favours the common case.
- **`AtomicU64` counters (`hits`, `misses`, a logical `clock`) sit outside the lock entirely.**
  Per-entry `last_used` is also an `AtomicU64`, updated with `Ordering::Relaxed` on every lookup, so recording recency for LRU-ish eviction does not require upgrading a read lock to a write lock.
- **Sampled eviction** (`evict_sample_rate`) avoids scanning the whole table under the write lock when `max_entries` is exceeded: a random sample of entries is drawn via `rand::seq::IteratorRandom` and the least-recently-used of the sample is evicted.
  This trades eviction precision for bounded lock-hold time regardless of table size.
- **Deny-vs-allow asymmetry** in `ResolveCache`: a `Denied` SSRF verdict is treated as effectively permanent, while `Allowed` verdicts expire after `allow_ttl_ms`.

### 4.1.3 What is deliberately *not* shared across threads

As `subresource.rs` top comment says:*"Bodies are fetched, sanitised and dropped inside the same stack frame, so nothing is shared and no lifetime crosses a thread."*
Each worker owns its input's entire sub-resource fan-out locally and only the final `Outcome` crosses the channel back to the aggregator.
The *only* state shared between threads is the handful of `Arc`-wrapped, mostly-immutable structures (policy, block-lists, caches), and everything else is worker-local by construction.
This lets `catch_unwind` isolate one worker's panic without any cross-thread cleanup being required.

## 4.2 Lifetimes

The use of explicit lifetime parameters is concentrated in the hot loop that borrows the input buffer and a handful of policy/cache references for the duration of a single call. Some examples are:

### 4.2.1 `UrlChecker<'a>`

```rust
pub struct UrlChecker<'a> {
    blockset: &'a BlockSet,
    skeletons: &'a SkeletonSet,
    verdictcache: &'a VerdictCache,
    rules: &'a UrlRules,
}
```

`UrlChecker` borrows all four of its dependencies rather than owning `Arc` clones of them.
The `Engine` already owns these structures behind `Arc`, so `UrlChecker` is constructed as a *view* over state that already outlives it.
The lifetime `'a` ties the checker's validity to the borrow of the engine's compiled policy artefacts, and the compiler statically guarantees a `UrlChecker` cannot outlive the data it inspects.

### 4.2.2 `Ctx<'a>` in the HTML rewriter

```rust
struct Ctx<'a> {
    rules: &'a HtmlRules,
    url: &'a UrlChecker<'a>,
    input: &'a [u8],
    newlines: &'a [usize],
    actions: RefCell<Vec<SanitisationAction>>,
    refused: Cell<bool>,
    references: RefCell<Vec<Reference>>,
    base: RefCell<Option<String>>,
}
```

- `rules`, `url`, `input`, and `newlines` are all **borrowed**, as `Ctx` is built once per `sanitize_html` call and dropped at the end of it.
- `actions`, `refused`, `references`, and `base` are **owned but wrapped in `Cell`/`RefCell`**, not borrowed, because they are *written to* by the per-element callback `lol_html` invokes.

The net effect: `Ctx<'a>` cannot leak out of the function that builds it, so there is no risk of an HTML rewrite result referencing a dangling `input` buffer.

### 4.2.3 Zero-copy parsing, and where it stops

`sanitize_html`'s signature `fn sanitize_html(input: &[u8], rules: &HtmlRules, url: &UrlChecker) -> HtmlOutcome` shows that the input document is never copied into an owned buffer before being parsed.
`lol_html` tokenizes directly over the borrowed `&[u8]`, and `Ctx` borrows that same slice for the lifetime of the call.
Locations reported in `SanitisationAction` are computed against that same borrowed buffer rather than against a re-scanned copy.

Zero-copy stops, deliberately, at the write side and at the thread boundary:

- **The rewriter's *output* is necessarily an owned `Vec<u8>`** because sanitisation only sometimes leaves bytes unchanged.
  Where it removes a `<script>` block or rewrites a `javascript:` URL, the output diverges from the input.
- **Nothing is shared across threads as a borrowed `Arc<[u8]>` buffer.**
  `Ctx<'a>`'s borrows never have to become `Send` or `Sync`, because they never cross a thread.
  Each worker in `process_batch` owns its input's bytes locally, runs the whole acquire → sniff → route → sanitise → report pipeline against that local buffer, and only the final, fully-owned `Outcome` is moved across the `mpsc` result channel.
- **Parser state itself never needs to be `Send`.**
  Because `Ctx` and the `HtmlRewriter` it drives are constructed, used, and dropped entirely within one call on one thread, the question "can this parser state be handed to another thread mid-parse" never arises.

## 4.3 Error handling

The project has three distinct error-handling mechanisms, each used where it fits, rather than picking one uniformly:

### 4.3.1 Typed errors via `thiserror`

Every module boundary that can fail in a way callers need to distinguish defines its own `#[derive(Error)]` (e.g. `ConfigError` in `policy/mod.rs`).
Each variant carries the structured data needed to act on it, and this is what lets the report layer surface a precise, machine-readable cause rather than an opaque failure.

### 4.3.2 `anyhow`/`Box<dyn Error>` at the front-end boundary

`main.rs` uses `Result<u8, Box<dyn Error>>` for `run()`, and `anyhow` is a listed dependency for the same layer: once an error has crossed from a specific library module into the CLI front-end, its precise type stops mattering, the front-end's only remaining job is to print it and choose an exit code.
This creates a split: typed errors (`thiserror`) inside the library where callers act on variants, erased errors (`anyhow`/ `Box<dyn Error>`) at the binary boundary.

### 4.3.3 Panic isolation as a last line of defence

`Engine::process_indexed` wraps the whole per-input pipeline in `catch_unwind(AssertUnwindSafe(...))`. This is to avoid a bug (an unexpected panic or other) taking down a whole batch run.
Combined with the worker-local ownership, a caught panic in one worker's input cannot corrupt shared state, the `Arc` it read are still valid, and the panic unwound only its own stack frame.

`catch_unwind` requires its closure to be `UnwindSafe`, a marker trait that says no reference captured by this closure will be observed in a torn, inconsistent state if we unwind through it and keep going.
The engine's per-input state does not actually satisfy this automatically (interior mutability like `RefCell`/`Cell` is not `UnwindSafe` by default), so the code asserts the safety manually.
This assertion is sound *because* of the worker-local ownership discipline: nothing captured by the closure is shared with another thread that could observe a torn value, so there is no actual unwind-safety hazard to assert away.

## 4.4 `unsafe` code

`unsafe` has been entirely avoided for this project. As the project requests said, use of unsafe was discouraged, hence the entirety of the project has been made with the idea to avoid unsafe code.
