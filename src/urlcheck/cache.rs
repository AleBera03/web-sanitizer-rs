//! Redis-style manually implemented cache.

use rand::seq::IteratorRandom;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::urlcheck::Verdict;

struct Entry {
    verdict: Verdict,
    last_used: AtomicU64,
}

pub struct VerdictCache {
    table: RwLock<HashMap<String, Entry>>,
    hits: AtomicU64,
    misses: AtomicU64,
    clock: AtomicU64,
    max_entries: usize,
    evict_sample_rate: usize, // default 5
}

impl Default for VerdictCache {
    fn default() -> Self {
        VerdictCache {
            table: RwLock::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            clock: AtomicU64::new(0),
            max_entries: 100_000,
            evict_sample_rate: 5,
        }
    }
}

impl VerdictCache {
    pub fn new(max_entries: NonZeroUsize, evict_sample_rate: NonZeroUsize) -> Self {
        VerdictCache {
            table: RwLock::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            clock: AtomicU64::new(0),
            max_entries: max_entries.get(),
            evict_sample_rate: evict_sample_rate.get(),
        }
    }

    pub fn get(&self, url: &str) -> Option<Verdict> {
        // read lock: shared read access among thread
        let table = self.table.read().unwrap();
        match table.get(url) {
            Some(entry) => {
                let t = self.clock.fetch_add(1, Ordering::Relaxed);
                entry.last_used.store(t, Ordering::Relaxed);
                self.hits.fetch_add(1, Ordering::Relaxed);
                Some(entry.verdict.clone())
            }
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                None
            }
        }
    }

    pub fn insert(&self, url: String, verdict: Verdict) {
        let mut table = self.table.write().unwrap();
        if table.len() >= self.max_entries && !table.contains_key(&url) {
            self.evict_one(&mut table);
        }
        let t = self.clock.fetch_add(1, Ordering::Relaxed);
        table.insert(
            url,
            Entry {
                verdict,
                last_used: AtomicU64::new(t),
            },
        );
    }

    fn evict_one(&self, table: &mut HashMap<String, Entry>) {
        let mut rng = rand::rng();
        let victim = table
            .iter()
            .sample(&mut rng, self.evict_sample_rate)
            .into_iter()
            .map(|(k, v)| (k.clone(), v.last_used.load(Ordering::Relaxed)))
            .min_by_key(|(_, t)| *t)
            .map(|(k, _)| k);

        if let Some(key) = victim {
            table.remove(&key);
        }
    }

    /// Lookups served from the table, for `run.cache_hits`.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn hit_rate(&self) -> f64 {
        let h = self.hits.load(Ordering::Relaxed) as f64;
        let m = self.misses.load(Ordering::Relaxed) as f64;
        if h + m == 0.0 { 0.0 } else { h / (h + m) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::urlcheck::Label;

    fn len(cache: &VerdictCache) -> usize {
        cache.table.read().unwrap().len()
    }

    fn counters(cache: &VerdictCache) -> (u64, u64) {
        (
            cache.hits.load(Ordering::Relaxed),
            cache.misses.load(Ordering::Relaxed),
        )
    }

    fn contains(cache: &VerdictCache, url: &str) -> bool {
        cache.table.read().unwrap().contains_key(url)
    }

    // lookup + counters

    #[test]
    fn lookup_on_empty_cache_is_a_miss() {
        let cache = VerdictCache::default();
        assert_eq!(cache.get("https://example.com/"), None);
        assert_eq!(counters(&cache), (0, 1));
        assert_eq!(len(&cache), 0);
    }

    #[test]
    fn insert_then_get_returns_the_verdict_and_counts_a_hit() {
        let cache = VerdictCache::default();
        cache.insert(
            "https://evil.com/".to_string(),
            Verdict::plain(Label::Blocked),
        );
        assert_eq!(
            cache.get("https://evil.com/"),
            Some(Verdict::plain(Label::Blocked))
        );
        assert_eq!(
            cache.get("https://evil.com/"),
            Some(Verdict::plain(Label::Blocked))
        );
        assert_eq!(counters(&cache), (2, 0));
        assert_eq!(len(&cache), 1);
    }

    #[test]
    fn distinct_urls_keep_distinct_verdicts() {
        let cache = VerdictCache::default();
        cache.insert(
            "https://evil.com/".to_string(),
            Verdict::plain(Label::Blocked),
        );
        cache.insert(
            "https://xn--mnchen-3ya.de/".to_string(),
            Verdict::plain(Label::Idn),
        );
        cache.insert(
            "https://example.com/".to_string(),
            Verdict::plain(Label::Clean),
        );
        assert_eq!(
            cache.get("https://evil.com/"),
            Some(Verdict::plain(Label::Blocked))
        );
        assert_eq!(
            cache.get("https://xn--mnchen-3ya.de/"),
            Some(Verdict::plain(Label::Idn))
        );
        assert_eq!(
            cache.get("https://example.com/"),
            Some(Verdict::plain(Label::Clean))
        );
        assert_eq!(len(&cache), 3);
    }

    #[test]
    fn reinsert_overwrites_the_verdict_without_growing() {
        let cache = VerdictCache::default();
        cache.insert(
            "https://example.com/".to_string(),
            Verdict::plain(Label::Clean),
        );
        cache.insert(
            "https://example.com/".to_string(),
            Verdict::plain(Label::Blocked),
        );
        assert_eq!(
            cache.get("https://example.com/"),
            Some(Verdict::plain(Label::Blocked))
        );
        assert_eq!(len(&cache), 1);
    }

    #[test]
    fn keys_are_the_raw_string_with_no_normalisation() {
        // the cache sits in front of `UrlChecker::check`, which is fed the
        // attribute value verbatim: two spellings of the same host are two keys
        let cache = VerdictCache::default();
        cache.insert(
            "http://evil.com/".to_string(),
            Verdict::plain(Label::Blocked),
        );
        assert_eq!(cache.get("http://EVIL.com/"), None);
        assert_eq!(cache.get("http://evil.com"), None);
        assert_eq!(cache.get(""), None);
        assert_eq!(
            cache.get("http://evil.com/"),
            Some(Verdict::plain(Label::Blocked))
        );
    }

    #[test]
    fn empty_url_is_a_usable_key() {
        let cache = VerdictCache::default();
        cache.insert(String::new(), Verdict::plain(Label::Clean));
        assert_eq!(cache.get(""), Some(Verdict::plain(Label::Clean)));
    }

    #[test]
    fn hit_rate_is_zero_before_any_lookup() {
        let cache = VerdictCache::default();
        assert_eq!(cache.hit_rate(), 0.0);
        // an insert alone moves no counter
        cache.insert(
            "https://example.com/".to_string(),
            Verdict::plain(Label::Clean),
        );
        assert_eq!(cache.hit_rate(), 0.0);
    }

    #[test]
    fn hit_rate_is_hits_over_lookups() {
        let cache = VerdictCache::default();
        cache.insert(
            "https://example.com/".to_string(),
            Verdict::plain(Label::Clean),
        );
        cache.get("https://example.com/"); // hit
        cache.get("https://other.com/"); // miss
        assert_eq!(counters(&cache), (1, 1));
        assert!((cache.hit_rate() - 0.5).abs() < f64::EPSILON);
        cache.get("https://example.com/"); // hit
        cache.get("https://example.com/"); // hit
        assert!((cache.hit_rate() - 0.75).abs() < f64::EPSILON);
    }

    // eviction

    #[test]
    fn table_never_grows_past_max_entries() {
        let cache = VerdictCache::new(
            NonZeroUsize::new(10).unwrap(),
            NonZeroUsize::new(5).unwrap(),
        );
        for i in 0..100 {
            cache.insert(format!("https://h{i}.test/"), Verdict::plain(Label::Clean));
        }
        assert_eq!(len(&cache), 10);
    }

    #[test]
    fn a_full_sample_evicts_the_least_recently_used() {
        // sample rate above the table size makes the reservoir cover every
        // entry, so the random pick degenerates into an exact LRU choice
        let cache = VerdictCache::new(NonZeroUsize::new(3).unwrap(), NonZeroUsize::new(8).unwrap());
        cache.insert("a".to_string(), Verdict::plain(Label::Clean));
        cache.insert("b".to_string(), Verdict::plain(Label::Clean));
        cache.insert("c".to_string(), Verdict::plain(Label::Clean));

        // touch a and b: c is now the oldest
        assert!(cache.get("a").is_some());
        assert!(cache.get("b").is_some());

        cache.insert("d".to_string(), Verdict::plain(Label::Blocked));
        assert_eq!(len(&cache), 3);
        assert!(!contains(&cache, "c"));
        assert!(contains(&cache, "a"));
        assert!(contains(&cache, "b"));
        assert_eq!(cache.get("d"), Some(Verdict::plain(Label::Blocked)));
    }

    #[test]
    fn insertion_order_alone_decides_the_victim_without_reads() {
        let cache = VerdictCache::new(NonZeroUsize::new(3).unwrap(), NonZeroUsize::new(8).unwrap());
        cache.insert("a".to_string(), Verdict::plain(Label::Clean));
        cache.insert("b".to_string(), Verdict::plain(Label::Clean));
        cache.insert("c".to_string(), Verdict::plain(Label::Clean));
        cache.insert("d".to_string(), Verdict::plain(Label::Clean));
        assert!(!contains(&cache, "a"));
        assert_eq!(len(&cache), 3);
    }

    #[test]
    fn reinserting_an_existing_key_at_capacity_evicts_nothing() {
        // the `!contains_key` guard: overwriting does not grow the table, so
        // paying an eviction for it would drop a live entry for free
        let cache = VerdictCache::new(NonZeroUsize::new(2).unwrap(), NonZeroUsize::new(8).unwrap());
        cache.insert("a".to_string(), Verdict::plain(Label::Clean));
        cache.insert("b".to_string(), Verdict::plain(Label::Clean));
        cache.insert("a".to_string(), Verdict::plain(Label::Blocked));
        assert_eq!(len(&cache), 2);
        assert!(contains(&cache, "b"));
        assert_eq!(cache.get("a"), Some(Verdict::plain(Label::Blocked)));
    }

    #[test]
    fn each_overflowing_insert_drops_exactly_one_entry() {
        // partial sample: which key dies is random, how many die is not
        let cache = VerdictCache::new(
            NonZeroUsize::new(20).unwrap(),
            NonZeroUsize::new(5).unwrap(),
        );
        for i in 0..20 {
            cache.insert(format!("k{i}"), Verdict::plain(Label::Clean));
        }
        assert_eq!(len(&cache), 20);
        for i in 20..40 {
            cache.insert(format!("k{i}"), Verdict::plain(Label::Clean));
            assert_eq!(len(&cache), 20);
        }
    }

    #[test]
    fn capacity_of_one_keeps_only_the_last_url() {
        let cache = VerdictCache::new(NonZeroUsize::new(1).unwrap(), NonZeroUsize::new(1).unwrap());
        cache.insert("a".to_string(), Verdict::plain(Label::Clean));
        cache.insert("b".to_string(), Verdict::plain(Label::Blocked));
        assert_eq!(len(&cache), 1);
        assert_eq!(cache.get("a"), None);
        assert_eq!(cache.get("b"), Some(Verdict::plain(Label::Blocked)));
    }

    // concurrency

    #[test]
    fn shared_across_threads_agrees_and_counts_every_lookup() {
        const THREADS: usize = 8;
        const OPS: usize = 200;
        const HOSTS: usize = 16;

        let cache = VerdictCache::new(
            NonZeroUsize::new(64).unwrap(),
            NonZeroUsize::new(5).unwrap(),
        );
        std::thread::scope(|s| {
            for _ in 0..THREADS {
                s.spawn(|| {
                    for i in 0..OPS {
                        let url = format!("https://h{}.test/", i % HOSTS);
                        if cache.get(&url).is_none() {
                            cache.insert(url, Verdict::plain(Label::Blocked));
                        }
                    }
                });
            }
        });

        assert_eq!(len(&cache), HOSTS);
        assert!(
            cache
                .table
                .read()
                .unwrap()
                .values()
                .all(|e| e.verdict == Verdict::plain(Label::Blocked))
        );

        // no lookup is lost: every get lands on exactly one counter
        let (hits, misses) = counters(&cache);
        assert_eq!(hits + misses, (THREADS * OPS) as u64);
        // benign race: between a miss and its insert other threads may miss the
        // same url, at worst once per thread — never fewer than one per host
        assert!(misses >= HOSTS as u64);
        assert!(misses <= (THREADS * HOSTS) as u64);
    }

    #[test]
    fn concurrent_inserts_stay_within_capacity() {
        const THREADS: usize = 8;
        let cache = VerdictCache::new(
            NonZeroUsize::new(32).unwrap(),
            NonZeroUsize::new(5).unwrap(),
        );
        let cache = &cache;
        std::thread::scope(|s| {
            for t in 0..THREADS {
                s.spawn(move || {
                    for i in 0..200 {
                        cache.insert(
                            format!("https://t{t}-{i}.test/"),
                            Verdict::plain(Label::Clean),
                        );
                    }
                });
            }
        });
        assert_eq!(len(cache), 32);
    }
}
