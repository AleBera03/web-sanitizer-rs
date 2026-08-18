use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use rand::seq::IteratorRandom;

/// What the guard decided about one `(host, port)` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveVerdict {
    /// Every address survived the deny table; connect to one of _these_.
    Allowed { addrs: Vec<SocketAddr> },
    /// At least one address was forbidden, so the whole request is refused.
    Denied { addr: IpAddr, rule: &'static str },
}

struct Entry {
    verdict: ResolveVerdict,
    decided_at: Instant,
    last_used: AtomicU64,
}

pub struct ResolveCache {
    table: RwLock<HashMap<String, Entry>>,
    hits: AtomicU64,
    misses: AtomicU64,
    clock: AtomicU64,
    max_entries: usize,
    evict_sample_rate: usize,
}

impl Default for ResolveCache {
    fn default() -> ResolveCache {
        ResolveCache {
            table: RwLock::new(HashMap::new()),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            clock: AtomicU64::new(0),
            max_entries: 10_000,
            evict_sample_rate: 5,
        }
    }
}

impl ResolveCache {
    pub fn new(max_entries: NonZeroUsize, evict_sample_rate: NonZeroUsize) -> ResolveCache {
        ResolveCache {
            max_entries: max_entries.get(),
            evict_sample_rate: evict_sample_rate.get(),
            ..ResolveCache::default()
        }
    }

    /// A usable verdict for `(host, port)`, or `None` when the guard has to
    /// resolve. An allow older than `allow_ttl` counts as a miss.
    pub fn get(&self, host: &str, port: u16, allow_ttl: Duration) -> Option<ResolveVerdict> {
        let table = self.table.read().unwrap_or_else(|e| e.into_inner());
        let entry = match table.get(&key(host, port)) {
            Some(entry) => entry,
            None => {
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        };
        if matches!(entry.verdict, ResolveVerdict::Allowed { .. })
            && entry.decided_at.elapsed() >= allow_ttl
        {
            self.misses.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let t = self.clock.fetch_add(1, Ordering::Relaxed);
        entry.last_used.store(t, Ordering::Relaxed);
        self.hits.fetch_add(1, Ordering::Relaxed);
        Some(entry.verdict.clone())
    }

    /// Record a verdict.
    pub fn insert(&self, host: &str, port: u16, verdict: ResolveVerdict) {
        let key = key(host, port);
        let mut table = self.table.write().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = table.get(&key)
            && matches!(existing.verdict, ResolveVerdict::Denied { .. })
        {
            return;
        }
        if table.len() >= self.max_entries && !table.contains_key(&key) {
            self.evict_one(&mut table);
        }
        let t = self.clock.fetch_add(1, Ordering::Relaxed);
        table.insert(
            key,
            Entry {
                verdict,
                decided_at: Instant::now(),
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

    /// Lookups served from the table, for `run.resolve_cache_hits`.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }
}

fn key(host: &str, port: u16) -> String {
    format!(
        "{}:{port}",
        host.trim_matches(['[', ']']).to_ascii_lowercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const TTL: Duration = Duration::from_secs(30);

    fn addr(text: &str) -> SocketAddr {
        text.parse().expect("test address parses")
    }

    fn allowed(text: &str) -> ResolveVerdict {
        ResolveVerdict::Allowed {
            addrs: vec![addr(text)],
        }
    }

    fn denied(text: &str) -> ResolveVerdict {
        ResolveVerdict::Denied {
            addr: text.parse().unwrap(),
            rule: "ssrf.loopback",
        }
    }

    fn len(cache: &ResolveCache) -> usize {
        cache.table.read().unwrap().len()
    }

    #[test]
    fn lookup_on_an_empty_cache_is_a_miss() {
        let cache = ResolveCache::default();
        assert_eq!(cache.get("example.com", 80, TTL), None);
        assert_eq!((cache.hits(), cache.misses()), (0, 1));
    }

    #[test]
    fn host_and_port_are_one_key() {
        let cache = ResolveCache::default();
        cache.insert("h.test", 80, allowed("93.184.216.34:80"));
        assert!(cache.get("h.test", 80, TTL).is_some());
        assert_eq!(cache.get("h.test", 8080, TTL), None);
    }

    #[test]
    fn keys_ignore_case_and_brackets() {
        let cache = ResolveCache::default();
        cache.insert("Example.COM", 443, allowed("93.184.216.34:443"));
        assert!(cache.get("example.com", 443, TTL).is_some());
        cache.insert("[::1]", 80, denied("::1"));
        assert!(cache.get("::1", 80, TTL).is_some());
    }

    #[test]
    fn an_allow_expires_with_its_ttl() {
        let cache = ResolveCache::default();
        cache.insert("h.test", 80, allowed("93.184.216.34:80"));
        assert!(cache.get("h.test", 80, TTL).is_some());
        assert_eq!(cache.get("h.test", 80, Duration::ZERO), None);
    }

    #[test]
    fn a_deny_never_expires() {
        let cache = ResolveCache::default();
        cache.insert("rebind.test", 80, denied("127.0.0.1"));
        assert_eq!(
            cache.get("rebind.test", 80, Duration::ZERO),
            Some(denied("127.0.0.1"))
        );
    }

    #[test]
    fn a_deny_is_never_upgraded_to_an_allow() {
        let cache = ResolveCache::default();
        cache.insert("rebind.test", 80, denied("127.0.0.1"));
        cache.insert("rebind.test", 80, allowed("93.184.216.34:80"));
        assert_eq!(cache.get("rebind.test", 80, TTL), Some(denied("127.0.0.1")));
    }

    #[test]
    fn an_allow_can_be_refreshed_by_a_later_resolution() {
        let cache = ResolveCache::default();
        cache.insert("h.test", 80, allowed("93.184.216.34:80"));
        cache.insert("h.test", 80, allowed("93.184.216.35:80"));
        assert_eq!(
            cache.get("h.test", 80, TTL),
            Some(allowed("93.184.216.35:80"))
        );
    }

    #[test]
    fn an_allow_can_become_a_deny() {
        let cache = ResolveCache::default();
        cache.insert("h.test", 80, allowed("93.184.216.34:80"));
        cache.insert("h.test", 80, denied("127.0.0.1"));
        assert_eq!(cache.get("h.test", 80, TTL), Some(denied("127.0.0.1")));
    }

    #[test]
    fn the_table_never_grows_past_its_bound() {
        let cache = ResolveCache::new(
            NonZeroUsize::new(16).unwrap(),
            NonZeroUsize::new(5).unwrap(),
        );
        for i in 0..500 {
            cache.insert(&format!("h{i}.test"), 80, allowed("93.184.216.34:80"));
        }
        assert_eq!(len(&cache), 16);
    }

    #[test]
    fn a_full_sample_evicts_the_least_recently_used() {
        let cache = ResolveCache::new(NonZeroUsize::new(3).unwrap(), NonZeroUsize::new(8).unwrap());
        for name in ["a", "b", "c"] {
            cache.insert(name, 80, allowed("93.184.216.34:80"));
        }
        assert!(cache.get("a", 80, TTL).is_some());
        assert!(cache.get("b", 80, TTL).is_some());
        cache.insert("d", 80, allowed("93.184.216.34:80"));
        assert_eq!(len(&cache), 3);
        assert_eq!(cache.get("c", 80, TTL), None);
    }

    #[test]
    fn shared_across_threads_every_worker_sees_the_same_refusal() {
        // the same private host referenced by many workers
        let cache = ResolveCache::default();
        std::thread::scope(|s| {
            for _ in 0..8 {
                s.spawn(|| {
                    for _ in 0..50 {
                        match cache.get("internal.test", 80, TTL) {
                            Some(v) => assert_eq!(v, denied("127.0.0.1")),
                            None => cache.insert("internal.test", 80, denied("127.0.0.1")),
                        }
                    }
                });
            }
        });
        assert_eq!(len(&cache), 1);
        assert_eq!(
            cache.get("internal.test", 80, TTL),
            Some(denied("127.0.0.1"))
        );
        assert_eq!(cache.hits() + cache.misses(), 8 * 50 + 1);
    }
}
