//! Per-process verdict cache for an external HTTP authorizer
//! (`[authorizers.cache]`).
//!
//! - **Key**: a SHA-256 digest over the configured request fields (by default
//!   everything the authorizer sees except `request_id`). Fields are
//!   length-prefixed and tagged so distinct inputs can't collide by
//!   concatenation, and only the digest is stored - bearer tokens and API keys
//!   are never held in memory as cache keys.
//! - **Policy vs storage**: [`VerdictCache`] owns the policy (key, TTL,
//!   `Cache-Control` hints, `cache_denies`, metrics); a [`CacheStore`] backend
//!   only stores digests → verdicts with an expiry. Today the only backend is
//!   [`MemoryStore`] (per process). The store API is async so a shared backend
//!   (NATS KV, Redis, ...) can be added as another `CacheStore` variant
//!   without changing callers.
//! - **Memory backend**: `SHARDS` `Mutex<HashMap>` shards picked by the
//!   digest. Critical sections are a lookup or an insert - no I/O, never held
//!   across an await. Expired entries are dropped on read. A full shard
//!   samples a few entries (digests are uniformly distributed, so map order
//!   is effectively random) and evicts expired ones, else the one closest to
//!   expiry - O(1) per insert regardless of `max_entries`.
//! - **Scope**: one cache per `HttpAuthorizer`, so a config reload (which
//!   rebuilds authorizers) starts empty.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use http::{HeaderMap, HeaderName};
use metrics::Counter;
use sha2::{Digest, Sha256};

use super::authorizer::{AuthzRequest, AuthzVerdict};
use crate::config::{AuthorizerCacheConfig, CacheBackend};

const SHARDS: usize = 64;

/// Entries inspected per eviction when a memory shard is full.
const EVICTION_SAMPLE: usize = 8;

type Key = [u8; 32];

/// How the authorizer's response says to cache it (`Cache-Control`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheHint {
    /// No directive: use the configured TTL.
    Default,
    /// `no-store` / `no-cache` / `private` / `max-age=0`: don't cache.
    NoStore,
    /// `max-age=N`: cache for at most N seconds (capped at the configured TTL).
    MaxAge(Duration),
}

impl CacheHint {
    /// Parse a `Cache-Control` header value. Unknown directives are ignored.
    pub fn from_cache_control(value: Option<&str>) -> Self {
        let Some(value) = value else {
            return CacheHint::Default;
        };
        let mut hint = CacheHint::Default;
        for directive in value.split(',').map(|d| d.trim().to_ascii_lowercase()) {
            match directive.as_str() {
                "no-store" | "no-cache" | "private" => return CacheHint::NoStore,
                d => {
                    if let Some(secs) = d.strip_prefix("max-age=")
                        && let Ok(n) = secs.trim_matches('"').parse::<u64>()
                    {
                        if n == 0 {
                            return CacheHint::NoStore;
                        }
                        hint = CacheHint::MaxAge(Duration::from_secs(n));
                    }
                }
            }
        }
        hint
    }
}

/// One component of a narrowed cache key.
#[derive(Debug, Clone, PartialEq, Eq)]
enum KeyField {
    Method,
    Host,
    Path,
    Query,
    SourceIp,
    Claims,
    Header(HeaderName),
}

pub struct CacheMetrics {
    pub hit: Counter,
    pub miss: Counter,
    pub evicted: Counter,
}

impl CacheMetrics {
    fn new(authorizer: &str) -> Self {
        let c = |result: &'static str| {
            metrics::counter!("quik_authorizer_cache_total",
                "authorizer" => authorizer.to_owned(),
                "result" => result
            )
        };
        Self {
            hit: c("hit"),
            miss: c("miss"),
            evicted: c("evicted"),
        }
    }
}

struct Entry {
    expires: Instant,
    verdict: Arc<AuthzVerdict>,
}

/// Where cached verdicts live. One variant per backend; enum dispatch keeps
/// the hot path free of trait objects. Add shared backends here.
pub enum CacheStore {
    /// Per-process, in-memory (the default).
    Memory(MemoryStore),
}

impl CacheStore {
    async fn get(&self, key: &Key) -> Option<Arc<AuthzVerdict>> {
        match self {
            CacheStore::Memory(m) => m.get(key),
        }
    }

    /// Returns how many entries were evicted to make room.
    async fn put(&self, key: Key, verdict: Arc<AuthzVerdict>, ttl: Duration) -> u64 {
        match self {
            CacheStore::Memory(m) => m.put(key, verdict, ttl),
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        match self {
            CacheStore::Memory(m) => m.len(),
        }
    }
}

pub struct MemoryStore {
    shards: Box<[Mutex<HashMap<Key, Entry>>]>,
    per_shard_cap: usize,
}

impl MemoryStore {
    fn new(max_entries: usize) -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            per_shard_cap: max_entries.div_ceil(SHARDS).max(1),
        }
    }

    fn shard(&self, key: &Key) -> std::sync::MutexGuard<'_, HashMap<Key, Entry>> {
        self.shards[key[0] as usize % SHARDS]
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    fn get(&self, key: &Key) -> Option<Arc<AuthzVerdict>> {
        let mut shard = self.shard(key);
        match shard.get(key) {
            Some(e) if e.expires > Instant::now() => Some(e.verdict.clone()),
            Some(_) => {
                shard.remove(key);
                None
            }
            None => None,
        }
    }

    /// Insert, evicting (from a small sample) if the shard is full. Returns
    /// the number of entries evicted.
    fn put(&self, key: Key, verdict: Arc<AuthzVerdict>, ttl: Duration) -> u64 {
        let now = Instant::now();
        let mut shard = self.shard(&key);
        let mut evicted = 0;
        if shard.len() >= self.per_shard_cap && !shard.contains_key(&key) {
            let mut sample = [None; EVICTION_SAMPLE];
            for (slot, (k, e)) in sample.iter_mut().zip(shard.iter()) {
                *slot = Some((*k, e.expires));
            }
            for (k, expires) in sample.iter().flatten() {
                if *expires <= now {
                    shard.remove(k);
                    evicted += 1;
                }
            }
            if evicted == 0
                && let Some((k, _)) = sample.iter().flatten().min_by_key(|(_, e)| *e)
            {
                shard.remove(k);
                evicted = 1;
            }
        }
        shard.insert(
            key,
            Entry {
                expires: now + ttl,
                verdict,
            },
        );
        evicted
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
    }
}

pub struct VerdictCache {
    ttl: Duration,
    cache_denies: bool,
    /// `None` keys on the whole envelope (minus request_id).
    fields: Option<Vec<KeyField>>,
    store: CacheStore,
    pub metrics: CacheMetrics,
}

impl VerdictCache {
    /// `None` when the cache is disabled (`ttl_seconds = 0`).
    pub fn from_config(authorizer: &str, cfg: &AuthorizerCacheConfig) -> Result<Option<Self>> {
        if cfg.ttl_seconds == 0 {
            return Ok(None);
        }
        let fields = match &cfg.key {
            None => None,
            Some(entries) => Some(
                entries
                    .iter()
                    .map(|e| parse_field(e))
                    .collect::<Result<Vec<_>>>()?,
            ),
        };
        let store = match cfg.backend {
            CacheBackend::Memory => CacheStore::Memory(MemoryStore::new(cfg.max_entries)),
        };
        Ok(Some(Self {
            ttl: Duration::from_secs(cfg.ttl_seconds),
            cache_denies: cfg.cache_denies,
            fields,
            store,
            metrics: CacheMetrics::new(authorizer),
        }))
    }

    /// Digest the request fields that identify a cacheable verdict.
    /// `forward_headers` are the authorizer's own (what it sees) and are used
    /// when keying on the whole envelope.
    pub fn key(&self, req: &AuthzRequest<'_>, forward_headers: &[HeaderName]) -> Key {
        let mut h = Sha256::new();
        match &self.fields {
            None => {
                feed_method(&mut h, req);
                feed_host(&mut h, req);
                feed(&mut h, b"path", req.uri.path().as_bytes());
                feed(&mut h, b"query", req.uri.query().unwrap_or("").as_bytes());
                feed_ip(&mut h, req.source_ip);
                for name in forward_headers {
                    feed_header(&mut h, req.headers, name);
                }
                feed_claims(&mut h, req);
            }
            Some(fields) => {
                for f in fields {
                    match f {
                        KeyField::Method => feed_method(&mut h, req),
                        KeyField::Host => feed_host(&mut h, req),
                        KeyField::Path => feed(&mut h, b"path", req.uri.path().as_bytes()),
                        KeyField::Query => {
                            feed(&mut h, b"query", req.uri.query().unwrap_or("").as_bytes())
                        }
                        KeyField::SourceIp => feed_ip(&mut h, req.source_ip),
                        KeyField::Claims => feed_claims(&mut h, req),
                        KeyField::Header(name) => feed_header(&mut h, req.headers, name),
                    }
                }
            }
        }
        h.finalize().into()
    }

    /// A live cached verdict for `key`, if any.
    pub async fn get(&self, key: &Key) -> Option<Arc<AuthzVerdict>> {
        let hit = self.store.get(key).await;
        match &hit {
            Some(_) => self.metrics.hit.increment(1),
            None => self.metrics.miss.increment(1),
        }
        hit
    }

    /// Cache a fresh verdict, honouring the authorizer's `Cache-Control` hint
    /// and `cache_denies`.
    pub async fn put(&self, key: Key, verdict: &AuthzVerdict, hint: CacheHint) {
        if matches!(verdict, AuthzVerdict::Deny { .. }) && !self.cache_denies {
            return;
        }
        let ttl = match hint {
            CacheHint::NoStore => return,
            CacheHint::Default => self.ttl,
            CacheHint::MaxAge(d) => d.min(self.ttl),
        };
        let evicted = self.store.put(key, Arc::new(verdict.clone()), ttl).await;
        if evicted > 0 {
            self.metrics.evicted.increment(evicted);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.store.len()
    }
}

fn parse_field(entry: &str) -> Result<KeyField> {
    Ok(match entry {
        "method" => KeyField::Method,
        "host" => KeyField::Host,
        "path" => KeyField::Path,
        "query" => KeyField::Query,
        "source_ip" => KeyField::SourceIp,
        "claims" => KeyField::Claims,
        other => match other.strip_prefix("header:") {
            Some(h) => KeyField::Header(HeaderName::try_from(h)?),
            None => bail!("invalid cache.key entry '{other}'"),
        },
    })
}

/// Tag + length-prefix each field so `("ab","c")` and `("a","bc")` differ.
fn feed(h: &mut Sha256, tag: &[u8], value: &[u8]) {
    h.update(tag);
    h.update((value.len() as u64).to_le_bytes());
    h.update(value);
}

fn feed_method(h: &mut Sha256, req: &AuthzRequest<'_>) {
    feed(h, b"method", req.method.as_str().as_bytes());
}

fn feed_host(h: &mut Sha256, req: &AuthzRequest<'_>) {
    let host = req
        .headers
        .get(http::header::HOST)
        .map(|v| v.as_bytes())
        .or_else(|| req.uri.authority().map(|a| a.as_str().as_bytes()))
        .unwrap_or(b"");
    feed(h, b"host", host);
}

fn feed_ip(h: &mut Sha256, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => feed(h, b"ip", &v4.octets()),
        IpAddr::V6(v6) => feed(h, b"ip", &v6.octets()),
    }
}

/// Every value of `name`, in order. Absent and empty-valued are distinct.
fn feed_header(h: &mut Sha256, headers: &HeaderMap, name: &HeaderName) {
    feed(h, b"hname", name.as_str().as_bytes());
    let values = headers.get_all(name);
    let count = values.iter().count() as u64;
    h.update(count.to_le_bytes());
    for v in values {
        feed(h, b"hval", v.as_bytes());
    }
}

/// Claims are a serde_json map, which serialises with sorted keys, so equal
/// claim sets always hash the same.
fn feed_claims(h: &mut Sha256, req: &AuthzRequest<'_>) {
    match req.claims {
        Some(c) => feed(h, b"claims", &serde_json::to_vec(c).unwrap_or_default()),
        None => feed(h, b"noclaims", b""),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderValue, Method, StatusCode, Uri};

    fn cfg(ttl: u64, key: Option<&[&str]>, max: usize) -> AuthorizerCacheConfig {
        AuthorizerCacheConfig {
            ttl_seconds: ttl,
            key: key.map(|k| k.iter().map(|s| s.to_string()).collect()),
            max_entries: max,
            ..Default::default()
        }
    }

    struct Req {
        method: Method,
        uri: Uri,
        headers: HeaderMap,
    }

    impl Req {
        fn new(path: &str, auth: &str) -> Self {
            let mut headers = HeaderMap::new();
            headers.insert("authorization", HeaderValue::from_str(auth).unwrap());
            headers.insert("host", HeaderValue::from_static("api.example.com"));
            Self {
                method: Method::GET,
                uri: path.parse().unwrap(),
                headers,
            }
        }
        fn authz(&self) -> AuthzRequest<'_> {
            AuthzRequest {
                method: &self.method,
                uri: &self.uri,
                headers: &self.headers,
                source_ip: "10.0.0.1".parse().unwrap(),
                route: "r",
                request_id: "ignored",
                claims: None,
                body: None,
            }
        }
    }

    fn fwd() -> Vec<HeaderName> {
        vec![HeaderName::from_static("authorization")]
    }

    fn allow() -> AuthzVerdict {
        AuthzVerdict::Allow(vec![(
            HeaderName::from_static("x-user-id"),
            HeaderValue::from_static("u1"),
        )])
    }

    #[test]
    fn disabled_at_zero_ttl() {
        assert!(
            VerdictCache::from_config("a", &cfg(0, None, 10))
                .unwrap()
                .is_none()
        );
    }

    /// SECURITY: with the default key, a verdict for one path must not be
    /// reused for another - the authorizer may decide per path.
    #[test]
    fn default_key_distinguishes_every_envelope_field() {
        let c = VerdictCache::from_config("a", &cfg(60, None, 10))
            .unwrap()
            .unwrap();
        let base = Req::new("/api/orders", "Bearer t1");
        let k = c.key(&base.authz(), &fwd());

        // request_id is not part of the key.
        let mut same = base.authz();
        same.request_id = "different";
        assert_eq!(k, c.key(&same, &fwd()));

        for other in [
            Req::new("/api/admin", "Bearer t1"),
            Req::new("/api/orders?x=1", "Bearer t1"),
            Req::new("/api/orders", "Bearer t2"),
        ] {
            assert_ne!(k, c.key(&other.authz(), &fwd()), "{}", other.uri);
        }
        let mut post = Req::new("/api/orders", "Bearer t1");
        post.method = Method::POST;
        assert_ne!(k, c.key(&post.authz(), &fwd()));
        let mut ip = base.authz();
        ip.source_ip = "10.0.0.2".parse().unwrap();
        assert_ne!(k, c.key(&ip, &fwd()));
    }

    #[test]
    fn narrowed_key_ignores_other_fields() {
        let c = VerdictCache::from_config("a", &cfg(60, Some(&["header:authorization"]), 10))
            .unwrap()
            .unwrap();
        let a = Req::new("/api/orders", "Bearer t1");
        let b = Req::new("/api/other", "Bearer t1");
        let d = Req::new("/api/orders", "Bearer t2");
        assert_eq!(c.key(&a.authz(), &[]), c.key(&b.authz(), &[]));
        assert_ne!(c.key(&a.authz(), &[]), c.key(&d.authz(), &[]));
    }

    #[tokio::test]
    async fn hit_miss_and_expiry() {
        let c = VerdictCache::from_config("a", &cfg(60, None, 10))
            .unwrap()
            .unwrap();
        let r = Req::new("/x", "Bearer t");
        let k = c.key(&r.authz(), &fwd());
        assert!(c.get(&k).await.is_none());
        c.put(k, &allow(), CacheHint::Default).await;
        assert!(matches!(*c.get(&k).await.unwrap(), AuthzVerdict::Allow(_)));
        // max-age shorter than ttl wins; an already-expired entry is a miss.
        c.put(k, &allow(), CacheHint::MaxAge(Duration::ZERO)).await;
        assert!(c.get(&k).await.is_none());
        assert_eq!(c.len(), 0, "expired entry removed on read");
    }

    #[tokio::test]
    async fn no_store_and_cache_denies() {
        let mut conf = cfg(60, None, 10);
        conf.cache_denies = false;
        let c = VerdictCache::from_config("a", &conf).unwrap().unwrap();
        let k = [7u8; 32];
        c.put(k, &allow(), CacheHint::NoStore).await;
        assert!(c.get(&k).await.is_none());
        let deny = AuthzVerdict::Deny {
            status: StatusCode::FORBIDDEN,
            headers: HeaderMap::new(),
            body: Bytes::new(),
        };
        c.put(k, &deny, CacheHint::Default).await;
        assert!(
            c.get(&k).await.is_none(),
            "denies not cached when cache_denies=false"
        );
    }

    #[test]
    fn parses_cache_control() {
        use CacheHint::*;
        assert_eq!(CacheHint::from_cache_control(None), Default);
        assert_eq!(CacheHint::from_cache_control(Some("no-store")), NoStore);
        assert_eq!(
            CacheHint::from_cache_control(Some("private, max-age=60")),
            NoStore
        );
        assert_eq!(CacheHint::from_cache_control(Some("max-age=0")), NoStore);
        assert_eq!(
            CacheHint::from_cache_control(Some("public, Max-Age=30")),
            MaxAge(Duration::from_secs(30))
        );
        assert_eq!(
            CacheHint::from_cache_control(Some("must-revalidate")),
            Default
        );
    }

    #[tokio::test]
    async fn bounded_by_max_entries() {
        // SHARDS shards × 1 entry each; many more distinct keys than fit.
        let c = VerdictCache::from_config("a", &cfg(60, None, SHARDS))
            .unwrap()
            .unwrap();
        for i in 0..4096u32 {
            let mut k = [0u8; 32];
            k[..4].copy_from_slice(&i.to_le_bytes());
            c.put(k, &allow(), CacheHint::Default).await;
        }
        assert_eq!(c.len(), SHARDS);
    }

    /// A full shard prefers evicting expired entries over live ones.
    #[test]
    fn eviction_prefers_expired_entries() {
        let m = MemoryStore::new(SHARDS * 2); // 2 per shard
        let v = Arc::new(allow());
        // Same first byte → same shard.
        let k = |b: u8| {
            let mut k = [0u8; 32];
            k[1] = b;
            k
        };
        m.put(k(1), v.clone(), Duration::ZERO); // already expired
        m.put(k(2), v.clone(), Duration::from_secs(60));
        assert_eq!(m.put(k(3), v.clone(), Duration::from_secs(60)), 1);
        assert!(m.get(&k(2)).is_some(), "live entry kept");
        assert!(m.get(&k(3)).is_some());
    }
}
