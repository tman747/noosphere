//! Anti-DoS state: token buckets, content-digest duplicate caches, peer
//! scoring, and progressive cooldowns (p2p-v1.md §7; ch01 §10.4 anti-DoS).
//!
//! All logic here is pure over a caller-supplied `now_ms` monotonic clock so
//! unit tests are deterministic; the node feeds a process-monotonic clock.

use crate::envelope::Protocol;
use std::collections::{HashMap, VecDeque};

// ---------------------------------------------------------------------------
// Token bucket
// ---------------------------------------------------------------------------

/// Integer token bucket in milli-tokens: no floats, no drift.
#[derive(Debug, Clone)]
pub struct TokenBucket {
    capacity_milli: u64,
    available_milli: u64,
    refill_milli_per_ms: u64,
    last_ms: u64,
}

impl TokenBucket {
    /// `burst` whole tokens of capacity, refilled at `per_second` tokens/s.
    pub fn new(burst: u32, per_second: u32, now_ms: u64) -> Self {
        let capacity_milli = u64::from(burst).saturating_mul(1000);
        TokenBucket {
            capacity_milli,
            available_milli: capacity_milli,
            refill_milli_per_ms: u64::from(per_second), // tokens/s == milli-tokens/ms
            last_ms: now_ms,
        }
    }

    /// Takes one token; `false` = rate limit exceeded.
    pub fn try_take(&mut self, now_ms: u64) -> bool {
        let elapsed = now_ms.saturating_sub(self.last_ms);
        self.last_ms = now_ms;
        self.available_milli = self
            .available_milli
            .saturating_add(elapsed.saturating_mul(self.refill_milli_per_ms))
            .min(self.capacity_milli);
        if self.available_milli >= 1000 {
            self.available_milli = self.available_milli.saturating_sub(1000);
            true
        } else {
            false
        }
    }
}

/// Per-protocol inbound request limits (PROPOSED-G0 defaults, p2p-v1.md §7.1).
#[derive(Debug, Clone, Copy)]
pub struct RateLimit {
    pub burst: u32,
    pub per_second: u32,
}

/// Per-peer limit table over the eight application protocols.
#[derive(Debug, Clone)]
pub struct LimitsConfig {
    pub per_protocol: [RateLimit; 8],
}

impl Default for LimitsConfig {
    fn default() -> Self {
        // Indexed by Protocol::app_index(): header, body, vote, tx, range,
        // snapshot, shard, loom receipt.
        LimitsConfig {
            per_protocol: [
                RateLimit {
                    burst: 64,
                    per_second: 32,
                }, // braid/header
                RateLimit {
                    burst: 16,
                    per_second: 8,
                }, // braid/body
                RateLimit {
                    burst: 128,
                    per_second: 64,
                }, // braid/vote
                RateLimit {
                    burst: 256,
                    per_second: 128,
                }, // lumen/tx
                RateLimit {
                    burst: 8,
                    per_second: 4,
                }, // sync/range
                RateLimit {
                    burst: 16,
                    per_second: 8,
                }, // sync/snapshot
                RateLimit {
                    burst: 32,
                    per_second: 16,
                }, // blob/shard
                RateLimit {
                    burst: 16,
                    per_second: 8,
                }, // loom/receipt
            ],
        }
    }
}

impl LimitsConfig {
    pub fn bucket_for(&self, protocol: Protocol, now_ms: u64) -> Option<TokenBucket> {
        let idx = protocol.app_index()?;
        let rl = self.per_protocol[idx];
        Some(TokenBucket::new(rl.burst, rl.per_second, now_ms))
    }
}

// ---------------------------------------------------------------------------
// Duplicate cache (content-digest LRU)
// ---------------------------------------------------------------------------

/// Bounded LRU set of 32-byte content digests. Lazy eviction: the order queue
/// may hold stale entries for re-touched digests; `map` sequence numbers
/// disambiguate.
#[derive(Debug)]
pub struct DupCache {
    capacity: usize,
    seq: u64,
    map: HashMap<[u8; 32], u64>,
    order: VecDeque<([u8; 32], u64)>,
}

impl DupCache {
    pub fn new(capacity: usize) -> Self {
        DupCache {
            capacity: capacity.max(1),
            seq: 0,
            map: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    /// Inserts (or refreshes) a digest. Returns `false` when it was already
    /// cached — a duplicate.
    pub fn insert(&mut self, digest: [u8; 32]) -> bool {
        self.seq = self.seq.wrapping_add(1);
        let fresh = self.map.insert(digest, self.seq).is_none();
        self.order.push_back((digest, self.seq));
        while self.map.len() > self.capacity {
            self.evict_one();
        }
        // Bound the lazy queue against pathological re-touch loops.
        while self.order.len() > self.capacity.saturating_mul(4) {
            self.pop_stale();
        }
        fresh
    }

    pub fn contains(&self, digest: &[u8; 32]) -> bool {
        self.map.contains_key(digest)
    }

    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    fn pop_stale(&mut self) {
        if let Some((digest, seq)) = self.order.pop_front() {
            if self.map.get(&digest) == Some(&seq) {
                // Not stale after all: this is the live entry; keep it live
                // by re-appending (it is the oldest live digest).
                self.order.push_front((digest, seq));
            }
        }
    }

    fn evict_one(&mut self) {
        while let Some((digest, seq)) = self.order.pop_front() {
            if self.map.get(&digest) == Some(&seq) {
                self.map.remove(&digest);
                return;
            }
            // Stale queue entry for a refreshed digest: skip.
        }
    }
}

// ---------------------------------------------------------------------------
// Violations and peer scoring
// ---------------------------------------------------------------------------

/// Protocol violations with fixed penalties (PROPOSED-G0, p2p-v1.md §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Violation {
    /// Frame declared beyond the 1 MiB law: immediate disconnect.
    OversizeFrame,
    /// Envelope failed canonical decode.
    MalformedEnvelope,
    /// Envelope chain_id differs from the attested chain: immediate disconnect.
    WrongChainEnvelope,
    /// Per-protocol token bucket exhausted.
    RateLimitExceeded,
    /// Application stream before handshake completion (or after rejection).
    StreamBeforeHandshake,
    /// Handshake did not complete within the deadline.
    HandshakeTimeout,
}

impl Violation {
    /// (penalty points, immediate disconnect).
    pub const fn penalty(self) -> (u32, bool) {
        match self {
            Violation::OversizeFrame => (100, true),
            Violation::MalformedEnvelope => (40, false),
            Violation::WrongChainEnvelope => (100, true),
            Violation::RateLimitExceeded => (15, false),
            Violation::StreamBeforeHandshake => (40, false),
            Violation::HandshakeTimeout => (100, true),
        }
    }

    pub const fn class_name(self) -> &'static str {
        match self {
            Violation::OversizeFrame => "oversize_frame",
            Violation::MalformedEnvelope => "malformed_envelope",
            Violation::WrongChainEnvelope => "wrong_chain_envelope",
            Violation::RateLimitExceeded => "rate_limit_exceeded",
            Violation::StreamBeforeHandshake => "stream_before_handshake",
            Violation::HandshakeTimeout => "handshake_timeout",
        }
    }
}

/// Disconnect threshold: accumulated penalty at or above this disconnects and
/// starts a cooldown (PROPOSED-G0).
pub const DISCONNECT_SCORE: u32 = 100;

/// Progressive cooldown after a violation disconnect: `base << (strikes-1)`
/// capped at `max` (PROPOSED-G0).
pub const COOLDOWN_BASE_MS: u64 = 30_000;
pub const COOLDOWN_MAX_MS: u64 = 600_000;

/// Per-peer cooldown ledger. Strikes persist across cooldowns so repeat
/// offenders wait progressively longer.
#[derive(Debug, Default)]
pub struct CooldownLedger {
    entries: HashMap<Vec<u8>, CooldownEntry>,
}

#[derive(Debug, Clone, Copy)]
struct CooldownEntry {
    until_ms: u64,
    strikes: u32,
}

impl CooldownLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a violation disconnect; returns the cooldown deadline.
    pub fn strike(&mut self, peer: &[u8], now_ms: u64) -> u64 {
        let entry = self.entries.entry(peer.to_vec()).or_insert(CooldownEntry {
            until_ms: 0,
            strikes: 0,
        });
        entry.strikes = entry.strikes.saturating_add(1);
        let shift = entry.strikes.saturating_sub(1).min(31);
        let dur = COOLDOWN_BASE_MS
            .saturating_mul(1u64 << shift)
            .min(COOLDOWN_MAX_MS);
        entry.until_ms = now_ms.saturating_add(dur);
        entry.until_ms
    }

    /// Is the peer currently cooling down?
    pub fn active(&self, peer: &[u8], now_ms: u64) -> bool {
        self.entries.get(peer).is_some_and(|e| e.until_ms > now_ms)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn token_bucket_burst_then_refill() {
        let mut b = TokenBucket::new(2, 1, 0);
        assert!(b.try_take(0));
        assert!(b.try_take(0));
        assert!(!b.try_take(0), "burst exhausted");
        assert!(!b.try_take(500), "half a token is not a token");
        assert!(b.try_take(1000), "one token refilled after 1s");
        assert!(!b.try_take(1000));
        // Refill never exceeds capacity.
        assert!(b.try_take(100_000));
        assert!(b.try_take(100_000));
        assert!(!b.try_take(100_000));
    }

    #[test]
    fn zero_refill_bucket_never_recovers() {
        let mut b = TokenBucket::new(1, 0, 0);
        assert!(b.try_take(0));
        assert!(!b.try_take(u64::MAX / 2));
    }

    #[test]
    fn dup_cache_detects_duplicates_and_evicts_lru() {
        let mut c = DupCache::new(2);
        let d = |i: u8| [i; 32];
        assert!(c.insert(d(1)));
        assert!(c.insert(d(2)));
        assert!(!c.insert(d(1)), "duplicate detected (and refreshed)");
        // Capacity 2; inserting a third evicts the LEAST recently used = d(2)
        // because d(1) was just refreshed.
        assert!(c.insert(d(3)));
        assert_eq!(c.len(), 2);
        assert!(c.contains(&d(1)), "recently refreshed survives");
        assert!(!c.contains(&d(2)), "LRU victim evicted");
        assert!(c.contains(&d(3)));
    }

    #[test]
    fn dup_cache_retouch_storm_stays_bounded() {
        let mut c = DupCache::new(4);
        for _ in 0..10_000 {
            c.insert([9; 32]);
        }
        assert_eq!(c.len(), 1);
        assert!(c.order.len() <= 16, "lazy queue bounded: {}", c.order.len());
    }

    #[test]
    fn cooldown_progression_doubles_and_caps() {
        let mut l = CooldownLedger::new();
        let peer = b"peer-a".as_slice();
        assert_eq!(l.strike(peer, 0), 30_000);
        assert!(l.active(peer, 29_999));
        assert!(!l.active(peer, 30_000));
        assert_eq!(l.strike(peer, 100_000), 100_000 + 60_000);
        assert_eq!(l.strike(peer, 200_000), 200_000 + 120_000);
        // Strikes keep doubling until the cap.
        for _ in 0..10 {
            l.strike(peer, 300_000);
        }
        assert_eq!(l.strike(peer, 300_000), 300_000 + COOLDOWN_MAX_MS);
    }

    #[test]
    fn penalties_reach_disconnect() {
        let (p, immediate) = Violation::OversizeFrame.penalty();
        assert!(p >= DISCONNECT_SCORE && immediate);
        let (p, immediate) = Violation::RateLimitExceeded.penalty();
        assert!(!immediate);
        // Seven rate-limit trips cross the threshold.
        assert!(p * 7 >= DISCONNECT_SCORE);
    }
}
