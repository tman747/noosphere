//! Loopix-style deep-route queue primitive.
//!
//! The node accepts only fixed-size ciphertext from a separately registered
//! Sphinx packet suite, schedules bounded exponential delays, injects
//! indistinguishable cover ciphertext, and keeps packet identifiers local.
//! It does not implement or claim a Sphinx cryptographic suite; that external
//! dependency and global-observer evidence gate deep routing.

#![forbid(unsafe_code)]

use noos_crypto::{hash_domain, DomainId};
use std::collections::BTreeMap;

pub type Hash32 = [u8; 32];
pub const MIX_PACKET_BUCKETS: [usize; 3] = [4_096, 16_384, 65_536];
pub const MAX_MIX_QUEUE: usize = 65_536;
pub const WWM_DEEP_MIX_ENABLED: bool = false;
pub const WWM_MIX_CONSENSUS_WEIGHT: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MixError {
    InvalidConfig,
    InvalidPacket,
    QueueFull,
    PacketExpired,
    ArithmeticOverflow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MixNodeConfig {
    pub sphinx_suite_root: Hash32,
    pub failure_domain: Hash32,
    pub packet_bucket_bytes: u32,
    pub mean_delay_ms: u32,
    pub maximum_delay_ms: u32,
    pub maximum_queue: u32,
    pub cover_packets_per_minute: u32,
    pub loop_rate_per_million: u32,
    pub drop_rate_per_million: u32,
}

impl MixNodeConfig {
    pub fn validate(&self) -> Result<(), MixError> {
        let bucket =
            usize::try_from(self.packet_bucket_bytes).map_err(|_| MixError::InvalidConfig)?;
        if self.sphinx_suite_root == [0; 32]
            || self.failure_domain == [0; 32]
            || !MIX_PACKET_BUCKETS.contains(&bucket)
            || self.mean_delay_ms == 0
            || self.maximum_delay_ms < self.mean_delay_ms
            || self.maximum_queue == 0
            || usize::try_from(self.maximum_queue).map_or(true, |value| value > MAX_MIX_QUEUE)
            || self.cover_packets_per_minute == 0
            || self.loop_rate_per_million > 1_000_000
            || self.drop_rate_per_million > 1_000_000
            || self
                .loop_rate_per_million
                .checked_add(self.drop_rate_per_million)
                .is_none_or(|value| value > 1_000_000)
        {
            return Err(MixError::InvalidConfig);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedMixPacket {
    /// Local queue identity. Never emitted on the wire.
    local_packet_id: Hash32,
    ciphertext: Vec<u8>,
    sphinx_suite_root: Hash32,
    deadline_ms: u64,
}

impl FixedMixPacket {
    pub fn new(
        config: &MixNodeConfig,
        ciphertext: Vec<u8>,
        deadline_ms: u64,
        local_entropy: Hash32,
    ) -> Result<Self, MixError> {
        config.validate()?;
        if ciphertext.len()
            != usize::try_from(config.packet_bucket_bytes).map_err(|_| MixError::InvalidPacket)?
            || deadline_ms == 0
            || local_entropy == [0; 32]
        {
            return Err(MixError::InvalidPacket);
        }
        let ciphertext_root = digest(
            DomainId::WwmMixPacket,
            &[b"CIPHERTEXT", &config.sphinx_suite_root, &ciphertext],
        )?;
        let local_packet_id = digest(
            DomainId::WwmMixPacket,
            &[b"LOCAL", &local_entropy, &ciphertext_root],
        )?;
        Ok(Self {
            local_packet_id,
            ciphertext,
            sphinx_suite_root: config.sphinx_suite_root,
            deadline_ms,
        })
    }

    #[must_use]
    pub fn wire_bytes(&self) -> &[u8] {
        &self.ciphertext
    }

    #[must_use]
    pub fn wire_len(&self) -> usize {
        self.ciphertext.len()
    }

    #[must_use]
    pub fn suite_root(&self) -> Hash32 {
        self.sphinx_suite_root
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MixDisposition {
    Forward,
    Loop,
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadyPacket {
    pub packet: FixedMixPacket,
    pub disposition: MixDisposition,
}

#[derive(Debug, Clone)]
struct QueuedPacket {
    action_entropy: Hash32,
    packet: FixedMixPacket,
}

#[derive(Debug)]
pub struct MixQueue {
    config: MixNodeConfig,
    queue: BTreeMap<(u64, Hash32), QueuedPacket>,
    next_cover_at_ms: u64,
}

impl MixQueue {
    pub fn new(config: MixNodeConfig, now_ms: u64) -> Result<Self, MixError> {
        config.validate()?;
        let cover_interval = 60_000_u64
            .checked_div(u64::from(config.cover_packets_per_minute))
            .ok_or(MixError::InvalidConfig)?
            .max(1);
        Ok(Self {
            config,
            queue: BTreeMap::new(),
            next_cover_at_ms: now_ms
                .checked_add(cover_interval)
                .ok_or(MixError::ArithmeticOverflow)?,
        })
    }

    pub fn enqueue(
        &mut self,
        packet: FixedMixPacket,
        now_ms: u64,
        scheduling_entropy: Hash32,
    ) -> Result<u64, MixError> {
        if self.queue.len()
            >= usize::try_from(self.config.maximum_queue).map_err(|_| MixError::QueueFull)?
        {
            return Err(MixError::QueueFull);
        }
        if packet.sphinx_suite_root != self.config.sphinx_suite_root
            || packet.wire_len()
                != usize::try_from(self.config.packet_bucket_bytes)
                    .map_err(|_| MixError::InvalidPacket)?
            || scheduling_entropy == [0; 32]
            || now_ms >= packet.deadline_ms
        {
            return Err(MixError::InvalidPacket);
        }
        let delay = exponential_delay_ms(
            scheduling_entropy,
            self.config.mean_delay_ms,
            self.config.maximum_delay_ms,
        )?;
        let ready_at_ms = now_ms
            .checked_add(u64::from(delay))
            .ok_or(MixError::ArithmeticOverflow)?;
        if ready_at_ms >= packet.deadline_ms {
            return Err(MixError::PacketExpired);
        }
        let key = (ready_at_ms, packet.local_packet_id);
        if self.queue.contains_key(&key) {
            return Err(MixError::InvalidPacket);
        }
        let action_entropy = digest(
            DomainId::WwmMixPacket,
            &[b"ACTION", &scheduling_entropy, &packet.local_packet_id],
        )?;
        self.queue.insert(
            key,
            QueuedPacket {
                action_entropy,
                packet,
            },
        );
        Ok(ready_at_ms)
    }

    pub fn take_ready(&mut self, now_ms: u64) -> Vec<ReadyPacket> {
        let keys = self
            .queue
            .range(..=(now_ms, [u8::MAX; 32]))
            .map(|(key, _)| *key)
            .collect::<Vec<_>>();
        let mut ready = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(queued) = self.queue.remove(&key) {
                if now_ms >= queued.packet.deadline_ms {
                    continue;
                }
                ready.push(ReadyPacket {
                    disposition: disposition(
                        queued.action_entropy,
                        self.config.loop_rate_per_million,
                        self.config.drop_rate_per_million,
                    ),
                    packet: queued.packet,
                });
            }
        }
        ready
    }

    pub fn cover_due(
        &mut self,
        now_ms: u64,
        entropy: Hash32,
        deadline_ms: u64,
    ) -> Result<Option<FixedMixPacket>, MixError> {
        if now_ms < self.next_cover_at_ms {
            return Ok(None);
        }
        let bucket = usize::try_from(self.config.packet_bucket_bytes)
            .map_err(|_| MixError::InvalidConfig)?;
        let ciphertext = expand_cover(entropy, bucket)?;
        let packet = FixedMixPacket::new(&self.config, ciphertext, deadline_ms, entropy)?;
        let interval = 60_000_u64
            .checked_div(u64::from(self.config.cover_packets_per_minute))
            .ok_or(MixError::InvalidConfig)?
            .max(1);
        self.next_cover_at_ms = now_ms
            .checked_add(interval)
            .ok_or(MixError::ArithmeticOverflow)?;
        Ok(Some(packet))
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Samples a bounded exponential delay from 53 bits of local entropy. This is
/// an off-chain scheduler, never a consensus calculation.
pub fn exponential_delay_ms(
    entropy: Hash32,
    mean_delay_ms: u32,
    maximum_delay_ms: u32,
) -> Result<u32, MixError> {
    if entropy == [0; 32] || mean_delay_ms == 0 || maximum_delay_ms < mean_delay_ms {
        return Err(MixError::InvalidConfig);
    }
    let raw = u64::from_le_bytes(
        entropy[..8]
            .try_into()
            .map_err(|_| MixError::InvalidConfig)?,
    );
    let mantissa = (raw >> 11).max(1);
    let denominator = (1_u64 << 53) as f64;
    let uniform = mantissa as f64 / denominator;
    let sampled = (-uniform.ln() * f64::from(mean_delay_ms)).round();
    let bounded = sampled.clamp(1.0, f64::from(maximum_delay_ms));
    Ok(bounded as u32)
}

fn disposition(entropy: Hash32, loop_rate: u32, drop_rate: u32) -> MixDisposition {
    let draw = u32::from_le_bytes(entropy[..4].try_into().unwrap_or([0; 4])) % 1_000_000;
    if draw < drop_rate {
        MixDisposition::Drop
    } else if draw < drop_rate.saturating_add(loop_rate) {
        MixDisposition::Loop
    } else {
        MixDisposition::Forward
    }
}

fn expand_cover(entropy: Hash32, length: usize) -> Result<Vec<u8>, MixError> {
    if entropy == [0; 32] || !MIX_PACKET_BUCKETS.contains(&length) {
        return Err(MixError::InvalidPacket);
    }
    let mut output = vec![0; length];
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/WWM/MIX/COVER/V1");
    hasher.update(&entropy);
    hasher.finalize_xof().fill(&mut output);
    Ok(output)
}

fn digest(domain: DomainId, parts: &[&[u8]]) -> Result<Hash32, MixError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| MixError::InvalidPacket)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::assertions_on_constants, clippy::unwrap_used)]
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn config() -> MixNodeConfig {
        MixNodeConfig {
            sphinx_suite_root: h(1),
            failure_domain: h(2),
            packet_bucket_bytes: 4_096,
            mean_delay_ms: 200,
            maximum_delay_ms: 2_000,
            maximum_queue: 8,
            cover_packets_per_minute: 60,
            loop_rate_per_million: 50_000,
            drop_rate_per_million: 10_000,
        }
    }

    fn packet(value: u8, entropy: u8) -> FixedMixPacket {
        FixedMixPacket::new(&config(), vec![value; 4_096], 10_000, h(entropy)).unwrap()
    }

    #[test]
    fn real_and_cover_packets_have_identical_wire_shape() {
        let mut queue = MixQueue::new(config(), 0).unwrap();
        let real = packet(7, 8);
        let cover = queue.cover_due(1_000, h(9), 10_000).unwrap().unwrap();
        assert_eq!(real.wire_len(), cover.wire_len());
        assert_eq!(real.wire_len(), 4_096);
        assert_eq!(real.suite_root(), cover.suite_root());
    }

    #[test]
    fn bounded_delay_queue_reorders_and_exposes_no_wire_metadata() {
        let mut queue = MixQueue::new(config(), 0).unwrap();
        let first_ready = queue.enqueue(packet(1, 10), 0, h(11)).unwrap();
        let second_ready = queue.enqueue(packet(2, 12), 0, h(200)).unwrap();
        assert_eq!(queue.len(), 2);
        let ready = queue.take_ready(first_ready.max(second_ready));
        assert_eq!(ready.len(), 2);
        assert!(ready
            .iter()
            .all(|entry| entry.packet.wire_bytes().len() == 4_096));
        assert!(queue.is_empty());
    }

    #[test]
    fn queue_and_deadline_fail_closed() {
        let mut cfg = config();
        cfg.maximum_queue = 1;
        let mut queue = MixQueue::new(cfg.clone(), 0).unwrap();
        let first = FixedMixPacket::new(&cfg, vec![1; 4_096], 10_000, h(20)).unwrap();
        queue.enqueue(first, 0, h(21)).unwrap();
        let second = FixedMixPacket::new(&cfg, vec![2; 4_096], 10_000, h(22)).unwrap();
        assert_eq!(queue.enqueue(second, 0, h(23)), Err(MixError::QueueFull));
        let expired = FixedMixPacket::new(&cfg, vec![3; 4_096], 1, h(24)).unwrap();
        assert_eq!(
            MixQueue::new(cfg, 0).unwrap().enqueue(expired, 1, h(25)),
            Err(MixError::InvalidPacket)
        );
    }

    #[test]
    fn mix_is_explicitly_external_gated_and_non_consensus() {
        assert!(!WWM_DEEP_MIX_ENABLED);
        assert_eq!(WWM_MIX_CONSENSUS_WEIGHT, 0);
    }
}
