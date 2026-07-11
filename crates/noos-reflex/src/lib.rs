//! Disabled application-only Reflex tick stream. A tick commits transaction,
//! receipt, and cumulative-gas roots; this API deliberately has no state root.
#![forbid(unsafe_code)]
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub type Hash32 = [u8; 32];
pub const LIFECYCLE: &str = "EXPERIMENTAL";
pub const RESULT: &str = "DISABLED_PENDING_LIVE_DRILL";
pub const REFLEX_LANE_ENABLED: bool = false;
pub const MAX_TICK_MS: u64 = 250;
pub const PROPOSAL_WEIGHT: u64 = 0;
pub const FINALITY_WEIGHT: u64 = 0;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tick {
    pub slot: u64,
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub leader_key: [u8; 32],
    pub bond_id: Hash32,
    pub tx_root: Hash32,
    pub receipt_root: Hash32,
    pub cumulative_gas_root: Hash32,
    pub prior_accumulator: Hash32,
    pub signature: [u8; 64],
}
impl Tick {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(32 * 6 + 8 * 3);
        b.extend_from_slice(b"NOOS/A-REFLEX/TICK/V1");
        b.extend_from_slice(&self.slot.to_le_bytes());
        b.extend_from_slice(&self.sequence.to_le_bytes());
        b.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        b.extend_from_slice(&self.leader_key);
        b.extend_from_slice(&self.bond_id);
        b.extend_from_slice(&self.tx_root);
        b.extend_from_slice(&self.receipt_root);
        b.extend_from_slice(&self.cumulative_gas_root);
        b.extend_from_slice(&self.prior_accumulator);
        b
    }
    #[must_use]
    pub fn digest(&self) -> Hash32 {
        *blake3::hash(&self.signing_bytes()).as_bytes()
    }
    pub fn verify_signature(&self) -> Result<(), ReflexError> {
        let key = VerifyingKey::from_bytes(&self.leader_key).map_err(|_| ReflexError::Signature)?;
        key.verify(
            &self.signing_bytes(),
            &Signature::from_bytes(&self.signature),
        )
        .map_err(|_| ReflexError::Signature)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LeaderRegistration {
    pub slot: u64,
    pub leader_key: [u8; 32],
    pub bond_id: Hash32,
    pub bond_amount: u128,
}
#[derive(Default)]
pub struct ReflexAccumulator {
    root: Hash32,
    last_tick: Option<Tick>,
    leaders: BTreeMap<u64, LeaderRegistration>,
    paused_slots: BTreeSet<u64>,
}
impl ReflexAccumulator {
    #[must_use]
    pub fn root(&self) -> Hash32 {
        self.root
    }
    pub fn register_leader(&mut self, r: LeaderRegistration) -> Result<(), ReflexError> {
        if r.bond_amount == 0 || r.bond_id == [0; 32] || self.leaders.insert(r.slot, r).is_some() {
            return Err(ReflexError::Leader);
        }
        Ok(())
    }
    pub fn pause_handoff(&mut self, slot: u64) -> Result<(), ReflexError> {
        if !self.leaders.contains_key(&slot) {
            return Err(ReflexError::Leader);
        }
        self.paused_slots.insert(slot);
        Ok(())
    }
    pub fn complete_handoff(&mut self, slot: u64) -> Result<(), ReflexError> {
        if !self.paused_slots.remove(&slot) {
            return Err(ReflexError::Handoff);
        }
        Ok(())
    }
    pub fn append(&mut self, tick: Tick) -> Result<Hash32, ReflexError> {
        let leader = self.leaders.get(&tick.slot).ok_or(ReflexError::Leader)?;
        if self.paused_slots.contains(&tick.slot) {
            return Err(ReflexError::Handoff);
        }
        if tick.leader_key != leader.leader_key || tick.bond_id != leader.bond_id {
            return Err(ReflexError::Leader);
        }
        tick.verify_signature()?;
        if tick.prior_accumulator != self.root {
            return Err(ReflexError::Accumulator);
        }
        if let Some(last) = &self.last_tick {
            let expected_sequence = last.sequence.checked_add(1).ok_or(ReflexError::Sequence)?;
            let elapsed = tick
                .timestamp_ms
                .checked_sub(last.timestamp_ms)
                .ok_or(ReflexError::Sequence)?;
            if tick.sequence != expected_sequence || elapsed > MAX_TICK_MS {
                return Err(ReflexError::Sequence);
            }
            if tick.slot < last.slot {
                return Err(ReflexError::Sequence);
            }
        } else if tick.sequence != 0 {
            return Err(ReflexError::Sequence);
        }
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/A-REFLEX/ACCUMULATOR/V1");
        h.update(&self.root);
        h.update(&tick.digest());
        self.root = *h.finalize().as_bytes();
        self.last_tick = Some(tick);
        Ok(self.root)
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContradictionProof {
    pub left: Tick,
    pub right: Tick,
}
impl ContradictionProof {
    pub fn verify(&self) -> Result<Hash32, ReflexError> {
        self.left.verify_signature()?;
        self.right.verify_signature()?;
        if self.left.leader_key != self.right.leader_key
            || self.left.slot != self.right.slot
            || self.left.sequence != self.right.sequence
            || self.left.digest() == self.right.digest()
        {
            return Err(ReflexError::NotContradiction);
        }
        let mut pair = [self.left.digest(), self.right.digest()];
        pair.sort();
        let mut h = blake3::Hasher::new();
        h.update(b"NOOS/A-REFLEX/CONTRADICTION/V1");
        h.update(&pair[0]);
        h.update(&pair[1]);
        Ok(*h.finalize().as_bytes())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveDrill {
    pub accepted_contradictions: u64,
    pub handoff_gap_p95_ticks: u8,
    pub split_view_liability_bps: u16,
    pub compensation_exact: bool,
    pub disable_rollback_rehearsed: bool,
}
impl LiveDrill {
    #[must_use]
    pub fn passes(&self) -> bool {
        self.accepted_contradictions == 0
            && self.handoff_gap_p95_ticks <= 2
            && self.split_view_liability_bps == 10_000
            && self.compensation_exact
            && self.disable_rollback_rehearsed
    }
}
#[must_use]
pub const fn can_enable_from_shape_evidence(_f9_passed: bool) -> bool {
    false
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReflexError {
    #[error("unregistered leader or bond")]
    Leader,
    #[error("invalid tick signature")]
    Signature,
    #[error("noncanonical accumulator link")]
    Accumulator,
    #[error("tick cadence or sequence violation")]
    Sequence,
    #[error("slot handoff paused")]
    Handoff,
    #[error("not a same-key contradiction")]
    NotContradiction,
}
#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    fn h(v: u8) -> Hash32 {
        [v; 32]
    }
    fn signed(key: &SigningKey, slot: u64, seq: u64, time: u64, prior: Hash32, tx: u8) -> Tick {
        let mut t = Tick {
            slot,
            sequence: seq,
            timestamp_ms: time,
            leader_key: key.verifying_key().to_bytes(),
            bond_id: h(9),
            tx_root: h(tx),
            receipt_root: h(2),
            cumulative_gas_root: h(3),
            prior_accumulator: prior,
            signature: [0; 64],
        };
        t.signature = key.sign(&t.signing_bytes()).to_bytes();
        t
    }
    #[test]
    fn signed_bonded_ticks_accumulate() {
        let key = SigningKey::from_bytes(&h(7));
        let mut a = ReflexAccumulator::default();
        a.register_leader(LeaderRegistration {
            slot: 1,
            leader_key: key.verifying_key().to_bytes(),
            bond_id: h(9),
            bond_amount: 1,
        })
        .unwrap();
        let r = a.append(signed(&key, 1, 0, 100, [0; 32], 1)).unwrap();
        assert_ne!(r, [0; 32]);
        assert!(a.append(signed(&key, 1, 1, 351, r, 2)).is_err());
    }
    #[test]
    fn contradiction_is_same_key_same_position() {
        let key = SigningKey::from_bytes(&h(7));
        let p = ContradictionProof {
            left: signed(&key, 1, 0, 100, [0; 32], 1),
            right: signed(&key, 1, 0, 100, [0; 32], 2),
        };
        assert!(p.verify().is_ok());
        let same = ContradictionProof {
            right: p.left.clone(),
            left: p.left,
        };
        assert_eq!(same.verify(), Err(ReflexError::NotContradiction));
    }
    #[test]
    fn handoff_pauses_acceptance() {
        let key = SigningKey::from_bytes(&h(7));
        let mut a = ReflexAccumulator::default();
        a.register_leader(LeaderRegistration {
            slot: 1,
            leader_key: key.verifying_key().to_bytes(),
            bond_id: h(9),
            bond_amount: 1,
        })
        .unwrap();
        a.pause_handoff(1).unwrap();
        assert_eq!(
            a.append(signed(&key, 1, 0, 0, [0; 32], 1)),
            Err(ReflexError::Handoff)
        );
        a.complete_handoff(1).unwrap();
        assert!(a.append(signed(&key, 1, 0, 0, [0; 32], 1)).is_ok());
    }
    #[test]
    fn lane_defaults_and_live_thresholds() {
        assert!(!REFLEX_LANE_ENABLED && !can_enable_from_shape_evidence(true));
        assert_eq!((PROPOSAL_WEIGHT, FINALITY_WEIGHT), (0, 0));
        assert_eq!(
            (LIFECYCLE, RESULT),
            ("EXPERIMENTAL", "DISABLED_PENDING_LIVE_DRILL")
        );
        let d = LiveDrill {
            accepted_contradictions: 0,
            handoff_gap_p95_ticks: 2,
            split_view_liability_bps: 10_000,
            compensation_exact: true,
            disable_rollback_rehearsed: true,
        };
        assert!(d.passes());
    }
}
