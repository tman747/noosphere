//! Application-only Reflex promise clock and canonical Braid anchor bridge.
//!
//! Reflex ticks carry compact transaction/receipt commitments and cumulative
//! gas. They have no state root, proposal weight, finality weight, or base
//! transition authority. Only a canonical Braid anchor supplies finality.
#![forbid(unsafe_code)]
pub mod dream;

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use noos_agent_class::{authorize_class_v2, ClassGateDenial, ClassGateRequest, PublicFinality};
use std::collections::{BTreeMap, BTreeSet};
use thiserror::Error;

pub mod clock;
pub mod identity;

pub type Hash32 = [u8; 32];
pub const LIFECYCLE: &str = "EXPERIMENTAL";
pub const RESULT: &str = "DISABLED_PENDING_LIVE_DEVNET_DRILL";
pub const REFLEX_LANE_ENABLED: bool = false;
pub const MAX_TICK_MS: u64 = 250;
pub const MAX_HANDOFF_GAP_MS: u64 = MAX_TICK_MS * 2;
pub const PROPOSAL_WEIGHT: u64 = 0;
pub const FINALITY_WEIGHT: u64 = 0;
pub const E_REFLEX_01_LIFECYCLE: &str = "WITHDRAWN";
pub const E_REFLEX_01_EVIDENCE_WEIGHT: u8 = 0;
pub const E_REFLEX_01_SUPERSEDED_BY: &str = "E-REFLEX-02";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tick {
    pub slot: u64,
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub leader_key: [u8; 32],
    pub bond_id: Hash32,
    pub event_count: u32,
    pub tx_root: Hash32,
    pub receipt_root: Hash32,
    pub cumulative_gas: u64,
    pub prior_accumulator: Hash32,
    pub signature: [u8; 64],
}

impl Tick {
    fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(256);
        bytes.extend_from_slice(b"NOOS/A-REFLEX/TICK/V2");
        bytes.extend_from_slice(&self.slot.to_le_bytes());
        bytes.extend_from_slice(&self.sequence.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp_ms.to_le_bytes());
        bytes.extend_from_slice(&self.leader_key);
        bytes.extend_from_slice(&self.bond_id);
        bytes.extend_from_slice(&self.event_count.to_le_bytes());
        bytes.extend_from_slice(&self.tx_root);
        bytes.extend_from_slice(&self.receipt_root);
        bytes.extend_from_slice(&self.cumulative_gas.to_le_bytes());
        bytes.extend_from_slice(&self.prior_accumulator);
        bytes
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Handoff {
    outgoing: u64,
    incoming: u64,
}

#[derive(Default)]
pub struct ReflexAccumulator {
    root: Hash32,
    ticks: Vec<Tick>,
    leaders: BTreeMap<u64, LeaderRegistration>,
    active_slot: Option<u64>,
    handoff: Option<Handoff>,
    closed_slots: BTreeSet<u64>,
}

impl ReflexAccumulator {
    #[must_use]
    pub fn root(&self) -> Hash32 {
        self.root
    }

    #[must_use]
    pub fn ticks(&self) -> &[Tick] {
        &self.ticks
    }

    pub fn register_leader(&mut self, registration: LeaderRegistration) -> Result<(), ReflexError> {
        if registration.bond_amount == 0
            || registration.bond_id == [0; 32]
            || registration.leader_key == [0; 32]
            || self.leaders.contains_key(&registration.slot)
        {
            return Err(ReflexError::Leader);
        }
        let slot = registration.slot;
        self.leaders.insert(slot, registration);
        if self.active_slot.is_none() {
            self.active_slot = Some(slot);
        }
        Ok(())
    }

    /// Begin the mandatory empty acceptance interval between slot leaders.
    pub fn pause_handoff(&mut self, outgoing: u64, incoming: u64) -> Result<(), ReflexError> {
        if self.active_slot != Some(outgoing)
            || !self.leaders.contains_key(&incoming)
            || outgoing == incoming
            || self.handoff.is_some()
        {
            return Err(ReflexError::Handoff);
        }
        self.handoff = Some(Handoff { outgoing, incoming });
        self.active_slot = None;
        Ok(())
    }

    pub fn complete_handoff(&mut self, outgoing: u64, incoming: u64) -> Result<(), ReflexError> {
        if self.handoff != Some(Handoff { outgoing, incoming }) {
            return Err(ReflexError::Handoff);
        }
        self.closed_slots.insert(outgoing);
        self.handoff = None;
        self.active_slot = Some(incoming);
        Ok(())
    }

    pub fn append(&mut self, tick: Tick) -> Result<Hash32, ReflexError> {
        if self.handoff.is_some() || self.active_slot != Some(tick.slot) {
            return Err(ReflexError::Handoff);
        }
        if self.closed_slots.contains(&tick.slot) {
            return Err(ReflexError::Handoff);
        }
        let leader = self.leaders.get(&tick.slot).ok_or(ReflexError::Leader)?;
        if tick.leader_key != leader.leader_key || tick.bond_id != leader.bond_id {
            return Err(ReflexError::Leader);
        }
        tick.verify_signature()?;
        if tick.prior_accumulator != self.root {
            return Err(ReflexError::Accumulator);
        }
        if let Some(last) = self.ticks.last() {
            let expected_sequence = last.sequence.checked_add(1).ok_or(ReflexError::Sequence)?;
            let elapsed = tick
                .timestamp_ms
                .checked_sub(last.timestamp_ms)
                .ok_or(ReflexError::ClockRollback)?;
            let max_gap = if tick.slot == last.slot {
                MAX_TICK_MS
            } else {
                MAX_HANDOFF_GAP_MS
            };
            if tick.sequence != expected_sequence
                || elapsed > max_gap
                || tick.cumulative_gas < last.cumulative_gas
            {
                return Err(ReflexError::Sequence);
            }
        } else if tick.sequence != 0 {
            return Err(ReflexError::Sequence);
        }
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"NOOS/A-REFLEX/ACCUMULATOR/V2");
        hasher.update(&self.root);
        hasher.update(&tick.digest());
        self.root = *hasher.finalize().as_bytes();
        self.ticks.push(tick);
        Ok(self.root)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContradictionProof {
    pub left: Tick,
    pub right: Tick,
    pub left_events: Vec<SettlementEvent>,
    pub right_events: Vec<SettlementEvent>,
}
impl ContradictionProof {
    pub fn verify(&self) -> Result<Hash32, ReflexError> {
        self.left.verify_signature()?;
        self.right.verify_signature()?;
        if self.left.event_count as usize != self.left_events.len()
            || self.right.event_count as usize != self.right_events.len()
            || self.left.tx_root != event_tx_root(&self.left_events)
            || self.right.tx_root != event_tx_root(&self.right_events)
            || self.left.receipt_root != event_receipt_root(&self.left_events)
            || self.right.receipt_root != event_receipt_root(&self.right_events)
            || self.left.leader_key != self.right.leader_key
            || self.left.bond_id != self.right.bond_id
            || self.left.slot != self.right.slot
            || self.left.sequence != self.right.sequence
            || self.left.digest() == self.right.digest()
        {
            return Err(ReflexError::NotContradiction);
        }
        let mut left_promises = BTreeSet::new();
        let mut right_promises = BTreeSet::new();
        if self.left_events.iter().any(|event| {
            event.promise_id == [0; 32]
                || event.beneficiary == [0; 32]
                || !left_promises.insert(event.promise_id)
        }) || self.right_events.iter().any(|event| {
            event.promise_id == [0; 32]
                || event.beneficiary == [0; 32]
                || !right_promises.insert(event.promise_id)
        }) {
            return Err(ReflexError::NotContradiction);
        }
        let mut pair = [self.left.digest(), self.right.digest()];
        pair.sort();
        Ok(hash_parts(
            b"NOOS/A-REFLEX/CONTRADICTION/V2",
            &[&pair[0], &pair[1]],
        ))
    }

    fn promised_liabilities(&self) -> Result<BTreeMap<Hash32, u128>, ReflexError> {
        let mut promises = BTreeMap::<Hash32, SettlementEvent>::new();
        for event in self.left_events.iter().chain(&self.right_events) {
            match promises.entry(event.promise_id) {
                std::collections::btree_map::Entry::Vacant(entry) => {
                    entry.insert(event.clone());
                }
                std::collections::btree_map::Entry::Occupied(mut entry) => {
                    if entry.get().beneficiary != event.beneficiary {
                        return Err(ReflexError::CompensationMismatch);
                    }
                    if event.liability > entry.get().liability {
                        entry.get_mut().liability = event.liability;
                    }
                }
            }
        }
        let mut by_beneficiary = BTreeMap::<Hash32, u128>::new();
        for event in promises.values() {
            let total = by_beneficiary.entry(event.beneficiary).or_default();
            *total = total
                .checked_add(event.liability)
                .ok_or(ReflexError::Arithmetic)?;
        }
        Ok(by_beneficiary)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorVerdict {
    Included,
    Omitted,
    Contradiction,
}

/// Canonical count plus per-index committed tick variants and receipt roots.
/// This is the F9 local model surface; an actual chain stores the root and
/// verifies inclusion proofs rather than retaining this vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalAnchor {
    pub finality_height: u64,
    pub tick_count: u64,
    pub accumulator_root: Hash32,
    tick_variants: Vec<Tick>,
    receipt_roots: Vec<Hash32>,
}

impl CanonicalAnchor {
    pub fn from_ticks(finality_height: u64, ticks: &[Tick]) -> Result<Self, ReflexError> {
        let mut root = [0; 32];
        let mut receipt_roots = Vec::with_capacity(ticks.len());
        for (index, tick) in ticks.iter().enumerate() {
            tick.verify_signature()?;
            if tick.sequence != index as u64 || tick.prior_accumulator != root {
                return Err(ReflexError::Accumulator);
            }
            root = hash_parts(b"NOOS/A-REFLEX/ACCUMULATOR/V2", &[&root, &tick.digest()]);
            receipt_roots.push(tick.receipt_root);
        }
        Ok(Self {
            finality_height,
            tick_count: ticks.len() as u64,
            accumulator_root: root,
            tick_variants: ticks.to_vec(),
            receipt_roots,
        })
    }

    pub fn verdict(&self, tick: &Tick) -> Result<AnchorVerdict, ReflexError> {
        tick.verify_signature()?;
        let Some(canonical) = self.tick_variants.get(tick.sequence as usize) else {
            return Ok(AnchorVerdict::Omitted);
        };
        if canonical.slot != tick.slot || canonical.sequence != tick.sequence {
            return Ok(AnchorVerdict::Omitted);
        }
        if canonical.digest() == tick.digest() {
            Ok(AnchorVerdict::Included)
        } else if canonical.leader_key == tick.leader_key && canonical.bond_id == tick.bond_id {
            Ok(AnchorVerdict::Contradiction)
        } else {
            Ok(AnchorVerdict::Omitted)
        }
    }

    #[must_use]
    pub fn receipt_root(&self, sequence: u64) -> Option<Hash32> {
        self.receipt_roots.get(sequence as usize).copied()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SettlementEvent {
    pub promise_id: Hash32,
    pub beneficiary: Hash32,
    pub action_root: Hash32,
    pub receipt_root: Hash32,
    pub gas: u64,
    pub liability: u128,
}

#[must_use]
pub fn event_tx_root(events: &[SettlementEvent]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/A-REFLEX/TX-ROOT/V1");
    hasher.update(&(events.len() as u64).to_le_bytes());
    for event in events {
        hasher.update(&event.promise_id);
        hasher.update(&event.beneficiary);
        hasher.update(&event.action_root);
        hasher.update(&event.gas.to_le_bytes());
        hasher.update(&event.liability.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

#[must_use]
pub fn event_receipt_root(events: &[SettlementEvent]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/A-REFLEX/RECEIPT-ROOT/V1");
    hasher.update(&(events.len() as u64).to_le_bytes());
    for event in events {
        hasher.update(&event.promise_id);
        hasher.update(&event.receipt_root);
    }
    *hasher.finalize().as_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PromiseRecord {
    event: SettlementEvent,
    tick_digest: Hash32,
    anchored: bool,
    consumed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReflexEffect {
    pub promise_id: Hash32,
    pub action_root: Hash32,
    pub remaining_budget: u128,
    pub base_chain_authority: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VictimClaim {
    pub account: Hash32,
    pub amount: u128,
}

/// Complete application lifecycle. `new_lab` constructs a locally enabled
/// drill object, but cannot alter the compile-time production control.
pub struct ReflexLifecycle {
    accumulator: ReflexAccumulator,
    lab_accepting: bool,
    bonds: BTreeMap<Hash32, u128>,
    bond_leaders: BTreeMap<Hash32, [u8; 32]>,
    promises: BTreeMap<Hash32, PromiseRecord>,
    budget_ceiling: BTreeMap<Hash32, u128>,
    compensation: BTreeMap<Hash32, u128>,
    settled_proofs: BTreeSet<Hash32>,
    last_anchor_height: Option<u64>,
}

impl ReflexLifecycle {
    #[must_use]
    pub fn new_lab() -> Self {
        Self {
            accumulator: ReflexAccumulator::default(),
            lab_accepting: true,
            bonds: BTreeMap::new(),
            bond_leaders: BTreeMap::new(),
            promises: BTreeMap::new(),
            budget_ceiling: BTreeMap::new(),
            compensation: BTreeMap::new(),
            settled_proofs: BTreeSet::new(),
            last_anchor_height: None,
        }
    }

    pub fn register_leader(&mut self, registration: LeaderRegistration) -> Result<(), ReflexError> {
        if self.bonds.contains_key(&registration.bond_id) {
            return Err(ReflexError::Leader);
        }
        self.accumulator.register_leader(registration.clone())?;
        self.bonds
            .insert(registration.bond_id, registration.bond_amount);
        self.bond_leaders
            .insert(registration.bond_id, registration.leader_key);
        Ok(())
    }

    pub fn pause_handoff(&mut self, outgoing: u64, incoming: u64) -> Result<(), ReflexError> {
        self.accumulator.pause_handoff(outgoing, incoming)
    }

    pub fn complete_handoff(&mut self, outgoing: u64, incoming: u64) -> Result<(), ReflexError> {
        self.accumulator.complete_handoff(outgoing, incoming)
    }

    pub fn submit_tick(
        &mut self,
        tick: Tick,
        events: Vec<SettlementEvent>,
    ) -> Result<Hash32, ReflexError> {
        if !self.lab_accepting {
            return Err(ReflexError::LaneDisabled);
        }
        if tick.event_count as usize != events.len()
            || tick.tx_root != event_tx_root(&events)
            || tick.receipt_root != event_receipt_root(&events)
        {
            return Err(ReflexError::ReceiptMapping);
        }
        let gas = events.iter().try_fold(0_u64, |sum, event| {
            sum.checked_add(event.gas).ok_or(ReflexError::Arithmetic)
        })?;
        let prior_gas = self
            .accumulator
            .ticks()
            .last()
            .map_or(0, |prior| prior.cumulative_gas);
        if prior_gas.checked_add(gas) != Some(tick.cumulative_gas) {
            return Err(ReflexError::ReceiptMapping);
        }
        let mut seen = BTreeSet::new();
        if events.iter().any(|event| {
            event.promise_id == [0; 32]
                || self.promises.contains_key(&event.promise_id)
                || !seen.insert(event.promise_id)
        }) {
            return Err(ReflexError::PromiseReplay);
        }
        let tick_digest = tick.digest();
        let root = self.accumulator.append(tick)?;
        for event in events {
            self.promises.insert(
                event.promise_id,
                PromiseRecord {
                    event,
                    tick_digest,
                    anchored: false,
                    consumed: false,
                },
            );
        }
        Ok(root)
    }

    /// Bind the promise clock to a canonical finality hand. Reflex never
    /// supplies the height or changes the base accumulator.
    pub fn anchor(&mut self, anchor: &CanonicalAnchor) -> Result<(), ReflexError> {
        if self
            .last_anchor_height
            .is_some_and(|height| anchor.finality_height <= height)
            || anchor.accumulator_root != self.accumulator.root()
            || anchor.tick_count != self.accumulator.ticks().len() as u64
        {
            return Err(ReflexError::ForeignFinality);
        }
        for promise in self.promises.values_mut() {
            promise.anchored = self
                .accumulator
                .ticks()
                .iter()
                .any(|tick| tick.digest() == promise.tick_digest);
        }
        self.last_anchor_height = Some(anchor.finality_height);
        Ok(())
    }

    /// The only path from a Reflex promise to an application effect. It
    /// reuses A-CLASS-GATE.v2 and persists its composition budget so callers
    /// cannot replay an older, larger capability snapshot.
    pub fn consume_promise(
        &mut self,
        promise_id: Hash32,
        mut request: ClassGateRequest,
    ) -> Result<ReflexEffect, ReflexError> {
        let promise = self
            .promises
            .get(&promise_id)
            .ok_or(ReflexError::UnknownPromise)?;
        if promise.consumed {
            return Err(ReflexError::PromiseReplay);
        }
        if !request.required_provenance.contains(&promise.tick_digest)
            || !request
                .required_provenance
                .contains(&promise.event.action_root)
        {
            return Err(ReflexError::CausalBinding);
        }
        if request.irreversible
            && (!promise.anchored || request.required_finality != PublicFinality::NoosFinalized)
        {
            return Err(ReflexError::ForeignFinality);
        }
        let budget_key = provenance_key(&request.required_provenance);
        let presented = request
            .consumed
            .iter()
            .map(|capability| capability.remaining_budget)
            .min()
            .ok_or(ReflexError::ClassGate(ClassGateDenial::Empty))?;
        if self
            .budget_ceiling
            .get(&budget_key)
            .is_some_and(|ceiling| presented > *ceiling)
        {
            return Err(ReflexError::BudgetRollback);
        }
        if let Some(ceiling) = self.budget_ceiling.get(&budget_key).copied() {
            for capability in &mut request.consumed {
                capability.remaining_budget = capability.remaining_budget.min(ceiling);
            }
        }
        let authorization = authorize_class_v2(&request).map_err(ReflexError::ClassGate)?;
        self.budget_ceiling
            .insert(budget_key, authorization.remaining_budget);
        let promise = self
            .promises
            .get_mut(&promise_id)
            .ok_or(ReflexError::UnknownPromise)?;
        promise.consumed = true;
        Ok(ReflexEffect {
            promise_id,
            action_root: promise.event.action_root,
            remaining_budget: authorization.remaining_budget,
            base_chain_authority: false,
        })
    }

    /// Slash one signer's own contradiction and compensate every supplied
    /// victim integer-exactly from that signer's registered Ground bond.
    pub fn settle_contradiction(
        &mut self,
        proof: &ContradictionProof,
        victims: &[VictimClaim],
    ) -> Result<u128, ReflexError> {
        let proof_id = proof.verify()?;
        let promised_liabilities = proof.promised_liabilities()?;
        if self.settled_proofs.contains(&proof_id) {
            return Err(ReflexError::PromiseReplay);
        }
        if self.bond_leaders.get(&proof.left.bond_id) != Some(&proof.left.leader_key) {
            return Err(ReflexError::Leader);
        }
        let mut claimed_liabilities = BTreeMap::new();
        for victim in victims {
            if victim.account == [0; 32]
                || victim.amount == 0
                || claimed_liabilities
                    .insert(victim.account, victim.amount)
                    .is_some()
            {
                return Err(ReflexError::CompensationMismatch);
            }
        }
        if claimed_liabilities != promised_liabilities {
            return Err(ReflexError::CompensationMismatch);
        }
        let total = victims.iter().try_fold(0_u128, |sum, victim| {
            sum.checked_add(victim.amount)
                .ok_or(ReflexError::Arithmetic)
        })?;
        let bond = self
            .bonds
            .get(&proof.left.bond_id)
            .copied()
            .ok_or(ReflexError::Leader)?;
        let remaining_bond = bond
            .checked_sub(total)
            .ok_or(ReflexError::InsufficientBond)?;
        let mut resulting_balances = Vec::with_capacity(victims.len());
        for victim in victims {
            let resulting = self
                .compensation
                .get(&victim.account)
                .copied()
                .unwrap_or(0)
                .checked_add(victim.amount)
                .ok_or(ReflexError::Arithmetic)?;
            resulting_balances.push((victim.account, resulting));
        }
        self.bonds.insert(proof.left.bond_id, remaining_bond);
        for (account, balance) in resulting_balances {
            self.compensation.insert(account, balance);
        }
        self.settled_proofs.insert(proof_id);
        Ok(total)
    }

    /// Rollback is application-local: stop ticks/promises; canonical blocks
    /// remain the only authority and no historical base state is rewritten.
    pub fn rollback_to_canonical_only(&mut self) {
        self.lab_accepting = false;
    }

    #[must_use]
    pub fn accumulator(&self) -> &ReflexAccumulator {
        &self.accumulator
    }

    #[must_use]
    pub fn bond_balance(&self, bond_id: Hash32) -> u128 {
        self.bonds.get(&bond_id).copied().unwrap_or(0)
    }

    #[must_use]
    pub fn compensation_balance(&self, account: Hash32) -> u128 {
        self.compensation.get(&account).copied().unwrap_or(0)
    }

    #[must_use]
    pub const fn base_chain_delta(&self) -> Option<Hash32> {
        None
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

/// No simulated, shape-only, F9, or withdrawn-v1 evidence can enable the
/// production lane. A real live-devnet gate must change the external control.
#[must_use]
pub const fn can_enable_from_local_evidence(_f9_passed: bool, _drill: &LiveDrill) -> bool {
    false
}

#[must_use]
pub const fn can_enable_from_shape_evidence(_f9_passed: bool) -> bool {
    false
}

fn provenance_key(provenance: &BTreeSet<Hash32>) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/A-REFLEX/PROVENANCE-BUDGET/V1");
    for item in provenance {
        hasher.update(item);
    }
    *hasher.finalize().as_bytes()
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    *hasher.finalize().as_bytes()
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReflexError {
    #[error("unregistered leader or bond")]
    Leader,
    #[error("invalid tick signature")]
    Signature,
    #[error("noncanonical accumulator link")]
    Accumulator,
    #[error("tick cadence, sequence, or cumulative gas violation")]
    Sequence,
    #[error("tick timestamp rolled backward")]
    ClockRollback,
    #[error("slot handoff is incomplete or ambiguous")]
    Handoff,
    #[error("not a same-key, same-position contradiction")]
    NotContradiction,
    #[error("tick roots do not map to the supplied events")]
    ReceiptMapping,
    #[error("promise is unknown")]
    UnknownPromise,
    #[error("promise or contradiction replay")]
    PromiseReplay,
    #[error("class gate lacks causal tick/action provenance")]
    CausalBinding,
    #[error("foreign or missing canonical finality")]
    ForeignFinality,
    #[error("class budget attempted to increase")]
    BudgetRollback,
    #[error("A-CLASS-GATE.v2 rejected: {0}")]
    ClassGate(ClassGateDenial),
    #[error("bond cannot compensate every victim")]
    InsufficientBond,
    #[error("victim claims do not exactly cover the disclosed promise liabilities")]
    CompensationMismatch,
    #[error("integer arithmetic overflow")]
    Arithmetic,
    #[error("Reflex lane rolled back to canonical blocks only")]
    LaneDisabled,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::arithmetic_side_effects, clippy::unwrap_used)]

    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use noos_agent_class::{Attestation, CapabilityClass};

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn event(id: u8, gas: u64, liability: u128) -> SettlementEvent {
        SettlementEvent {
            promise_id: h(id),
            action_root: h(id.wrapping_add(20)),
            beneficiary: h(id.wrapping_add(60)),
            receipt_root: h(id.wrapping_add(40)),
            gas,
            liability,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn signed(
        key: &SigningKey,
        slot: u64,
        sequence: u64,
        timestamp_ms: u64,
        prior: Hash32,
        bond_id: Hash32,
        events: &[SettlementEvent],
        cumulative_gas: u64,
    ) -> Tick {
        let mut tick = Tick {
            slot,
            sequence,
            timestamp_ms,
            leader_key: key.verifying_key().to_bytes(),
            bond_id,
            event_count: events.len() as u32,
            tx_root: event_tx_root(events),
            receipt_root: event_receipt_root(events),
            cumulative_gas,
            prior_accumulator: prior,
            signature: [0; 64],
        };
        tick.signature = key.sign(&tick.signing_bytes()).to_bytes();
        tick
    }

    fn registration(key: &SigningKey, slot: u64, bond: u8, amount: u128) -> LeaderRegistration {
        LeaderRegistration {
            slot,
            leader_key: key.verifying_key().to_bytes(),
            bond_id: h(bond),
            bond_amount: amount,
        }
    }

    fn class(
        finality: PublicFinality,
        provenance: BTreeSet<Hash32>,
        budget: u128,
    ) -> CapabilityClass {
        CapabilityClass {
            public_finality: finality,
            attestation: Attestation::None,
            provenance,
            remaining_budget: budget,
            revocation_epoch: 7,
        }
    }

    fn request(
        finality: PublicFinality,
        provenance: BTreeSet<Hash32>,
        budget: u128,
        spend: u128,
    ) -> ClassGateRequest {
        ClassGateRequest {
            consumed: vec![class(finality, provenance.clone(), budget)],
            required_finality: finality,
            required_attestation: Attestation::None,
            required_provenance: provenance,
            requested_budget: spend,
            irreversible: false,
            current_revocation_epoch: 7,
        }
    }

    #[test]
    fn clock_rollback_skew_and_handoff_branch_ambiguity_reject() {
        let first = SigningKey::from_bytes(&h(7));
        let second = SigningKey::from_bytes(&h(8));
        let mut lifecycle = ReflexLifecycle::new_lab();
        lifecycle
            .register_leader(registration(&first, 1, 9, 100))
            .unwrap();
        lifecycle
            .register_leader(registration(&second, 2, 10, 100))
            .unwrap();
        let events = vec![event(1, 5, 1)];
        let tick0 = signed(&first, 1, 0, 100, [0; 32], h(9), &events, 5);
        let root = lifecycle.submit_tick(tick0, events).unwrap();

        let rollback = signed(&first, 1, 1, 99, root, h(9), &[], 5);
        assert_eq!(
            lifecycle.submit_tick(rollback, Vec::new()),
            Err(ReflexError::ClockRollback)
        );
        let skew = signed(&first, 1, 1, 351, root, h(9), &[], 5);
        assert_eq!(
            lifecycle.submit_tick(skew, Vec::new()),
            Err(ReflexError::Sequence)
        );

        lifecycle.pause_handoff(1, 2).unwrap();
        let late = signed(&first, 1, 1, 200, root, h(9), &[], 5);
        assert_eq!(
            lifecycle.submit_tick(late, Vec::new()),
            Err(ReflexError::Handoff)
        );
        lifecycle.complete_handoff(1, 2).unwrap();
        let outgoing_again = signed(&first, 1, 1, 200, root, h(9), &[], 5);
        assert_eq!(
            lifecycle.submit_tick(outgoing_again, Vec::new()),
            Err(ReflexError::Handoff)
        );
        let incoming = signed(&second, 2, 1, 600, root, h(10), &[], 5);
        assert!(lifecycle.submit_tick(incoming, Vec::new()).is_ok());
    }

    #[test]
    fn canonical_anchor_inclusion_omission_contradiction_and_receipt_mapping() {
        let key = SigningKey::from_bytes(&h(7));
        let events = vec![event(1, 5, 1)];
        let tick = signed(&key, 1, 0, 100, [0; 32], h(9), &events, 5);
        let anchor = CanonicalAnchor::from_ticks(10, std::slice::from_ref(&tick)).unwrap();
        assert_eq!(anchor.verdict(&tick).unwrap(), AnchorVerdict::Included);
        assert_eq!(anchor.receipt_root(0), Some(tick.receipt_root));

        let omitted = signed(&key, 1, 1, 200, anchor.accumulator_root, h(9), &[], 5);
        assert_eq!(anchor.verdict(&omitted).unwrap(), AnchorVerdict::Omitted);
        let alternate_events = vec![event(2, 5, 1)];
        let alternate = signed(&key, 1, 0, 100, [0; 32], h(9), &alternate_events, 5);
        assert_eq!(
            anchor.verdict(&alternate).unwrap(),
            AnchorVerdict::Contradiction
        );
    }

    #[test]
    fn class_gate_bypass_foreign_finality_and_budget_rollback_reject() {
        let key = SigningKey::from_bytes(&h(7));
        let mut lifecycle = ReflexLifecycle::new_lab();
        lifecycle
            .register_leader(registration(&key, 1, 9, 100))
            .unwrap();
        let events = vec![event(1, 5, 1), event(2, 6, 1)];
        let tick = signed(&key, 1, 0, 100, [0; 32], h(9), &events, 11);
        let digest = tick.digest();
        lifecycle.submit_tick(tick, events.clone()).unwrap();

        let missing_tick = BTreeSet::from([events[0].action_root]);
        assert_eq!(
            lifecycle.consume_promise(
                events[0].promise_id,
                request(PublicFinality::Unfinalized, missing_tick, 10, 3)
            ),
            Err(ReflexError::CausalBinding)
        );

        let provenance = BTreeSet::from([digest, events[0].action_root]);
        let mut foreign = request(PublicFinality::ForeignFinalized, provenance.clone(), 10, 3);
        foreign.required_finality = PublicFinality::NoosFinalized;
        assert_eq!(
            lifecycle.consume_promise(events[0].promise_id, foreign),
            Err(ReflexError::ClassGate(ClassGateDenial::Finality))
        );

        let first = lifecycle
            .consume_promise(
                events[0].promise_id,
                request(PublicFinality::Unfinalized, provenance, 10, 3),
            )
            .unwrap();
        assert_eq!(first.remaining_budget, 7);
        assert!(!first.base_chain_authority);

        // The budget key includes the action root, so use a shared causal
        // provenance superset for both promises to exercise one budget.
        let mut lifecycle2 = ReflexLifecycle::new_lab();
        lifecycle2
            .register_leader(registration(&key, 1, 19, 100))
            .unwrap();
        let tick2 = signed(&key, 1, 0, 100, [0; 32], h(19), &events, 11);
        let shared = BTreeSet::from([tick2.digest(), events[0].action_root, events[1].action_root]);
        lifecycle2.submit_tick(tick2, events.clone()).unwrap();
        lifecycle2
            .consume_promise(
                events[0].promise_id,
                request(PublicFinality::Unfinalized, shared.clone(), 10, 3),
            )
            .unwrap();
        assert_eq!(
            lifecycle2.consume_promise(
                events[1].promise_id,
                request(PublicFinality::Unfinalized, shared.clone(), 10, 1)
            ),
            Err(ReflexError::BudgetRollback)
        );
        let second = lifecycle2
            .consume_promise(
                events[1].promise_id,
                request(PublicFinality::Unfinalized, shared, 7, 1),
            )
            .unwrap();
        assert_eq!(second.remaining_budget, 6);
    }

    #[test]
    fn canonical_finality_cannot_authorize_irreversible_reflex_budget() {
        let key = SigningKey::from_bytes(&h(7));
        let mut lifecycle = ReflexLifecycle::new_lab();
        lifecycle
            .register_leader(registration(&key, 1, 9, 100))
            .unwrap();
        let events = vec![event(1, 5, 1)];
        let tick = signed(&key, 1, 0, 100, [0; 32], h(9), &events, 5);
        let digest = tick.digest();
        lifecycle.submit_tick(tick, events.clone()).unwrap();
        let anchor = CanonicalAnchor::from_ticks(10, lifecycle.accumulator().ticks()).unwrap();
        lifecycle.anchor(&anchor).unwrap();
        let provenance = BTreeSet::from([digest, events[0].action_root]);
        let mut irreversible = request(PublicFinality::NoosFinalized, provenance, 10, 1);
        irreversible.irreversible = true;
        assert_eq!(
            lifecycle.consume_promise(events[0].promise_id, irreversible),
            Err(ReflexError::ClassGate(
                ClassGateDenial::IrreversibleBudgetZero
            ))
        );
    }

    #[test]
    fn split_view_liability_and_compensation_are_delivery_independent_and_exact() {
        let key = SigningKey::from_bytes(&h(7));
        let mut lifecycle = ReflexLifecycle::new_lab();
        lifecycle
            .register_leader(registration(&key, 1, 9, 100))
            .unwrap();
        let left_events = vec![event(1, 5, 4)];
        let right_events = vec![event(2, 5, 6)];
        let proof = ContradictionProof {
            left: signed(&key, 1, 0, 100, [0; 32], h(9), &left_events, 5),
            right: signed(&key, 1, 0, 100, [0; 32], h(9), &right_events, 5),
            left_events: left_events.clone(),
            right_events: right_events.clone(),
        };
        assert_ne!(proof.verify().unwrap(), [0; 32]);
        let victims = vec![
            VictimClaim {
                account: left_events[0].beneficiary,
                amount: 4,
            },
            VictimClaim {
                account: right_events[0].beneficiary,
                amount: 6,
            },
        ];
        assert_eq!(
            lifecycle.settle_contradiction(&proof, &victims).unwrap(),
            10
        );
        assert_eq!(lifecycle.bond_balance(h(9)), 90);
        assert_eq!(lifecycle.compensation_balance(left_events[0].beneficiary), 4);
        assert_eq!(lifecycle.compensation_balance(right_events[0].beneficiary), 6);
        assert_eq!(
            lifecycle.settle_contradiction(&proof, &victims),
            Err(ReflexError::PromiseReplay)
        );
    }

    #[test]
    fn contradiction_compensation_falsifiers_reject_without_partial_mutation() {
        let key = SigningKey::from_bytes(&h(7));
        let left_events = vec![event(1, 5, 4)];
        let right_events = vec![event(2, 5, 6)];
        let proof = ContradictionProof {
            left: signed(&key, 1, 0, 100, [0; 32], h(9), &left_events, 5),
            right: signed(&key, 1, 0, 100, [0; 32], h(9), &right_events, 5),
            left_events: left_events.clone(),
            right_events: right_events.clone(),
        };
        let mut lifecycle = ReflexLifecycle::new_lab();
        lifecycle
            .register_leader(registration(&key, 1, 9, 100))
            .unwrap();
        let underpaid = [VictimClaim {
            account: left_events[0].beneficiary,
            amount: 9,
        }];
        assert_eq!(
            lifecycle.settle_contradiction(&proof, &underpaid),
            Err(ReflexError::CompensationMismatch)
        );
        assert_eq!(lifecycle.bond_balance(h(9)), 100);
        assert_eq!(lifecycle.compensation_balance(left_events[0].beneficiary), 0);

        let duplicate = [
            VictimClaim {
                account: left_events[0].beneficiary,
                amount: 4,
            },
            VictimClaim {
                account: left_events[0].beneficiary,
                amount: 6,
            },
        ];
        assert_eq!(
            lifecycle.settle_contradiction(&proof, &duplicate),
            Err(ReflexError::CompensationMismatch)
        );
        assert_eq!(lifecycle.bond_balance(h(9)), 100);

        let mut bad_disclosure = proof;
        bad_disclosure.left_events[0].liability = 5;
        assert_eq!(bad_disclosure.verify(), Err(ReflexError::NotContradiction));

        let shared = event(3, 1, 2);
        let extra = event(4, 1, 3);
        let overlapping = ContradictionProof {
            left: signed(&key, 1, 0, 100, [0; 32], h(9), std::slice::from_ref(&shared), 1),
            right: signed(
                &key,
                1,
                0,
                100,
                [0; 32],
                h(9),
                &[shared.clone(), extra.clone()],
                2,
            ),
            left_events: vec![shared.clone()],
            right_events: vec![shared.clone(), extra.clone()],
        };
        assert!(overlapping.verify().is_ok());
        let overlap_victims = [
            VictimClaim {
                account: shared.beneficiary,
                amount: shared.liability,
            },
            VictimClaim {
                account: extra.beneficiary,
                amount: extra.liability,
            },
        ];
        assert_eq!(
            lifecycle
                .settle_contradiction(&overlapping, &overlap_victims)
                .unwrap(),
            5
        );
    }

    #[test]
    fn rollback_and_base_chain_non_authority_are_structural() {
        let key = SigningKey::from_bytes(&h(7));
        let mut lifecycle = ReflexLifecycle::new_lab();
        lifecycle
            .register_leader(registration(&key, 1, 9, 100))
            .unwrap();
        lifecycle.rollback_to_canonical_only();
        let tick = signed(&key, 1, 0, 0, [0; 32], h(9), &[], 0);
        assert_eq!(
            lifecycle.submit_tick(tick, Vec::new()),
            Err(ReflexError::LaneDisabled)
        );
        assert_eq!(lifecycle.base_chain_delta(), None);
        assert_eq!((PROPOSAL_WEIGHT, FINALITY_WEIGHT), (0, 0));
        assert_eq!(E_REFLEX_01_LIFECYCLE, "WITHDRAWN");
        assert_eq!(E_REFLEX_01_EVIDENCE_WEIGHT, 0);
        let drill = LiveDrill {
            accepted_contradictions: 0,
            handoff_gap_p95_ticks: 2,
            split_view_liability_bps: 10_000,
            compensation_exact: true,
            disable_rollback_rehearsed: true,
        };
        assert!(drill.passes());
        assert!(!can_enable_from_local_evidence(true, &drill));
    }
}
