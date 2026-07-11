//! Epoch membership snapshot (witness-v1.md §2; ch01 §4.6; plan §6.5).
//!
//! For epoch `e` the candidate list comes from finalized Lumen state at the
//! `e-2` boundary ONLY. Lumen integration stays behind
//! [`CandidateSource`]; this module consumes a deterministic candidate
//! list and freezes everything downstream:
//!
//! 1. eligibility: `activation_epoch ≤ e < exit_epoch`, bonded ≥ minimum;
//! 2. linear raw weight `r_i = bonded_noos_i`;
//! 3. active set: top `N_max = 256` by `r_i`, ties by ascending
//!    `H("NOOS/WITNESS/TIEBREAK/V1" || epoch_le || validator_id)`;
//! 4. reserve: remainder ordered ascending by
//!    `H("NOOS/WITNESS/SAMPLE/V1" || epoch_le || R_{e-1} || validator_id)`
//!    (a PRF order is a without-replacement sample); the first
//!    `N_tail = 32` are the reserve, and the SAME order is the
//!    deterministic admission order of the cap-repair loop;
//! 5. cap law: no key at or above one third of total raw OR effective
//!    weight. While violated: admit the next sampled candidate (up to
//!    `N_hard = 1024`), then reduce proofpower bonuses, then continue the
//!    PREVIOUS set for exactly one emergency epoch, then HALT — an unsafe
//!    set is never normalized;
//! 6. declared control clusters aggregate conservatively for TELEMETRY;
//!    an empty declaration is unknown and all unknowns are treated as one
//!    correlated cluster;
//! 7. `membership_root` = noos-lumen SMT root over
//!    `validator_id → consensus_bls_key(48) || r_i(u128 LE) || eff_i(u128 LE)`.
//!
//! The canonical MEMBER ORDER (bitmap indexing, beacon mix fold) is
//! ascending `validator_id` — the SMT's own key order (PROPOSED-G0, frozen
//! in `constants-v1.toml [witness] bitmap_bit_order`).

use std::collections::{BTreeMap, BTreeSet};

use noos_braid::Bytes48;
use noos_crypto::{hash_domain, DomainId};
use noos_lumen::smt::Smt;

use crate::bond::WitnessBondV1;
use crate::{WitnessError, N_HARD, N_MAX, N_TAIL, PROOFPOWER_GENESIS_CAP};

/// Deterministic candidate feed from finalized `e-2` Lumen state
/// (plan §2.6 layer edge; implemented by the Lumen integration layer).
pub trait CandidateSource {
    /// Bonds locked before the `e-2` snapshot boundary for epoch `e`, in
    /// any order (selection re-sorts deterministically).
    fn candidates_for_epoch(&self, epoch: u64) -> Vec<WitnessBondV1>;
}

/// One snapshot member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberV1 {
    pub validator_id: [u8; 32],
    pub consensus_bls_key: Bytes48,
    /// Linear raw weight: `bonded_noos` (µNOOS).
    pub raw_weight: u128,
    /// Effective weight; `== raw_weight` at genesis (§7).
    pub effective_weight: u128,
    /// Declared failure domains — informative telemetry, never identity.
    pub failure_domains: Vec<u8>,
}

/// Immutable epoch membership snapshot. Constructed only by
/// [`build_snapshot`]; the members, totals, and root cannot be mutated —
/// membership never changes mid-epoch (§1.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipSnapshotV1 {
    epoch: u64,
    /// Ascending `validator_id`: the canonical member order.
    members: Vec<MemberV1>,
    root: [u8; 32],
    total_raw: u128,
    total_effective: u128,
}

impl MembershipSnapshotV1 {
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Members in canonical (ascending `validator_id`) order.
    #[must_use]
    pub fn members(&self) -> &[MemberV1] {
        &self.members
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.members.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The SMT membership root (§2.7).
    #[must_use]
    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    #[must_use]
    pub fn total_raw_weight(&self) -> u128 {
        self.total_raw
    }

    #[must_use]
    pub fn total_effective_weight(&self) -> u128 {
        self.total_effective
    }

    /// Canonical index of a validator, if a member.
    #[must_use]
    pub fn index_of(&self, validator_id: &[u8; 32]) -> Option<usize> {
        self.members
            .binary_search_by(|m| m.validator_id.cmp(validator_id))
            .ok()
    }

    #[must_use]
    pub fn member(&self, validator_id: &[u8; 32]) -> Option<&MemberV1> {
        self.index_of(validator_id).map(|i| &self.members[i])
    }

    /// Re-stamps the same set for the next epoch (emergency continuation).
    fn continued_for(&self, epoch: u64) -> Self {
        Self {
            epoch,
            members: self.members.clone(),
            root: self.root,
            total_raw: self.total_raw,
            total_effective: self.total_effective,
        }
    }
}

/// Snapshot construction outcome (§2.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnapshotOutcome {
    /// A valid weight vector exists.
    Normal(MembershipSnapshotV1),
    /// No valid vector: the previous epoch set continues for exactly ONE
    /// emergency epoch.
    EmergencyContinuation(MembershipSnapshotV1),
    /// Second consecutive failure: finality HALTS. An unsafe set is never
    /// normalized.
    Halt,
}

/// Domain-bound 32-byte hash with the crate error type.
fn domain_hash32(domain: DomainId, parts: &[&[u8]]) -> Result<[u8; 32], WitnessError> {
    hash_domain(domain, parts)
        .map(noos_crypto::Hash32::into_bytes)
        .map_err(|_| WitnessError::CryptoRejected)
}

/// Epoch-salted tie-break hash (ascending order wins; §2.3).
pub fn tiebreak_hash(epoch: u64, validator_id: &[u8; 32]) -> Result<[u8; 32], WitnessError> {
    domain_hash32(
        DomainId::WitnessTiebreak,
        &[&epoch.to_le_bytes(), validator_id],
    )
}

/// Reserve-sampling PRF key (ascending order = sample order; §2.4).
pub fn sample_hash(
    epoch: u64,
    randomness: &[u8; 32],
    validator_id: &[u8; 32],
) -> Result<[u8; 32], WitnessError> {
    domain_hash32(
        DomainId::WitnessSample,
        &[&epoch.to_le_bytes(), randomness, validator_id],
    )
}

/// Effective weight under genesis controls (§7): the proofpower path exists
/// behind the flag, but the compile-time zero cap clamps any bonus, so
/// `eff ≡ raw`.
// The min-with-cap IS the point: the state-transition check enforcing the
// zero cap (plan §6.8) even though the clamp is currently saturating-at-0.
#[allow(clippy::unnecessary_min_or_max)]
#[must_use]
pub fn effective_weight(raw: u128, proofpower_bonus: u128, bonus_enabled: bool) -> u128 {
    let bonus = if bonus_enabled {
        proofpower_bonus.min(PROOFPOWER_GENESIS_CAP)
    } else {
        0
    };
    // bonus is clamped to PROOFPOWER_GENESIS_CAP == 0: saturation unreachable.
    raw.saturating_add(bonus)
}

/// Cap-law violation: some key holds ≥ ⅓ of total raw OR effective weight
/// (§2.5; equivalently the key's weight ≥ `ceil(W/3)`).
#[must_use]
pub fn cap_violated(members: &[MemberV1]) -> bool {
    fn third_reached(weight: u128, total: u128) -> bool {
        if total == 0 {
            return false;
        }
        // ceil(total/3): total/3 <= u128::MAX/3, +1 cannot overflow.
        #[allow(clippy::arithmetic_side_effects)]
        let ceil_third = total / 3 + u128::from(!total.is_multiple_of(3));
        weight >= ceil_third
    }
    let (mut total_raw, mut total_eff) = (0_u128, 0_u128);
    for m in members {
        total_raw = total_raw.saturating_add(m.raw_weight);
        total_eff = total_eff.saturating_add(m.effective_weight);
    }
    members.iter().any(|m| {
        third_reached(m.raw_weight, total_raw) || third_reached(m.effective_weight, total_eff)
    })
}

/// Reduces proofpower bonuses toward raw weight (`eff_i := raw_i`), the
/// second cap-repair arm (§2.5). Returns whether anything changed — at
/// genesis `eff ≡ raw`, so this is structurally present but a no-op.
pub fn reduce_proofpower(members: &mut [MemberV1]) -> bool {
    let mut changed = false;
    for m in members {
        if m.effective_weight != m.raw_weight {
            m.effective_weight = m.raw_weight;
            changed = true;
        }
    }
    changed
}

/// SMT membership root over the canonical member map (§2.7).
#[must_use]
pub fn membership_root(members: &[MemberV1]) -> [u8; 32] {
    let mut smt = Smt::new();
    for m in members {
        let mut value = Vec::with_capacity(48 + 16 + 16);
        value.extend_from_slice(&m.consensus_bls_key.0);
        value.extend_from_slice(&m.raw_weight.to_le_bytes());
        value.extend_from_slice(&m.effective_weight.to_le_bytes());
        smt.insert(m.validator_id, value);
    }
    smt.root()
}

fn finish_snapshot(
    epoch: u64,
    mut members: Vec<MemberV1>,
) -> Result<MembershipSnapshotV1, WitnessError> {
    members.sort_by_key(|m| m.validator_id);
    let mut total_raw = 0_u128;
    let mut total_eff = 0_u128;
    for m in &members {
        total_raw = total_raw
            .checked_add(m.raw_weight)
            .ok_or(WitnessError::ArithmeticOverflow)?;
        total_eff = total_eff
            .checked_add(m.effective_weight)
            .ok_or(WitnessError::ArithmeticOverflow)?;
    }
    let root = membership_root(&members);
    Ok(MembershipSnapshotV1 {
        epoch,
        members,
        root,
        total_raw,
        total_effective: total_eff,
    })
}

fn member_from_bond(bond: &WitnessBondV1) -> MemberV1 {
    let raw = bond.bonded_noos;
    MemberV1 {
        validator_id: bond.validator_id,
        consensus_bls_key: bond.consensus_bls_key,
        raw_weight: raw,
        // Genesis controls: bonus disabled AND cap zero (§7).
        effective_weight: effective_weight(raw, 0, false),
        failure_domains: bond.failure_domains.as_slice().to_vec(),
    }
}

/// Builds the epoch-`e` snapshot (§2).
///
/// * `candidates` — the deterministic candidate list from finalized `e-2`
///   state (see [`CandidateSource`]);
/// * `randomness` — finalized epoch randomness `R_{e-1}` (§4 beacon);
/// * `prev` — the previous epoch's snapshot, for emergency continuation;
/// * `prev_was_emergency` — whether `prev` itself was an emergency
///   continuation (a second consecutive failure halts).
pub fn build_snapshot(
    epoch: u64,
    candidates: &[WitnessBondV1],
    randomness: &[u8; 32],
    min_bond: u128,
    prev: Option<&MembershipSnapshotV1>,
    prev_was_emergency: bool,
) -> Result<SnapshotOutcome, WitnessError> {
    // Set-level registration validity (§1.1): duplicate validator ids
    // (conflicting declarations) and duplicate consensus keys are invalid.
    let mut ids = BTreeSet::new();
    let mut keys = BTreeSet::new();
    for c in candidates {
        if !ids.insert(c.validator_id) {
            return Err(WitnessError::DuplicateValidatorId);
        }
        if !keys.insert(c.consensus_bls_key.0) {
            return Err(WitnessError::DuplicateConsensusKey);
        }
    }

    // 1. Eligibility.
    let eligible: Vec<&WitnessBondV1> = candidates
        .iter()
        .filter(|c| c.active_at(epoch) && c.bonded_noos >= min_bond)
        .collect();

    let fail = |prev: Option<&MembershipSnapshotV1>, prev_was_emergency: bool| {
        if prev_was_emergency {
            return SnapshotOutcome::Halt;
        }
        match prev {
            Some(p) => SnapshotOutcome::EmergencyContinuation(p.continued_for(epoch)),
            None => SnapshotOutcome::Halt,
        }
    };

    if eligible.is_empty() {
        return Ok(fail(prev, prev_was_emergency));
    }

    // 2–3. Active set: top N_max by raw weight, epoch-salted tie-break.
    let mut ranked: Vec<(&WitnessBondV1, [u8; 32])> = eligible
        .iter()
        .map(|c| Ok((*c, tiebreak_hash(epoch, &c.validator_id)?)))
        .collect::<Result<_, WitnessError>>()?;
    ranked.sort_by(|(a, ta), (b, tb)| {
        b.bonded_noos
            .cmp(&a.bonded_noos)
            .then_with(|| ta.cmp(tb))
            .then_with(|| a.validator_id.cmp(&b.validator_id))
    });
    let split = ranked.len().min(N_MAX);
    let (active, remainder) = ranked.split_at(split);

    // 4. Sample order over the remainder: reserve = first N_tail; the same
    // order drives cap-repair admission.
    let mut sampled: Vec<(&WitnessBondV1, [u8; 32])> = remainder
        .iter()
        .map(|(c, _)| Ok((*c, sample_hash(epoch, randomness, &c.validator_id)?)))
        .collect::<Result<_, WitnessError>>()?;
    sampled
        .sort_by(|(a, sa), (b, sb)| sa.cmp(sb).then_with(|| a.validator_id.cmp(&b.validator_id)));

    let mut members: Vec<MemberV1> = active.iter().map(|(c, _)| member_from_bond(c)).collect();
    let mut admission = sampled.iter().map(|(c, _)| *c);

    // 5. Cap-repair loop.
    loop {
        if !cap_violated(&members) {
            return finish_snapshot(epoch, members).map(SnapshotOutcome::Normal);
        }
        if members.len() < N_HARD {
            if let Some(next) = admission.next() {
                members.push(member_from_bond(next));
                continue;
            }
        }
        // Admission exhausted: reduce proofpower bonuses before touching
        // raw weight. At genesis this never changes anything.
        if reduce_proofpower(&mut members) {
            continue;
        }
        // No valid vector exists.
        return Ok(fail(prev, prev_was_emergency));
    }
}

/// The sampled reserve (first `N_tail` of the sample order), exposed for
/// telemetry/tests; [`build_snapshot`] derives admission internally.
pub fn reserve_sample(
    epoch: u64,
    remainder: &[WitnessBondV1],
    randomness: &[u8; 32],
) -> Result<Vec<[u8; 32]>, WitnessError> {
    let mut sampled: Vec<([u8; 32], [u8; 32])> = remainder
        .iter()
        .map(|c| {
            Ok((
                sample_hash(epoch, randomness, &c.validator_id)?,
                c.validator_id,
            ))
        })
        .collect::<Result<_, WitnessError>>()?;
    sampled.sort();
    Ok(sampled.into_iter().take(N_TAIL).map(|(_, id)| id).collect())
}

/// Declared-cluster telemetry (§2.6): conservative aggregation of declared
/// control clusters; UNKNOWN (empty) declarations are treated as one
/// correlated cluster. Informative only — never selection input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterStat {
    /// Raw declared failure-domain bytes; empty = the correlated
    /// unknown-declaration pseudo-cluster.
    pub cluster_key: Vec<u8>,
    pub member_count: u32,
    pub raw_weight: u128,
    pub effective_weight: u128,
    /// False for the aggregated unknown cluster.
    pub declared: bool,
}

/// Aggregates snapshot members into declared clusters, deterministically
/// ordered by cluster key (unknown cluster first, as the empty key).
#[must_use]
pub fn cluster_telemetry(snapshot: &MembershipSnapshotV1) -> Vec<ClusterStat> {
    let mut clusters: BTreeMap<Vec<u8>, ClusterStat> = BTreeMap::new();
    for m in snapshot.members() {
        let key = m.failure_domains.clone();
        let entry = clusters.entry(key.clone()).or_insert_with(|| ClusterStat {
            declared: !key.is_empty(),
            cluster_key: key,
            member_count: 0,
            raw_weight: 0,
            effective_weight: 0,
        });
        entry.member_count = entry.member_count.saturating_add(1);
        entry.raw_weight = entry.raw_weight.saturating_add(m.raw_weight);
        entry.effective_weight = entry.effective_weight.saturating_add(m.effective_weight);
    }
    clusters.into_values().collect()
}
