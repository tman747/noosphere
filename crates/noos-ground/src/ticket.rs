//! Ground v1 challenge/ticket law (ch01 §4.2; plan §6.2).
//!
//! ```text
//! GroundChallenge = BLAKE3-256(
//!   "NOOS/GROUND/CHALLENGE/V1" || chain_id || parent_hash ||
//!   parent_ground_target_le || slot_le || proposal_commitment || proposer_pubkey
//! )
//! digest = BLAKE3-256-keyed(
//!   key   = GroundChallenge,
//!   input = "NOOS/GROUND/TICKET/V1" || nonce_le_u64 || extra_nonce_32
//! )
//! ```
//!
//! A ticket is valid only under the eight-rule law of ch01 §4.2, checked
//! by [`validate_ticket`] in exactly that order. Duplicate exclusion
//! (rule 8) is delegated to the DAG layer through [`DuplicateSet`].

use crate::u256::U256;
use core::fmt;
use noos_crypto::{hash_domain, keyed_hash_domain, CryptoError, DomainId, Hash32};

/// Ground profile under Braid version 1 (ch01 §4.2 rule 1).
pub const GROUND_PROFILE_ID_V1: u32 = 1;
/// Slot duration in milliseconds (ch01 §4.2 rule 6: 6-second slots).
pub const SLOT_MS: u64 = 6000;
/// Maximum slots a child may lead its parent by (ch01 §4.2 rule 6).
pub const MAX_SLOT_SKIP: u64 = 20;
/// Median-time-past window in blocks (ch01 §4.1).
pub const MEDIAN_TIME_PAST_BLOCKS: usize = 11;
/// Devnet future-drift bound in milliseconds (constants-v1.toml `[ground]`;
/// the mainnet value is OWNER_BLOCKED pending E-WAN).
pub const DEVNET_MAX_FUTURE_DRIFT_MS: u64 = 12000;
/// Fixed `extra_nonce` width (ch01 §4.2 rule 3).
pub const EXTRA_NONCE_BYTES: usize = 32;
/// Proposer public key width: BLS `Bytes48` per the header schema table.
pub const PROPOSER_PUBKEY_BYTES: usize = 48;
/// Canonical fixed-width ticket encoding size:
/// `profile_id u32 LE || nonce u64 LE || extra_nonce[32] || digest[32]`.
pub const TICKET_ENCODED_BYTES: usize = 76;

/// The Ground ticket carried by every block (ch01 §4.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GroundTicketV1 {
    /// Must equal [`GROUND_PROFILE_ID_V1`] under Braid v1.
    pub profile_id: u32,
    /// Search nonce, hashed as canonical little-endian.
    pub nonce: u64,
    /// Fixed 32-byte extra nonce.
    pub extra_nonce: [u8; 32],
    /// Claimed keyed-BLAKE3 digest; recomputed during validation.
    pub digest: Hash32,
}

impl GroundTicketV1 {
    /// Canonical fixed-width encoding (little-endian scalars, then raw
    /// byte arrays), matching the noos-codec field conventions.
    #[must_use]
    pub fn encode(&self) -> [u8; TICKET_ENCODED_BYTES] {
        let mut out = [0_u8; TICKET_ENCODED_BYTES];
        out[0..4].copy_from_slice(&self.profile_id.to_le_bytes());
        out[4..12].copy_from_slice(&self.nonce.to_le_bytes());
        out[12..44].copy_from_slice(&self.extra_nonce);
        out[44..76].copy_from_slice(self.digest.as_bytes());
        out
    }

    /// Strict inverse of [`encode`](Self::encode): exact length, no
    /// trailing bytes.
    #[must_use]
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; TICKET_ENCODED_BYTES] = bytes.try_into().ok()?;
        let mut profile = [0_u8; 4];
        profile.copy_from_slice(&bytes[0..4]);
        let mut nonce = [0_u8; 8];
        nonce.copy_from_slice(&bytes[4..12]);
        let mut extra_nonce = [0_u8; 32];
        extra_nonce.copy_from_slice(&bytes[12..44]);
        let mut digest = [0_u8; 32];
        digest.copy_from_slice(&bytes[44..76]);
        Some(Self {
            profile_id: u32::from_le_bytes(profile),
            nonce: u64::from_le_bytes(nonce),
            extra_nonce,
            digest: Hash32::from_bytes(digest),
        })
    }
}

/// Inputs bound by the Ground challenge, in exact concatenation order.
#[derive(Clone, Copy, Debug)]
pub struct ChallengeInputs<'a> {
    /// Frozen chain identity.
    pub chain_id: &'a Hash32,
    /// Parent block hash.
    pub parent_hash: &'a Hash32,
    /// Parent's Ground target, encoded as 32 bytes little-endian.
    pub parent_ground_target: &'a U256,
    /// Child slot, encoded as u64 little-endian.
    pub slot: u64,
    /// Domain-separated hash of every canonical header field except the
    /// ticket root, the ticket, the proposer signature, and the block hash
    /// (ch01 §4.2).
    pub proposal_commitment: &'a Hash32,
    /// Proposer BLS public key bytes (header schema `Bytes48`).
    pub proposer_pubkey: &'a [u8; PROPOSER_PUBKEY_BYTES],
}

/// `GroundChallenge` under `D-GROUND-CHALLENGE` (`NOOS/GROUND/CHALLENGE/V1`).
///
/// # Errors
/// Only on registry misuse inside `noos-crypto`; the Ground rows are
/// registered, so callers may treat an error as a build defect.
pub fn ground_challenge(inputs: &ChallengeInputs<'_>) -> Result<Hash32, CryptoError> {
    hash_domain(
        DomainId::GroundChallenge,
        &[
            inputs.chain_id.as_bytes(),
            inputs.parent_hash.as_bytes(),
            &inputs.parent_ground_target.to_le_bytes(),
            &inputs.slot.to_le_bytes(),
            inputs.proposal_commitment.as_bytes(),
            inputs.proposer_pubkey,
        ],
    )
}

/// Ticket digest under `D-GROUND-TICKET` (`NOOS/GROUND/TICKET/V1`), keyed
/// by the challenge.
///
/// # Errors
/// Only on registry misuse inside `noos-crypto` (see [`ground_challenge`]).
pub fn ground_digest(
    challenge: &Hash32,
    nonce: u64,
    extra_nonce: &[u8; EXTRA_NONCE_BYTES],
) -> Result<Hash32, CryptoError> {
    keyed_hash_domain(
        DomainId::GroundTicket,
        challenge,
        &[&nonce.to_le_bytes(), extra_nonce],
    )
}

/// Normalized base proposal work `G(b) = floor((2^256 - 1) / (target + 1))`
/// (ch01 §4.2), exact.
///
/// `target = 2^256 - 1` yields exactly zero; `target = 0` (never valid on
/// chain) yields `2^256 - 1`. Total on all inputs.
#[must_use]
pub fn ground_work(target: &U256) -> U256 {
    match target.checked_add_one() {
        // target + 1 = 2^256: floor((2^256-1)/2^256) = 0.
        None => U256::ZERO,
        // Divisor >= 1, so the division cannot fail.
        Some(divisor) => U256::MAX.checked_div(&divisor).unwrap_or(U256::ZERO),
    }
}

/// Slot for a timestamp: `floor((timestamp_ms - genesis_time_ms) / 6000)`
/// (ch01 §4.2 rule 6). `None` when the timestamp precedes genesis.
#[must_use]
pub fn slot_from_timestamp(timestamp_ms: u64, genesis_time_ms: u64) -> Option<u64> {
    timestamp_ms
        .checked_sub(genesis_time_ms)
        .map(|elapsed| elapsed / SLOT_MS)
}

/// Median-time-past over the parent chain's most recent timestamps
/// (up to [`MEDIAN_TIME_PAST_BLOCKS`]; fewer only near genesis).
///
/// Law: sort ascending, take index `len / 2` (the exact middle for the
/// full odd-sized window). `None` on an empty or oversized window.
#[must_use]
pub fn median_time_past_ms(parent_timestamps_ms: &[u64]) -> Option<u64> {
    if parent_timestamps_ms.is_empty() || parent_timestamps_ms.len() > MEDIAN_TIME_PAST_BLOCKS {
        return None;
    }
    let mut sorted: [u64; MEDIAN_TIME_PAST_BLOCKS] = [0; MEDIAN_TIME_PAST_BLOCKS];
    let window = &mut sorted[..parent_timestamps_ms.len()];
    window.copy_from_slice(parent_timestamps_ms);
    window.sort_unstable();
    Some(window[window.len() / 2])
}

/// Ancestor duplicate scan for ch01 §4.2 rule 8, supplied by the DAG layer.
///
/// `contains` must answer: has this exact `(proposer_pubkey, nonce,
/// extra_nonce)` tuple appeared in any ancestor of the block under
/// validation after (strictly above) the last finalized checkpoint?
pub trait DuplicateSet {
    /// True iff the tuple already appeared in the scan scope.
    fn contains(
        &self,
        proposer_pubkey: &[u8; PROPOSER_PUBKEY_BYTES],
        nonce: u64,
        extra_nonce: &[u8; EXTRA_NONCE_BYTES],
    ) -> bool;
}

/// Everything [`validate_ticket`] needs besides the ticket itself. All
/// fields are recomputed context (header fields, parent-chain data, Pulse
/// output), never taken from the ticket.
#[derive(Clone, Copy, Debug)]
pub struct TicketContext<'a> {
    /// Frozen chain identity.
    pub chain_id: &'a Hash32,
    /// Parent block hash.
    pub parent_hash: &'a Hash32,
    /// Parent's Ground target (challenge input).
    pub parent_ground_target: &'a U256,
    /// Child header slot claim.
    pub slot: u64,
    /// Child header timestamp, milliseconds.
    pub timestamp_ms: u64,
    /// Genesis time, milliseconds.
    pub genesis_time_ms: u64,
    /// Parent header slot.
    pub parent_slot: u64,
    /// Most recent parent-chain timestamps for the MTP window (up to 11).
    pub parent_timestamps_ms: &'a [u64],
    /// Validating node's adjusted network time, milliseconds.
    pub adjusted_now_ms: u64,
    /// Future-drift bound, milliseconds (12000 on devnet).
    pub max_future_drift_ms: u64,
    /// Header's `ground_target` claim.
    pub ground_target: &'a U256,
    /// Deterministic Pulse output for this parent (rule 5 comparand),
    /// computed by the caller via [`crate::pulse_target_v1`].
    pub expected_target: &'a U256,
    /// Header proposal commitment (challenge input).
    pub proposal_commitment: &'a Hash32,
    /// Proposer public key bytes (challenge input + duplicate-scan key).
    pub proposer_pubkey: &'a [u8; PROPOSER_PUBKEY_BYTES],
}

/// Ground validation failures, one variant per ch01 §4.2 rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GroundError {
    /// Rule 1: `profile_id != 1` under Braid v1.
    WrongProfileId {
        /// Offending profile id.
        got: u32,
    },
    /// Rules 2–3: recomputed keyed digest does not equal the claim.
    DigestMismatch,
    /// Rule 4: `uint256_le(digest) < ground_target` fails (equality
    /// included — the comparison is strict).
    DigestNotBelowTarget,
    /// Rule 5: header target differs from the deterministic Pulse output.
    TargetMismatch,
    /// Rule 6: timestamp precedes genesis, so no slot exists.
    TimestampBeforeGenesis,
    /// Rule 6: header slot is not `floor((timestamp_ms - genesis)/6000)`.
    SlotMismatch {
        /// Slot derived from the timestamp.
        expected: u64,
        /// Header slot claim.
        got: u64,
    },
    /// Rule 6: slot below the parent slot.
    SlotBehindParent {
        /// Parent slot.
        parent_slot: u64,
        /// Header slot claim.
        got: u64,
    },
    /// Rule 6: slot more than `max_slot_skip = 20` ahead of the parent.
    SlotSkipTooLarge {
        /// Parent slot.
        parent_slot: u64,
        /// Header slot claim.
        got: u64,
    },
    /// Rule 7: empty/oversized MTP window (caller contract violation).
    BadTimestampWindow,
    /// Rule 7: timestamp not strictly greater than the parent MTP.
    TimestampNotAfterMedianTimePast {
        /// Parent median-time-past, milliseconds.
        median_ms: u64,
        /// Header timestamp.
        got: u64,
    },
    /// Rule 7: timestamp beyond adjusted time plus the drift bound.
    TimestampTooFarInFuture {
        /// `adjusted_now_ms + max_future_drift_ms` (saturating).
        limit_ms: u64,
        /// Header timestamp.
        got: u64,
    },
    /// Rule 8: `(proposer_pubkey, nonce, extra_nonce)` reuse since the
    /// last finalized checkpoint.
    DuplicateTicket,
    /// Domain-registry misuse inside `noos-crypto` (build defect, not a
    /// consensus verdict).
    Crypto(CryptoError),
}

impl fmt::Display for GroundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongProfileId { got } => write!(f, "ground profile_id {got} != 1"),
            Self::DigestMismatch => f.write_str("recomputed ticket digest mismatch"),
            Self::DigestNotBelowTarget => f.write_str("digest not strictly below ground_target"),
            Self::TargetMismatch => f.write_str("ground_target differs from Pulse output"),
            Self::TimestampBeforeGenesis => f.write_str("timestamp precedes genesis time"),
            Self::SlotMismatch { expected, got } => {
                write!(f, "slot {got} != floor-derived slot {expected}")
            }
            Self::SlotBehindParent { parent_slot, got } => {
                write!(f, "slot {got} behind parent slot {parent_slot}")
            }
            Self::SlotSkipTooLarge { parent_slot, got } => write!(
                f,
                "slot {got} more than {MAX_SLOT_SKIP} ahead of parent slot {parent_slot}"
            ),
            Self::BadTimestampWindow => f.write_str("empty or oversized median-time-past window"),
            Self::TimestampNotAfterMedianTimePast { median_ms, got } => {
                write!(f, "timestamp {got} not after median-time-past {median_ms}")
            }
            Self::TimestampTooFarInFuture { limit_ms, got } => {
                write!(f, "timestamp {got} beyond future-drift limit {limit_ms}")
            }
            Self::DuplicateTicket => {
                f.write_str("(proposer, nonce, extra_nonce) reused since last finalized checkpoint")
            }
            Self::Crypto(e) => write!(f, "crypto domain misuse: {e}"),
        }
    }
}

impl From<CryptoError> for GroundError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

/// Full Ground ticket validation, checks in the exact order of ch01 §4.2:
///
/// 1. `profile_id = 1`;
/// 2. challenge recomputation binds parent, parent target, slot, proposal
///    commitment, and proposer;
/// 3. keyed digest recomputation over `nonce_le || extra_nonce` matches;
/// 4. `uint256_le(digest) < ground_target` (strict);
/// 5. `ground_target` equals the deterministic Pulse output;
/// 6. slot law: derived from the timestamp, `>= parent_slot`, at most
///    `max_slot_skip = 20` ahead;
/// 7. timestamp strictly above the parent median-time-past and at most
///    `max_future_drift_ms` beyond adjusted network time;
/// 8. no `(proposer_pubkey, nonce, extra_nonce)` reuse since the last
///    finalized checkpoint ([`DuplicateSet`]).
///
/// # Errors
/// The first failing rule, as a [`GroundError`].
pub fn validate_ticket(
    ctx: &TicketContext<'_>,
    ticket: &GroundTicketV1,
    duplicates: &impl DuplicateSet,
) -> Result<(), GroundError> {
    // Rule 1.
    if ticket.profile_id != GROUND_PROFILE_ID_V1 {
        return Err(GroundError::WrongProfileId {
            got: ticket.profile_id,
        });
    }

    // Rules 2–3: exact recomputation.
    let challenge = ground_challenge(&ChallengeInputs {
        chain_id: ctx.chain_id,
        parent_hash: ctx.parent_hash,
        parent_ground_target: ctx.parent_ground_target,
        slot: ctx.slot,
        proposal_commitment: ctx.proposal_commitment,
        proposer_pubkey: ctx.proposer_pubkey,
    })?;
    let digest = ground_digest(&challenge, ticket.nonce, &ticket.extra_nonce)?;
    if digest != ticket.digest {
        return Err(GroundError::DigestMismatch);
    }

    // Rule 4: strict less-than on the little-endian digest value.
    if U256::from_le_bytes(digest.as_bytes()) >= *ctx.ground_target {
        return Err(GroundError::DigestNotBelowTarget);
    }

    // Rule 5.
    if ctx.ground_target != ctx.expected_target {
        return Err(GroundError::TargetMismatch);
    }

    // Rule 6: slot law.
    let expected_slot = slot_from_timestamp(ctx.timestamp_ms, ctx.genesis_time_ms)
        .ok_or(GroundError::TimestampBeforeGenesis)?;
    if ctx.slot != expected_slot {
        return Err(GroundError::SlotMismatch {
            expected: expected_slot,
            got: ctx.slot,
        });
    }
    if ctx.slot < ctx.parent_slot {
        return Err(GroundError::SlotBehindParent {
            parent_slot: ctx.parent_slot,
            got: ctx.slot,
        });
    }
    if ctx
        .slot
        .checked_sub(ctx.parent_slot)
        .is_none_or(|skip| skip > MAX_SLOT_SKIP)
    {
        return Err(GroundError::SlotSkipTooLarge {
            parent_slot: ctx.parent_slot,
            got: ctx.slot,
        });
    }

    // Rule 7: median-time-past and future drift.
    let median_ms =
        median_time_past_ms(ctx.parent_timestamps_ms).ok_or(GroundError::BadTimestampWindow)?;
    if ctx.timestamp_ms <= median_ms {
        return Err(GroundError::TimestampNotAfterMedianTimePast {
            median_ms,
            got: ctx.timestamp_ms,
        });
    }
    let limit_ms = ctx.adjusted_now_ms.saturating_add(ctx.max_future_drift_ms);
    if ctx.timestamp_ms > limit_ms {
        return Err(GroundError::TimestampTooFarInFuture {
            limit_ms,
            got: ctx.timestamp_ms,
        });
    }

    // Rule 8: duplicate exclusion (DAG-supplied scan).
    if duplicates.contains(ctx.proposer_pubkey, ticket.nonce, &ticket.extra_nonce) {
        return Err(GroundError::DuplicateTicket);
    }

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;

    /// Duplicate set driven by a fixed answer.
    struct FixedDup(bool);
    impl DuplicateSet for FixedDup {
        fn contains(&self, _: &[u8; 48], _: u64, _: &[u8; 32]) -> bool {
            self.0
        }
    }

    struct Fixture {
        chain_id: Hash32,
        parent_hash: Hash32,
        parent_ground_target: U256,
        target: U256,
        proposal_commitment: Hash32,
        proposer_pubkey: [u8; 48],
        genesis_time_ms: u64,
        timestamp_ms: u64,
        parent_slot: u64,
        parent_timestamps_ms: Vec<u64>,
        adjusted_now_ms: u64,
    }

    impl Fixture {
        fn new() -> Self {
            let genesis_time_ms = 1_000_000;
            // 11-block parent window ending well below the child timestamp.
            let parent_timestamps_ms: Vec<u64> =
                (0..11).map(|i| genesis_time_ms + 6_000 * (i + 1)).collect();
            Self {
                chain_id: Hash32::from_bytes([0x11; 32]),
                parent_hash: Hash32::from_bytes([0x22; 32]),
                parent_ground_target: U256::from_u128(1 << 100),
                // Comfortably permissive target: 2^255.
                target: {
                    let mut limbs = [0_u64; 4];
                    limbs[3] = 1 << 63;
                    U256::from_limbs(limbs)
                },
                proposal_commitment: Hash32::from_bytes([0x33; 32]),
                proposer_pubkey: [0x44; 48],
                genesis_time_ms,
                timestamp_ms: genesis_time_ms + 150_000, // slot 25
                parent_slot: 22,
                parent_timestamps_ms,
                adjusted_now_ms: genesis_time_ms + 150_000,
            }
        }

        fn slot(&self) -> u64 {
            slot_from_timestamp(self.timestamp_ms, self.genesis_time_ms).unwrap()
        }

        fn ctx(&self) -> TicketContext<'_> {
            TicketContext {
                chain_id: &self.chain_id,
                parent_hash: &self.parent_hash,
                parent_ground_target: &self.parent_ground_target,
                slot: self.slot(),
                timestamp_ms: self.timestamp_ms,
                genesis_time_ms: self.genesis_time_ms,
                parent_slot: self.parent_slot,
                parent_timestamps_ms: &self.parent_timestamps_ms,
                adjusted_now_ms: self.adjusted_now_ms,
                max_future_drift_ms: DEVNET_MAX_FUTURE_DRIFT_MS,
                ground_target: &self.target,
                expected_target: &self.target,
                proposal_commitment: &self.proposal_commitment,
                proposer_pubkey: &self.proposer_pubkey,
            }
        }

        /// Searches the first nonce whose digest beats the fixture target.
        fn mine(&self) -> GroundTicketV1 {
            let challenge = ground_challenge(&ChallengeInputs {
                chain_id: &self.chain_id,
                parent_hash: &self.parent_hash,
                parent_ground_target: &self.parent_ground_target,
                slot: self.slot(),
                proposal_commitment: &self.proposal_commitment,
                proposer_pubkey: &self.proposer_pubkey,
            })
            .unwrap();
            let extra_nonce = [0x55; 32];
            for nonce in 0..1_000 {
                let digest = ground_digest(&challenge, nonce, &extra_nonce).unwrap();
                if U256::from_le_bytes(digest.as_bytes()) < self.target {
                    return GroundTicketV1 {
                        profile_id: GROUND_PROFILE_ID_V1,
                        nonce,
                        extra_nonce,
                        digest,
                    };
                }
            }
            panic!("no nonce beat a 2^255 target within 1000 tries");
        }
    }

    #[test]
    fn positive_ticket_validates() {
        let fx = Fixture::new();
        assert_eq!(
            validate_ticket(&fx.ctx(), &fx.mine(), &FixedDup(false)),
            Ok(())
        );
    }

    #[test]
    fn every_challenge_field_mutation_rejects() {
        let fx = Fixture::new();
        let ticket = fx.mine();

        let mut m = Fixture::new();
        m.chain_id = Hash32::from_bytes([0xAA; 32]);
        assert_eq!(
            validate_ticket(&m.ctx(), &ticket, &FixedDup(false)),
            Err(GroundError::DigestMismatch),
            "chain_id"
        );

        let mut m = Fixture::new();
        m.parent_hash = Hash32::from_bytes([0xAB; 32]);
        assert_eq!(
            validate_ticket(&m.ctx(), &ticket, &FixedDup(false)),
            Err(GroundError::DigestMismatch),
            "parent_hash"
        );

        let mut m = Fixture::new();
        m.parent_ground_target = U256::from_u128((1 << 100) + 1);
        assert_eq!(
            validate_ticket(&m.ctx(), &ticket, &FixedDup(false)),
            Err(GroundError::DigestMismatch),
            "parent_ground_target"
        );

        // Slot change (moves the timestamp by one slot to keep rule 6
        // internally consistent — the challenge then binds a new slot).
        let mut m = Fixture::new();
        m.timestamp_ms += SLOT_MS;
        m.adjusted_now_ms += SLOT_MS;
        assert_eq!(
            validate_ticket(&m.ctx(), &ticket, &FixedDup(false)),
            Err(GroundError::DigestMismatch),
            "slot"
        );

        let mut m = Fixture::new();
        m.proposal_commitment = Hash32::from_bytes([0xAC; 32]);
        assert_eq!(
            validate_ticket(&m.ctx(), &ticket, &FixedDup(false)),
            Err(GroundError::DigestMismatch),
            "proposal_commitment"
        );

        let mut m = Fixture::new();
        m.proposer_pubkey = [0xAD; 48];
        assert_eq!(
            validate_ticket(&m.ctx(), &ticket, &FixedDup(false)),
            Err(GroundError::DigestMismatch),
            "proposer_pubkey"
        );

        // Ticket-side mutations.
        let fx = Fixture::new();
        let mut t = ticket;
        t.nonce ^= 1;
        assert_eq!(
            validate_ticket(&fx.ctx(), &t, &FixedDup(false)),
            Err(GroundError::DigestMismatch),
            "nonce"
        );
        let mut t = ticket;
        t.extra_nonce[31] ^= 1;
        assert_eq!(
            validate_ticket(&fx.ctx(), &t, &FixedDup(false)),
            Err(GroundError::DigestMismatch),
            "extra_nonce"
        );
        let mut t = ticket;
        let mut d = *t.digest.as_bytes();
        d[0] ^= 1;
        t.digest = Hash32::from_bytes(d);
        assert_eq!(
            validate_ticket(&fx.ctx(), &t, &FixedDup(false)),
            Err(GroundError::DigestMismatch),
            "digest"
        );
        let mut t = ticket;
        t.profile_id = 2;
        assert_eq!(
            validate_ticket(&fx.ctx(), &t, &FixedDup(false)),
            Err(GroundError::WrongProfileId { got: 2 }),
            "profile_id"
        );
    }

    #[test]
    fn digest_equal_to_target_rejects_and_one_below_accepts() {
        let mut fx = Fixture::new();
        let ticket = fx.mine();
        let digest_value = U256::from_le_bytes(ticket.digest.as_bytes());

        // ground_target == digest: strict `<` must reject.
        fx.target = digest_value;
        assert_eq!(
            validate_ticket(&fx.ctx(), &ticket, &FixedDup(false)),
            Err(GroundError::DigestNotBelowTarget)
        );

        // ground_target == digest + 1 (digest == target - 1): accepts.
        fx.target = digest_value.checked_add_one().unwrap();
        assert_eq!(
            validate_ticket(&fx.ctx(), &ticket, &FixedDup(false)),
            Ok(())
        );
    }

    #[test]
    fn pulse_disagreement_rejects() {
        let fx = Fixture::new();
        let ticket = fx.mine();
        let expected = U256::from_u128(1 << 90);
        let mut ctx = fx.ctx();
        ctx.expected_target = &expected;
        assert_eq!(
            validate_ticket(&ctx, &ticket, &FixedDup(false)),
            Err(GroundError::TargetMismatch)
        );
    }

    #[test]
    fn slot_law() {
        // Header slot must equal the floor-derived slot.
        let fx = Fixture::new();
        let ticket = fx.mine();
        let mut ctx = fx.ctx();
        ctx.slot += 1; // challenge binds this slot too, but rule order puts
                       // recomputation first: mismatched slot changes the
                       // challenge, so DigestMismatch fires before slot law.
        assert_eq!(
            validate_ticket(&ctx, &ticket, &FixedDup(false)),
            Err(GroundError::DigestMismatch)
        );

        // Slot behind parent.
        let mut fx = Fixture::new();
        fx.parent_slot = fx.slot() + 1;
        let ticket = fx.mine();
        assert_eq!(
            validate_ticket(&fx.ctx(), &ticket, &FixedDup(false)),
            Err(GroundError::SlotBehindParent {
                parent_slot: fx.parent_slot,
                got: fx.slot()
            })
        );

        // Exactly max_slot_skip ahead: accepted.
        let mut fx = Fixture::new();
        fx.parent_slot = fx.slot() - MAX_SLOT_SKIP;
        let ticket = fx.mine();
        assert_eq!(
            validate_ticket(&fx.ctx(), &ticket, &FixedDup(false)),
            Ok(())
        );

        // One past max_slot_skip: rejected.
        let mut fx = Fixture::new();
        fx.parent_slot = fx.slot() - MAX_SLOT_SKIP - 1;
        let ticket = fx.mine();
        assert_eq!(
            validate_ticket(&fx.ctx(), &ticket, &FixedDup(false)),
            Err(GroundError::SlotSkipTooLarge {
                parent_slot: fx.parent_slot,
                got: fx.slot()
            })
        );

        // Same slot as parent: allowed (slot >= parent_slot).
        let mut fx = Fixture::new();
        fx.parent_slot = fx.slot();
        let ticket = fx.mine();
        assert_eq!(
            validate_ticket(&fx.ctx(), &ticket, &FixedDup(false)),
            Ok(())
        );

        // Timestamp before genesis: mine at the normal slot (the challenge
        // binds the slot, not the timestamp), then move the timestamp back
        // before genesis so rule 6 has no slot to derive.
        let fx = Fixture::new();
        let ticket = fx.mine();
        let mut ctx = fx.ctx();
        ctx.timestamp_ms = fx.genesis_time_ms - 1;
        assert_eq!(
            validate_ticket(&ctx, &ticket, &FixedDup(false)),
            Err(GroundError::TimestampBeforeGenesis)
        );
    }

    #[test]
    fn median_time_past_law() {
        // Median of a full 11-window is the 6th smallest (index 5).
        let window: Vec<u64> = vec![9, 1, 8, 2, 7, 3, 6, 4, 5, 10, 11];
        assert_eq!(median_time_past_ms(&window), Some(6));
        // Near genesis: median of [a] is a; of [a, b] is max index 1.
        assert_eq!(median_time_past_ms(&[42]), Some(42));
        assert_eq!(median_time_past_ms(&[5, 9]), Some(9));
        assert_eq!(median_time_past_ms(&[]), None);
        assert_eq!(median_time_past_ms(&[0; 12]), None);

        // timestamp == MTP rejects; MTP + 1 accepts.
        let mut fx = Fixture::new();
        let median = median_time_past_ms(&fx.parent_timestamps_ms).unwrap();
        fx.timestamp_ms = median;
        // Keep slot law consistent for this timestamp.
        fx.parent_slot = slot_from_timestamp(median, fx.genesis_time_ms).unwrap();
        let ticket = fx.mine();
        assert_eq!(
            validate_ticket(&fx.ctx(), &ticket, &FixedDup(false)),
            Err(GroundError::TimestampNotAfterMedianTimePast {
                median_ms: median,
                got: median
            })
        );
        fx.timestamp_ms = median + 1;
        let ticket = fx.mine();
        assert_eq!(
            validate_ticket(&fx.ctx(), &ticket, &FixedDup(false)),
            Ok(())
        );
    }

    #[test]
    fn future_drift_law() {
        // timestamp == now + drift accepts; one past rejects.
        let mut fx = Fixture::new();
        fx.adjusted_now_ms = fx.timestamp_ms - DEVNET_MAX_FUTURE_DRIFT_MS;
        let ticket = fx.mine();
        assert_eq!(
            validate_ticket(&fx.ctx(), &ticket, &FixedDup(false)),
            Ok(())
        );
        fx.adjusted_now_ms -= 1;
        let ticket = fx.mine();
        assert_eq!(
            validate_ticket(&fx.ctx(), &ticket, &FixedDup(false)),
            Err(GroundError::TimestampTooFarInFuture {
                limit_ms: fx.adjusted_now_ms + DEVNET_MAX_FUTURE_DRIFT_MS,
                got: fx.timestamp_ms
            })
        );
    }

    #[test]
    fn duplicate_tuple_rejects() {
        let fx = Fixture::new();
        let ticket = fx.mine();
        assert_eq!(
            validate_ticket(&fx.ctx(), &ticket, &FixedDup(true)),
            Err(GroundError::DuplicateTicket)
        );
    }

    #[test]
    fn ground_work_integer_edges() {
        // target = 2^256 - 1 -> 0.
        assert_eq!(ground_work(&U256::MAX), U256::ZERO);
        // target = 1 -> floor((2^256-1)/2) = 2^255 - 1.
        let expected = {
            let mut limbs = [u64::MAX; 4];
            limbs[3] = u64::MAX >> 1;
            U256::from_limbs(limbs)
        };
        assert_eq!(ground_work(&U256::ONE), expected);
        // target = 0 (never valid on chain) -> 2^256 - 1, total function.
        assert_eq!(ground_work(&U256::ZERO), U256::MAX);
        // target = 2^255 - 1 -> floor((2^256-1)/2^255) = 1.
        let mut limbs = [u64::MAX; 4];
        limbs[3] = u64::MAX >> 1;
        assert_eq!(ground_work(&U256::from_limbs(limbs)), U256::ONE);
        // target = 2^255 -> 1 as well.
        let mut limbs = [0_u64; 4];
        limbs[3] = 1 << 63;
        assert_eq!(ground_work(&U256::from_limbs(limbs)), U256::ONE);
        // Monotone: smaller target, more work.
        assert!(ground_work(&U256::from_u64(100)) > ground_work(&U256::from_u64(1000)));
    }

    #[test]
    fn ticket_encoding_round_trips_strictly() {
        let fx = Fixture::new();
        let ticket = fx.mine();
        let bytes = ticket.encode();
        assert_eq!(GroundTicketV1::decode(&bytes), Some(ticket));
        assert_eq!(GroundTicketV1::decode(&bytes[..75]), None);
        let mut long = bytes.to_vec();
        long.push(0);
        assert_eq!(GroundTicketV1::decode(&long), None);
    }
}
