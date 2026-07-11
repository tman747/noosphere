//! A-UMBRA-HIDDEN local contract: hidden-footprint concurrency conceals read/write sets while
//! proving nonconflict. State keys never appear in a footprint; each key is replaced by an
//! epoch-scoped PRF tag, so the checker sees only tag equality (the registered leakage model:
//! equality-of-access within one epoch plus set sizes). Overlapping accesses always produce
//! equal tags, so a false nonconflict is impossible for sealed footprints; a wire-forged
//! footprint (mutated tag dodging the equality check) fails the keyed binding; conflicting
//! writes return a typed `Conflict` requiring serialization; tags are unlinkable across epochs.
//!
//! Local scope note: sealing completeness (that a transition declared ALL keys it touched) is
//! the zero-knowledge derivation relation and stays external, as does the AUC / mutual-
//! information leakage measurement of E-UMBRA-01.

use crate::Hash32;

pub const HIDDEN_TAG_DOMAIN: &[u8] = b"NOOS/UMBRA/HIDDEN-FOOTPRINT-TAG/V1";
pub const HIDDEN_BIND_DOMAIN: &[u8] = b"NOOS/UMBRA/HIDDEN-FOOTPRINT-BIND/V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HiddenError {
    /// The footprint binding does not verify: a tag was forged or the epoch relabeled.
    ForgedFootprint,
    /// Footprints from different epochs are incomparable by design (unlinkability).
    EpochMismatch,
    /// The transitions touch a common key with at least one write: they must serialize.
    Conflict,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EpochKey(pub [u8; 32]);

fn epoch_tag_key(key: &EpochKey, epoch: u64) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_keyed(&key.0);
    hasher.update(HIDDEN_TAG_DOMAIN);
    hasher.update(&epoch.to_le_bytes());
    *hasher.finalize().as_bytes()
}

/// Epoch-scoped access tag for one state key. Equal keys collide within an epoch (that is how
/// conflicts are found); across epochs the tags are unlinkable.
#[must_use]
pub fn access_tag(key: &EpochKey, epoch: u64, state_key: &Hash32) -> Hash32 {
    *blake3::keyed_hash(&epoch_tag_key(key, epoch), state_key).as_bytes()
}

/// A sealed footprint: sorted, deduplicated access tags plus a keyed binding. Fields are
/// private; the only honest constructor is `seal_footprint`, and wire data re-enters through
/// `from_wire`, whose binding is checked before any comparison.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Footprint {
    epoch: u64,
    read_tags: Vec<Hash32>,
    write_tags: Vec<Hash32>,
    binding: Hash32,
}

fn binding(key: &EpochKey, epoch: u64, reads: &[Hash32], writes: &[Hash32]) -> Hash32 {
    let mut hasher = blake3::Hasher::new_keyed(&key.0);
    hasher.update(HIDDEN_BIND_DOMAIN);
    hasher.update(&epoch.to_le_bytes());
    hasher.update(&(reads.len() as u64).to_le_bytes());
    for tag in reads {
        hasher.update(tag);
    }
    hasher.update(&(writes.len() as u64).to_le_bytes());
    for tag in writes {
        hasher.update(tag);
    }
    *hasher.finalize().as_bytes()
}

fn sorted_tags(key: &EpochKey, epoch: u64, keys: &[Hash32]) -> Vec<Hash32> {
    let mut tags: Vec<Hash32> = keys.iter().map(|k| access_tag(key, epoch, k)).collect();
    tags.sort_unstable();
    tags.dedup();
    tags
}

/// Seals a transition's read and write key sets into a concealed footprint.
#[must_use]
pub fn seal_footprint(
    key: &EpochKey,
    epoch: u64,
    read_keys: &[Hash32],
    write_keys: &[Hash32],
) -> Footprint {
    let read_tags = sorted_tags(key, epoch, read_keys);
    let write_tags = sorted_tags(key, epoch, write_keys);
    let binding = binding(key, epoch, &read_tags, &write_tags);
    Footprint {
        epoch,
        read_tags,
        write_tags,
        binding,
    }
}

impl Footprint {
    /// Reconstructs a footprint from wire data. The binding is carried as-is and checked by
    /// every consumer; a forger without the epoch key cannot produce a verifying binding.
    #[must_use]
    pub fn from_wire(
        epoch: u64,
        read_tags: Vec<Hash32>,
        write_tags: Vec<Hash32>,
        binding: Hash32,
    ) -> Self {
        Self {
            epoch,
            read_tags,
            write_tags,
            binding,
        }
    }

    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    fn verify(&self, key: &EpochKey) -> Result<(), HiddenError> {
        if self.binding != binding(key, self.epoch, &self.read_tags, &self.write_tags) {
            return Err(HiddenError::ForgedFootprint);
        }
        Ok(())
    }
}

/// Nonconflict certificate for two concurrent hidden transitions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonConflict {
    pub epoch: u64,
}

fn sorted_intersects(a: &[Hash32], b: &[Hash32]) -> bool {
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i = i.saturating_add(1),
            std::cmp::Ordering::Greater => j = j.saturating_add(1),
            std::cmp::Ordering::Equal => return true,
        }
    }
    false
}

/// Checks two sealed footprints for nonconflict without ever seeing a state key. Conflict rule:
/// write/write or write/read overlap on any tag. The cost is linear in the tag counts, so a
/// denial attempt pays proportionally to its own declared footprint size.
pub fn prove_nonconflict(
    key: &EpochKey,
    a: &Footprint,
    b: &Footprint,
) -> Result<NonConflict, HiddenError> {
    a.verify(key)?;
    b.verify(key)?;
    if a.epoch != b.epoch {
        return Err(HiddenError::EpochMismatch);
    }
    if sorted_intersects(&a.write_tags, &b.write_tags)
        || sorted_intersects(&a.write_tags, &b.read_tags)
        || sorted_intersects(&a.read_tags, &b.write_tags)
    {
        return Err(HiddenError::Conflict);
    }
    Ok(NonConflict { epoch: a.epoch })
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    const KEY: EpochKey = EpochKey([17u8; 32]);

    fn k(v: u8) -> Hash32 {
        [v; 32]
    }

    #[test]
    fn disjoint_transitions_prove_nonconflict_without_revealing_keys() {
        let a = seal_footprint(&KEY, 1, &[k(1)], &[k(2)]);
        let b = seal_footprint(&KEY, 1, &[k(3)], &[k(4)]);
        assert_eq!(
            prove_nonconflict(&KEY, &a, &b),
            Ok(NonConflict { epoch: 1 })
        );
        // Read/read sharing is not a conflict.
        let c = seal_footprint(&KEY, 1, &[k(1)], &[k(5)]);
        assert_eq!(
            prove_nonconflict(&KEY, &a, &c),
            Ok(NonConflict { epoch: 1 })
        );
    }

    #[test]
    fn falsifier_overlapping_writes_always_conflict() {
        // Equal keys produce equal tags deterministically: a false nonconflict is impossible
        // for sealed footprints.
        let a = seal_footprint(&KEY, 1, &[], &[k(2), k(9)]);
        let b = seal_footprint(&KEY, 1, &[], &[k(9)]);
        assert_eq!(prove_nonconflict(&KEY, &a, &b), Err(HiddenError::Conflict));
        // Write/read overlap conflicts too, in both orders.
        let r = seal_footprint(&KEY, 1, &[k(9)], &[]);
        assert_eq!(prove_nonconflict(&KEY, &a, &r), Err(HiddenError::Conflict));
        assert_eq!(prove_nonconflict(&KEY, &r, &a), Err(HiddenError::Conflict));
    }

    #[test]
    fn falsifier_wire_forged_tag_rejects_instead_of_dodging_conflict() {
        let honest = seal_footprint(&KEY, 1, &[], &[k(9)]);
        let other = seal_footprint(&KEY, 1, &[], &[k(9), k(3)]);
        // The adversary swaps its conflicting tag for a random one to fake disjointness, but
        // cannot recompute the keyed binding.
        let forged = Footprint::from_wire(1, Vec::new(), vec![[0xEEu8; 32]], {
            // Reuses the honest binding bytes: stale for the mutated tag list.
            honest.binding
        });
        assert_eq!(
            prove_nonconflict(&KEY, &forged, &other),
            Err(HiddenError::ForgedFootprint)
        );
        // Round-tripping honest wire data still verifies.
        let wire = Footprint::from_wire(
            honest.epoch,
            honest.read_tags.clone(),
            honest.write_tags.clone(),
            honest.binding,
        );
        assert_eq!(
            prove_nonconflict(&KEY, &wire, &other),
            Err(HiddenError::Conflict)
        );
    }

    #[test]
    fn falsifier_epoch_relabeling_rejects() {
        let a = seal_footprint(&KEY, 1, &[], &[k(1)]);
        let mut relabeled = a.clone();
        relabeled.epoch = 2;
        let b = seal_footprint(&KEY, 2, &[], &[k(2)]);
        // The binding covers the epoch, so relabeling is a forgery, not a comparison.
        assert_eq!(
            prove_nonconflict(&KEY, &relabeled, &b),
            Err(HiddenError::ForgedFootprint)
        );
        // Honest cross-epoch comparison is refused as incomparable.
        let c = seal_footprint(&KEY, 1, &[], &[k(3)]);
        assert_eq!(
            prove_nonconflict(&KEY, &c, &b),
            Err(HiddenError::EpochMismatch)
        );
    }

    #[test]
    fn tags_conceal_keys_and_unlink_across_epochs() {
        // The footprint never contains the state key bytes.
        let secret_key = k(42);
        let sealed = seal_footprint(&KEY, 1, &[], &[secret_key]);
        assert!(!sealed.write_tags.contains(&secret_key));
        // The same key tags differently in the next epoch: no cross-epoch linkage.
        assert_ne!(
            access_tag(&KEY, 1, &secret_key),
            access_tag(&KEY, 2, &secret_key)
        );
        // Distinct keys never share a tag within an epoch (deterministic PRF, no collisions
        // in the test universe).
        assert_ne!(access_tag(&KEY, 1, &k(1)), access_tag(&KEY, 1, &k(2)));
    }
}
