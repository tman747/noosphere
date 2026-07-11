//! Consensus-side key-custody policy.
//!
//! Braid may authorize a workload-scoped decryption event, but it never
//! accepts or stores decryption key material.  Client-held workloads always
//! require an off-chain client authorization.  Threshold workloads name a
//! bounded committee, an exact key epoch, and an expiry epoch; authorizations
//! are opaque receipts over member identities, not secret shares.

use std::collections::{BTreeMap, BTreeSet};

/// Maximum threshold committee admitted by the consensus policy.
pub const MAX_KEY_COMMITTEE_MEMBERS: usize = 64;

/// Public custody description.  Neither variant contains key bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkloadKeyCustody {
    /// Only the client can authorize decryption.  Consensus cannot do so.
    ClientHeld,
    /// A narrowly scoped, expiring threshold committee.
    Threshold {
        key_epoch: u64,
        active_from_epoch: u64,
        expires_after_epoch: u64,
        threshold: u16,
        members: BTreeSet<[u8; 32]>,
    },
}

/// A successful consensus authorization.  This carries no key material.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecryptAuthorization {
    pub workload_id: [u8; 32],
    pub key_epoch: u64,
    pub authorized_at_epoch: u64,
}

/// Stable rejection classes for the keyless policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeylessError {
    UniversalScope,
    InvalidCommittee,
    StaleKeyEpoch,
    ClientAuthorizationRequired,
    UnknownWorkload,
    WrongKeyEpoch,
    Expired,
    InsufficientShares,
}

/// Public-policy registry used by consensus.  Secret/key/share bytes have no
/// representation in this type, making a universal consensus decrypt key an
/// unrepresentable state.
#[derive(Clone, Debug, Default)]
pub struct KeylessConsensus {
    workloads: BTreeMap<[u8; 32], WorkloadKeyCustody>,
}

impl KeylessConsensus {
    /// Registers or rotates one workload's public custody policy.
    pub fn set_custody(
        &mut self,
        workload_id: [u8; 32],
        custody: WorkloadKeyCustody,
    ) -> Result<(), KeylessError> {
        if workload_id == [0; 32] {
            return Err(KeylessError::UniversalScope);
        }
        if let WorkloadKeyCustody::Threshold {
            key_epoch,
            active_from_epoch,
            expires_after_epoch,
            threshold,
            members,
        } = &custody
        {
            let threshold = usize::from(*threshold);
            if members.is_empty()
                || members.len() > MAX_KEY_COMMITTEE_MEMBERS
                || threshold == 0
                || threshold > members.len()
                || expires_after_epoch < active_from_epoch
            {
                return Err(KeylessError::InvalidCommittee);
            }
            if let Some(WorkloadKeyCustody::Threshold {
                key_epoch: current, ..
            }) = self.workloads.get(&workload_id)
            {
                if key_epoch <= current {
                    return Err(KeylessError::StaleKeyEpoch);
                }
            }
        }
        self.workloads.insert(workload_id, custody);
        Ok(())
    }

    /// Authorizes one current-epoch, workload-scoped threshold operation.
    /// `share_holders` are authenticated public member identities.  Actual
    /// secret shares remain outside consensus.
    pub fn authorize(
        &self,
        workload_id: [u8; 32],
        key_epoch: u64,
        chain_epoch: u64,
        share_holders: &[[u8; 32]],
    ) -> Result<DecryptAuthorization, KeylessError> {
        let custody = self
            .workloads
            .get(&workload_id)
            .ok_or(KeylessError::UnknownWorkload)?;
        let WorkloadKeyCustody::Threshold {
            key_epoch: registered_epoch,
            active_from_epoch,
            expires_after_epoch,
            threshold,
            members,
        } = custody
        else {
            return Err(KeylessError::ClientAuthorizationRequired);
        };
        if key_epoch != *registered_epoch || chain_epoch < *active_from_epoch {
            return Err(KeylessError::WrongKeyEpoch);
        }
        if chain_epoch > *expires_after_epoch {
            return Err(KeylessError::Expired);
        }
        let distinct = share_holders
            .iter()
            .filter(|holder| members.contains(*holder))
            .copied()
            .collect::<BTreeSet<_>>();
        if distinct.len() < usize::from(*threshold) {
            return Err(KeylessError::InsufficientShares);
        }
        Ok(DecryptAuthorization {
            workload_id,
            key_epoch,
            authorized_at_epoch: chain_epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members(start: u8, count: u8) -> BTreeSet<[u8; 32]> {
        (start..start.saturating_add(count))
            .map(|value| [value; 32])
            .collect()
    }

    #[test]
    fn adaptive_corruption_never_crosses_the_declared_threshold() {
        let workload = [0xA1; 32];
        let committee = members(1, 5);
        let mut policy = KeylessConsensus::default();
        assert_eq!(
            policy.set_custody(
                workload,
                WorkloadKeyCustody::Threshold {
                    key_epoch: 7,
                    active_from_epoch: 7,
                    expires_after_epoch: 9,
                    threshold: 3,
                    members: committee.clone(),
                },
            ),
            Ok(())
        );

        let identities = committee.iter().copied().collect::<Vec<_>>();
        for mask in 0_u32..(1_u32 << identities.len()) {
            let presented = identities
                .iter()
                .enumerate()
                .filter(|(index, _)| mask & (1_u32 << index) != 0)
                .map(|(_, member)| *member)
                .collect::<Vec<_>>();
            let result = policy.authorize(workload, 7, 8, &presented);
            assert_eq!(result.is_ok(), presented.len() >= 3, "mask={mask:#x}");
        }

        assert_eq!(
            policy.authorize(workload, 7, 8, &[[1; 32], [1; 32], [2; 32]]),
            Err(KeylessError::InsufficientShares),
            "duplicate identities are never extra shares"
        );
    }

    #[test]
    fn rotation_expires_old_shares_and_cannot_create_global_scope() {
        let workload = [0xB2; 32];
        let mut policy = KeylessConsensus::default();
        assert_eq!(
            policy.set_custody([0; 32], WorkloadKeyCustody::ClientHeld),
            Err(KeylessError::UniversalScope)
        );
        assert_eq!(
            policy.set_custody(
                workload,
                WorkloadKeyCustody::Threshold {
                    key_epoch: 3,
                    active_from_epoch: 3,
                    expires_after_epoch: 4,
                    threshold: 2,
                    members: members(1, 3),
                },
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize(workload, 3, 5, &[[1; 32], [2; 32]]),
            Err(KeylessError::Expired)
        );
        assert_eq!(
            policy.set_custody(
                workload,
                WorkloadKeyCustody::Threshold {
                    key_epoch: 5,
                    active_from_epoch: 5,
                    expires_after_epoch: 7,
                    threshold: 2,
                    members: members(4, 3),
                },
            ),
            Ok(())
        );
        assert_eq!(
            policy.authorize(workload, 3, 5, &[[1; 32], [2; 32]]),
            Err(KeylessError::WrongKeyEpoch)
        );
        assert_eq!(
            policy.authorize(workload, 5, 5, &[[1; 32], [2; 32], [3; 32]]),
            Err(KeylessError::InsufficientShares)
        );
        assert!(policy
            .authorize(workload, 5, 5, &[[4; 32], [5; 32]])
            .is_ok());
    }

    #[test]
    fn client_held_keys_have_no_consensus_authorization_path() {
        let workload = [0xC3; 32];
        let mut policy = KeylessConsensus::default();
        assert_eq!(
            policy.set_custody(workload, WorkloadKeyCustody::ClientHeld),
            Ok(())
        );
        assert_eq!(
            policy.authorize(workload, 0, 0, &[[7; 32]; 64]),
            Err(KeylessError::ClientAuthorizationRequired)
        );
    }
}
