//! Bounded governance and treasury state machine for application activation.
//!
//! Proposals snapshot voting power and one-hop delegation, reserve treasury
//! spend before voting, require quorum plus approval, wait through an explicit
//! timelock, and execute one closed effect. Emergency authority can only pause
//! execution for a bounded interval. Every treasury transition conserves the
//! opening balance plus recorded inflows.

use crate::Hash32;
use std::collections::{BTreeMap, BTreeSet};

pub const BPS: u16 = 10_000;
pub const MAX_GOVERNANCE_VOTERS: usize = 4_096;
pub const MAX_OPEN_PROPOSALS: usize = 1_024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceError {
    InvalidPolicy,
    InvalidAccount,
    DuplicateAccount,
    UnknownAccount,
    InvalidDelegation,
    DuplicateProposal,
    UnknownProposal,
    TooManyRecords,
    InvalidSchedule,
    InvalidAction,
    InsufficientTreasury,
    WrongStatus,
    VotingClosed,
    NoVotingPower,
    AlreadyVoted,
    QuorumNotMet,
    ApprovalNotMet,
    Timelocked,
    EmergencyPaused,
    Unauthorized,
    ArithmeticOverflow,
    ConservationFailure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernancePolicy {
    pub minimum_voting_blocks: u64,
    pub maximum_voting_blocks: u64,
    pub execution_delay_blocks: u64,
    pub quorum_bps: u16,
    pub approval_bps: u16,
    pub proposal_deposit: u128,
    pub maximum_treasury_spend: u128,
    pub minimum_treasury_reserve: u128,
    pub maximum_emergency_pause_blocks: u64,
}

impl GovernancePolicy {
    pub fn validate(self) -> Result<(), GovernanceError> {
        if self.minimum_voting_blocks == 0
            || self.maximum_voting_blocks < self.minimum_voting_blocks
            || self.execution_delay_blocks == 0
            || self.quorum_bps == 0
            || self.quorum_bps > BPS
            || self.approval_bps == 0
            || self.approval_bps > BPS
            || self.proposal_deposit == 0
            || self.maximum_treasury_spend == 0
            || self.maximum_emergency_pause_blocks == 0
        {
            return Err(GovernanceError::InvalidPolicy);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VotingAccount {
    pub account: Hash32,
    pub voting_power: u128,
    pub delegate: Option<Hash32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoteChoice {
    Approve,
    Reject,
    Abstain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceAction {
    TreasuryTransfer {
        recipient: Hash32,
        amount: u128,
    },
    ParameterUpdate {
        parameter_key: Hash32,
        value_root: Hash32,
    },
    PolicyUpdate {
        policy_root: Hash32,
    },
}

impl GovernanceAction {
    fn validate(self, policy: GovernancePolicy) -> Result<(), GovernanceError> {
        match self {
            Self::TreasuryTransfer { recipient, amount } => {
                if recipient == [0; 32] || amount == 0 || amount > policy.maximum_treasury_spend {
                    return Err(GovernanceError::InvalidAction);
                }
            }
            Self::ParameterUpdate {
                parameter_key,
                value_root,
            } => {
                if parameter_key == [0; 32] || value_root == [0; 32] {
                    return Err(GovernanceError::InvalidAction);
                }
            }
            Self::PolicyUpdate { policy_root } if policy_root == [0; 32] => {
                return Err(GovernanceError::InvalidAction);
            }
            Self::PolicyUpdate { .. } => {}
        }
        Ok(())
    }

    const fn treasury_amount(self) -> u128 {
        match self {
            Self::TreasuryTransfer { amount, .. } => amount,
            Self::ParameterUpdate { .. } | Self::PolicyUpdate { .. } => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalStatus {
    Voting,
    Defeated,
    Timelocked,
    Executed,
    Cancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteRecord {
    pub principal: Hash32,
    pub cast_by: Hash32,
    pub choice: VoteChoice,
    pub voting_power: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceProposal {
    pub proposal_id: Hash32,
    pub proposer: Hash32,
    pub action: GovernanceAction,
    pub deposit: u128,
    pub voting_start: u64,
    pub voting_end: u64,
    pub execute_after: u64,
    pub snapshot_total_power: u128,
    pub approve_power: u128,
    pub reject_power: u128,
    pub abstain_power: u128,
    pub status: ProposalStatus,
    pub deposit_refunded: bool,
    snapshot: BTreeMap<Hash32, VotingAccount>,
    votes: BTreeMap<Hash32, VoteRecord>,
}

impl GovernanceProposal {
    #[must_use]
    pub fn votes(&self) -> Vec<VoteRecord> {
        self.votes.values().copied().collect()
    }

    #[must_use]
    pub fn turnout(&self) -> u128 {
        self.approve_power
            .saturating_add(self.reject_power)
            .saturating_add(self.abstain_power)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreasuryState {
    pub opening_balance: u128,
    pub liquid_balance: u128,
    pub reserved_balance: u128,
    pub recorded_inflows: u128,
    pub executed_outflows: u128,
}

impl TreasuryState {
    pub fn new(opening_balance: u128) -> Self {
        Self {
            opening_balance,
            liquid_balance: opening_balance,
            reserved_balance: 0,
            recorded_inflows: 0,
            executed_outflows: 0,
        }
    }

    pub fn validate(self) -> Result<(), GovernanceError> {
        let sources = self
            .opening_balance
            .checked_add(self.recorded_inflows)
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        let uses = self
            .liquid_balance
            .checked_add(self.reserved_balance)
            .and_then(|value| value.checked_add(self.executed_outflows))
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        if sources != uses {
            return Err(GovernanceError::ConservationFailure);
        }
        Ok(())
    }

    pub fn record_inflow(&mut self, amount: u128) -> Result<(), GovernanceError> {
        if amount == 0 {
            return Err(GovernanceError::InvalidAction);
        }
        let mut candidate = *self;
        candidate.recorded_inflows = candidate
            .recorded_inflows
            .checked_add(amount)
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        candidate.liquid_balance = candidate
            .liquid_balance
            .checked_add(amount)
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    fn reserve(&mut self, amount: u128, floor: u128) -> Result<(), GovernanceError> {
        if amount == 0 {
            return Ok(());
        }
        let mut candidate = *self;
        let remaining = candidate
            .liquid_balance
            .checked_sub(amount)
            .ok_or(GovernanceError::InsufficientTreasury)?;
        if remaining < floor {
            return Err(GovernanceError::InsufficientTreasury);
        }
        candidate.liquid_balance = remaining;
        candidate.reserved_balance = candidate
            .reserved_balance
            .checked_add(amount)
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    fn release(&mut self, amount: u128) -> Result<(), GovernanceError> {
        if amount == 0 {
            return Ok(());
        }
        let mut candidate = *self;
        candidate.reserved_balance = candidate
            .reserved_balance
            .checked_sub(amount)
            .ok_or(GovernanceError::ConservationFailure)?;
        candidate.liquid_balance = candidate
            .liquid_balance
            .checked_add(amount)
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }

    fn execute(&mut self, amount: u128) -> Result<(), GovernanceError> {
        if amount == 0 {
            return Ok(());
        }
        let mut candidate = *self;
        candidate.reserved_balance = candidate
            .reserved_balance
            .checked_sub(amount)
            .ok_or(GovernanceError::ConservationFailure)?;
        candidate.executed_outflows = candidate
            .executed_outflows
            .checked_add(amount)
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        candidate.validate()?;
        *self = candidate;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GovernanceEffect {
    pub proposal_id: Hash32,
    pub action: GovernanceAction,
    pub executed_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoterExit {
    pub account: Hash32,
    pub returned_voting_power: u128,
    pub cleared_incoming_delegations: u32,
}

pub struct GovernanceBook {
    policy: GovernancePolicy,
    emergency_authority: Hash32,
    voters: BTreeMap<Hash32, VotingAccount>,
    proposals: BTreeMap<Hash32, GovernanceProposal>,
    treasury: TreasuryState,
    emergency_paused_until: u64,
    latest_emergency_evidence_root: Hash32,
}

impl GovernanceBook {
    pub fn new(
        policy: GovernancePolicy,
        emergency_authority: Hash32,
        treasury_opening_balance: u128,
    ) -> Result<Self, GovernanceError> {
        policy.validate()?;
        if emergency_authority == [0; 32]
            || treasury_opening_balance < policy.minimum_treasury_reserve
        {
            return Err(GovernanceError::InvalidPolicy);
        }
        let treasury = TreasuryState::new(treasury_opening_balance);
        treasury.validate()?;
        Ok(Self {
            policy,
            emergency_authority,
            voters: BTreeMap::new(),
            proposals: BTreeMap::new(),
            treasury,
            emergency_paused_until: 0,
            latest_emergency_evidence_root: [0; 32],
        })
    }

    #[must_use]
    pub const fn treasury(&self) -> TreasuryState {
        self.treasury
    }

    #[must_use]
    pub fn proposal(&self, proposal_id: &Hash32) -> Option<&GovernanceProposal> {
        self.proposals.get(proposal_id)
    }

    pub fn record_treasury_inflow(&mut self, amount: u128) -> Result<(), GovernanceError> {
        self.treasury.record_inflow(amount)
    }

    pub fn register_voter(
        &mut self,
        account: Hash32,
        voting_power: u128,
    ) -> Result<(), GovernanceError> {
        if account == [0; 32] || voting_power == 0 {
            return Err(GovernanceError::InvalidAccount);
        }
        if self.voters.contains_key(&account) {
            return Err(GovernanceError::DuplicateAccount);
        }
        if self.voters.len() >= MAX_GOVERNANCE_VOTERS {
            return Err(GovernanceError::TooManyRecords);
        }
        self.voters.insert(
            account,
            VotingAccount {
                account,
                voting_power,
                delegate: None,
            },
        );
        Ok(())
    }

    pub fn set_delegate(
        &mut self,
        owner: Hash32,
        delegate: Option<Hash32>,
    ) -> Result<(), GovernanceError> {
        if delegate == Some(owner) {
            return Err(GovernanceError::InvalidDelegation);
        }
        if let Some(target) = delegate {
            let target_account = self
                .voters
                .get(&target)
                .ok_or(GovernanceError::UnknownAccount)?;
            if target_account.delegate.is_some()
                || self
                    .voters
                    .values()
                    .any(|account| account.account == target && account.delegate == Some(owner))
            {
                return Err(GovernanceError::InvalidDelegation);
            }
        }
        let account = self
            .voters
            .get_mut(&owner)
            .ok_or(GovernanceError::UnknownAccount)?;
        account.delegate = delegate;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn open_proposal(
        &mut self,
        proposal_id: Hash32,
        proposer: Hash32,
        action: GovernanceAction,
        deposit: u128,
        voting_start: u64,
        voting_end: u64,
        execute_after: u64,
        current_height: u64,
    ) -> Result<(), GovernanceError> {
        if proposal_id == [0; 32]
            || !self.voters.contains_key(&proposer)
            || deposit != self.policy.proposal_deposit
        {
            return Err(GovernanceError::InvalidAccount);
        }
        action.validate(self.policy)?;
        let voting_blocks = voting_end
            .checked_sub(voting_start)
            .ok_or(GovernanceError::InvalidSchedule)?;
        let earliest_execution = voting_end
            .checked_add(self.policy.execution_delay_blocks)
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        if voting_start < current_height
            || voting_blocks < self.policy.minimum_voting_blocks
            || voting_blocks > self.policy.maximum_voting_blocks
            || execute_after < earliest_execution
        {
            return Err(GovernanceError::InvalidSchedule);
        }
        if self.proposals.contains_key(&proposal_id) {
            return Err(GovernanceError::DuplicateProposal);
        }
        let open = self
            .proposals
            .values()
            .filter(|proposal| {
                matches!(
                    proposal.status,
                    ProposalStatus::Voting | ProposalStatus::Timelocked
                )
            })
            .count();
        if open >= MAX_OPEN_PROPOSALS {
            return Err(GovernanceError::TooManyRecords);
        }
        let snapshot_total_power = self.voters.values().try_fold(0_u128, |total, account| {
            total
                .checked_add(account.voting_power)
                .ok_or(GovernanceError::ArithmeticOverflow)
        })?;
        if snapshot_total_power == 0 {
            return Err(GovernanceError::NoVotingPower);
        }
        self.treasury.reserve(
            action.treasury_amount(),
            self.policy.minimum_treasury_reserve,
        )?;
        self.proposals.insert(
            proposal_id,
            GovernanceProposal {
                proposal_id,
                proposer,
                action,
                deposit,
                voting_start,
                voting_end,
                execute_after,
                snapshot_total_power,
                approve_power: 0,
                reject_power: 0,
                abstain_power: 0,
                status: ProposalStatus::Voting,
                deposit_refunded: false,
                snapshot: self.voters.clone(),
                votes: BTreeMap::new(),
            },
        );
        Ok(())
    }

    pub fn cancel_proposal(
        &mut self,
        proposal_id: Hash32,
        proposer: Hash32,
        current_height: u64,
    ) -> Result<(), GovernanceError> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovernanceError::UnknownProposal)?;
        if proposal.proposer != proposer {
            return Err(GovernanceError::Unauthorized);
        }
        if proposal.status != ProposalStatus::Voting || current_height >= proposal.voting_start {
            return Err(GovernanceError::WrongStatus);
        }
        proposal.status = ProposalStatus::Cancelled;
        proposal.deposit_refunded = true;
        self.treasury.release(proposal.action.treasury_amount())
    }

    pub fn cast_vote(
        &mut self,
        proposal_id: Hash32,
        cast_by: Hash32,
        choice: VoteChoice,
        current_height: u64,
    ) -> Result<u128, GovernanceError> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovernanceError::UnknownProposal)?;
        if proposal.status != ProposalStatus::Voting
            || current_height < proposal.voting_start
            || current_height >= proposal.voting_end
        {
            return Err(GovernanceError::VotingClosed);
        }
        let principals = proposal
            .snapshot
            .values()
            .filter(|account| account.delegate.unwrap_or(account.account) == cast_by)
            .map(|account| account.account)
            .collect::<Vec<_>>();
        if principals.is_empty() {
            return Err(GovernanceError::NoVotingPower);
        }
        if principals
            .iter()
            .all(|principal| proposal.votes.contains_key(principal))
        {
            return Err(GovernanceError::AlreadyVoted);
        }
        let mut cast_power = 0_u128;
        for principal in principals {
            if proposal.votes.contains_key(&principal) {
                continue;
            }
            let account = proposal
                .snapshot
                .get(&principal)
                .ok_or(GovernanceError::UnknownAccount)?;
            cast_power = cast_power
                .checked_add(account.voting_power)
                .ok_or(GovernanceError::ArithmeticOverflow)?;
            proposal.votes.insert(
                principal,
                VoteRecord {
                    principal,
                    cast_by,
                    choice,
                    voting_power: account.voting_power,
                },
            );
        }
        let tally = match choice {
            VoteChoice::Approve => &mut proposal.approve_power,
            VoteChoice::Reject => &mut proposal.reject_power,
            VoteChoice::Abstain => &mut proposal.abstain_power,
        };
        *tally = tally
            .checked_add(cast_power)
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        Ok(cast_power)
    }

    pub fn close_proposal(
        &mut self,
        proposal_id: Hash32,
        current_height: u64,
    ) -> Result<ProposalStatus, GovernanceError> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovernanceError::UnknownProposal)?;
        if proposal.status != ProposalStatus::Voting || current_height < proposal.voting_end {
            return Err(GovernanceError::WrongStatus);
        }
        let turnout = proposal.turnout();
        let quorum_met = ratio_at_least(
            turnout,
            proposal.snapshot_total_power,
            self.policy.quorum_bps,
        )?;
        let decisive = proposal
            .approve_power
            .checked_add(proposal.reject_power)
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        let approval_met = decisive > 0
            && ratio_at_least(proposal.approve_power, decisive, self.policy.approval_bps)?;
        proposal.deposit_refunded = true;
        if quorum_met && approval_met {
            proposal.status = ProposalStatus::Timelocked;
        } else {
            proposal.status = ProposalStatus::Defeated;
            self.treasury.release(proposal.action.treasury_amount())?;
        }
        Ok(proposal.status)
    }

    pub fn execute_proposal(
        &mut self,
        proposal_id: Hash32,
        current_height: u64,
    ) -> Result<GovernanceEffect, GovernanceError> {
        if current_height < self.emergency_paused_until {
            return Err(GovernanceError::EmergencyPaused);
        }
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovernanceError::UnknownProposal)?;
        if proposal.status != ProposalStatus::Timelocked {
            return Err(GovernanceError::WrongStatus);
        }
        if current_height < proposal.execute_after {
            return Err(GovernanceError::Timelocked);
        }
        self.treasury.execute(proposal.action.treasury_amount())?;
        proposal.status = ProposalStatus::Executed;
        Ok(GovernanceEffect {
            proposal_id,
            action: proposal.action,
            executed_at: current_height,
        })
    }

    pub fn emergency_pause(
        &mut self,
        authority: Hash32,
        current_height: u64,
        paused_until: u64,
        evidence_root: Hash32,
    ) -> Result<(), GovernanceError> {
        let maximum = current_height
            .checked_add(self.policy.maximum_emergency_pause_blocks)
            .ok_or(GovernanceError::ArithmeticOverflow)?;
        if authority != self.emergency_authority
            || evidence_root == [0; 32]
            || paused_until <= current_height
            || paused_until > maximum
            || paused_until <= self.emergency_paused_until
        {
            return Err(GovernanceError::Unauthorized);
        }
        self.emergency_paused_until = paused_until;
        self.latest_emergency_evidence_root = evidence_root;
        Ok(())
    }

    pub fn exit_voter(&mut self, account: Hash32) -> Result<VoterExit, GovernanceError> {
        let removed = self
            .voters
            .remove(&account)
            .ok_or(GovernanceError::UnknownAccount)?;
        let mut cleared = 0_u32;
        for voter in self.voters.values_mut() {
            if voter.delegate == Some(account) {
                voter.delegate = None;
                cleared = cleared
                    .checked_add(1)
                    .ok_or(GovernanceError::ArithmeticOverflow)?;
            }
        }
        Ok(VoterExit {
            account,
            returned_voting_power: removed.voting_power,
            cleared_incoming_delegations: cleared,
        })
    }

    pub fn validate(&self) -> Result<(), GovernanceError> {
        self.policy.validate()?;
        self.treasury.validate()?;
        let ids = self
            .proposals
            .values()
            .map(|proposal| proposal.proposal_id)
            .collect::<BTreeSet<_>>();
        if ids.len() != self.proposals.len()
            || self
                .proposals
                .iter()
                .any(|(key, proposal)| *key != proposal.proposal_id)
        {
            return Err(GovernanceError::ConservationFailure);
        }
        let reserved = self
            .proposals
            .values()
            .filter(|proposal| {
                matches!(
                    proposal.status,
                    ProposalStatus::Voting | ProposalStatus::Timelocked
                )
            })
            .try_fold(0_u128, |total, proposal| {
                total
                    .checked_add(proposal.action.treasury_amount())
                    .ok_or(GovernanceError::ArithmeticOverflow)
            })?;
        if reserved != self.treasury.reserved_balance {
            return Err(GovernanceError::ConservationFailure);
        }
        Ok(())
    }
}

fn ratio_at_least(
    numerator: u128,
    denominator: u128,
    threshold_bps: u16,
) -> Result<bool, GovernanceError> {
    if denominator == 0 {
        return Ok(false);
    }
    let left = numerator
        .checked_mul(u128::from(BPS))
        .ok_or(GovernanceError::ArithmeticOverflow)?;
    let right = denominator
        .checked_mul(u128::from(threshold_bps))
        .ok_or(GovernanceError::ArithmeticOverflow)?;
    Ok(left >= right)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(value: u8) -> Hash32 {
        [value; 32]
    }

    fn policy() -> GovernancePolicy {
        GovernancePolicy {
            minimum_voting_blocks: 10,
            maximum_voting_blocks: 100,
            execution_delay_blocks: 20,
            quorum_bps: 5_000,
            approval_bps: 6_000,
            proposal_deposit: 100,
            maximum_treasury_spend: 10_000,
            minimum_treasury_reserve: 1_000,
            maximum_emergency_pause_blocks: 50,
        }
    }

    fn book() -> GovernanceBook {
        let mut book = GovernanceBook::new(policy(), h(99), 20_000).unwrap();
        book.register_voter(h(1), 40).unwrap();
        book.register_voter(h(2), 30).unwrap();
        book.register_voter(h(3), 30).unwrap();
        book
    }

    #[test]
    fn failed_inflow_and_duplicate_voter_leave_state_unchanged() {
        let mut treasury = TreasuryState::new(u128::MAX);
        assert_eq!(
            treasury.record_inflow(1),
            Err(GovernanceError::ArithmeticOverflow)
        );
        assert_eq!(treasury, TreasuryState::new(u128::MAX));

        let mut book = book();
        assert_eq!(
            book.register_voter(h(1), 1),
            Err(GovernanceError::DuplicateAccount)
        );
        assert_eq!(book.voters.get(&h(1)).unwrap().voting_power, 40);
    }

    #[test]
    fn delegated_vote_timelock_and_treasury_transfer_conserve() {
        let mut book = book();
        book.set_delegate(h(2), Some(h(1))).unwrap();
        book.open_proposal(
            h(10),
            h(1),
            GovernanceAction::TreasuryTransfer {
                recipient: h(20),
                amount: 5_000,
            },
            100,
            10,
            20,
            40,
            1,
        )
        .unwrap();
        assert_eq!(book.treasury().liquid_balance, 15_000);
        assert_eq!(book.treasury().reserved_balance, 5_000);
        assert_eq!(book.cast_vote(h(10), h(1), VoteChoice::Approve, 10), Ok(70));
        assert_eq!(book.cast_vote(h(10), h(3), VoteChoice::Reject, 11), Ok(30));
        assert_eq!(
            book.close_proposal(h(10), 20),
            Ok(ProposalStatus::Timelocked)
        );
        assert_eq!(
            book.execute_proposal(h(10), 39),
            Err(GovernanceError::Timelocked)
        );
        let effect = book.execute_proposal(h(10), 40).unwrap();
        assert_eq!(effect.executed_at, 40);
        assert_eq!(book.treasury().executed_outflows, 5_000);
        assert_eq!(book.treasury().reserved_balance, 0);
        book.validate().unwrap();
    }

    #[test]
    fn defeat_cancel_and_oversubscription_release_or_refuse_reserves() {
        let mut book = book();
        book.open_proposal(
            h(10),
            h(1),
            GovernanceAction::TreasuryTransfer {
                recipient: h(20),
                amount: 9_001,
            },
            100,
            10,
            20,
            40,
            1,
        )
        .unwrap();
        assert_eq!(
            book.open_proposal(
                h(11),
                h(2),
                GovernanceAction::TreasuryTransfer {
                    recipient: h(21),
                    amount: 10_000,
                },
                100,
                10,
                20,
                40,
                1,
            ),
            Err(GovernanceError::InsufficientTreasury)
        );
        book.cast_vote(h(10), h(1), VoteChoice::Reject, 10).unwrap();
        assert_eq!(book.close_proposal(h(10), 20), Ok(ProposalStatus::Defeated));
        assert_eq!(book.treasury().reserved_balance, 0);
        assert_eq!(book.treasury().liquid_balance, 20_000);

        book.open_proposal(
            h(12),
            h(2),
            GovernanceAction::PolicyUpdate { policy_root: h(30) },
            100,
            30,
            40,
            60,
            20,
        )
        .unwrap();
        book.cancel_proposal(h(12), h(2), 29).unwrap();
        assert_eq!(
            book.proposal(&h(12)).unwrap().status,
            ProposalStatus::Cancelled
        );
        book.validate().unwrap();
    }

    #[test]
    fn emergency_authority_only_pauses_and_automatically_expires() {
        let mut book = book();
        book.open_proposal(
            h(10),
            h(1),
            GovernanceAction::ParameterUpdate {
                parameter_key: h(21),
                value_root: h(22),
            },
            100,
            10,
            20,
            40,
            1,
        )
        .unwrap();
        book.cast_vote(h(10), h(1), VoteChoice::Approve, 10)
            .unwrap();
        book.cast_vote(h(10), h(2), VoteChoice::Approve, 10)
            .unwrap();
        book.close_proposal(h(10), 20).unwrap();
        assert_eq!(
            book.emergency_pause(h(98), 30, 50, h(60)),
            Err(GovernanceError::Unauthorized)
        );
        book.emergency_pause(h(99), 30, 50, h(60)).unwrap();
        assert_eq!(
            book.execute_proposal(h(10), 40),
            Err(GovernanceError::EmergencyPaused)
        );
        book.execute_proposal(h(10), 50).unwrap();
    }

    #[test]
    fn snapshot_vote_survives_exit_without_double_vote_or_delegation_cycle() {
        let mut book = book();
        book.set_delegate(h(2), Some(h(1))).unwrap();
        assert_eq!(
            book.set_delegate(h(1), Some(h(2))),
            Err(GovernanceError::InvalidDelegation)
        );
        book.open_proposal(
            h(10),
            h(1),
            GovernanceAction::PolicyUpdate { policy_root: h(30) },
            100,
            10,
            20,
            40,
            1,
        )
        .unwrap();
        let exit = book.exit_voter(h(2)).unwrap();
        assert_eq!(exit.returned_voting_power, 30);
        assert_eq!(book.cast_vote(h(10), h(1), VoteChoice::Approve, 10), Ok(70));
        assert_eq!(
            book.cast_vote(h(10), h(1), VoteChoice::Reject, 11),
            Err(GovernanceError::AlreadyVoted)
        );
    }

    #[test]
    fn malformed_schedule_policy_and_treasury_floor_fail_closed() {
        let mut book = book();
        assert_eq!(
            book.open_proposal(
                h(10),
                h(1),
                GovernanceAction::TreasuryTransfer {
                    recipient: h(2),
                    amount: 19_001,
                },
                100,
                10,
                20,
                40,
                1,
            ),
            Err(GovernanceError::InvalidAction)
        );
        assert_eq!(
            book.open_proposal(
                h(11),
                h(1),
                GovernanceAction::PolicyUpdate { policy_root: h(3) },
                100,
                10,
                19,
                40,
                1,
            ),
            Err(GovernanceError::InvalidSchedule)
        );
    }
}
