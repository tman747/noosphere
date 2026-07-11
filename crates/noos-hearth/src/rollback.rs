//! Named H-* fallbacks. Every rollback preserves the ordinary base chain.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HearthMechanism {
    Hearth,
    Federate,
    Seed,
    Audit,
    Repair,
    Train,
    Relay,
    Pay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HearthFallbacks {
    pub base_chain_live: bool,
    pub work_loom_weight_cap: u16,
    pub slashable_hearth_jobs: bool,
    pub advisory_v0_v1_only: bool,
    pub wan_interactive_prohibited: bool,
    pub model_size_cap_steps_down: bool,
    pub single_source_large_model_allowed: bool,
    pub phone_exact_audits: bool,
    pub desktop_exact_audits: bool,
    pub minimum_stateful_availability_bps: u16,
    pub four_device_classes_open: bool,
    pub training_credit_enabled: bool,
    pub trusted_federation_training: bool,
    pub relay_tolerant_classes_only: bool,
    pub diversity_signals_consensus_weighted: bool,
    pub bond_only_influence: bool,
}

impl Default for HearthFallbacks {
    fn default() -> Self {
        Self {
            base_chain_live: true,
            work_loom_weight_cap: 0,
            slashable_hearth_jobs: false,
            advisory_v0_v1_only: true,
            wan_interactive_prohibited: true,
            model_size_cap_steps_down: false,
            single_source_large_model_allowed: false,
            phone_exact_audits: false,
            desktop_exact_audits: true,
            minimum_stateful_availability_bps: 9_000,
            four_device_classes_open: false,
            training_credit_enabled: false,
            trusted_federation_training: true,
            relay_tolerant_classes_only: false,
            diversity_signals_consensus_weighted: false,
            bond_only_influence: true,
        }
    }
}

#[must_use]
pub fn rollback(mechanism: HearthMechanism) -> HearthFallbacks {
    let mut fallback = HearthFallbacks::default();
    match mechanism {
        HearthMechanism::Hearth => {
            fallback.advisory_v0_v1_only = true;
            fallback.slashable_hearth_jobs = false;
        }
        HearthMechanism::Federate => {
            // Confirmation keeps the law; refutation retires and replaces the
            // registry row before this bit can change.
            fallback.wan_interactive_prohibited = true;
        }
        HearthMechanism::Seed => {
            fallback.model_size_cap_steps_down = true;
            fallback.single_source_large_model_allowed = false;
        }
        HearthMechanism::Audit => {
            fallback.phone_exact_audits = false;
            fallback.desktop_exact_audits = true;
        }
        HearthMechanism::Repair => {
            fallback.minimum_stateful_availability_bps = 9_000;
            fallback.four_device_classes_open = false;
        }
        HearthMechanism::Train => {
            fallback.training_credit_enabled = false;
            fallback.trusted_federation_training = true;
        }
        HearthMechanism::Relay => {
            fallback.relay_tolerant_classes_only = true;
        }
        HearthMechanism::Pay => {
            fallback.diversity_signals_consensus_weighted = false;
            fallback.bond_only_influence = true;
        }
    }
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_named_rollback_is_fail_closed_and_base_continuous() {
        for mechanism in [
            HearthMechanism::Hearth,
            HearthMechanism::Federate,
            HearthMechanism::Seed,
            HearthMechanism::Audit,
            HearthMechanism::Repair,
            HearthMechanism::Train,
            HearthMechanism::Relay,
            HearthMechanism::Pay,
        ] {
            let fallback = rollback(mechanism);
            assert!(fallback.base_chain_live);
            assert_eq!(fallback.work_loom_weight_cap, 0);
            assert!(!fallback.slashable_hearth_jobs);
            assert!(!fallback.training_credit_enabled);
            assert!(!fallback.diversity_signals_consensus_weighted);
            assert!(!fallback.single_source_large_model_allowed);
        }
    }

    #[test]
    fn mechanism_specific_fallbacks_match_the_frozen_ledger() {
        assert!(rollback(HearthMechanism::Seed).model_size_cap_steps_down);
        assert!(!rollback(HearthMechanism::Audit).phone_exact_audits);
        assert!(rollback(HearthMechanism::Audit).desktop_exact_audits);
        assert_eq!(
            rollback(HearthMechanism::Repair).minimum_stateful_availability_bps,
            9_000
        );
        assert!(rollback(HearthMechanism::Train).trusted_federation_training);
        assert!(rollback(HearthMechanism::Relay).relay_tolerant_classes_only);
        assert!(rollback(HearthMechanism::Pay).bond_only_influence);
    }
}
