//! Deterministic adversarial application-economy campaign.
//!
//! The campaign exercises the real governance-adjacent primitives rather than
//! source-text assertions: marketplace conservation, oracle divergence,
//! liquidation cascades, thin redemption liquidity, explicit bad debt,
//! fail-closed bridge review, signed review integrity, wallet identity review,
//! incident exits, and capped-value rejection.

use crate::marketplace::{Marketplace, MarketplaceError, MarketplacePolicy, UniqueAsset};
use crate::review_gate::{
    ApplicationOperation, ApplicationReviewGate, GateDecision, ReviewAttestation, ReviewGateError,
    ReviewTarget, ReviewedSurface,
};
use crate::Hash32;
use ed25519_dalek::SigningKey;
use noos_stable_operator::oracle_controls::{
    OracleControlError, OracleControlPlane, OracleControlPolicy, RejectionReason, ReporterIdentity,
    ReporterSet, UpdateOutcome,
};
use noos_stable_safety::v2::{
    StableDebtPositionV2, StableReservePolicyV2, StableReserveStateV2, StableV2Error, PRICE_SCALE,
};
use noos_wallet::{
    balance as wallet_balance, select_notes, IdentityGate, NodeIdentity, Note, WalletError,
    API_VERSION,
};
use serde::Serialize;
use std::collections::BTreeMap;

pub const CAMPAIGN_SCHEMA: &str = "noos/application-economy-adversarial-campaign/v1";
pub const CAMPAIGN_IDS: [&str; 10] = [
    "conservation",
    "oracle_divergence",
    "liquidation_cascade",
    "thin_redemption_liquidity",
    "explicit_bad_debt",
    "bridge_reconciliation",
    "signed_review_integrity",
    "wallet_review",
    "incident_exit_continuity",
    "capped_value",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CampaignError {
    InvalidSourceRevision,
    Invariant(&'static str),
    Marketplace(MarketplaceError),
    Oracle(OracleControlError),
    Stable(StableV2Error),
    Review(ReviewGateError),
    Wallet(WalletError),
}

impl From<MarketplaceError> for CampaignError {
    fn from(value: MarketplaceError) -> Self {
        Self::Marketplace(value)
    }
}

impl From<OracleControlError> for CampaignError {
    fn from(value: OracleControlError) -> Self {
        Self::Oracle(value)
    }
}

impl From<StableV2Error> for CampaignError {
    fn from(value: StableV2Error) -> Self {
        Self::Stable(value)
    }
}

impl From<ReviewGateError> for CampaignError {
    fn from(value: ReviewGateError) -> Self {
        Self::Review(value)
    }
}

impl From<WalletError> for CampaignError {
    fn from(value: WalletError) -> Self {
        Self::Wallet(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CampaignStep {
    pub campaign_id: String,
    pub verdict: String,
    pub metrics: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApplicationEconomyCampaignReport {
    pub schema: String,
    pub source_revision: String,
    pub seed: u64,
    pub production_authorized: bool,
    pub promotion_effect: String,
    pub verdict: String,
    pub steps: Vec<CampaignStep>,
}

#[derive(Clone, Copy)]
struct CampaignIds {
    seller: Hash32,
    buyer: Hash32,
    payment_asset: Hash32,
    treasury: Hash32,
    publisher: Hash32,
    royalty: Hash32,
}

#[derive(Clone, Copy)]
struct StableFixture {
    policy: StableReservePolicyV2,
}

impl StableFixture {
    const fn new() -> Self {
        Self {
            policy: StableReservePolicyV2 {
                liquidation_threshold_bps: 7_500,
                liquidation_bonus_bps: 500,
                psm_fee_bps: 20,
                max_psm_debt: 200_000,
                max_psm_mint_per_epoch: 100_000,
                max_psm_redeem_per_epoch: 100_000,
                max_backstop_burn_per_epoch: 50_000,
                max_uncovered_bad_debt: 500_000,
                epoch_blocks: 100,
            },
        }
    }
}

pub fn run_application_economy_campaign(
    source_revision: &str,
    seed: u64,
) -> Result<ApplicationEconomyCampaignReport, CampaignError> {
    if source_revision.len() != 40
        || !source_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CampaignError::InvalidSourceRevision);
    }
    let ids = CampaignIds {
        seller: derive_id(seed, b"seller"),
        buyer: derive_id(seed, b"buyer"),
        payment_asset: derive_id(seed, b"payment"),
        treasury: derive_id(seed, b"treasury"),
        publisher: derive_id(seed, b"publisher"),
        royalty: derive_id(seed, b"royalty"),
    };
    let stable = StableFixture::new();
    let steps = vec![
        conservation_campaign(ids)?,
        oracle_divergence_campaign(seed)?,
        liquidation_cascade_campaign(stable)?,
        thin_liquidity_campaign(stable)?,
        explicit_bad_debt_campaign(stable)?,
        bridge_reconciliation_campaign()?,
        signed_review_integrity_campaign(seed, source_revision)?,
        wallet_review_campaign(seed)?,
        incident_exit_campaign(stable)?,
        capped_value_campaign(ids, stable)?,
    ];
    if steps.len() != CAMPAIGN_IDS.len()
        || steps
            .iter()
            .zip(CAMPAIGN_IDS)
            .any(|(step, expected)| step.campaign_id != expected || step.verdict != "PASS")
    {
        return Err(CampaignError::Invariant("campaign coverage mismatch"));
    }
    Ok(ApplicationEconomyCampaignReport {
        schema: CAMPAIGN_SCHEMA.to_owned(),
        source_revision: source_revision.to_owned(),
        seed,
        production_authorized: false,
        promotion_effect: "NONE".to_owned(),
        verdict: "PASS".to_owned(),
        steps,
    })
}

fn conservation_campaign(ids: CampaignIds) -> Result<CampaignStep, CampaignError> {
    let mut market = Marketplace::new(MarketplacePolicy {
        treasury: ids.treasury,
        protocol_fee_bps: 250,
        maximum_price: 1_000_000,
        maximum_listing_blocks: 100,
    })?;
    let asset = UniqueAsset::new(
        ids.publisher,
        derive_id(1, b"collection"),
        derive_id(1, b"content"),
        derive_id(1, b"metadata"),
        1,
        ids.royalty,
        1_000,
        ids.seller,
    )?;
    let asset_id = market.register(asset)?;
    market.deposit(ids.buyer, ids.payment_asset, 100_000)?;
    let listing = market.list(asset_id, ids.seller, ids.payment_asset, 100_000, 10, 100)?;
    let settlement = market.buy(listing, ids.buyer, ids.payment_asset, 100_000, 50)?;
    market.validate()?;
    require(
        settlement.seller_proceeds + settlement.royalty_amount + settlement.protocol_fee
            == settlement.gross_price,
        "market distribution did not conserve",
    )?;
    let report = market.payment_conservation(ids.payment_asset)?;
    report.validate()?;
    Ok(step(
        "conservation",
        [
            ("gross_price", settlement.gross_price.to_string()),
            ("internal_balances", report.internal_balances.to_string()),
            (
                "ownership_nonce",
                settlement.ownership.next_nonce.to_string(),
            ),
        ],
    ))
}

fn oracle_divergence_campaign(seed: u64) -> Result<CampaignStep, CampaignError> {
    let policy = OracleControlPolicy {
        max_report_age_blocks: 10,
        max_last_good_age_blocks: 100,
        max_deviation_bps: 500,
        max_confidence_bps: 100,
        operation_buffer_bps: 200,
        minimum_rotation_delay_blocks: 20,
    };
    let reporters = reporter_set(seed, 1);
    let mut plane = OracleControlPlane::new(policy, reporters)?;
    for (index, price) in [1_000_u128, 1_010, 990].into_iter().enumerate() {
        let outcome =
            plane.submit_report(reporters.members[index].reporter, price, 10, 1, 10, 10)?;
        if index == 2 {
            require(
                outcome
                    == UpdateOutcome::QuorumAccepted {
                        median_price_q9: 1_000,
                    },
                "oracle quorum median mismatch",
            )?;
        }
    }
    plane.submit_report(reporters.members[0].reporter, 2_000, 10, 2, 11, 11)?;
    let rejected = plane.submit_report(reporters.members[1].reporter, 2_000, 10, 2, 11, 11);
    require(
        rejected == Err(OracleControlError::ExcessiveDeviation),
        "divergent quorum was accepted",
    )?;
    let monitor = plane.rejected_updates();
    require(
        monitor.count(RejectionReason::ExcessiveDeviation) == 1,
        "divergence rejection was not monitored",
    )?;
    Ok(step(
        "oracle_divergence",
        [
            (
                "last_good_price_q9",
                plane.last_good().unwrap().price_q9.to_string(),
            ),
            ("rejected_updates", monitor.total.to_string()),
            ("divergence_rejections", "1".to_owned()),
        ],
    ))
}

fn liquidation_cascade_campaign(stable: StableFixture) -> Result<CampaignStep, CampaignError> {
    let mut state = StableReserveStateV2::default();
    state.fund_backstop(stable.policy, 50_000)?;
    let mut total_burned = 0_u128;
    let mut total_bad_debt = 0_u128;
    for _ in 0..3 {
        let result = state.backstop_liquidate(
            stable.policy,
            StableDebtPositionV2 {
                collateral: 20_000,
                debt: 40_000,
            },
            PRICE_SCALE,
            1,
        )?;
        total_burned = total_burned
            .checked_add(result.stable_burned)
            .ok_or(CampaignError::Invariant("cascade burn overflow"))?;
        total_bad_debt = total_bad_debt
            .checked_add(result.newly_uncovered_bad_debt)
            .ok_or(CampaignError::Invariant("cascade bad debt overflow"))?;
    }
    state.validate(stable.policy)?;
    require(total_burned == 50_000, "backstop cap was not enforced")?;
    require(total_bad_debt == 70_000, "cascade bad debt was hidden")?;
    require(
        state.seized_collateral_inventory == 60_000 && state.psm_collateral_inventory == 0,
        "liquidation collateral contaminated redemption inventory",
    )?;
    Ok(step(
        "liquidation_cascade",
        [
            ("stable_burned", total_burned.to_string()),
            ("uncovered_bad_debt", total_bad_debt.to_string()),
            (
                "seized_collateral",
                state.seized_collateral_inventory.to_string(),
            ),
        ],
    ))
}

fn thin_liquidity_campaign(stable: StableFixture) -> Result<CampaignStep, CampaignError> {
    let mut state = StableReserveStateV2::default();
    state.psm_mint(stable.policy, 10_000, PRICE_SCALE, 1)?;
    let before = state;
    let result = state.psm_redeem(stable.policy, 20_000, PRICE_SCALE, 2);
    require(
        result == Err(StableV2Error::InsufficientRedemptionInventory),
        "thin redemption inventory did not fail closed",
    )?;
    require(
        state == before,
        "thin-liquidity rejection mutated reserve state",
    )?;
    Ok(step(
        "thin_redemption_liquidity",
        [
            ("psm_debt", state.psm_debt.to_string()),
            (
                "collateral_inventory",
                state.psm_collateral_inventory.to_string(),
            ),
            ("rejected_redemption", "true".to_owned()),
        ],
    ))
}

fn explicit_bad_debt_campaign(stable: StableFixture) -> Result<CampaignStep, CampaignError> {
    let mut state = StableReserveStateV2::default();
    state.fund_backstop(stable.policy, 10_000)?;
    let liquidation = state.backstop_liquidate(
        stable.policy,
        StableDebtPositionV2 {
            collateral: 20_000,
            debt: 60_000,
        },
        PRICE_SCALE,
        1,
    )?;
    require(
        liquidation.newly_uncovered_bad_debt == 50_000,
        "reserve shortfall was not explicit",
    )?;
    state.fund_backstop(stable.policy, 50_000)?;
    state.resolve_bad_debt(stable.policy, 50_000, 100)?;
    state.validate(stable.policy)?;
    require(
        state.uncovered_bad_debt == 0,
        "funded bad debt did not resolve",
    )?;
    Ok(step(
        "explicit_bad_debt",
        [
            ("initial_shortfall", "50000".to_owned()),
            ("remaining_bad_debt", state.uncovered_bad_debt.to_string()),
            (
                "backstop_burned_total",
                state.backstop_stable_burned_total.to_string(),
            ),
        ],
    ))
}

fn bridge_reconciliation_campaign() -> Result<CampaignStep, CampaignError> {
    let gate = ApplicationReviewGate::default();
    let revision = [1; 32];
    let lock = gate.authorize_operation(ApplicationOperation::BridgeLock, revision, 1);
    let mint = gate.authorize_operation(ApplicationOperation::BridgeMint, revision, 1);
    let exit = gate.authorize_operation(ApplicationOperation::BridgeExit, revision, 1);
    require(
        lock == GateDecision::MissingTarget && mint == GateDecision::MissingTarget,
        "unreviewed bridge risk path opened",
    )?;
    require(
        exit == GateDecision::ExitAllowedWhileClosed,
        "bridge exit was not preserved",
    )?;
    Ok(step(
        "bridge_reconciliation",
        [
            ("locked_value", "0".to_owned()),
            ("minted_value", "0".to_owned()),
            ("unreconciled_exposure", "0".to_owned()),
        ],
    ))
}

fn signed_review_integrity_campaign(
    seed: u64,
    source_revision: &str,
) -> Result<CampaignStep, CampaignError> {
    let mut revision = [0_u8; 32];
    revision[..20].copy_from_slice(&decode_revision(source_revision)?);
    revision[20..].copy_from_slice(&derive_id(seed, b"revision-tail")[20..]);
    let target = ReviewTarget {
        surface: ReviewedSurface::Lending,
        revision,
        implementation_root: derive_id(seed, b"implementation"),
        design_roots: [
            derive_id(seed, b"oracle"),
            derive_id(seed, b"liquidation"),
            derive_id(seed, b"cross-chain"),
            derive_id(seed, b"exposure"),
            derive_id(seed, b"failure"),
            derive_id(seed, b"emergency"),
        ],
        activation_not_before: 20,
        expires_at: 200,
        minimum_independent_organizations: 2,
    };
    let mut gate = ApplicationReviewGate::default();
    gate.install_target(target, 1)?;
    for (key_seed, organization) in [(31_u8, 41_u8), (32, 42)] {
        let review = ReviewAttestation::sign(
            target.target_root(),
            &SigningKey::from_bytes(&[key_seed; 32]),
            [organization; 32],
            ReviewedSurface::Lending.required_scopes(),
            [key_seed.wrapping_add(100); 32],
            0,
            0,
            true,
            10,
            190,
        );
        gate.submit_attestation(ReviewedSurface::Lending, review, 10)?;
    }
    require(
        gate.decision(ReviewedSurface::Lending, revision, 20) == GateDecision::Ready,
        "independent signed reviews did not open exact target",
    )?;
    let mut tampered = ReviewAttestation::sign(
        target.target_root(),
        &SigningKey::from_bytes(&[33; 32]),
        [43; 32],
        ReviewedSurface::Lending.required_scopes(),
        [44; 32],
        0,
        0,
        true,
        10,
        190,
    );
    tampered.findings_root = [99; 32];
    require(
        gate.submit_attestation(ReviewedSurface::Lending, tampered, 10)
            == Err(ReviewGateError::InvalidSignature),
        "tampered review signature was accepted",
    )?;
    Ok(step(
        "signed_review_integrity",
        [
            ("independent_organizations", "2".to_owned()),
            ("tampered_reviews_rejected", "1".to_owned()),
            ("exact_revision_ready", "true".to_owned()),
        ],
    ))
}

fn wallet_review_campaign(seed: u64) -> Result<CampaignStep, CampaignError> {
    let expected = NodeIdentity {
        chain_id: derive_id(seed, b"wallet-chain"),
        genesis_hash: derive_id(seed, b"wallet-genesis"),
        api_version: API_VERSION,
    };
    let notes = [
        Note {
            id: derive_id(seed, b"wallet-note-1"),
            amount: 50,
        },
        Note {
            id: derive_id(seed, b"wallet-note-2"),
            amount: 100,
        },
    ];
    let mut gate = IdentityGate::new(expected);
    require(
        wallet_balance(&gate, &notes) == Err(WalletError::HandshakeRequired),
        "wallet read bypassed identity handshake",
    )?;
    let mut wrong = expected;
    wrong.genesis_hash = derive_id(seed, b"wrong-wallet-genesis");
    require(
        gate.verify(wrong) == Err(WalletError::WrongProtocolIdentity),
        "wallet accepted wrong protocol identity",
    )?;
    require(
        wallet_balance(&gate, &notes) == Err(WalletError::HandshakeRequired),
        "failed wallet identity left gate open",
    )?;
    gate.verify(expected)?;
    let selection = select_notes(&gate, &notes, 120)?;
    require(
        selection.total == 150 && selection.change == 30,
        "wallet selection changed after exact identity review",
    )?;
    Ok(step(
        "wallet_review",
        [
            ("wrong_identities_rejected", "1".to_owned()),
            ("selected_total", selection.total.to_string()),
            ("change", selection.change.to_string()),
        ],
    ))
}

fn incident_exit_campaign(stable: StableFixture) -> Result<CampaignStep, CampaignError> {
    let mut state = StableReserveStateV2::default();
    let mint = state.psm_mint(stable.policy, 10_000, PRICE_SCALE, 1)?;
    state.set_risk_increasing_pause(true);
    require(
        state.psm_mint(stable.policy, 1_000, PRICE_SCALE, 2)
            == Err(StableV2Error::RiskIncreasingPaused),
        "incident pause allowed risk-increasing mint",
    )?;
    let redemption = state.psm_redeem(stable.policy, mint.stable_to_user, PRICE_SCALE, 2)?;
    let mut gate = ApplicationReviewGate::default();
    gate.emergency_disable(ReviewedSurface::Lending);
    require(
        gate.authorize_operation(ApplicationOperation::LendingBorrow, [1; 32], 2)
            == GateDecision::MissingTarget,
        "missing review target did not close borrow",
    )?;
    require(
        gate.authorize_operation(ApplicationOperation::LendingRepay, [1; 32], 2)
            == GateDecision::ExitAllowedWhileClosed,
        "incident gate closed repayment",
    )?;
    Ok(step(
        "incident_exit_continuity",
        [
            ("risk_mint_blocked", "true".to_owned()),
            (
                "redemption_collateral_out",
                redemption.collateral_to_user.to_string(),
            ),
            ("repayment_class_open", "true".to_owned()),
        ],
    ))
}

fn capped_value_campaign(
    ids: CampaignIds,
    stable: StableFixture,
) -> Result<CampaignStep, CampaignError> {
    let mut state = StableReserveStateV2::default();
    let mut capped_policy = stable.policy;
    capped_policy.max_psm_debt = 10_000;
    capped_policy.max_psm_mint_per_epoch = 10_000;
    state.psm_mint(capped_policy, 10_000, PRICE_SCALE, 1)?;
    let before = state;
    require(
        state.psm_mint(capped_policy, 1, PRICE_SCALE, 2) == Err(StableV2Error::CapExceeded),
        "stable value cap did not reject",
    )?;
    require(state == before, "stable value cap rejection mutated state")?;

    let mut market = Marketplace::new(MarketplacePolicy {
        treasury: ids.treasury,
        protocol_fee_bps: 250,
        maximum_price: 1_000,
        maximum_listing_blocks: 100,
    })?;
    let asset = UniqueAsset::new(
        ids.publisher,
        derive_id(2, b"collection"),
        derive_id(2, b"content"),
        derive_id(2, b"metadata"),
        2,
        ids.royalty,
        100,
        ids.seller,
    )?;
    let asset_id = market.register(asset)?;
    require(
        market.list(asset_id, ids.seller, ids.payment_asset, 1_001, 1, 10)
            == Err(MarketplaceError::InvalidListing),
        "market value cap did not reject",
    )?;
    require(
        market.ownership_history(&asset_id).is_empty(),
        "market cap rejection changed ownership",
    )?;
    Ok(step(
        "capped_value",
        [
            ("stable_cap", "10000".to_owned()),
            ("market_price_cap", "1000".to_owned()),
            ("failed_mutations", "0".to_owned()),
        ],
    ))
}

fn reporter_set(seed: u64, epoch: u64) -> ReporterSet {
    let member = |index: u8, provider: u8, region: u8| ReporterIdentity {
        reporter: derive_id(seed, &[b'r', index]),
        operator: derive_id(seed, &[b'o', index]),
        provider: derive_id(seed, &[b'p', provider]),
        region: derive_id(seed, &[b'g', region]),
    };
    ReporterSet {
        epoch,
        members: [
            member(1, 1, 1),
            member(2, 1, 1),
            member(3, 2, 2),
            member(4, 2, 2),
            member(5, 3, 3),
        ],
    }
}

fn derive_id(seed: u64, label: &[u8]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"NOOS/APPLICATION-ECONOMY-CAMPAIGN/ID/V1\0");
    hasher.update(&seed.to_le_bytes());
    hasher.update(label);
    *hasher.finalize().as_bytes()
}

fn decode_revision(source_revision: &str) -> Result<[u8; 20], CampaignError> {
    let mut decoded = [0_u8; 20];
    for (index, pair) in source_revision.as_bytes().chunks_exact(2).enumerate() {
        decoded[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    Ok(decoded)
}

fn hex_nibble(value: u8) -> Result<u8, CampaignError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(CampaignError::InvalidSourceRevision),
    }
}

fn require(condition: bool, message: &'static str) -> Result<(), CampaignError> {
    if condition {
        Ok(())
    } else {
        Err(CampaignError::Invariant(message))
    }
}

fn step<const N: usize>(id: &str, metrics: [(&str, String); N]) -> CampaignStep {
    CampaignStep {
        campaign_id: id.to_owned(),
        verdict: "PASS".to_owned(),
        metrics: metrics
            .into_iter()
            .map(|(key, value)| (key.to_owned(), value))
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const REVISION: &str = "9a3542b33290dfda636749f50dce4e92fcb23b42";

    #[test]
    fn campaign_executes_every_required_adversarial_scenario() {
        let report = run_application_economy_campaign(REVISION, 7).unwrap();
        assert_eq!(report.schema, CAMPAIGN_SCHEMA);
        assert_eq!(report.verdict, "PASS");
        assert!(!report.production_authorized);
        assert_eq!(report.promotion_effect, "NONE");
        assert_eq!(report.steps.len(), CAMPAIGN_IDS.len());
        assert_eq!(
            report
                .steps
                .iter()
                .map(|step| step.campaign_id.as_str())
                .collect::<Vec<_>>(),
            CAMPAIGN_IDS
        );
    }

    #[test]
    fn campaign_is_seeded_and_reproducible() {
        let first = run_application_economy_campaign(REVISION, 99).unwrap();
        let second = run_application_economy_campaign(REVISION, 99).unwrap();
        assert_eq!(first, second);
        assert_ne!(
            first,
            run_application_economy_campaign(REVISION, 100).unwrap()
        );
    }

    #[test]
    fn campaign_rejects_unfrozen_source_identity() {
        assert_eq!(
            run_application_economy_campaign("9A3542B", 1),
            Err(CampaignError::InvalidSourceRevision)
        );
    }
}
