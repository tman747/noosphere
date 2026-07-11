# Production economics owner-proposal review packet

Status: **DRAFT / UNSIGNED / NOT FROZEN / NOT PRODUCTION LOADABLE**.

This packet recommends conservative integer parameters. It records no owner
approval and no legal or economic review. `constants-v1.toml` remains unchanged:
its `OWNER_BLOCKED` and `UNRESOLVED_SOURCE` markers are still authoritative until
the exact reviewed artifact is signed.

## Recommended envelope

- Chain name: `MindChain Mainnet`.
- Hard cap: `1,000,000,000.000000 NOOS`.
- Genesis allocation ceiling: `300,000,000.000000 NOOS` (30%); exact category
  envelopes are committed, but every recipient entry and the allocation root are
  `OWNER_INPUT_REQUIRED`.
- Scheduled emission: `699,999,861.600000 NOOS`; `138.400000 NOOS` of the
  700-million envelope is deliberately unmintable integer headroom.
- Law: heights are 1-based; five 20-year ranges at six-second target spacing;
  `E_0=3.436932 NOOS/height`, then integer floor halvings. Terminal height is
  `525,600,000`; height zero and every later height emit zero.
- Split: 50% Ground, 40% Witness, 10% treasury. Witness and treasury round
  down; Ground takes the exact remainder.
- Base fees and deterministic failure fees burn 100%; explicit priority tips go
  100% to the Ground proposer. WorkJob escrow is a transfer, never a fee or mint.
- Useful-work credit, proofpower, and duplex issuance remain hard zero under the
  killed `E-DEMAND-WASH-01` consensus claim.

At 100% height realization, year-one issuance is about 18.065 million NOOS,
6.02% of the full 300-million genesis allocation. The analysis deliberately
also tests partial allocation circulation, missed-height realization, fee burn,
schedule perturbations, validator counts, bond multiples, and hypothetical
prices. Those are stress scenarios, not forecasts.

The 250,000-NOOS minimum bond means 256 minimum-size validators bond 64 million
NOOS (6.4% of cap); one-third-plus-one of that minimum set is about 21.333
million NOOS. This is only a lower-bound accounting measure. It does not prove
liquidity-adjusted attack cost, operator independence, token value, or adequate
security. The public self-hosted operator requirement still needs real evidence.

## Exact unresolved owner and external inputs

The freeze gate must continue to reject the proposal until all of these exist:

1. E-WAN-01 evidence over `{12000,18000,30000}` ms and selection of the smallest
   passing drift. Current evidence is insufficient, so drift is explicitly pending.
2. A complete allocation entry list under the tested `noos-bech32m-v1` law,
   including recipient, amount, category, unlock height, memo, duplicate checks,
   exact 300-million-NOOS sum, and canonical allocation root.
3. The release-owner Ed25519 public key and detached signature over the exact
   final manifest. The selected policy has one required signing role; this draft
   contains no signature.
4. Named public self-hosted 5-of-7 DKG participants and the post-Quiet-Week
   transcript root. No participant identity or transcript is invented here.
5. Quiet-Week claim-registry, conformance-vector, and software-manifest roots;
   the later Bitcoin anchor and all ceremony evidence.
6. Independent economist and counsel reports over the exact revision, with all
   severity-one findings resolved. Counsel must review allocation, contributor,
   treasury, public-distribution, vesting, tax, sanctions, and marketing language.
7. A-FEES 24-hour adversarial marginal-cost evidence for every proposed capacity,
   initial price, controller clamp, and the one-NOOS failure fee.

## Independent economist checklist

- [ ] Recompute the range table, BLAKE3 root, scheduled total, cap headroom,
  terminal zero, and every share residue independently.
- [ ] Challenge the 30/70 genesis/emission split and all five allocation category
  ceilings; quantify concentration and vesting sensitivity using actual entries.
- [ ] Review year-one through year-100 gross and net inflation under missed
  heights and fee burn; do not assume full allocation is circulating.
- [ ] Model Ground cost, Witness participation, treasury runway, fee revenue, and
  validator exit at pessimistic token prices and utilization.
- [ ] Model bribery, stake rental, derivatives, liquidity slippage, correlated
  operators, and ≥1/3 acquisition; do not equate nominal minimum bond with attack cost.
- [ ] Stress the 50/40/10 reward split and 250,000-NOOS minimum bond against 32,
  64, 128, and 256 active validators and heterogeneous stake.
- [ ] Review 50/10/40 slashing and the 145.6-day evidence/exit horizon for both
  deterrence and false-positive/operator-solvency risk.
- [ ] Review the 0.5%-per-epoch inactivity leak after eight epochs under partitions,
  correlated outages, and censorship; verify it cannot alter a current snapshot.
- [ ] Require empirical A-FEES evidence; initial prices carry no fiat-cost claim.
- [ ] Confirm that no governance, emergency, Loom, NEL, or fee path can exceed the
  envelope, recreate missed emission, or turn burned amounts into a mint credit.

## Independent counsel checklist

- [ ] Review the exact allocation recipients, beneficial owners, categories,
  vesting/unlock terms, disclosures, conflicts, and treasury controls.
- [ ] Review securities, commodities, money-transmission, tax, sanctions/AML,
  consumer-protection, privacy, and jurisdiction-specific launch obligations.
- [ ] Require public language to distinguish a hard technical cap from value,
  price, yield, profitability, decentralization, or security guarantees.
- [ ] Require explicit disclosure that scenario prices and returns are not
  forecasts and that independent public operators/DKG participants are not yet evidenced.
- [ ] Verify authority and custody for the single release-owner key, incident
  succession, conflicts, and the legal effect of the signature and allocation root.
- [ ] Confirm that the final signed record references the exact source revision,
  table root, allocation root, reviews, and Quiet-Week publication.

## Reproduction

```powershell
python tools/genesis/generate_emission_table.py
python tools/gates/check_economics_proposal.py --allow-draft
python tools/gates/check_economics_proposal.py --self-test
cargo test -p noos-lumen issuance --lib
cargo test -p noos-work-loom zero_jobs_and_shadow_never_influence_production --lib
```

Running the freeze gate without `--allow-draft` must return exit code 2 and
`DRAFT_BLOCKED`. A production loader accepting this unsigned proposal is a
release-blocking defect.
