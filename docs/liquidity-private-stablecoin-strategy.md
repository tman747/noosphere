# MindChain liquidity and private stable-payment strategy

## Product thesis

MindChain should not compete by advertising the highest temporary APY. It should create recurring reasons to hold and move stable value: AI-agent settlement, compute escrow, private invoices, merchant payouts, and treasury automation. Liquidity incentives then deepen the routes that serve verified payment demand.

The native stable asset is an overcollateralized debt instrument. Its private-payment rail is a commitment escrow: payer, asset, amount, and timing are public; recipient and memo remain commitment-hidden until claim. The recipient receives the claim secret through an X25519/ChaCha20-Poly1305 stealth envelope. This is recipient and metadata privacy, not hidden-amount privacy. Confidential amounts require an independently audited zero-knowledge proving system and are a later protocol tier.

## Stable asset structure

1. **Solvency before growth.** Stable supply must always equal market debt. Collateral factors remain below liquidation thresholds. Debt ceilings are per market and start small.
2. **Price safety.** Three authenticated reporters, two fresh reports required, confidence-adjusted conservative pricing, sequence replay protection, and fail-closed borrowing.
3. **No algorithmic peg promise.** The asset is debt-backed, not reflexively backed by its own governance token.
4. **Multiple collateral silos.** Each collateral type gets an isolated market, oracle, debt ceiling, and liquidation parameters. A failure does not silently cross-subsidize another silo.
5. **Payment privacy tiers.** Tier 0 is ordinary transparent transfer. Tier 1 is recipient/memo-hidden escrow implemented now. Tier 2 is confidential amount and balance proofs only after two independent verifier implementations, audited circuits, parameter governance, and an emergency exit relation.
6. **No custody in public gateways.** Wallets generate and encrypt Ed25519 keys locally. RPC services build unsigned transactions and accept signatures; they never receive private keys.
## Fable 5 critical-review decisions

The design review changes the implementation and rollout in four concrete ways:

- **Privacy is tiered honestly.** Tier 0 is transparent. Tier 1 hides the recipient and memo only; amount, payer, timing, funding, and claim/sweep behavior remain public. Tier 2 amount confidentiality is not announced until audited commitment-tree/nullifier circuits and two independent verifier implementations exist.
- **Agent limits are consensus controls.** MindChain now supports an agent-signed private payment action that must reference an on-chain capability grant. Consensus checks the grant issuer, agent session account, exact stable asset and recipient commitment scope, per-payment limit, remaining cumulative budget, grant expiry, and payment expiry before moving funds. Revoking the grant invalidates subsequent payments. Wallet policy remains defense in depth, not the security boundary.
- **Liquidity follows peg infrastructure.** Protocol-owned flagship depth and executable liquidation capacity precede emissions. Incentives are finite and judged by post-cut retention, not peak TVL.
- **The oracle needs a growth path.** The present three-reporter quorum is a guarded test-network mechanism, not a complete production oracle security model. Production gates include operation-specific conservative semantics, deviation bounds, last-good-price behavior, independent signer infrastructure, rejected-update monitoring, and expansion beyond three reporters.

Remaining gates from the review are explicit: relayed sweep privacy, native secure-enclave desktop/mobile shells, rolling-window and counterparty-concentration agent limits, a backstop liquidator, a funded bad-debt reserve, redemption/PSM design, and external legal and cryptographic review. The installable PWA is the reduced-trust wallet tier; it is not represented as equivalent to a mobile secure enclave.


## Liquidity acquisition sequence

### 1. Create payment demand

- Settle compute-market jobs in the stable asset, with explicit job reference commitments.
- Let AI agents pay under local wallet policies: allowed stable assets, per-payment limits, epoch spend limits, and policy expiry.
- Support private invoices with recipient-hidden claim escrow and expiry refunds.
- Give merchants deterministic receipts, reference commitments, and indexer APIs.
- Quote network services in stable base units so users do not need to manage volatile fee accounting.

Success measure: organic stable transfer volume and repeat payers, not gross minted supply.

### 2. Establish two flagship routes

- Stable/NOOS for native fees and collateral rebalancing.
- Stable/high-quality external stable only after a separately audited bridge or native issuer integration exists.

Do not scatter incentives across thin pools. Publish depth at 10, 50, and 100 basis points of price impact, reserve concentration, daily fee revenue, and liquidity retention.

### 3. Seed protocol-owned liquidity

Use a capped treasury mandate to own a base layer of flagship LP shares. Treasury LP shares are transparent, time-locked by policy, and never counted as circulating user liquidity. This creates a permanent execution floor without endless rental emissions.

Required controls:

- Per-pool treasury cap.
- Maximum acquisition price deviation.
- Public position and fee accounting.
- Delayed governance changes.
- No borrowing against protocol-owned LP shares.

### 4. Add finite, time-locked campaigns

Sponsors escrow a fixed reward budget for one pool and duration. Providers opt into a non-transferable LP-share lock. Rewards are proportional to committed shares and duration; early exits forfeit rewards. Campaigns have fixed maximum budgets and cannot mint unbounded rewards.

Prefer stable or partner-funded rewards over high native-token inflation. Measure 30/60/90-day retained liquidity after each campaign. Stop campaigns whose retained depth does not justify spend.

### 5. Reward useful liquidity rather than wash volume

Use time-weighted liquidity and realized fee contribution. Do not pay raw volume, which is cheap to self-trade. Exclude self-swaps, same-block round trips, and routes with no net inventory risk. Campaign accounting must remain deterministic and bounded.

### 6. Recruit professional market makers

Provide:

- Authenticated low-latency RPC endpoints.
- Deterministic block and receipt streams.
- Pool/reserve/oracle APIs.
- Historical depth and execution-quality exports.
- Public incident status and upgrade calendars.
- Testnet inventory and repeatable conformance suites.

Offer capped fee rebates tied to quoted depth and uptime, not opaque bilateral token grants.

### 7. Integrate distribution, not just bridges

Priority integrations:

- AI inference and data marketplaces.
- Merchant payout and invoicing providers.
- Treasury automation systems.
- Wallet directories and payment-link platforms.
- Regulated fiat on/off-ramp partners where legally supported.

A bridge does not create durable demand by itself. No bridge should be marketed until its validator/security assumptions, withdrawal failure modes, rate limits, and emergency procedures are independently reviewed.

## Wallet product

Harbor Wallet is one installable PWA codebase for web, desktop, and mobile. It uses WebCrypto Ed25519 keys, PBKDF2-SHA-256 with 310,000 rounds, AES-256-GCM vault encryption, IndexedDB persistence, non-extractable runtime keys, encrypted backup export/import, local transaction signing, and explicit chain/genesis identity checks.

The local engineering gateway may sponsor valueless test funding. Production wallet distribution must use TLS, origin isolation, a reviewed content-security policy, reproducible builds, signed releases, and no server-side seed storage.

## Launch gates

Before material value:

1. Two independent audits of consensus state transitions and wallet key handling.
2. Economic simulation for oracle divergence, liquidation cascades, thin liquidity, and bad debt.
3. Formal or property-based conservation checks for pool reserves, LP shares, stable supply/debt, and payment escrow.
4. Stable issuer, redemption, sanctions, privacy, consumer-protection, and money-transmission legal analysis in each target jurisdiction.
5. Small debt ceilings and treasury liquidity caps with staged increases based on observed behavior.
6. Public incident response, oracle key rotation, governance key custody, and emergency pause procedures.
7. No claim that privacy defeats lawful endpoint controls or that software is impossible to exploit.

## Scorecard

Track weekly:

- Stable supply and collateralization by silo.
- Debt utilization and liquidation coverage.
- Oracle freshness and reporter divergence.
- Flagship depth at 10/50/100 bps.
- Organic swap volume and fees.
- Unique repeat stable payers.
- Agent payments settled under policy.
- Private payments opened, claimed, refunded, and expired.
- 30/60/90-day campaign liquidity retention.
- Treasury-owned versus user-owned liquidity.
- Wallet transaction success, signing refusal, and wrong-chain rejection rates.
