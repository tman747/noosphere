# MindChain native DeFi security model

## Security claim

No protocol can honestly guarantee that it “cannot be hacked.” The enforceable target is narrower: deterministic state transitions, explicit authorization, conserved assets, bounded arithmetic, manipulation-resistant inputs, fail-closed validation, atomic rollback, adversarial tests, and independent review before production value is enabled.

All current deployments remain valueless test networks. Production-value activation is blocked on an exact-revision external audit and a public economic-risk review.

## Native execution boundary

DeFi transitions execute inside the Lumen copy-on-write overlay. They cannot perform external calls, callbacks, dynamic code loading, filesystem access, network access, or reentrant execution. A failed action discards the complete transaction overlay.

## Required invariants

### Authorization

- Every balance-decreasing action names an account present in the signed account-input set.
- Governance and oracle administration use separately configured authorities.
- A gateway, indexer, or browser never has authority to create ledger truth.

### Asset conservation

- Swaps, liquidity additions, removals, loan operations, repayments, and liquidations conserve every existing asset.
- Only fixed-supply asset creation may create a user asset.
- No DeFi action can mint NOOS.
- Stable debt issuance must equal recorded debt and be fully reversible by repayment or liquidation.

### Arithmetic and rounding

- All quantities use checked integer arithmetic.
- Division rounds against the initiating user whenever rounding the other way would dilute existing liquidity or under-collateralize debt.
- Zero-output, zero-share, reserve-draining, and dust-producing transitions fail closed.
- AMM fees stay in reserves and therefore accrue to liquidity shares.

### AMM

- Asset ordering and pool IDs are canonical.
- Initial shares derive from integer square root of reserve product.
- Permanently locked minimum liquidity prevents division-by-zero and complete reserve withdrawal.
- Added liquidity cannot dilute existing shares.
- Removed liquidity cannot burn shares the signer does not own.
- Exact-input swaps enforce a caller-provided minimum output.
- The post-swap reserve product cannot decrease.

### Oracle

- Credit state must not consume a single arbitrary reporter value.
- Reports bind asset, quote asset, price, confidence, reporter, sequence, and observation height.
- Duplicate, regressed, future, stale, or unauthorized reports fail closed.
- A price becomes usable only after quorum and deterministic median aggregation.
- Oracle freshness is checked again during borrow and liquidation.

### Lending and stable debt

- Collateral and debt positions are isolated by owner and collateral asset.
- Borrowing uses the lower confidence bound, never the optimistic spot price.
- Debt ceilings, per-position minimums, collateral factors, liquidation thresholds, close factors, and bonuses are hard bounded.
- Repayment cannot increase debt; withdrawal cannot leave a position below its required ratio.
- Liquidation requires an actually unhealthy position and cannot seize more collateral than the repaid debt plus bounded bonus permits.
- Bad debt cannot be silently socialized or represented as settled.

## Explicitly excluded

Until separate designs and reviews exist, the native suite does not include flash loans, leveraged looping, rehypothecation, cross-chain collateral, algorithmic unbacked stablecoins, arbitrary callback hooks, external requester code, upgradeable proxy contracts, or governance-controlled seizure of user balances.

## Assurance gates

1. Unit tests for every transition and rejection path.
2. Property tests for conservation, monotonicity, reserve product, share dilution, collateralization, and replay rejection.
3. Differential arithmetic tests against an independent big-integer model.
4. Stateful fuzzing over action sequences and failed-transaction rollback.
5. Live valueless-network launch, add/remove liquidity, swap, borrow, repay, and liquidation drills.
6. Independent protocol, implementation, and economic review at the exact release revision before production value is permitted.
