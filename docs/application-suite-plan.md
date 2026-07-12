# MindChain application suite plan

## Research baseline

Mature general-purpose L1 ecosystems converge on a small set of application surfaces:

- discovery and trust: explorer, wallet, naming/identity, attestations;
- economic activity: payments, asset issuance, DEX liquidity, lending and stable assets;
- ownership and coordination: collectibles, marketplaces, governance and DAOs;
- interoperability and utility: bridges, oracles, storage, social, gaming and physical infrastructure.

Ethereum’s official application catalog groups deployed applications into DeFi, collectibles, social, gaming, bridges, productivity, privacy and DAOs. Its DeFi examples include DEXs, lending and stablecoin issuance. Solana’s official ecosystem emphasizes DeFi, payments, DePIN, gaming and collectibles. Sources:

- https://ethereum.org/apps/
- https://solana.com/ecosystem
- https://solana.com/docs

## Existing MindChain primitives

The current protocol safely supports these application classes end to end:

| Primitive | Consensus action/API | Application |
| --- | --- | --- |
| Payments and portfolio | account debit/credit, balance and transaction APIs | `noos-wallet-app`, `wallet_transfer.py` |
| Fixed-supply assets | `CreateAsset`, asset queries | Mind Market Foundry |
| Spot liquidity | `CreatePool`, `SwapExactIn`, pool queries | Mind Market Current |
| Compute/DePIN | worker registration, escrowed jobs, result settlement | Compute Market |
| Network trust | block, receipt, finality and node APIs | Network Dashboard |

Lending, stablecoin issuance, NFTs, governance, bridges and external oracles do not yet have frozen consensus objects or economic/security laws. A browser-only mock would create off-chain custody or false settlement claims, so those applications are deferred until their protocol primitives and adversarial tests exist.

## Build order

1. **MindScan explorer** — public, read-only chain discovery: independent head state, recent blocks, block/transaction search, identity binding, loading/empty/error states, and mobile layout.
2. **Application directory** — expose wallet, Foundry, Current, Compute Market and Network Dashboard from the explorer without merging their trust boundaries.
3. **Live integration** — serve through a bounded same-origin gateway, never expose the operator token, and verify against the durable indexer.
4. **Next protocol-backed applications** — governance/treasury first, then unique assets and marketplace; lending and bridges only after oracle, liquidation and cross-chain verification designs are independently reviewed.

## Acceptance

- Explorer status binds chain ID and genesis hash and labels unsafe, justified and finalized state separately.
- Recent blocks and exact block/transaction lookup use indexer truth; no fabricated metrics or sample records.
- Search rejects malformed identifiers client-side and the gateway enforces path and response-size allowlists.
- A live smoke test observes a real block height, retrieves that block, and survives indexer restart from a persisted generation.
- Existing asset launch, swap, compute settlement, wallet and dashboard links remain separate applications with explicit trust boundaries.
