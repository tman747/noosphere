# Owner Decision Record (ODR) Ledger — no dead ends

Status: LIVE tracking document. Every `OWNER_BLOCKED`, `UNRESOLVED_SOURCE`, and
`PROPOSED-G0` marker in the repository MUST appear here with a resolution path.
A marker without a ledger row is a release-blocking defect (checked at the
claim-matrix gate). Rows are appended/updated, never deleted; resolution links
the signing artifact.

Resolution classes:
- **OWNER**: requires a signed owner decision (economics/counsel) — blocks mainnet only.
- **G0-REVIEW**: engineering value frozen by an implementation, awaiting G0 sign-off — blocks G1 exit.
- **GATE**: value selected by a preregistered experiment — blocks the naming gate.
- **RESOLVED**: decided; row records where.

| ODR | Subject | Class | Blocks | Where frozen / to be decided |
|---|---|---|---|---|
| ODR-GROUND-001 | mainnet `max_future_drift_ms` | GATE (E-WAN over {12000,18000,30000}) | mainnet | constants-v1.toml [ground] |
| ODR-ECON-001 | mainnet minimum witness bond | OWNER | mainnet | constants-v1.toml [witness]; genesis manifest field 16 |
| ODR-EMISSION-001..007 | max supply, curve, terminal height, recipient shares, rounding, fee disposition, allocation | OWNER (+economic review, counsel) | mainnet | constants-v1.toml [emission]; genesis manifest fields 25–33 |
| ODR-WITNESS-002 | slash burn/reporter fractions | G0-REVIEW (corpus names rule, no numbers) | G1 | constants-v1.toml [witness]; to be frozen with noos-witness vectors |
| ODR-WITNESS-003 | inactivity leak rate | G0-REVIEW | G1 | constants-v1.toml [witness] |
| ODR-WITNESS-004 | activation/exit delay epochs | G0-REVIEW | G1 | constants-v1.toml [witness] |
| ODR-WITNESS-005 | evidence horizon epochs | G0-REVIEW | G1 | constants-v1.toml [witness] |
| ODR-FEES-001 | fee controller coefficients/clamps | G0-REVIEW | G1 | FeeParamsV1 params-tree record (lumen-v1.md §6.3); testnet fixture exists |
| ODR-FEES-002 | per-dimension block capacity; R-dimension approximation | G0-REVIEW | G1 | FeeParamsV1; co-freeze with ODR-DA-001 body size |
| ODR-FEES-003 | frozen deterministic failure-fee value | G0-REVIEW | G1 | FeeParamsV1 field 9 |
| ODR-GRAIN-001 | Grain v1 integer cost table | RESOLVED (PROPOSED-G0) | G0 sign-off | protocol/schemas/grain-v1.md §10 + 78 vectors + Go grainref parity |
| ODR-GRAIN-002 | Grain limits (arena/noun/formula/depth) | RESOLVED (PROPOSED-G0) | G0 sign-off | grain-v1.md §2 |
| ODR-WALLET-001 | numeric hardened derivation indices | G0-REVIEW | G1 (wallet phase) | constants-v1.toml [lumen]; to be frozen in wallet phase with vectors |
| ODR-NEL-001 | `anchor_deadline_blocks` | G0-REVIEW | NEL activation gate | constants-v1.toml [nel]; nel-v1.md phase |
| ODR-DA-001 | body shard size/count parameters | G0-REVIEW | G1 (DA phase) | schema-tables/da.md proposed values |
| ODR-DA-002 | body/blob collection maxima | G0-REVIEW | G1 (DA phase) | schema-tables/da.md + header-body.md |

Additional PROPOSED-G0 families (frozen by implementation, awaiting the same G0
sign-off, tracked at their definition sites): lumen object tags/widths/maxima
(schema-tables/lumen-objects.md + lumen-v1.md), header/body field widths
(schema-tables/header-body.md), Grain trap codes (schema-tables/grain.md,
adopted by grain-v1.md §5), NEL assigned domain strings and wire widths
(crypto-domains-v1.csv ASSIGNED rows; schema-tables/nel-wire.md), address
version/type/payload layout (identity-v1.md §2.1 — OWNER class, blocks any
address emission).

Rule restated (plan §1.7): no marker may enter code as a developer default;
mainnet-blocking markers block mainnet genesis; G1-blocking markers block G1
exit. Test networks run on named valueless `NOOS_TEST` fixtures only.
