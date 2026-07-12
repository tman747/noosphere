# G3 evidence location

No public-duration evidence is checked in. A real run appends canonical one-line JSON
checkpoints to `checkpoints.ndjson` only after the active exact-revision manifest and
the required independent operator signatures exist, and only after the exact signed
checkpoint has a live-verified, six-confirmation Bitcoin-mainnet OpenTimestamps proof.
Corrections are new signed and externally timestamped records; prior lines are never
edited, removed, re-stamped, or waived. Local deterministic timestamp fixtures,
`TEST_ONLY` keys, simulated clocks, and pending calendar receipts are never copied here.
