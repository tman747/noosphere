# Loam application schema v1

`LoamCapsule(capsule_id, owner, content_commitment, encrypted_content?, storage_plane, provenance[], observed_at, confidence_statement, sensitivity, rights_expression, purpose_limits[], retention_rule, consent_receipt?, lineage_parents[], index_derivatives[], state, ingested_at)` is local-first. Plaintext or encrypted content, observations, confidence notes, indexes, and retrieval history remain local or in encrypted availability; only `capsule_id`, `rights_root`, `provenance_root`, and `repair_debt_refs[]` project to Lumen.

`ConsentCompiler` authorizes a principal, purpose, height, and explicit mode, then emits a bounded operator plan. Modes are `NO_EXPORT`, `RAW_DISCLOSURE`, `PRIVATE_OPERATOR`, `AGGREGATE_STATISTICS`, `PREFERENCE_PACKET`, and `TRAJECTORY_PACKET`. A local-only right denies every export mode.

Retention is `UNTIL_HEIGHT`, `FOR_BLOCKS`, or `INDEFINITE_UNTIL_REVOKED`. Expiry moves the capsule to `EXHAUSTED` and drops disposable indexes. Index deletion never deletes the authoritative capsule.

`RepairDebt(debt_id, revoked_root, affected_artifacts[], required_actions[], responsible_principals[], deadline, residual_risk, state, repairability_literal)` records incomplete repair. An impossible repair MUST carry the exact literal `NON_REPAIRABLE` and `DOCUMENT_IMPOSSIBILITY`. The protocol never claims that plaintext already disclosed has been forgotten; revocation prevents future authorized use only.
