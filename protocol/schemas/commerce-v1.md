# Commerce overlay schema v1

`CommerceJob(job_id, class_id:u32, client, provider?, evaluator_policy, request_schema, request_commitment, species_selector?, assurance_requirement, quality_requirement, confidentiality_requirement, rights_requirement, budget?, evaluator_fee:u128, expiry:u64, state, negotiated_terms_root?, work_job_id?, work_commitment?, availability_certificate?)` is negotiation and evaluation metadata over exactly one Work Loom job.

Mapping: `AGREED/FUNDED -> OPEN`, provider offer -> `COMMITTED`, execution -> `RUNNING`, submission -> `SUBMITTED`, entitled retrieval -> `CHALLENGEABLE`, award -> `SETTLED`, objective failure -> `REJECTED`, dispute -> `DISPUTED`, and deadline -> `EXPIRED`. Only Work Loom moves escrow. Evaluation cannot begin before finalized availability.

`Q0_NO_QUALITY_ASSURANCE` is the only skip-evaluation mode and MUST NOT be displayed as quality assurance. Subjective work cannot be objectively slashed.

Undecryptable delivery, withholding-clock abuse, attempted double payout, and subjective-as-objective slashing immediately disable only the affected class. Subsequent calls fail with `FeatureDisabled { cause, evidence_root }`; they never return empty success.
