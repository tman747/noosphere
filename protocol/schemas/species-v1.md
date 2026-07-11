# Species application schema v1

All identifiers are 32-byte hashes. Collections are canonically ordered and u32 length bounded. These are immutable application objects; registration is insert-once.

## Domains and objects

- `NOOS/ARTIFACT/V1`: `Artifact(artifact_id, kind, media_type, byte_length:u64, chunking_profile, availability_root, encoding, numeric_profile?, encryption_profile?, rights_root, creator, created_at:u64, annotations_root)`.
- `NOOS/SPECIES/V1`: `SpeciesManifest(species_id, manifest_version:u64, domain, input_schema, output_schema, tokenizer_relation, behavioral_relations[], conformance_suites[], evaluator_policies[], admissible_numeric_profiles[], minimum_availability, minimum_rights, promotion_rule, safety_constraints[], predecessor?)`.
- `NOOS/SPECIES/REVISION/V1`: `SpeciesRevision(revision_id, species_id, manifest_version, composition_root, required_artifacts[], execution_manifest, relation_claims[], serving_profiles[], availability_certificate, rights_certificate, lifecycle)`.
- `NOOS/SPECIES/EQUIVALENCE/V1`: directional `EquivalenceClaim(claim_id, species_id, candidate, reference_set[], relation, domain_slice, numeric_profile, test_commitment, result_commitment, evaluator_receipts[], confidence_statement, valid_from, expires_at?, challenger_bond:u128)`.
- `NumericProfile` freezes accumulation order, rounding, saturation, PRNG, sampling, termination, tensor encoding, NaN policy, substitutions, conformance status, and independent implementation count.
- `ServingProfile` carries three orthogonal axes: execution assurance V0..V3, quality Q0..Q4, and confidentiality.
- `NOOS/SPECIES/UPDATE/V1`: immutable `UpdatePacket`; `NOOS/SPECIES/LEARNING-RECORD/V1`: immutable decision record. Acceptance names a distinct, already-registered `SpeciesRevision`.

There is no `current_weights`. Tolerance/distance claims are never inferred transitively. Species, execution evidence, and quality evidence grant no proposal weight, finality weight, or consensus acceptance.
