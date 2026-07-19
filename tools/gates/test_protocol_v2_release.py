"""Focused protocol-v2 release/schema dispatch and fail-closed regressions."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import check_promotion
from validate_registry import schema_validate
from promotion_records import (
    PromotionValidationError,
    V1_PREDECESSOR_PATH,
    V1_PREDECESSOR_SHA256,
    V1_RELEASE_SCHEMA_PATH,
    V1_RELEASE_SCHEMA_SHA256,
    validate_promotion_ledger,
    validate_protocol_release_manifest_header,
)


class ProtocolV2ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.v1 = json.loads((ROOT / "protocol/release/promotion-blockers.json").read_text("utf-8"))
        cls.v2 = json.loads((ROOT / "protocol/release/promotion-blockers-v2.json").read_text("utf-8"))
        cls.v2_schema = json.loads((ROOT / "protocol/release/promotion-blockers-schema-v2.json").read_text("utf-8"))
        cls.release_schema = json.loads((ROOT / "protocol/release/protocol-release-manifest-v2.schema.json").read_text("utf-8"))

    def validate_v2(self, document: dict) -> dict:
        return validate_promotion_ledger(document, ROOT, schema_version=2)

    def release_v2(self) -> dict:
        return {
            "$schema": "protocol-release-manifest-v2.schema.json",
            "schema_version": 2,
            "manifest_kind": "noosphere-protocol-release-manifest-v2",
            "predecessor_binding": {
                "promotion_ledger": {
                    "path": V1_PREDECESSOR_PATH,
                    "schema_version": 1,
                    "protocol_version": "v1",
                    "api_version": "v1",
                    "root_algorithm": "SHA-256-EXACT-FILE-BYTES",
                    "root": V1_PREDECESSOR_SHA256,
                },
                "release_schema": {
                    "path": V1_RELEASE_SCHEMA_PATH,
                    "schema_version": 1,
                    "root_algorithm": "SHA-256-EXACT-FILE-BYTES",
                    "root": V1_RELEASE_SCHEMA_SHA256,
                },
                "relation": "CLEAN_V2_CUTOVER_FROM_IMMUTABLE_V1",
            },
            "release": {
                "version": "0.0.0-bonsai-v2-preproduction",
                "channel": "devnet",
                "date": "2026-07-14",
                "protocol_identity": "noos-protocol-identity-v2",
                "protocol_version": "v2",
                "api_version": "v2",
                "peer_identity": "v2-only",
            },
            "source": {
                "spec_revision": "protocol/schemas/wwm-v2.md",
                "plan_revision": "approved-bonsai-plan",
                "repo_revision": "1" * 40,
            },
            "identity": {
                "chain_name": "noos-devnet-v2",
                "is_test_network": True,
                "protocol_identity": "noos-protocol-identity-v2",
                "chain_id": "2" * 64,
                "genesis_hash": "3" * 64,
            },
            "activation_boundary": {
                "controls_enabled": False,
                "promotion_effect": "NONE",
                "dns_cutover": "PROHIBITED",
                "model_execution": "LARGE_MODELS_OFF_CHAIN_BOUNDED_L1_NEURAL_ONLY",
            },
            "contracts": {
                "wwm_v2_schema_sha256": "4" * 64,
                "crypto_domains_sha256": "5" * 64,
                "promotion_ledger_v2_sha256": "6" * 64,
                "action_variant_count": 66,
                "action_discriminants": list(range(40, 66)),
                "payload_tags": {
                    "41": ["InstallProfile", "TransitionCapability"],
                    "50": ["InstallProfile", "TransitionCapability"],
                    "52": ["StageFundProfile", "LockFundMutation", "ActivateFundProfile", "CloseFundProfile"],
                    "58": ["TransitionServingAlias"],
                    "59": ["Activate", "EmergencyDisable", "AuthorizeOperationalConfig", "ApplyOperationalConfig", "Recover"],
                },
                "resolver": {
                    "normal_max_bytes": 262144,
                    "normal_max_proofs": 17,
                    "authorized_max_bytes": 393216,
                    "neural_target": "/neural-oracle/<query_id>",
                    "neural_response_max_bytes": 16384,
                },
                "light_update": {"protocol": "/noos/sync/light-update/2", "min_items": 1, "max_items": 128, "max_item_bytes": 262144},
                "transaction_bounds": {"action_call_max_bytes": 65536, "tx_plus_witness_max_bytes": 65532, "tx_push_prefix_bytes": 4, "tx_push_max_bytes": 65536},
                "v1_wwm_decode": "REJECT",
            },
            "toolchain_locks": {"rustc": "pinned"},
            "artifact_hashes": {"release/artifact": "7" * 64},
            "checksums": {"path": "release/SHA256SUMS", "sha256": "8" * 64},
            "sbom": {"path": "release/sbom.json", "sha256": "9" * 64},
            "provenance": {"path": "release/provenance.jsonl", "sha256": "a" * 64},
            "reproducibility": {
                "target": "linux-x86_64",
                "trusted_repro_builders_sha256": "b" * 64,
                "assurance_report_sha256": "c" * 64,
            },
            "gate_verdicts": [
                {"gate": gate, "verdict": "BLOCKED", "ledger_record_hash": "OWNER_BLOCKED"}
                for gate in ("G0", "G1", "G2", "G3", "GENESIS", "G4", "G5")
            ],
            "unresolved_findings": [{
                "finding_id": "W0.BLOCKED", "severity": "BLOCKER",
                "summary": "Owner and external gates remain blocked",
                "owner": "protocol-owner", "status": "OPEN",
            }],
            "signatures": [],
        }

    def test_schema_files_are_closed_json_and_current_v2_ledger_validates(self) -> None:
        for relative in (
            "protocol/release/promotion-blockers-schema-v2.json",
            "protocol/release/promotion-blockers-v2.json",
            "protocol/release/protocol-release-manifest-v2.schema.json",
        ):
            value = json.loads((ROOT / relative).read_text("utf-8"))
            self.assertIsInstance(value, dict)
        summary = self.validate_v2(copy.deepcopy(self.v2))
        self.assertFalse(summary["all_passed"])
        self.assertEqual(schema_validate(self.v2, self.v2_schema), [])
        self.assertEqual(summary["record_hashes"], [])

    def test_v2_rejects_missing_wrong_and_cyclic_predecessors(self) -> None:
        cases = {}
        missing = copy.deepcopy(self.v2)
        del missing["predecessor"]
        cases["missing"] = missing
        wrong = copy.deepcopy(self.v2)
        wrong["predecessor"]["predecessor_root"] = "0" * 64
        cases["wrong"] = wrong
        cyclic = copy.deepcopy(self.v2)
        cyclic["predecessor"]["ledger_path"] = "protocol/release/promotion-blockers-v2.json"
        cyclic["predecessor"]["schema_version"] = 2
        cases["cyclic"] = cyclic
        for name, document in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(PromotionValidationError, "predecessor"):
                self.validate_v2(document)
            self.assertTrue(schema_validate(document, self.v2_schema))

    def test_v1_and_v2_dispatch_never_cross_decode(self) -> None:
        v1_summary = validate_promotion_ledger(copy.deepcopy(self.v1), ROOT, schema_version=1)
        self.assertFalse(v1_summary["all_passed"])
        with self.assertRaisesRegex(PromotionValidationError, "V2 promotion ledger/schema"):
            validate_promotion_ledger(copy.deepcopy(self.v1), ROOT, schema_version=2)
        with self.assertRaisesRegex(PromotionValidationError, "V1 promotion ledger"):
            validate_promotion_ledger(copy.deepcopy(self.v2), ROOT, schema_version=1)

    def test_v2_rejects_mixed_identity_unknown_actions_and_payload_tags(self) -> None:
        mutations = []
        for field, value in (("protocol_version", "v1"), ("api_version", "v1"), ("peer_identity", "v1")):
            document = copy.deepcopy(self.v2)
            document["protocol_binding"][field] = value
            mutations.append(document)
        unknown_action = copy.deepcopy(self.v2)
        unknown_action["contracts"]["action_registry"]["last_discriminant"] = 66
        mutations.append(unknown_action)
        unknown_tag = copy.deepcopy(self.v2)
        unknown_tag["contracts"]["payload_tags"]["action_59"].append("GenericGovernanceEnable")
        mutations.append(unknown_tag)
        for document in mutations:
            with self.assertRaises(PromotionValidationError):
                self.validate_v2(document)
            self.assertTrue(schema_validate(document, self.v2_schema))

    def test_v2_rejects_every_frozen_bound_plus_one(self) -> None:
        paths = (
            ("transaction_bounds", "action_call_max_bytes", 65537),
            ("transaction_bounds", "tx_plus_witness_max_bytes", 65533),
            ("transaction_bounds", "tx_push_max_bytes", 65537),
            ("light_update", "max_items", 129),
            ("light_update", "max_item_bytes", 262145),
            ("resolver", "max_bytes", 262145),
            ("resolver", "authorized_max_bytes", 393217),
        )
        for section, field, value in paths:
            document = copy.deepcopy(self.v2)
            document["contracts"][section][field] = value
            with self.subTest(section=section, field=field), self.assertRaises(PromotionValidationError):
                self.validate_v2(document)
            self.assertTrue(schema_validate(document, self.v2_schema))

    def test_fabricated_pass_cannot_authorize(self) -> None:
        document = copy.deepcopy(self.v2)
        document["gates"][0]["state"] = "PASSED"
        document["gates"][0]["signatures"] = [
            {
                "role": role,
                "key_id": f"fixture-{index}",
                "signature_ed25519_hex": f"{index + 1:02x}" * 64,
            }
            for index, role in enumerate(
                [
                    "release-owner",
                    "independent-build-reviewer",
                    "operations-owner",
                    "security-reviewer",
                ]
            )
        ]
        with self.assertRaisesRegex(
            PromotionValidationError,
            "PASSED gate requires|authorization[_ ]record",
        ):
            self.validate_v2(document)
        self.assertTrue(schema_validate(document, self.v2_schema))

    def test_release_manifest_dispatch_predecessor_bounds_and_pass_boundary(self) -> None:
        manifest = self.release_v2()
        validate_protocol_release_manifest_header(manifest, ROOT, 2)
        self.assertEqual(schema_validate(manifest, self.release_schema), [])
        cases = []
        missing = copy.deepcopy(manifest)
        del missing["predecessor_binding"]
        cases.append(missing)
        mixed = copy.deepcopy(manifest)
        mixed["release"]["api_version"] = "v1"
        cases.append(mixed)
        oversized = copy.deepcopy(manifest)
        oversized["contracts"]["transaction_bounds"]["tx_push_max_bytes"] = 65537
        cases.append(oversized)
        unknown_tag = copy.deepcopy(manifest)
        unknown_tag["contracts"]["payload_tags"]["59"].append("Unknown")
        cases.append(unknown_tag)
        fabricated = copy.deepcopy(manifest)
        fabricated["gate_verdicts"][-1] = {"gate": "G5", "verdict": "PASS", "ledger_record_hash": "4" * 64}
        cases.append(fabricated)
        for document in cases:
            with self.assertRaises(PromotionValidationError):
                validate_protocol_release_manifest_header(document, ROOT, 2)
            self.assertTrue(schema_validate(document, self.release_schema))
        with self.assertRaises(PromotionValidationError):
            validate_protocol_release_manifest_header(manifest, ROOT, 1)

    def test_check_promotion_requires_explicit_matching_selection(self) -> None:
        self.assertEqual(check_promotion.validate(ROOT, schema_version=1), [])
        self.assertEqual(check_promotion.validate(ROOT, schema_version=2), [])
        mixed_errors = check_promotion.validate(
            ROOT, schema_version=2,
            ledger_path=ROOT / "protocol/release/promotion-blockers.json",
        )
        self.assertTrue(any("explicit V2" in error for error in mixed_errors))


if __name__ == "__main__":
    unittest.main()
