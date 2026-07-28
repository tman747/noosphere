from __future__ import annotations

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.g4 import capped_value_canary as canary

REVISION = "1" * 40
CHAIN_ID = "2" * 64
GENESIS_HASH = "3" * 64


class CappedValueCanaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="noos-g4-canary-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.seed_paths: dict[str, Path] = {}
        operators = []
        for index, operator_id in enumerate(("operator-a", "operator-b", "operator-c"), 1):
            seed = bytes([index]) * 32
            private = Ed25519PrivateKey.from_private_bytes(seed)
            public = private.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
            seed_path = self.root / f"{operator_id}.seed"
            seed_path.write_text(seed.hex(), encoding="ascii")
            self.seed_paths[operator_id] = seed_path
            operators.append({
                "operator_id": operator_id,
                "organization_id": f"operator-org-{index}",
                "provider_id": f"provider-{index}",
                "region_id": f"region-{index}",
                "key_id": canary.sha256_bytes(public),
                "public_key_base64": base64.b64encode(public).decode("ascii"),
            })
        manifest = {
            "schema": canary.MANIFEST_SCHEMA,
            "manifest_state": "TEST_FIXTURE_NOT_EVIDENCE",
            "canary_id": "g4-fixture",
            "source_revision": REVISION,
            "chain_id": CHAIN_ID,
            "genesis_hash": GENESIS_HASH,
            "eligible_value_atoms": 1_000_000,
            "value_unit": "micro-noos",
            "cap_bps": 10,
            "checkpoint_interval_blocks": 10,
            "required_real_days": 180,
            "target_ids": ["base", "wwm"],
            "operators": operators,
            "signature_threshold": 2,
            "observer_organization_ids": ["observer-a", "observer-b", "observer-c"],
            "independence_limit": "Machine verification does not prove beneficial-owner independence.",
            "production_authorized": False,
            "promotion_effect": "NONE",
            "signatures": [],
        }
        manifest = canary.add_signature(manifest, manifest, "operator-a", self.seed_paths["operator-a"])
        manifest = canary.add_signature(manifest, manifest, "operator-b", self.seed_paths["operator-b"])
        canary.validate_manifest(manifest)
        self.manifest = manifest

    @staticmethod
    def active(target_id: str, exposure: int, new_risk: int = 0) -> dict[str, object]:
        return {
            "target_id": target_id,
            "state": "ACTIVE",
            "exposure_atoms": exposure,
            "new_risk_value_atoms": new_risk,
            "disable_request_height": None,
            "disabled_height": None,
            "recovery_authorization_id": None,
            "recovery_evidence_root": None,
        }

    @staticmethod
    def disabled(target_id: str, request: int = 20, disabled: int = 21) -> dict[str, object]:
        return {
            "target_id": target_id,
            "state": "DISABLED",
            "exposure_atoms": 0,
            "new_risk_value_atoms": 0,
            "disable_request_height": request,
            "disabled_height": disabled,
            "recovery_authorization_id": None,
            "recovery_evidence_root": None,
        }

    @staticmethod
    def recovering(target_id: str, request: int = 20, disabled: int = 21) -> dict[str, object]:
        return {
            "target_id": target_id,
            "state": "RECOVERING",
            "exposure_atoms": 0,
            "new_risk_value_atoms": 0,
            "disable_request_height": request,
            "disabled_height": disabled,
            "recovery_authorization_id": "4" * 64,
            "recovery_evidence_root": "5" * 64,
        }

    def checkpoint(
        self,
        sequence: int,
        targets: list[dict[str, object]],
        previous: dict[str, object] | None,
        *,
        incidents: list[dict[str, object]] | None = None,
        drills: list[dict[str, object]] | None = None,
    ) -> dict[str, object]:
        document: dict[str, object] = {
            "schema": canary.CHECKPOINT_SCHEMA,
            "canary_id": self.manifest["canary_id"],
            "source_revision": REVISION,
            "chain_id": CHAIN_ID,
            "genesis_hash": GENESIS_HASH,
            "sequence": sequence,
            "previous_checkpoint_sha256": "0" * 64 if previous is None else canary.checkpoint_hash(previous),
            "observed_at_utc": f"2026-07-{sequence + 1:02d}T00:00:00Z",
            "finalized_height": (sequence + 1) * 10,
            "target_observations": targets,
            "incidents": incidents or [],
            "drills": drills or [],
            "production_authorized": False,
            "promotion_effect": "NONE",
            "signatures": [],
        }
        return self.resign(document)

    def resign(self, document: dict[str, object]) -> dict[str, object]:
        value = copy.deepcopy(document)
        value["signatures"] = []
        value = canary.add_signature(value, self.manifest, "operator-a", self.seed_paths["operator-a"])
        return canary.add_signature(value, self.manifest, "operator-b", self.seed_paths["operator-b"])

    def full_ledger(self) -> list[dict[str, object]]:
        first = self.checkpoint(0, [self.active("base", 500, 100), self.active("wwm", 300, 50)], None)
        incident = {
            "incident_id": "incident-1",
            "target_id": "base",
            "detected_height": 19,
            "disable_requested_height": 20,
        }
        second = self.checkpoint(
            1,
            [self.active("base", 500), self.active("wwm", 300)],
            first,
            incidents=[incident],
        )
        third = self.checkpoint(
            2,
            [self.disabled("base"), self.active("wwm", 300)],
            second,
        )
        fourth = self.checkpoint(
            3,
            [self.recovering("base"), self.active("wwm", 300)],
            third,
        )
        drills = [
            {
                "drill_id": drill_id,
                "kind": kind,
                "target_id": target,
                "observer_organization_ids": ["observer-a", "observer-b"],
                "verdict": "PASS",
            }
            for drill_id, kind, target in (
                ("disable-drill", "one_checkpoint_disable", "base"),
                ("recovery-drill", "target_recovery", "base"),
                ("wan-drill", "wan", "wwm"),
                ("blackout-drill", "blackout", "base"),
                ("saturation-drill", "saturation", "wwm"),
                ("exit-drill-a", "exit", "base"),
                ("exit-drill-b", "exit", "wwm"),
            )
        ]
        fifth = self.checkpoint(
            4,
            [self.active("base", 200, 100), self.active("wwm", 300, 50)],
            fourth,
            drills=drills,
        )
        return [first, second, third, fourth, fifth]

    def test_full_control_lifecycle_passes_without_promotion_claim(self) -> None:
        report = canary.verify_evidence(self.manifest, self.full_ledger())
        self.assertTrue(report["control_contract_passed"])
        self.assertEqual(report["maximum_exposure_atoms"], 800)
        self.assertEqual(report["maximum_exposure_bps_ceil"], 8)
        self.assertFalse(report["production_authorized"])
        self.assertEqual(report["promotion_effect"], "NONE")
        self.assertEqual(report["duration_gate"], "EXTERNAL_PUBLIC_TIME_VERIFICATION_REQUIRED")

    def test_aggregate_exposure_over_ten_basis_points_rejects(self) -> None:
        first = self.checkpoint(0, [self.active("base", 900), self.active("wwm", 200)], None)
        with self.assertRaisesRegex(canary.CanaryError, "basis-point cap"):
            canary.verify_evidence(self.manifest, [first])

    def test_incident_must_disable_only_the_affected_target_by_next_checkpoint(self) -> None:
        ledger = self.full_ledger()
        delayed = copy.deepcopy(ledger[2])
        delayed["target_observations"][0] = self.active("base", 0)
        delayed = self.resign(delayed)
        with self.assertRaisesRegex(canary.CanaryError, "not disabled by the next checkpoint"):
            canary.verify_evidence(self.manifest, [ledger[0], ledger[1], delayed])
        self.assertEqual(ledger[2]["target_observations"][1]["state"], "ACTIVE")

    def test_disabled_target_cannot_reactivate_without_recovery_state(self) -> None:
        ledger = self.full_ledger()
        direct = self.checkpoint(
            3,
            [self.active("base", 100), self.active("wwm", 300)],
            ledger[2],
        )
        with self.assertRaisesRegex(canary.CanaryError, "illegal target state transition"):
            canary.verify_evidence(self.manifest, [*ledger[:3], direct])

    def test_recovery_cannot_change_disable_lineage(self) -> None:
        ledger = self.full_ledger()
        changed = self.checkpoint(
            3,
            [self.recovering("base", request=21, disabled=21), self.active("wwm", 300)],
            ledger[2],
        )
        with self.assertRaisesRegex(canary.CanaryError, "changed the disable lineage"):
            canary.verify_evidence(self.manifest, [*ledger[:3], changed])

    def test_checkpoint_chain_replay_and_signature_tamper_reject(self) -> None:
        ledger = self.full_ledger()
        replay = copy.deepcopy(ledger[2])
        replay["previous_checkpoint_sha256"] = "0" * 64
        replay = self.resign(replay)
        with self.assertRaisesRegex(canary.CanaryError, "discontinuous"):
            canary.verify_evidence(self.manifest, [ledger[0], ledger[1], replay])
        tampered = copy.deepcopy(ledger[0])
        tampered["signatures"][0]["signature_base64"] = base64.b64encode(bytes(64)).decode("ascii")
        with self.assertRaisesRegex(canary.CanaryError, "invalid signature"):
            canary.verify_evidence(self.manifest, [tampered])

    def test_missing_drills_and_pending_incident_remain_in_progress(self) -> None:
        ledger = self.full_ledger()
        report = canary.verify_evidence(self.manifest, ledger[:2])
        self.assertFalse(report["control_contract_passed"])
        self.assertTrue(any("missing drills" in blocker for blocker in report["blockers"]))
        self.assertTrue(any("pending incidents" in blocker for blocker in report["blockers"]))

    def test_declared_observers_cannot_share_operator_organization(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["observer_organization_ids"] = ["observer-a", "operator-org-1"]
        manifest["signatures"] = []
        manifest = canary.add_signature(manifest, manifest, "operator-a", self.seed_paths["operator-a"])
        manifest = canary.add_signature(manifest, manifest, "operator-b", self.seed_paths["operator-b"])
        with self.assertRaisesRegex(canary.CanaryError, "declared separately"):
            canary.validate_manifest(manifest)

    def test_wrong_seed_duplicate_signature_and_overwrite_refuse(self) -> None:
        wrong = self.root / "wrong.seed"
        wrong.write_text((bytes([9]) * 32).hex(), encoding="ascii")
        unsigned = copy.deepcopy(self.manifest)
        unsigned["signatures"] = []
        with self.assertRaisesRegex(canary.CanaryError, "does not match"):
            canary.add_signature(unsigned, unsigned, "operator-a", wrong)
        with self.assertRaisesRegex(canary.CanaryError, "already signed"):
            canary.add_signature(self.manifest, self.manifest, "operator-a", self.seed_paths["operator-a"])
        output = self.root / "result.json"
        canary.write_new(output, {"ok": True})
        with self.assertRaisesRegex(canary.CanaryError, "overwrite"):
            canary.write_new(output, {"ok": False})

    def test_unknown_fields_and_duplicate_json_keys_reject(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["unexpected"] = True
        with self.assertRaisesRegex(canary.CanaryError, "fields mismatch"):
            canary.validate_manifest(manifest)
        duplicate = self.root / "duplicate.json"
        duplicate.write_text('{"schema":"x","schema":"y"}', encoding="utf-8")
        with self.assertRaisesRegex(canary.CanaryError, "duplicate JSON key"):
            canary.load_json(duplicate)

    def test_cli_verify_writes_immutable_nonpromoting_summary(self) -> None:
        manifest_path = self.root / "manifest.json"
        ledger_path = self.root / "ledger.ndjson"
        output_path = self.root / "summary.json"
        manifest_path.write_bytes(canary.canonical_json(self.manifest) + b"\n")
        ledger_path.write_bytes(b"".join(canary.canonical_json(row) + b"\n" for row in self.full_ledger()))
        self.assertEqual(
            canary.main([
                "verify", "--manifest", str(manifest_path), "--ledger", str(ledger_path),
                "--output", str(output_path),
            ]),
            0,
        )
        summary = json.loads(output_path.read_text(encoding="utf-8"))
        self.assertTrue(summary["control_contract_passed"])
        self.assertFalse(summary["independent_control_established"])
        self.assertFalse(summary["production_authorized"])
        self.assertEqual(summary["promotion_effect"], "NONE")
        self.assertEqual(
            canary.main([
                "verify", "--manifest", str(manifest_path), "--ledger", str(ledger_path),
                "--output", str(output_path),
            ]),
            1,
        )


if __name__ == "__main__":
    unittest.main()
