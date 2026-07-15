from __future__ import annotations

import base64
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.gates import wwm_evidence_bundle as gate
from tools.operations import wwm_web_capacity_pilot as pilot


class WwmWebCapacityPilotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.start = datetime(2024, 1, 1, tzinfo=timezone.utc)
        self.keys = [Ed25519PrivateKey.generate() for _ in range(3)]
        self.roles = [
            "experiment_operator",
            "independent_reproducer",
            "independent_verifier",
        ]
        self.observers = []
        for index, (private, role) in enumerate(zip(self.keys, self.roles, strict=True)):
            public = private.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
            self.observers.append(
                {
                    "observer_id": f"observer-{index}",
                    "role": role,
                    "control_cluster_id": str(index + 1) * 64,
                    "public_key_base64": base64.b64encode(public).decode("ascii"),
                    "key_id": gate.sha256_bytes(public),
                }
            )
        manifest = json.loads(pilot.EXPERIMENT_MANIFEST.read_text(encoding="utf-8"))
        config = {
            "schema": pilot.LEDGER_SCHEMA,
            "experiment_id": "E-WWM-23",
            "model_id": manifest["model_binding"]["artifact_id"],
            "model_source_sha256": manifest["model_binding"]["source_sha256"],
            "source_revision": "a" * 40,
            "evidence_scope": "TEST_FIXTURE",
            "pilot_start_utc": pilot.format_utc(self.start),
            "initialized_at_utc": pilot.format_utc(self.start),
            "controls_enabled": False,
            "production_claim": False,
            "promotion_authorized": False,
            "trusted_observers": self.observers,
            "summary_signer_key_id": self.observers[0]["key_id"],
        }
        self.config_path = self.root / "pilot-config.json"
        self.config_path.write_bytes(pilot.canonical_json(config))
        self.ledger = self.root / "ledger"
        pilot.initialize_ledger(self.ledger, self.config_path)
        self.sequence = 0
        self.last_submitted = self.start
        self.observer_count = 3
        self.digests: dict[str, str] = {}

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def append(
        self,
        kind: str,
        content: dict[str, object] | bytes,
        *,
        observer: int = 0,
        start: datetime | None = None,
        end: datetime | None = None,
        submitted: datetime | None = None,
        forge: bool = False,
        unsigned: bool = False,
    ) -> dict[str, object]:
        self.sequence += 1
        observer %= self.observer_count
        start = start or self.start + timedelta(days=29)
        end = end or start + timedelta(days=1)
        submitted = submitted or max(self.last_submitted, end) + timedelta(seconds=1)
        self.last_submitted = submitted
        data = content if isinstance(content, bytes) else pilot.canonical_json(content)
        artifact = self.root / f"artifact-{self.sequence:04d}.bin"
        artifact.write_bytes(data)
        digest = gate.sha256_bytes(data)
        trusted = self.observers[observer]
        envelope: dict[str, object] = {
            "schema": pilot.ENVELOPE_SCHEMA,
            "envelope_id": "",
            "sequence": self.sequence,
            "experiment_id": "E-WWM-23",
            "model_id": json.loads(self.config_path.read_text(encoding="utf-8"))["model_id"],
            "source_revision": "a" * 40,
            "observed_start_utc": pilot.format_utc(start),
            "observed_end_utc": pilot.format_utc(end),
            "submitted_at_utc": pilot.format_utc(submitted),
            "artifact_kind": kind,
            "content_path": f"observations/{self.sequence:04d}-{kind}.bin",
            "content_sha256": digest,
            "content_bytes": len(data),
            "observer_id": trusted["observer_id"],
            "observer_role": trusted["role"],
            "control_cluster_id": trusted["control_cluster_id"],
            "public_key_base64": trusted["public_key_base64"],
            "key_id": trusted["key_id"],
            "privacy": dict(pilot.REQUIRED_PRIVACY),
            "signature_base64": "",
        }
        envelope["envelope_id"] = pilot.envelope_id(envelope)
        signing_key = self.keys[(observer + 1) % len(self.keys)] if forge else self.keys[observer]
        signature = signing_key.sign(pilot.envelope_message(envelope))
        envelope["signature_base64"] = "" if unsigned else base64.b64encode(signature).decode("ascii")
        envelope_path = self.root / f"envelope-{self.sequence:04d}.json"
        envelope_path.write_bytes(pilot.canonical_json(envelope))
        pilot.append_observation(self.ledger, envelope_path, artifact)
        self.digests[f"{kind}:{self.sequence}"] = digest
        return envelope

    def add_daily_observations(self, *, last_second_short: bool = False, omit_role: bool = False) -> None:
        for day_index in range(30):
            day_start = self.start + timedelta(days=day_index)
            day_end = day_start + timedelta(days=1)
            if last_second_short and day_index == 29:
                day_end -= timedelta(seconds=1)
            observer = day_index % (2 if omit_role else 3)
            self.append(
                "daily_observation",
                {"day_utc": day_start.date().isoformat(), "verdict": "PASS"},
                observer=observer,
                start=day_start,
                end=day_end,
                submitted=day_end,
            )

    def add_support(self, label: str, *, observer: int = 0) -> str:
        self.append(
            "supporting_evidence",
            {"test_fixture": True, "supporting_evidence": label},
            observer=observer,
        )
        return self.digests[f"supporting_evidence:{self.sequence}"]

    def build_complete_fixture(
        self,
        *,
        missing_artifact: str | None = None,
        missing_drill: str | None = None,
        missing_cell: str | None = None,
        omit_role: bool = False,
    ) -> None:
        self.observer_count = 2 if omit_role else 3
        self.add_daily_observations(omit_role=omit_role)
        required_hashes: list[str] = []
        for index, kind in enumerate(sorted(gate.E23_REQUIRED_ARTIFACT_KINDS)):
            if kind == missing_artifact:
                continue
            self.append(
                kind,
                {"test_fixture": True, "artifact_kind": kind, "observation": index + 1},
                observer=index % (2 if omit_role else 3),
            )
            required_hashes.append(self.digests[f"{kind}:{self.sequence}"])
        self.append("second_client_vector", b"fixture second client vector\n", observer=1)

        dependency_e03 = self.add_support("dependency-E-WWM-03", observer=1)
        dependency_e15 = self.add_support("dependency-E-WWM-15", observer=2)
        for requirement_id, evidence_hash, observer in (
            ("E-WWM-03", dependency_e03, 1),
            ("E-WWM-15", dependency_e15, 2),
        ):
            self.append(
                "dependency_receipt",
                {
                    "requirement_id": requirement_id,
                    "source_revision": "a" * 40,
                    "verdict": "PASS",
                    "evidence_sha256": evidence_hash,
                },
                observer=observer,
            )

        reproduction_environment = [
            self.add_support(f"reproduction-{index}-environment", observer=index)
            for index in (0, 1)
        ]
        reproduction_artifact = [
            self.add_support(f"reproduction-{index}-artifact", observer=index)
            for index in (0, 1)
        ]
        for index in (0, 1):
            self.append(
                "reproduction",
                {
                    "operator_id": f"reproducer-{index}",
                    "control_cluster_id": self.observers[index]["control_cluster_id"],
                    "source_revision": "a" * 40,
                    "environment_sha256": reproduction_environment[index],
                    "artifact_sha256": reproduction_artifact[index],
                    "verdict": "PASS",
                },
                observer=index,
            )

        build_hashes = [self.add_support(f"build-{index}", observer=index) for index in (0, 1)]
        for index in (0, 1):
            self.append(
                "reproducible_build",
                {
                    "builder_id": f"builder-{index}",
                    "control_cluster_id": self.observers[index]["control_cluster_id"],
                    "source_revision": "a" * 40,
                    "artifact_sha256": build_hashes[index],
                    "bit_identical": True,
                },
                observer=index,
            )

        funding = self.add_support("red-team-funding", observer=2)
        report = self.add_support("red-team-report", observer=2)
        self.append(
            "red_team_engagement",
            {
                "engagement_id": "red-team-fixture",
                "control_cluster_id": self.observers[2]["control_cluster_id"],
                "funding_proof_sha256": funding,
                "report_sha256": report,
                "severity1_open": 0,
            },
            observer=2,
        )

        for index, drill in enumerate(sorted(gate.E23_REQUIRED_DRILLS)):
            if drill == missing_drill:
                continue
            drill_hash = self.add_support(f"drill-{drill}", observer=index % 3)
            self.append(
                "drill",
                {"kind": drill, "artifact_sha256": drill_hash, "verdict": "PASS"},
                observer=index % 3,
            )

        _, cells = pilot._manifest_contract()
        for index, cell in enumerate(sorted(cells)):
            if cell == missing_cell:
                continue
            self.append(
                "cohort_cell",
                {"cell_id": cell, "verdict": "PASS"},
                observer=index % 3,
            )

        hold = self.add_support("promotion-hold", observer=0)
        self.append(
            "promotion_hold_record",
            {
                "decision": "HOLD",
                "record_sha256": hold,
                "approver_control_clusters": [
                    self.observers[0]["control_cluster_id"],
                    self.observers[1]["control_cluster_id"],
                ],
            },
            observer=0,
        )

    def bundle_attestations(self, candidate: Path) -> list[Path]:
        bundle = gate.load_json(candidate / "bundle.json")
        message = gate.attestation_message(bundle)
        paths = []
        for index, (private, observer) in enumerate(zip(self.keys, self.observers, strict=True)):
            attestation = {
                "operator_id": observer["observer_id"],
                "control_cluster_id": observer["control_cluster_id"],
                "role": observer["role"],
                "external_to_release_owner": True,
                "public_key_base64": observer["public_key_base64"],
                "key_id": observer["key_id"],
                "payload_sha256": gate.sha256_bytes(message),
                "signature_base64": base64.b64encode(private.sign(message)).decode("ascii"),
            }
            path = self.root / f"bundle-attestation-{index}.json"
            path.write_bytes(pilot.canonical_json(attestation))
            paths.append(path)
        return paths

    def test_29_days_23_hours_59_minutes_59_seconds_rejects(self) -> None:
        self.add_daily_observations(last_second_short=True)
        with self.assertRaisesRegex(pilot.PilotError, "under 30 elapsed days"):
            pilot.prepare_candidate_bundle(self.ledger, self.root / "candidate")

    def test_30_days_rejects_each_missing_contract_class(self) -> None:
        cases = (
            ("artifact", "authorized_origin_inventory"),
            ("role", "independent_verifier"),
            ("drill", "storage_pressure"),
            ("cell", "chromium_desktop_opfs"),
        )
        for missing_class, missing_value in cases:
            with self.subTest(missing_class=missing_class):
                self.tearDown()
                self.setUp()
                self.build_complete_fixture(
                    missing_artifact=missing_value if missing_class == "artifact" else None,
                    missing_drill=missing_value if missing_class == "drill" else None,
                    missing_cell=missing_value if missing_class == "cell" else None,
                    omit_role=missing_class == "role",
                )
                with self.assertRaises(pilot.PilotError):
                    pilot.prepare_candidate_bundle(self.ledger, self.root / "candidate")

    def test_forged_unsigned_replayed_and_lab_observations_reject(self) -> None:
        with self.assertRaisesRegex(pilot.PilotError, "forged|invalid"):
            self.append(
                "daily_observation",
                {"day_utc": "2024-01-01", "verdict": "PASS"},
                start=self.start,
                end=self.start + timedelta(days=1),
                submitted=self.start + timedelta(days=1),
                forge=True,
            )
        self.sequence = 0
        self.last_submitted = self.start
        envelope = self.append(
            "daily_observation",
            {"day_utc": "2024-01-01", "verdict": "PASS"},
            start=self.start,
            end=self.start + timedelta(days=1),
            submitted=self.start + timedelta(days=1),
        )
        replay_path = self.root / "replay.json"
        replay_path.write_bytes(pilot.canonical_json(envelope))
        artifact = self.ledger / "artifacts" / envelope["content_sha256"]
        with self.assertRaises(pilot.PilotError):
            pilot.append_observation(self.ledger, replay_path, artifact)

        self.tearDown()
        self.setUp()
        with self.assertRaisesRegex(pilot.PilotError, "missing|wrong length"):
            self.append(
                "daily_observation",
                {"day_utc": "2024-01-01", "verdict": "PASS"},
                start=self.start,
                end=self.start + timedelta(days=1),
                submitted=self.start + timedelta(days=1),
                unsigned=True,
            )
        self.sequence = 0
        self.last_submitted = self.start
        with self.assertRaisesRegex(pilot.PilotError, "lab-scope"):
            self.append(
                "bounded_synthetic_load_report",
                {
                    "schema": gate.E23_LAB_REPORT_SCHEMA,
                    "evidence_scope": gate.E23_LAB_SCOPE,
                    "real_duration": False,
                },
                start=self.start,
                end=self.start + timedelta(days=1),
                submitted=self.start + timedelta(days=1),
            )

    def test_overwrite_time_duplicate_privacy_and_production_reject(self) -> None:
        with self.assertRaisesRegex(pilot.PilotError, "insert-once"):
            pilot.initialize_ledger(self.ledger, self.config_path)

        enabled = json.loads(self.config_path.read_text(encoding="utf-8"))
        enabled["production_claim"] = True
        enabled_path = self.root / "enabled-config.json"
        enabled_path.write_bytes(pilot.canonical_json(enabled))
        with self.assertRaisesRegex(pilot.PilotError, "cannot enable"):
            pilot.initialize_ledger(self.root / "enabled-ledger", enabled_path)

        future = datetime(2035, 1, 1, tzinfo=timezone.utc)
        with self.assertRaisesRegex(pilot.PilotError, "future-dated"):
            self.append(
                "daily_observation",
                {"day_utc": "2035-01-01", "verdict": "PASS"},
                start=future,
                end=future + timedelta(days=1),
                submitted=future + timedelta(days=1),
            )

        self.tearDown()
        self.setUp()
        content = {"day_utc": "2024-01-01", "verdict": "PASS"}
        self.append(
            "daily_observation",
            content,
            start=self.start,
            end=self.start + timedelta(days=1),
            submitted=self.start + timedelta(days=9),
        )
        with self.assertRaisesRegex(pilot.PilotError, "rolled back"):
            self.append(
                "daily_observation",
                {"day_utc": "2024-01-02", "verdict": "PASS"},
                start=self.start + timedelta(days=1),
                end=self.start + timedelta(days=2),
                submitted=self.start + timedelta(days=3),
            )

        self.tearDown()
        self.setUp()
        self.append(
            "daily_observation",
            content,
            start=self.start,
            end=self.start + timedelta(days=1),
            submitted=self.start + timedelta(days=1),
        )
        with self.assertRaisesRegex(pilot.PilotError, "duplicate"):
            self.append(
                "daily_observation",
                content,
                start=self.start + timedelta(days=1),
                end=self.start + timedelta(days=2),
                submitted=self.start + timedelta(days=2),
            )

        self.tearDown()
        self.setUp()
        with self.assertRaisesRegex(pilot.PilotError, "raw identity"):
            self.append(
                "authorized_origin_inventory",
                {"participant_token": "forbidden"},
                start=self.start,
                end=self.start + timedelta(days=1),
                submitted=self.start + timedelta(days=1),
            )
        self.sequence = 0
        self.last_submitted = self.start
        with self.assertRaisesRegex(pilot.PilotError, "enabled-production"):
            self.append(
                "authorized_origin_inventory",
                {"promotion_authorized": True},
                start=self.start,
                end=self.start + timedelta(days=1),
                submitted=self.start + timedelta(days=1),
            )

    def test_fully_signed_fixture_seals_as_non_promoting_test_fixture(self) -> None:
        self.build_complete_fixture()
        preview = self.root / "preview"
        pilot.prepare_candidate_bundle(self.ledger, preview)
        attestations = self.bundle_attestations(preview)
        private_path = self.root / "summary-private.key"
        private_path.write_bytes(
            self.keys[0].private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        )
        sealed = self.root / "sealed"
        summary = pilot.seal_candidate(
            self.ledger,
            sealed,
            attestations,
            private_path,
        )
        self.assertEqual(summary["fixture_label"], "TEST_FIXTURE")
        self.assertEqual(summary["claim_scope"], "EXPERIMENTAL_EVIDENCE_ONLY")
        self.assertFalse(summary["promotion_authorized"])
        self.assertFalse(summary["production_claim"])
        self.assertFalse(summary["controls_enabled"])
        self.assertEqual(summary["elapsed_seconds"], 30 * 24 * 60 * 60)
        observed = gate.verify_bundle_directory(
            sealed,
            expected_revision="a" * 40,
            enforce_pass_policy=True,
        )
        self.assertEqual(observed["result"]["verdict"], "PASS")
        signed_summary = json.loads((sealed / "EvidenceSummary.json").read_text(encoding="utf-8"))
        signature = base64.b64decode(signed_summary.pop("signature_base64"), validate=True)
        public = base64.b64decode(signed_summary["signer_public_key_base64"], validate=True)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        Ed25519PublicKey.from_public_bytes(public).verify(
            signature,
            pilot.SUMMARY_DOMAIN + pilot.canonical_json(signed_summary),
        )
        with self.assertRaisesRegex(pilot.PilotError, "already exists"):
            pilot.seal_candidate(self.ledger, sealed, attestations, private_path)


if __name__ == "__main__":
    unittest.main()
