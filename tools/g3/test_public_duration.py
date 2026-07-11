#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import datetime as dt
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("public_duration", ROOT / "tools/g3/public_duration.py")
assert SPEC and SPEC.loader
G3 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(G3)


class PublicDurationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temp = tempfile.TemporaryDirectory(prefix="noos-g3-tests-")
        cls.tmp = Path(cls.temp.name)
        cls.keys: dict[str, tuple[Path, str]] = {}
        for operator_id in ("operator-a", "operator-b", "operator-c"):
            private = cls.tmp / f"{operator_id}.private.pem"
            public = cls.tmp / f"{operator_id}.public.pem"
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(private)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public)], check=True, capture_output=True)
            cls.keys[operator_id] = (private, public.read_text(encoding="ascii"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temp.cleanup()

    def setUp(self) -> None:
        self.manifest = json.loads((ROOT / "deploy/g3/public-testnet.manifest.template.json").read_text(encoding="utf-8"))
        self.manifest["manifest_state"] = "TEST_FIXTURE_NOT_EVIDENCE"
        self.manifest["network"].update(network_id="g3-test-fixture", chain_id="1" * 64, genesis_hash="2" * 64)
        self.manifest["release_binding"].update(exact_revision="3" * 40, release_manifest_path="fixture-only.json", release_manifest_sha256="4" * 64)
        for index, operator in enumerate(self.manifest["operators"]):
            operator_id = operator["operator_id"]
            operator.update(
                organization=f"Test fixture operator {index}",
                region=f"test-region-{index}",
                infrastructure_provider=f"test-provider-{index}",
                network_carrier=f"test-carrier-{index}",
                key_id=f"test-key-{index}",
                key_usage="TEST_ONLY",
                public_key_pem=self.keys[operator_id][1],
            )
        self.manifest["operators"][2]["client_family"] = "third-test-client"
        self.now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        G3.validate_manifest(self.manifest)

    def checkpoint(self, sequence: int, observed: dt.datetime, previous: dict | None = None, *, ai_enabled: bool = True) -> dict:
        observed_text = G3.format_utc(observed)
        start_text = G3.format_utc(observed - dt.timedelta(days=1))
        checkpoint = {
            "schema_version": 1,
            "record_kind": "noos-g3-daily-checkpoint",
            "network_id": self.manifest["network"]["network_id"],
            "manifest_sha256": G3.manifest_hash(self.manifest),
            "exact_revision": self.manifest["release_binding"]["exact_revision"],
            "sequence": sequence,
            "previous_checkpoint_sha256": "0" * 64 if previous is None else G3.checkpoint_hash(previous),
            "wall_clock": {
                "observed_at_utc": observed_text,
                "unix_time_ns": int(observed.timestamp() * 1_000_000_000),
                "monotonic_time_ns": 10_000_000_000 + sequence * 86_400_000_000_000,
                "clock_id": "test-boot-id",
                "clock_source": "system_utc_plus_monotonic",
                "time_mode": "REAL_WALL_CLOCK",
            },
            "lane_observations": [
                {
                    "lane_id": lane["lane_id"],
                    "state": "ACTIVE",
                    "telemetry_sequence": sequence + 1,
                    "sample_count": 5760,
                    "window_start_utc": start_text,
                    "window_end_utc": observed_text,
                    "maximum_sample_gap_seconds": 30,
                    "discontinuities": 0,
                }
                for lane in self.manifest["lanes"]
            ],
            "operator_observations": [
                {
                    "operator_id": operator["operator_id"],
                    "telemetry_url": operator["telemetry_url"],
                    "observed_at_utc": observed_text,
                    "telemetry_sequence": sequence + 1,
                    "chain_height": 1000 + sequence * 100,
                    "finalized_height": 990 + sequence * 100,
                    "telemetry_sha256": f"{index + 5:x}" * 64,
                    "ai_processes_enabled": ai_enabled,
                }
                for index, operator in enumerate(self.manifest["operators"])
            ],
            "drill_observations": [],
            "signatures": [],
        }
        digest = G3.payload_hash(checkpoint)
        for operator_id in ("operator-a", "operator-b"):
            signed_at = G3.format_utc(observed + dt.timedelta(minutes=5))
            raw = G3.sign_ed25519(self.keys[operator_id][0], G3.signature_message(digest, operator_id, signed_at))
            operator = next(item for item in self.manifest["operators"] if item["operator_id"] == operator_id)
            checkpoint["signatures"].append({
                "operator_id": operator_id,
                "key_id": operator["key_id"],
                "algorithm": "ed25519",
                "payload_sha256": digest,
                "signed_at_utc": signed_at,
                "signature_base64": base64.b64encode(raw).decode("ascii"),
            })
        return checkpoint

    def assert_rejected(self, checkpoint: dict, previous: dict | None, needle: str) -> None:
        with self.assertRaisesRegex(G3.EvidenceError, needle):
            G3.verify_checkpoint(self.manifest, checkpoint, previous, now=self.now + dt.timedelta(days=2))

    def test_template_is_honestly_not_started(self) -> None:
        template = json.loads((ROOT / "deploy/g3/public-testnet.manifest.template.json").read_text(encoding="utf-8"))
        result = G3.verify_evidence(template, [], now=self.now)
        self.assertEqual(result["status"], "NOT_STARTED")
        self.assertEqual(result["promotion_effect"], "NONE")

    def test_valid_signed_monotonic_chain(self) -> None:
        first = self.checkpoint(0, self.now - dt.timedelta(days=1))
        second = self.checkpoint(1, self.now, first)
        G3.verify_checkpoint(self.manifest, first, None, now=self.now)
        G3.verify_checkpoint(self.manifest, second, first, now=self.now)

    def test_rejects_revision_change_and_hash_chain_rewrite(self) -> None:
        first = self.checkpoint(0, self.now - dt.timedelta(days=1))
        changed = self.checkpoint(1, self.now, first)
        changed["exact_revision"] = "9" * 40
        self.assert_rejected(changed, first, "revision binding changed")
        rewritten = self.checkpoint(1, self.now, first)
        rewritten["previous_checkpoint_sha256"] = "0" * 64
        self.assert_rejected(rewritten, first, "hash chain is broken")

    def test_rejects_simulated_time_backdating_gap_and_clock_rollback(self) -> None:
        first = self.checkpoint(0, self.now - dt.timedelta(days=1))
        simulated = copy.deepcopy(first); simulated["wall_clock"]["time_mode"] = "SIMULATED"
        self.assert_rejected(simulated, None, "simulated")
        backdated = self.checkpoint(1, self.now - dt.timedelta(days=2), first)
        self.assert_rejected(backdated, first, "rolled back|backdated")
        gap = self.checkpoint(1, self.now + dt.timedelta(hours=3), first)
        self.assert_rejected(gap, first, "gap exceeds")
        rollback = self.checkpoint(1, self.now, first)
        rollback["wall_clock"]["monotonic_time_ns"] = first["wall_clock"]["monotonic_time_ns"]
        self.assert_rejected(rollback, first, "monotonic clock rolled back")

    def test_rejects_missing_independent_signature_and_test_keys_for_active_run(self) -> None:
        checkpoint = self.checkpoint(0, self.now)
        checkpoint["signatures"] = checkpoint["signatures"][:1]
        self.assert_rejected(checkpoint, None, "lacks independent operator signatures")

        active = copy.deepcopy(self.manifest)
        active["manifest_state"] = "ACTIVE"
        release_path = self.tmp / "release-manifest.json"
        release = {
            "release": {"protocol_version": "v1", "api_version": "v1"},
            "source": {"repo_revision": active["release_binding"]["exact_revision"]},
            "identity": {"chain_id": active["network"]["chain_id"], "genesis_hash": active["network"]["genesis_hash"]},
        }
        release_path.write_text(json.dumps(release), encoding="utf-8")
        active["release_binding"]["release_manifest_path"] = str(release_path)
        active["release_binding"]["release_manifest_sha256"] = G3.sha256_file(release_path)
        with self.assertRaisesRegex(G3.EvidenceError, "test-only keys"):
            G3.validate_manifest(active)

    def test_rejects_private_only_endpoint(self) -> None:
        private = copy.deepcopy(self.manifest)
        private["operators"][0]["telemetry_url"] = "https://127.0.0.1/snapshot.json"
        with self.assertRaisesRegex(G3.EvidenceError, "non-public IP|private-only"):
            G3.validate_manifest(private)

    def test_rejects_telemetry_discontinuity_and_counter_rollback(self) -> None:
        first = self.checkpoint(0, self.now - dt.timedelta(days=1))
        discontinuous = self.checkpoint(1, self.now, first)
        discontinuous["lane_observations"][0]["telemetry_sequence"] = 1
        self.assert_rejected(discontinuous, first, "telemetry sequence/window is discontinuous")
        counters = self.checkpoint(1, self.now, first)
        counters["operator_observations"][0]["chain_height"] = 999
        counters["operator_observations"][0]["finalized_height"] = 998
        self.assert_rejected(counters, first, "telemetry counter rolled back")

    def test_rejects_noncanonical_or_gapped_ledger(self) -> None:
        path = self.tmp / "bad-ledger.ndjson"
        path.write_text('{ "sequence": 0 }\n', encoding="utf-8")
        with self.assertRaisesRegex(G3.EvidenceError, "not canonical"):
            G3.read_ledger(path)
        path.write_text("{}\n\n", encoding="utf-8")
        with self.assertRaisesRegex(G3.EvidenceError, "blank"):
            G3.read_ledger(path)

    def test_lane_classification_is_exactly_30_and_90_real_days(self) -> None:
        classes = {lane["classification"]: lane["required_real_days"] for lane in self.manifest["lanes"]}
        self.assertEqual(classes, {"application": 30, "cryptographic_economic": 90})
        weakened = copy.deepcopy(self.manifest)
        weakened["lanes"][0]["required_real_days"] = 89
        with self.assertRaisesRegex(G3.EvidenceError, "30/90-day"):
            G3.validate_manifest(weakened)


if __name__ == "__main__":
    unittest.main()
