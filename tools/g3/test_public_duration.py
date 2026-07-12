#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import datetime as dt
import importlib.util
import io
import json
import subprocess
import tempfile
import unittest
from argparse import Namespace
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

    def checkpoint(self, sequence: int, observed: dt.datetime, previous: dict | None = None, *, ai_enabled: bool = True, published: dt.datetime | None = None) -> dict:
        observed_text = G3.format_utc(observed)
        start_text = G3.format_utc(observed - dt.timedelta(days=1))
        checkpoint = {
            "schema_version": 2,
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
            "external_timestamp_receipt": None,
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
        publication_text = G3.format_utc(published or (observed + dt.timedelta(minutes=10)))
        checkpoint["external_timestamp_receipt"] = {
            "receipt_version": 1,
            "system": "TEST_ONLY-deterministic",
            "commitment_sha256": G3.timestamp_commitment(checkpoint),
            "publication_time_utc": publication_text,
            "proof_sha256": G3.test_receipt_proof(checkpoint, publication_text),
        }
        return checkpoint

    def ots_receipt(self, checkpoint: dict, *, height: int = 800000) -> dict:
        from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.serialize import StreamSerializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

        commitment = G3.timestamp_commitment(checkpoint)
        detached = DetachedTimestampFile(OpSHA256(), Timestamp(bytes.fromhex(commitment)))
        detached.timestamp.attestations.add(BitcoinBlockHeaderAttestation(height))
        output = io.BytesIO()
        detached.serialize(StreamSerializationContext(output))
        return {
            "receipt_version": 1,
            "system": "opentimestamps-bitcoin",
            "bitcoin_network": "mainnet",
            "commitment_sha256": commitment,
            "proof_base64": base64.b64encode(output.getvalue()).decode("ascii"),
        }

    def active_manifest(self) -> dict:
        manifest = copy.deepcopy(self.manifest)
        manifest["manifest_state"] = "ACTIVE"
        for operator in manifest["operators"]:
            operator["key_usage"] = "production-evidence"
        release_path = self.tmp / "active-release-manifest.json"
        release = {
            "release": {"protocol_version": "v1", "api_version": "v1"},
            "source": {"repo_revision": manifest["release_binding"]["exact_revision"]},
            "identity": {
                "chain_id": manifest["network"]["chain_id"],
                "genesis_hash": manifest["network"]["genesis_hash"],
            },
        }
        release_path.write_text(json.dumps(release), encoding="utf-8")
        manifest["release_binding"]["release_manifest_path"] = str(release_path)
        manifest["release_binding"]["release_manifest_sha256"] = G3.sha256_file(release_path)
        digest = G3.manifest_signature_payload_hash(manifest)
        for operator_id in ("operator-a", "operator-b"):
            signed_at = G3.format_utc(self.now)
            raw = G3.sign_ed25519(
                self.keys[operator_id][0],
                G3.signature_message(digest, operator_id, signed_at, "exact-revision-manifest"),
            )
            operator = next(item for item in manifest["operators"] if item["operator_id"] == operator_id)
            manifest["manifest_signatures"].append({
                "operator_id": operator_id,
                "key_id": operator["key_id"],
                "algorithm": "ed25519",
                "payload_sha256": digest,
                "signed_at_utc": signed_at,
                "signature_base64": base64.b64encode(raw).decode("ascii"),
            })
        G3.validate_manifest(manifest)
        return manifest

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

    def test_valid_fixture_duration_comes_from_receipt_times(self) -> None:
        first = self.checkpoint(0, self.now - dt.timedelta(days=2), published=self.now - dt.timedelta(days=2, minutes=-20))
        second = self.checkpoint(1, self.now - dt.timedelta(days=1), first, published=self.now - dt.timedelta(days=1, minutes=-20))
        third = self.checkpoint(2, self.now, second, published=self.now + dt.timedelta(minutes=20))
        result = G3.verify_evidence(self.manifest, [first, second, third], now=self.now)
        self.assertEqual(result["status"], "IN_PROGRESS")
        self.assertEqual(result["qualifying_real_days"], 2.0)
        self.assertTrue(any("TEST_ONLY" in blocker for blocker in result["blockers"]))

    def test_retrospective_90_day_chain_first_anchored_now_is_rejected(self) -> None:
        backdated = self.checkpoint(0, self.now - dt.timedelta(days=90), published=self.now)
        self.assert_rejected(backdated, None, "publication time is too late")

    def test_fresh_append_without_external_receipt_is_rejected(self) -> None:
        checkpoint = self.checkpoint(0, self.now)
        checkpoint["external_timestamp_receipt"] = None
        manifest_path = self.tmp / "fixture-manifest.json"
        checkpoint_path = self.tmp / "unstamped-checkpoint.json"
        ledger_path = self.tmp / "unstamped-ledger.ndjson"
        manifest_path.write_text(json.dumps(self.manifest), encoding="utf-8")
        checkpoint_path.write_text(json.dumps(checkpoint), encoding="utf-8")
        with self.assertRaisesRegex(G3.EvidenceError, "external publication-time receipt"):
            G3.append_checkpoint(Namespace(
                manifest=manifest_path, checkpoint=checkpoint_path, ledger=ledger_path,
                bitcoin_rpc_url="http://127.0.0.1:8332",
            ))

    def test_receipt_replay_across_checkpoint_is_rejected(self) -> None:
        first = self.checkpoint(0, self.now - dt.timedelta(days=1))
        second = self.checkpoint(1, self.now, first)
        second["external_timestamp_receipt"] = copy.deepcopy(first["external_timestamp_receipt"])
        self.assert_rejected(second, first, "receipt|binding")

        changed_manifest = copy.deepcopy(self.manifest)
        changed_manifest["manifest_signatures"].append({"different": "signer-set"})
        with self.assertRaisesRegex(G3.EvidenceError, "manifest/revision binding"):
            G3.verify_checkpoint(changed_manifest, first, None, now=self.now)

        reordered_signers = copy.deepcopy(first)
        reordered_signers["signatures"].reverse()
        self.assertNotEqual(G3.timestamp_commitment(first), G3.timestamp_commitment(reordered_signers))

    def test_wall_and_external_anchor_divergence_is_rejected(self) -> None:
        divergent = self.checkpoint(0, self.now - dt.timedelta(days=3), published=self.now)
        self.assert_rejected(divergent, None, "publication time is too late")

    def test_active_offline_verification_can_never_complete(self) -> None:
        active = self.active_manifest()
        original = self.manifest
        try:
            self.manifest = active
            checkpoint = self.checkpoint(0, self.now)
        finally:
            self.manifest = original
        checkpoint["external_timestamp_receipt"] = self.ots_receipt(checkpoint)
        result = G3.verify_evidence(active, [checkpoint], now=self.now, live_trust=False)
        self.assertEqual(result["status"], "IN_PROGRESS")
        self.assertEqual(result["qualifying_real_days"], 0)
        self.assertTrue(any("live Bitcoin-mainnet trust-root" in blocker for blocker in result["blockers"]))

    def test_production_receipt_rejects_testnet_unconfirmed_and_offline_trust(self) -> None:
        checkpoint = self.checkpoint(0, self.now)
        active_stub = copy.deepcopy(self.manifest)
        active_stub["manifest_state"] = "ACTIVE"
        with self.assertRaisesRegex(G3.EvidenceError, "fields mismatch"):
            G3.verify_external_receipt(active_stub, checkpoint, live_trust=False, bitcoin_rpc=None)
        checkpoint["external_timestamp_receipt"] = self.ots_receipt(checkpoint)

        testnet = copy.deepcopy(checkpoint)
        testnet["external_timestamp_receipt"]["bitcoin_network"] = "testnet"
        with self.assertRaisesRegex(G3.EvidenceError, "network binding"):
            G3.verify_external_receipt(active_stub, testnet, live_trust=False, bitcoin_rpc=None)

        from opentimestamps.core.notary import PendingAttestation
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.serialize import StreamSerializationContext
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
        pending = DetachedTimestampFile(OpSHA256(), Timestamp(bytes.fromhex(G3.timestamp_commitment(checkpoint))))
        pending.timestamp.attestations.add(PendingAttestation("https://calendar.example.test"))
        pending_bytes = io.BytesIO(); pending.serialize(StreamSerializationContext(pending_bytes))
        unconfirmed = copy.deepcopy(checkpoint)
        unconfirmed["external_timestamp_receipt"]["proof_base64"] = base64.b64encode(pending_bytes.getvalue()).decode("ascii")
        with self.assertRaisesRegex(G3.EvidenceError, "unconfirmed"):
            G3.verify_external_receipt(active_stub, unconfirmed, live_trust=False, bitcoin_rpc=None)

        offline = G3.verify_external_receipt(active_stub, checkpoint, live_trust=False, bitcoin_rpc=None)
        self.assertIsNone(offline["publication_time"])
        self.assertFalse(offline["trusted"])
        with self.assertRaisesRegex(G3.EvidenceError, "verifier-controlled Bitcoin Core"):
            G3.verify_external_receipt(active_stub, checkpoint, live_trust=True, bitcoin_rpc=None)

        commitment_bytes = bytes.fromhex(G3.timestamp_commitment(checkpoint))
        publication_unix = int((self.now + dt.timedelta(minutes=10)).timestamp())

        class FixtureBitcoinRPC:
            def verify_mainnet(self) -> int:
                return 800005

            def active_block_header(self, height: int, tip_height: int) -> tuple[object, int]:
                header = type("Header", (), {})()
                header.hashMerkleRoot = commitment_bytes
                header.nTime = publication_unix
                return header, tip_height - height + 1

        live = G3.verify_external_receipt(
            active_stub, checkpoint, live_trust=True, bitcoin_rpc=FixtureBitcoinRPC()
        )
        self.assertTrue(live["trusted"])
        self.assertEqual(live["publication_time"], dt.datetime.fromtimestamp(publication_unix, tz=dt.timezone.utc))

        class UnderconfirmedBitcoinRPC(FixtureBitcoinRPC):
            def active_block_header(self, height: int, tip_height: int) -> tuple[object, int]:
                header, _ = super().active_block_header(height, tip_height)
                return header, 5

        with self.assertRaisesRegex(G3.EvidenceError, "fewer than 6"):
            G3.verify_external_receipt(
                active_stub, checkpoint, live_trust=True, bitcoin_rpc=UnderconfirmedBitcoinRPC()
            )

        class UntrustedBitcoinRPC(FixtureBitcoinRPC):
            def verify_mainnet(self) -> int:
                raise G3.EvidenceError("Bitcoin Core mainnet genesis trust root mismatch")

        with self.assertRaisesRegex(G3.EvidenceError, "trust root mismatch"):
            G3.verify_external_receipt(
                active_stub, checkpoint, live_trust=True, bitcoin_rpc=UntrustedBitcoinRPC()
            )

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
