from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import tarfile
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.operations import wwm_exact_release_evidence as evidence
from tools.operations import wwm_public_testnet_monitor as monitor
from tools.operations import wwm_release_drill as drill


class ExactReleaseEvidenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.revision = "49" * 20
        self.chain_id = "01" * 32
        self.genesis_hash = "8c" * 32
        self.bundle_id = "ba" * 32
        self.monitor_key = Ed25519PrivateKey.generate()
        self.drill_key = Ed25519PrivateKey.generate()
        self.sources = self.make_sources()

    def write_json(self, name: str, value: dict[str, object]) -> Path:
        path = self.root / name
        path.write_bytes(evidence.canonical_json(value) + b"\n")
        return path

    def make_release(self) -> tuple[Path, Path]:
        payload = b"exact noosd fixture\n"
        manifest: dict[str, object] = {
            "schema": "noos/wwm-public-testnet-release-bundle/v1",
            "source": {"revision": self.revision, "tree": "22" * 20, "source_date_epoch": 1},
            "chain_binding": {"chain_id": self.chain_id, "genesis_hash": self.genesis_hash},
            "boundary": {
                "environment": "public-testnet",
                "evidence_class": "OWNER_CONTROLLED_TESTNET_RELEASE",
                "independent_reproduction": False,
                "production": False,
                "production_capable": False,
                "promotion_effect": "NONE",
            },
            "build": {
                "source_revision_env": self.revision,
                "release_version_env": f"0.1.0+git.{self.revision}",
            },
            "bundle_id": self.bundle_id,
            "files": [
                {
                    "path": "bin/noosd",
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "component": "node",
                }
            ],
        }
        manifest_path = self.write_json("release-manifest.json", manifest)
        archive_path = self.root / "linux-release.tgz"
        with tarfile.open(archive_path, "w:gz") as archive:
            for name, content in (
                ("release-manifest.json", manifest_path.read_bytes()),
                ("bin/noosd", payload),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(content)
                info.mode = 0o755 if name.startswith("bin/") else 0o644
                archive.addfile(info, io.BytesIO(content))
        return manifest_path, archive_path

    def make_monitor_evidence(self) -> tuple[Path, Path]:
        public = monitor.public_key_bytes(self.monitor_key)
        signer_key_id = hashlib.sha256(public).hexdigest()
        deployment = "81" * 32
        started = datetime(2026, 7, 27, tzinfo=timezone.utc)
        samples: list[dict[str, object]] = []
        previous: str | None = None
        for index in range(1441):
            observed = started + timedelta(seconds=index * 60)
            payload: dict[str, object] = {
                "schema": monitor.SAMPLE_SCHEMA,
                "environment": "public-testnet",
                "production": False,
                "production_authorized": False,
                "promotion_effect": "NONE",
                "source_revision": self.revision,
                "release_version": f"0.1.0+git.{self.revision}",
                "deployment_sha256": deployment,
                "status": "ok",
                "observed_at_utc": observed.isoformat().replace("+00:00", "Z"),
                "previous_sample_id": previous,
                "checks": [
                    {
                        "name": "network_coherence",
                        "ok": True,
                        "latency_ms": 5,
                        "detail": {"validator_count": 4, "validator_min_height": 300000 + index},
                    },
                    {
                        "name": "gateway",
                        "ok": True,
                        "latency_ms": 2,
                        "detail": {"unsafe_height": 300000 + index},
                    },
                ],
            }
            sample = monitor.sign_payload(payload, self.monitor_key, monitor.SAMPLE_DOMAIN, "sample_id")
            samples.append(sample)
            previous = str(sample["sample_id"])
        ledger_path = self.root / "monitor-samples.jsonl"
        ledger_path.write_bytes(b"".join(monitor.canonical_json(sample) + b"\n" for sample in samples))
        burn = {
            "schema": "noos/wwm-signed-monitor-burn-in-result/v1",
            "result": "PASS",
            "release": {
                "source_revision": self.revision,
                "release_version": f"0.1.0+git.{self.revision}",
                "deployment_sha256": deployment,
            },
            "signer_key_id": signer_key_id,
            "observed_at_utc": samples[-1]["observed_at_utc"],
            "first_observed_at_utc": samples[0]["observed_at_utc"],
            "last_observed_at_utc": samples[-1]["observed_at_utc"],
            "observed_span_seconds": 86400,
            "maximum_sample_gap_seconds": 60.0,
            "sample_count": len(samples),
            "first_sample_id": samples[0]["sample_id"],
            "last_sample_id": samples[-1]["sample_id"],
            "check_names": ["gateway", "network_coherence"],
            "expected_check_count": 2,
            "wall_elapsed_seconds": 86401,
            "ledger": {
                "path": str(ledger_path),
                "bytes": ledger_path.stat().st_size,
                "sha256": evidence.sha256_file(ledger_path),
            },
            "acceptance": {
                "all_monitor_checks_passed": True,
                "elapsed_full_duration": True,
                "every_observed_sample_exact_release": True,
                "every_observed_sample_signature_valid": True,
                "production_boundary_fail_closed": True,
                "restart_recovery_supported": True,
                "sample_gap_within_bound": True,
                "sample_hash_chain_continuous": True,
            },
        }
        return self.write_json("burn-in.json", burn), ledger_path

    def signed_drill(self, kind: str) -> dict[str, object]:
        replay = {"finalized-record": {"bytes": 100, "canonical_sha256": "55" * 32}}
        authorization_sha256 = "33" * 32
        if kind == "ROLLING_RESTART":
            definitions = [
                ("restart-observer", "observer-1", "observer", "RESTART"),
                ("restart-witness-1", "witness-1", "witness", "RESTART"),
                ("restart-witness-2", "witness-2", "witness", "RESTART"),
                ("restart-witness-3", "witness-3", "witness", "RESTART"),
            ]
            prior_revision: str | None = None
        else:
            definitions = [
                ("activate-prior", "witness-3", "witness", "ACTIVATE_PRIOR"),
                ("activate-current", "witness-3", "witness", "ACTIVATE_CURRENT"),
            ]
            prior_revision = "2b" * 20
        baseline_sample = "70" * 32
        previous_sample = baseline_sample
        previous_coordinates = {
            "validator_count": 4,
            "validator_min_height": 300000,
            "validator_max_height": 300001,
            "finalized_epoch": 1200,
        }
        steps: list[dict[str, object]] = []
        state_identities: dict[str, str] = {}
        for index, (step_id, participant, role, action) in enumerate(definitions, 1):
            post_sample = index.to_bytes(32, "big").hex()
            post_coordinates = {
                "validator_count": 4,
                "validator_min_height": 300000 + index,
                "validator_max_height": 300001 + index,
                "finalized_epoch": 1200 + index // 2,
            }
            identity = hashlib.sha256(participant.encode()).hexdigest()
            state_identities[participant] = identity
            before = self.revision
            after = self.revision
            adapter_authorization = None
            if action == "ACTIVATE_PRIOR":
                after = str(prior_revision)
                adapter_authorization = authorization_sha256
            elif action == "ACTIVATE_CURRENT":
                before = str(prior_revision)
                adapter_authorization = authorization_sha256
            adapter = {
                "schema": drill.ADAPTER_SCHEMA,
                "step_id": step_id,
                "participant_id": participant,
                "action": action,
                "process": {
                    "identity": f"service:{participant}",
                    "pid_before": 1000 + index * 2,
                    "pid_after": 1001 + index * 2,
                    "peak_rss_bytes": 1000000,
                },
                "release": {
                    "before_revision": before,
                    "after_revision": after,
                    "binary_sha256": index.to_bytes(32, "big").hex(),
                },
                "durable_state": {"identity_sha256": identity, "reset": False, "deleted": False},
                "authorization_sha256": adapter_authorization,
            }
            steps.append(
                {
                    "step_id": step_id,
                    "participant_id": participant,
                    "role": role,
                    "action": action,
                    "adapter": adapter,
                    "pre_coordinates": previous_coordinates,
                    "post_coordinates": post_coordinates,
                    "pre_sample_id": previous_sample,
                    "post_sample_id": post_sample,
                    "observation_gap_seconds": 60,
                    "replay": replay,
                }
            )
            previous_sample = post_sample
            previous_coordinates = post_coordinates
        body = {
            "drill_id": "11" * 32 if kind == "ROLLING_RESTART" else "12" * 32,
            "kind": kind,
            "plan_sha256": "31" * 32,
            "chain_id": self.chain_id,
            "genesis_hash": self.genesis_hash,
            "current_revision": self.revision,
            "prior_revision": prior_revision,
            "authorization_key_id": "32" * 32,
            "authorization_sha256": authorization_sha256,
            "baseline_sample_id": baseline_sample,
            "final_sample_id": previous_sample,
            "durable_state_identities": state_identities,
            "replay_baseline": replay,
            "steps": steps,
            "verdict": "PASS",
            "production": False,
            "promotion_effect": "NONE",
        }
        public = self.drill_key.public_key().public_bytes_raw()
        document = {
            "schema": drill.RESULT_SCHEMA,
            "body": body,
            "attestation": {
                "key_id": hashlib.sha256(public).hexdigest(),
                "public_key_base64": base64.b64encode(public).decode("ascii"),
                "signature_base64": base64.b64encode(self.drill_key.sign(drill.EVIDENCE_DOMAIN + drill.canonical_json(body))).decode("ascii"),
            },
        }
        drill.verify_result(document)
        return document

    def make_sources(self) -> dict[str, Path]:
        release_manifest, release_archive = self.make_release()
        ci = {
            "schema": "noos/wwm-ci-release-result/v1",
            "result": "PASS",
            "workflow": {"head_sha": self.revision, "conclusion": "success"},
            "artifact": {
                "bundle_id": self.bundle_id,
                "verified_locally": True,
                "archive_digest": "sha256:" + "61" * 32,
            },
            "reproducibility": {"independent_reproduction_claimed": False},
        }
        release_test = {
            "schema": "noos/wwm-release-test-result/v1",
            "result": "PASS",
            "release": {"source_revision": self.revision, "release_version": f"0.1.0+git.{self.revision}"},
            "acceptance": {"exact_release_workflow_passed": True, "signed_receipt_contract_passed": True},
        }
        fleet = {
            "schema": "noos/exact-public-testnet-fleet-convergence-result/v1",
            "result": "PASS",
            "release": {"source_revision": self.revision, "release_version": f"0.1.0+git.{self.revision}"},
            "acceptance": {
                "exact_release_identity_on_all_nodes": True,
                "finalized_checkpoint_converged": True,
                "justified_checkpoint_converged": True,
                "memory_within_all_envelopes": True,
                "service_restart_counts_clean": True,
                "unsafe_heads_converged": True,
            },
        }
        burn_in, ledger = self.make_monitor_evidence()
        return {
            "release_manifest": release_manifest,
            "release_archive": release_archive,
            "ci_release_result": self.write_json("ci-release-result.json", ci),
            "release_test_result": self.write_json("release-test-result.json", release_test),
            "fleet_convergence": self.write_json("fleet-convergence.json", fleet),
            "burn_in": burn_in,
            "rolling_restart": self.write_json("rolling-restart.json", self.signed_drill("ROLLING_RESTART")),
            "rollback": self.write_json("rollback.json", self.signed_drill("PRESERVED_BUILD_ROLLBACK")),
            "monitor_ledger": ledger,
        }

    def test_seals_and_reverifies_immutable_exact_release_bundle(self) -> None:
        output = self.root / "sealed"
        manifest = evidence.seal(
            self.sources,
            output,
            self.revision,
            self.chain_id,
            self.genesis_hash,
            bytes.fromhex("51" * 32),
        )
        body = evidence.verify_directory(output)
        self.assertEqual(body["bundle_id"], manifest["body"]["bundle_id"])
        self.assertEqual(len(body["artifacts"]), len(evidence.ARTIFACT_FILENAMES))
        self.assertTrue(body["acceptance"]["continuous_signed_24h_burn_in"])
        self.assertFalse(body["independent_reproduction_claimed"])

    def test_verifier_rejects_tampered_artifact(self) -> None:
        output = self.root / "sealed-tamper"
        evidence.seal(
            self.sources,
            output,
            self.revision,
            self.chain_id,
            self.genesis_hash,
            bytes.fromhex("52" * 32),
        )
        ledger = output / evidence.ARTIFACT_FILENAMES["monitor_ledger"]
        ledger.write_bytes(ledger.read_bytes() + b"{}\n")
        with self.assertRaisesRegex(evidence.EvidenceError, "artifact integrity mismatch"):
            evidence.verify_directory(output)

    def test_rejects_short_or_identity_mismatched_evidence(self) -> None:
        short_sources = dict(self.sources)
        short = copy.deepcopy(json.loads(self.sources["burn_in"].read_text()))
        short["observed_span_seconds"] = 86399
        short_sources["burn_in"] = self.write_json("short-burn-in.json", short)
        with self.assertRaisesRegex(evidence.EvidenceError, "24 continuous hours"):
            evidence.seal(
                short_sources,
                self.root / "short-output",
                self.revision,
                self.chain_id,
                self.genesis_hash,
                bytes.fromhex("53" * 32),
            )

        wrong_sources = dict(self.sources)
        wrong_fleet = copy.deepcopy(json.loads(self.sources["fleet_convergence"].read_text()))
        wrong_fleet["release"]["source_revision"] = "aa" * 20
        wrong_sources["fleet_convergence"] = self.write_json("wrong-fleet.json", wrong_fleet)
        with self.assertRaisesRegex(evidence.EvidenceError, "release identity"):
            evidence.seal(
                wrong_sources,
                self.root / "wrong-output",
                self.revision,
                self.chain_id,
                self.genesis_hash,
                bytes.fromhex("54" * 32),
            )


if __name__ == "__main__":
    unittest.main()
