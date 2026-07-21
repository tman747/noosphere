from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import wwm_hosted_model_demo as demo
import wwm_neural_publisher as publisher


CHAIN_ID = "11" * 32
GENESIS_HASH = "22" * 32
JOB_ID = "31" * 32
RECEIPT_ID = "32" * 32
SETTLEMENT_ID = "33" * 32
OPEN_TXID = "41" * 32
CLOSE_TXID = "42" * 32
OUTPUT_ROOT = "51" * 32
TOKEN_ROOT = "52" * 32
BLOCK_HASH = "61" * 32


def manifest_fixture() -> dict[str, object]:
    return {
        "schema": publisher.MANIFEST_SCHEMA,
        "environment": "public-testnet",
        "production": False,
        "promotion_effect": "NONE",
        "chain_id": CHAIN_ID,
        "genesis_hash": GENESIS_HASH,
        "title": "Bonsai Live / Finalized Activity",
        "description": "fixture",
        "model": {
            "alias": "bonsai-q1",
            "name": "Bonsai-27B-Q1_0.gguf",
            "artifact_id": demo.ARTIFACT_ID,
            "artifact_sha256": demo.MODEL_SHA256,
            "manifest_root": demo.MANIFEST_ROOT,
            "capsule_id": "71" * 32,
            "execution_profile_id": "72" * 32,
            "query_policy_id": "73" * 32,
            "availability_certificate_id": "74" * 32,
            "fund_profile_id": "75" * 32,
        },
        "activity": [
            {
                "sequence": 1,
                "label": "Neural pulse 01",
                "transaction_id": "81" * 32,
                "included_height": 100,
                "included_block": "82" * 32,
                "fee_charged": "10",
                "job_id": "83" * 32,
                "receipt_id": "84" * 32,
                "settlement_id": "85" * 32,
                "prompt_commitment": "86" * 32,
                "input_tokens": 4,
                "output_tokens": 8,
                "output_bytes": 16,
                "duration_milliseconds": 25,
                "output_root": "87" * 32,
                "token_history_root": "88" * 32,
            }
        ],
        "topology": {
            "custody_positions": 12,
            "executor_profiles": 8,
            "selected_executors": 3,
            "reconstruction_threshold": 8,
        },
        "monitor_signer_key_id": "91" * 32,
        "indexer_origins": [
            "https://one.example",
            "https://two.example",
            "https://three.example",
        ],
        "disclosures": ["fixture"],
    }


def plan_fixture() -> dict[str, object]:
    return {
        "schema": "noos/wwm-chain-bound-inference-plan/v1",
        "run_id": "a" * 24,
        "job_id": JOB_ID,
        "receipt_id": RECEIPT_ID,
        "settlement_id": SETTLEMENT_ID,
        "prompt_commitment": "34" * 32,
        "executor_ids": ["35" * 32],
        "bindings": {"capsule_id": "71" * 32},
        "job": {"job_id": JOB_ID},
    }


class NeuralPublisherTests(unittest.TestCase):
    def make_runtime(self, root: Path) -> tuple[publisher.NeuralPublisher, publisher.PublisherConfig]:
        manifest_path = root / "neural-manifest.json"
        manifest_path.write_text(json.dumps(manifest_fixture()), encoding="utf-8")
        config = publisher.PublisherConfig(
            hosted_config=root / "hosted.json",
            manifest=manifest_path,
            state=root / "state.json",
            evidence_dir=root / "evidence",
            minimum_seconds=300,
            minimum_finalized_advance=256,
            poll_seconds=10,
        )
        paths = Mock()
        network = demo.Network(
            node_rpc="http://127.0.0.1:39652",
            node_token="token",
            artifact_url="http://127.0.0.1:29682",
            sidecar_url="http://127.0.0.1:29807",
            sidecar_token_hex="aa" * 32,
            proxy_host="127.0.0.1",
            proxy_port_start=12000,
        )
        runtime = publisher.NeuralPublisher(
            config,
            {"tokenizer_executable_sha256": "99" * 32},
            paths,
            network,
            now=lambda: "2026-07-21T12:00:00+00:00",
            sleep=lambda _seconds: None,
        )
        return runtime, config

    def test_manifest_rejects_duplicate_lifecycle_identity(self) -> None:
        value = manifest_fixture()
        duplicate = dict(value["activity"][0])
        duplicate["sequence"] = 2
        duplicate["included_height"] = 101
        value["activity"] = [duplicate, value["activity"][0]]
        with self.assertRaisesRegex(publisher.PublisherError, "duplicate transaction_id"):
            publisher.validate_manifest(value)

    def test_resume_waits_durable_open_transaction_without_resubmitting(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            runtime, _ = self.make_runtime(Path(temp))
            active = {
                "sequence": 2,
                "run_id": "a" * 24,
                "phase": "open_submitted",
                "started_at": "2026-07-21T11:00:00+00:00",
                "plan": plan_fixture(),
                "open_txid": OPEN_TXID,
            }
            runtime.state["active"] = active
            runtime._save_state()
            job_record = {"finalized_height": 200, "finalized_hash": "a1" * 32}
            with (
                patch.object(
                    demo,
                    "verify_chain_bound_job",
                    side_effect=[demo.DemoError("HTTP 404 missing"), job_record],
                ),
                patch.object(demo, "finalize_wwm_submission") as finalized,
                patch.object(demo, "submit_chain_bound_job") as submit,
            ):
                observed = runtime._ensure_open(active)
            self.assertEqual(observed, job_record)
            finalized.assert_called_once_with(runtime.network, OPEN_TXID)
            submit.assert_not_called()
            persisted = json.loads(runtime.config.state.read_text(encoding="utf-8"))
            self.assertEqual(persisted["active"]["phase"], "open_finalized")
            self.assertEqual(persisted["active"]["open_txid"], OPEN_TXID)

    def test_forced_publish_persists_callbacks_evidence_and_newest_activity(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            runtime, config = self.make_runtime(Path(temp))
            status = {
                "chain_id": CHAIN_ID,
                "genesis_hash": GENESIS_HASH,
                "finalized": {"epoch": 10},
            }
            resolution = {"active": {}}
            plan = plan_fixture()
            job_record = {"finalized_height": 200, "finalized_hash": "a1" * 32}
            inference = {
                "job_id": JOB_ID,
                "duration_seconds": 1.25,
                "output_bytes": 20,
                "output_tokens": 8,
                "output_root": OUTPUT_ROOT,
                "token_history_root": TOKEN_ROOT,
            }
            receipt_record = {"finalized_height": 300, "finalized_hash": "a2" * 32}
            settlement_record = {"finalized_height": 300, "finalized_hash": "a3" * 32}
            close_plan = {
                "schema": "noos/wwm-chain-bound-close-plan/v1",
                "receipt": {"receipt_id": RECEIPT_ID},
                "settlement": {"settlement_id": SETTLEMENT_ID},
            }
            indexed = {
                "txid": CLOSE_TXID,
                "state": "INCLUDED",
                "fee": "1506",
                "inclusion": {"height": "300", "hash": BLOCK_HASH, "index": "0"},
            }

            def submit_open(_config, _paths, _network, _plan, callback):
                callback(OPEN_TXID)
                return {"submission": {"txid": OPEN_TXID}, "record": job_record}

            def submit_close(
                _config,
                _paths,
                _network,
                _plan,
                _close,
                _job,
                _inference,
                callback,
            ):
                callback(CLOSE_TXID)
                return {
                    "submission": {"txid": CLOSE_TXID},
                    "receipt": receipt_record,
                    "settlement": settlement_record,
                }

            with (
                patch.object(runtime, "_preflight", return_value=(status, resolution)),
                patch.object(demo, "quote", return_value={"quote": "fixture"}),
                patch.object(demo, "prepare_chain_bound_inference", return_value=plan),
                patch.object(
                    demo,
                    "verify_chain_bound_job",
                    side_effect=demo.DemoError("HTTP 404 missing"),
                ),
                patch.object(demo, "submit_chain_bound_job", side_effect=submit_open),
                patch.object(demo, "run_inference", return_value=inference),
                patch.object(demo, "prepare_chain_bound_close", return_value=close_plan),
                patch.object(
                    demo,
                    "verify_chain_bound_close",
                    side_effect=demo.DemoError("HTTP 404 missing"),
                ),
                patch.object(demo, "submit_chain_bound_close", side_effect=submit_close),
                patch.object(runtime, "_wait_indexers", return_value=[indexed, indexed, indexed]),
                patch.object(demo, "http_json", return_value=status),
            ):
                result = runtime.publish(force=True)

            self.assertTrue(result["published"])
            updated = json.loads(config.manifest.read_text(encoding="utf-8"))
            self.assertEqual([item["sequence"] for item in updated["activity"]], [2, 1])
            self.assertEqual(updated["activity"][0]["transaction_id"], CLOSE_TXID)
            self.assertEqual(updated["activity"][0]["duration_milliseconds"], 1250)
            state = json.loads(config.state.read_text(encoding="utf-8"))
            self.assertIsNone(state["active"])
            self.assertEqual(state["last_completed"]["sequence"], 2)
            evidence = list(config.evidence_dir.glob("pulse-0002-*.json"))
            self.assertEqual(len(evidence), 1)
            proof = json.loads(evidence[0].read_text(encoding="utf-8"))
            self.assertEqual(proof["activity"]["job_id"], JOB_ID)
            self.assertTrue(proof["claims"]["three_indexers_agree"])


if __name__ == "__main__":
    unittest.main()
