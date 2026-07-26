from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from blake3 import blake3

from tools.operations.wwm_public_inference import (
    CHAIN_ID,
    GENESIS_HASH,
    PROMPT_DOMAIN,
    ExecutionResult,
    InferenceService,
    StateSnapshot,
)


def hex32(index: int) -> str:
    return index.to_bytes(32, "big").hex()


class SnapshotFixture:
    def __init__(self) -> None:
        active = {
            "authorized_config_id": hex32(1),
            "capsule_id": hex32(2),
            "artifact_id": hex32(3),
            "manifest_root": hex32(4),
            "runtime_root": hex32(5),
            "artifact_sha256": hex32(6),
            "artifact_bytes": 3_803_452_480,
            "stripe_count": 454,
            "availability_certificate_id": hex32(7),
            "certificate_issued_height": 40,
            "certificate_valid_until": 10_000,
            "execution_profile_id": hex32(8),
            "query_policy_id": hex32(9),
            "custodian_profiles": [
                {
                    "profile_id": hex32(20 + index),
                    "endpoint_root": hex32(40 + index),
                    "status": 0,
                }
                for index in range(12)
            ],
            "executor_profile_ids": [hex32(80 + index) for index in range(8)],
        }
        self.value = StateSnapshot(
            resolution={
                "schema": "noos/finalized-model-resolution/v1",
                "selector": "bonsai-q1",
                "trust_scope": "LOCAL_FULL_NODE_FINALIZED_STATE",
                "proof_count": 17,
                "proofs_verified": True,
                "chain_id": CHAIN_ID,
                "genesis_hash": GENESIS_HASH,
                "finalized_height": 80,
                "finalized_hash": hex32(100),
                "objects_root": hex32(101),
                "active": active,
            },
            monitor={
                "sample_id": hex32(102),
                "signer_key_id": hex32(103),
                "checks": [
                    {"name": "inference_worker", "ok": True, "detail": {"ready": True}},
                    {"name": "model_resolution", "ok": True},
                ],
            },
            head_height=90,
        )

    def snapshot(self) -> StateSnapshot:
        return self.value


class ExecutorFixture:
    def run(self, job_id, prompt, maximum_output_tokens, on_chunk) -> ExecutionResult:
        self.job_id = job_id
        self.prompt = prompt
        output = b"Bonsai"
        output_root = blake3(output).hexdigest()
        on_chunk(output, output_root)
        return ExecutionResult(
            output=output,
            output_root=output_root,
            output_tokens=2,
            token_history_root=hex32(104),
            tokenizer_sha256=hex32(105),
            duration_ms=7,
        )


class SettlementFixture:
    def __init__(self) -> None:
        self.checkpoints = []

    def capture(self, snapshot: StateSnapshot) -> dict:
        return {
            "capsule_id": snapshot.resolution["active"]["capsule_id"],
            "execution_profile_id": snapshot.resolution["active"]["execution_profile_id"],
            "query_policy_id": snapshot.resolution["active"]["query_policy_id"],
            "fund_profile_id": hex32(106),
        }

    @staticmethod
    def record(kind: str, identifier: str, height: int, value: dict) -> dict:
        return {
            "schema": "noos/finalized-wwm-record/v1",
            "trust_scope": "LOCAL_FULL_NODE_FINALIZED_STATE",
            "kind": kind,
            "id": identifier,
            "finalized_height": height,
            "finalized_hash": hex32(height),
            "objects_root": hex32(height + 20),
            "canonical_record_hex": "00",
            "proof_hex": "01",
            "record": value,
        }

    def settle(self, request, checkpoint, on_checkpoint) -> dict:
        self.request = request
        on_checkpoint({"phase": "open_finalized"})
        self.checkpoints.append("open_finalized")
        job_id = request["job_id"]
        receipt_id = request["receipt_id"]
        settlement_id = request["settlement_id"]
        quote = request["quote"]
        inference = request["inference"]
        binding = request["binding"]
        return {
            "schema": "noos/wwm-public-inference-settlement-result/v1",
            "job_id": job_id,
            "receipt_id": receipt_id,
            "settlement_id": settlement_id,
            "open_transaction_id": hex32(110),
            "close_transaction_id": hex32(111),
            "job": self.record(
                "job",
                job_id,
                120,
                {
                    "job_id": job_id,
                    "client_commitment": quote["prompt_commitment"],
                    "capsule_id": quote["capsule_id"],
                    "execution_profile_id": quote["execution_profile_id"],
                },
            ),
            "receipt": self.record(
                "receipt",
                receipt_id,
                121,
                {
                    "receipt_id": receipt_id,
                    "job_id": job_id,
                    "output_root": inference["output_root"],
                    "token_history_root": inference["token_history_root"],
                    "output_tokens": inference["output_tokens"],
                },
            ),
            "settlement": self.record(
                "settlement",
                settlement_id,
                122,
                {
                    "settlement_id": settlement_id,
                    "job_id": job_id,
                    "receipt_id": receipt_id,
                    "fund_profile_id": binding["fund_profile_id"],
                },
            ),
        }


class PublicInferenceSettlementTest(unittest.TestCase):
    def test_success_streams_provisional_then_finalized_chain_receipt(self) -> None:
        provider = SnapshotFixture()
        executor = ExecutorFixture()
        settlement = SettlementFixture()
        with tempfile.TemporaryDirectory() as temporary:
            service = InferenceService(
                database=Path(temporary) / "inference.sqlite3",
                signing_seed=bytes.fromhex("12" * 32),
                provider=provider,
                executor=executor,
                settlement_backend=settlement,
            )
            try:
                active = service.get("/api/wwm/v2/state", "", "127.0.0.1").value
                self.assertTrue(active["interactive_chain_settlement"])
                prompt = "Answer briefly"
                salt = "22" * 32
                commitment = hashlib.sha256(
                    PROMPT_DOMAIN + bytes.fromhex(salt) + prompt.encode("utf-8")
                ).hexdigest()
                quote = service.post(
                    "/api/wwm/v2/quotes",
                    {
                        "request_id": "33" * 16,
                        "pin_id": active["resolution"]["pin_id"],
                        "capsule_id": active["resolution"]["active"]["capsule_id"],
                        "execution_profile_id": active["resolution"]["active"]["execution_profile_id"],
                        "query_profile_id": active["resolution"]["active"]["query_profile_id"],
                        "prompt_commitment": commitment,
                        "input_tokens": 3,
                        "maximum_output_tokens": 8,
                        "payment": {"mode": "SPONSORED", "authorization": ""},
                        "client_nonce": "44" * 32,
                    },
                    "127.0.0.1",
                    None,
                ).value
                submitted = service.post(
                    "/api/wwm/v2/jobs",
                    {
                        "quote_id": quote["quote_id"],
                        "prompt": prompt,
                        "prompt_commitment": commitment,
                        "prompt_salt": salt,
                    },
                    "127.0.0.1",
                    "55" * 16,
                ).value
                job_id = submitted["job_id"]
                events = list(service.stream(f"/api/wwm/v2/jobs/{job_id}/stream", None))
                self.assertEqual(
                    [event["type"] for event in events],
                    ["output.delta", "receipt.completed", "settlement.finalized"],
                )
                self.assertEqual(events[1]["data"]["settlement_state"], "PENDING_CHAIN")
                self.assertEqual(events[2]["data"]["settlement_state"], "FINALIZED_PAID")
                final = service.get(
                    f"/api/wwm/v2/jobs/{job_id}/receipt",
                    "",
                    "127.0.0.1",
                ).value
                self.assertEqual(final["chain_anchor"], hex32(122))
                self.assertEqual(final["evidence_state"], "PROVISIONAL_SIGNED")
                self.assertEqual(final["output_commitment"], final["output_root"])
                self.assertEqual(
                    final["chain_settlement"]["settlement_id"],
                    settlement.request["settlement_id"],
                )
                self.assertEqual(settlement.checkpoints, ["open_finalized"])
            finally:
                service.close()


if __name__ == "__main__":
    unittest.main()
