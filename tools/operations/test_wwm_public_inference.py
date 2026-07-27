from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from blake3 import blake3

from tools.operations.wwm_public_inference import (
    CHAIN_ID,
    GENESIS_HASH,
    PROMPT_DOMAIN,
    ExecutionResult,
    InferenceError,
    InferenceService,
    StateSnapshot,
)
from tools.operations.wwm_public_settlement import (
    DevnetSettlementBackend,
    PublicSettlementError,
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
        terminal_code = {
            "COMPLETED": 0,
            "CANCELLED": 1,
            "FAILED": 2 if request.get("error_code") == "JOB_DEADLINE_EXPIRED" else 4,
            "NO_QUORUM": 3,
        }[request["terminal_status"]]
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
                    "terminal_code": terminal_code,
                    "paid_amount": "0",
                    "refunded_amount": "0",
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
                    "paid_amount": "0",
                    "refunded_amount": "0",
                    "released_amount": "0",
                },
            ),
        }

def submit_fixture_job(
    service: InferenceService,
    prompt: str,
    *,
    idempotency_key: str = "55" * 16,
) -> str:
    active = service.get("/api/wwm/v2/state", "", "127.0.0.1").value
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
    return service.post(
        "/api/wwm/v2/jobs",
        {
            "quote_id": quote["quote_id"],
            "prompt": prompt,
            "prompt_commitment": commitment,
            "prompt_salt": salt,
        },
        "127.0.0.1",
        idempotency_key,
    ).value["job_id"]


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
                resumed = list(
                    service.stream(f"/api/wwm/v2/jobs/{job_id}/stream", "1")
                )
                self.assertEqual(
                    [event["type"] for event in resumed],
                    ["receipt.completed", "settlement.finalized"],
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

    def test_prompt_and_stream_plaintext_never_persist(self) -> None:
        provider = SnapshotFixture()
        prompt = "PROMPT_CANARY_7f04c551"
        output = b"OUTPUT_CANARY_94ba913e"

        class CanaryExecutor:
            def run(self, job_id, observed_prompt, maximum_output_tokens, on_chunk):
                self.prompt = observed_prompt
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

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "inference.sqlite3"
            executor = CanaryExecutor()
            service = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=provider,
                executor=executor,
                start_worker=False,
            )
            try:
                active = service.get("/api/wwm/v2/state", "", "127.0.0.1").value
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
                        "execution_profile_id": active["resolution"]["active"][
                            "execution_profile_id"
                        ],
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
                with sqlite3.connect(database) as db:
                    stored_prompt = str(
                        db.execute(
                            "SELECT prompt FROM inference_jobs WHERE job_id=?",
                            (job_id,),
                        ).fetchone()[0]
                    )
                db.close()
                self.assertTrue(stored_prompt.startswith("enc:v1:"))
                self.assertNotIn(prompt, stored_prompt)

                service._execute_job(job_id)
                events = list(service.stream(f"/api/wwm/v2/jobs/{job_id}/stream", None))
                self.assertEqual(events[0]["data"]["delta"], output.decode("utf-8"))
                with sqlite3.connect(database) as db:
                    row = db.execute(
                        "SELECT prompt FROM inference_jobs WHERE job_id=?",
                        (job_id,),
                    ).fetchone()
                    stored_events = [
                        str(value[0])
                        for value in db.execute(
                            "SELECT payload_json FROM inference_events WHERE job_id=?",
                            (job_id,),
                        ).fetchall()
                    ]
                db.close()
                self.assertIsNone(row[0])
                self.assertTrue(stored_events)
                self.assertTrue(all(value.startswith("enc:v1:") for value in stored_events))
                for path in (
                    database,
                    Path(f"{database}-wal"),
                    Path(f"{database}-shm"),
                ):
                    if not path.exists():
                        continue
                    persisted = path.read_bytes()
                    self.assertNotIn(prompt.encode("utf-8"), persisted)
                    self.assertNotIn(output, persisted)
                self.assertEqual(executor.prompt, prompt)
            finally:
                service.close()

    def test_cancelled_job_clears_encrypted_prompt_without_output(self) -> None:
        prompt = "CANCEL_CANARY_03d62c7a"
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "inference.sqlite3"
            settlement = SettlementFixture()
            service = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=ExecutorFixture(),
                settlement_backend=settlement,
                start_worker=False,
            )
            try:
                job_id = submit_fixture_job(service, prompt)
                cancelled = service.post(
                    f"/api/wwm/v2/jobs/{job_id}/cancel",
                    {"reason": "USER_REQUESTED"},
                    "127.0.0.1",
                    None,
                ).value
                self.assertEqual(cancelled["status"], "CANCEL_REQUESTED")
                service._execute_job(job_id)
                service._settle_job(job_id)
                receipt = service.get(
                    f"/api/wwm/v2/jobs/{job_id}/receipt",
                    "",
                    "127.0.0.1",
                ).value
                self.assertEqual(receipt["terminal_status"], "CANCELLED")
                self.assertEqual(receipt["error_code"], "USER_REQUESTED")
                self.assertEqual(receipt["output_tokens"], 0)
                self.assertEqual(receipt["output_commitment"], "0" * 64)
                self.assertEqual(receipt["settlement_state"], "FINALIZED_REFUNDED")
                self.assertEqual(receipt["chain_anchor"], hex32(122))
                with sqlite3.connect(database) as db:
                    stored_prompt = db.execute(
                        "SELECT prompt FROM inference_jobs WHERE job_id=?",
                        (job_id,),
                    ).fetchone()[0]
                    stored_events = [
                        str(row[0])
                        for row in db.execute(
                            "SELECT payload_json FROM inference_events WHERE job_id=?",
                            (job_id,),
                        ).fetchall()
                    ]
                db.close()
                self.assertIsNone(stored_prompt)
                self.assertTrue(stored_events)
                self.assertTrue(all(value.startswith("enc:v1:") for value in stored_events))
                for path in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
                    if path.exists():
                        self.assertNotIn(prompt.encode("utf-8"), path.read_bytes())
            finally:
                service.close()

    def test_gateway_restart_fails_active_job_and_resumes_terminal_stream(self) -> None:
        prompt = "RESTART_CANARY_b01d84ec"
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "inference.sqlite3"
            first = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=ExecutorFixture(),
                start_worker=False,
            )
            job_id = submit_fixture_job(first, prompt)
            first.close()

            recovered = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=ExecutorFixture(),
                start_worker=False,
            )
            try:
                receipt = recovered.get(
                    f"/api/wwm/v2/jobs/{job_id}/receipt",
                    "",
                    "127.0.0.1",
                ).value
                self.assertEqual(receipt["terminal_status"], "FAILED")
                self.assertEqual(receipt["error_code"], "GATEWAY_RESTARTED")
                events = list(
                    recovered.stream(f"/api/wwm/v2/jobs/{job_id}/stream", "0")
                )
                self.assertEqual([event["type"] for event in events], ["receipt.completed"])
                self.assertEqual(events[0]["data"]["job_id"], job_id)
                for path in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
                    if path.exists():
                        self.assertNotIn(prompt.encode("utf-8"), path.read_bytes())
            finally:
                recovered.close()

    def test_executor_deadline_failure_clears_prompt_and_refuses_output(self) -> None:
        prompt = "TIMEOUT_CANARY_53da489c"

        class TimeoutExecutor:
            def run(self, job_id, observed_prompt, maximum_output_tokens, on_chunk):
                raise InferenceError(
                    504,
                    "JOB_DEADLINE_EXPIRED",
                    "The bounded inference deadline expired.",
                )

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "inference.sqlite3"
            settlement = SettlementFixture()
            service = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=TimeoutExecutor(),
                settlement_backend=settlement,
                start_worker=False,
            )
            try:
                job_id = submit_fixture_job(service, prompt)
                service._execute_job(job_id)
                service._settle_job(job_id)
                receipt = service.get(
                    f"/api/wwm/v2/jobs/{job_id}/receipt",
                    "",
                    "127.0.0.1",
                ).value
                self.assertEqual(receipt["terminal_status"], "FAILED")
                self.assertEqual(receipt["error_code"], "JOB_DEADLINE_EXPIRED")
                self.assertEqual(receipt["evidence_state"], "NONE")
                self.assertEqual(receipt["output_tokens"], 0)
                self.assertEqual(receipt["settlement_state"], "FINALIZED_REFUNDED")
                self.assertEqual(receipt["chain_anchor"], hex32(122))
                for path in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
                    if path.exists():
                        self.assertNotIn(prompt.encode("utf-8"), path.read_bytes())
            finally:
                service.close()

    def test_restart_migrates_legacy_plaintext_and_truncates_wal(self) -> None:
        prompt = "LEGACY_PROMPT_CANARY_a7d4f291"
        output = "LEGACY_OUTPUT_CANARY_e19f3c72"
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "inference.sqlite3"
            first = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=ExecutorFixture(),
                start_worker=False,
            )
            job_id = submit_fixture_job(first, prompt)
            first.close()
            legacy_event = {
                "id": 1,
                "type": "output.delta",
                "data": {"job_id": job_id, "delta": output},
            }
            with sqlite3.connect(database) as db:
                db.execute(
                    "UPDATE inference_jobs SET prompt=? WHERE job_id=?",
                    (prompt, job_id),
                )
                db.execute(
                    "INSERT INTO inference_events(job_id,event_id,event_type,payload_json,created_ms) VALUES(?,?,?,?,?)",
                    (
                        job_id,
                        1,
                        "output.delta",
                        json.dumps(legacy_event, separators=(",", ":")),
                        1,
                    ),
                )
            db.close()

            recovered = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=ExecutorFixture(),
                start_worker=False,
            )
            try:
                events = list(
                    recovered.stream(f"/api/wwm/v2/jobs/{job_id}/stream", "0")
                )
                self.assertEqual(events[0], legacy_event)
                self.assertEqual(events[1]["type"], "receipt.completed")
                with sqlite3.connect(database) as db:
                    saved = [
                        str(row[0])
                        for row in db.execute(
                            "SELECT payload_json FROM inference_events WHERE job_id=? ORDER BY event_id",
                            (job_id,),
                        ).fetchall()
                    ]
                db.close()
                self.assertTrue(all(value.startswith("enc:v1:") for value in saved))
                for path in (database, Path(f"{database}-wal"), Path(f"{database}-shm")):
                    if not path.exists():
                        continue
                    persisted = path.read_bytes()
                    self.assertNotIn(prompt.encode("utf-8"), persisted)
                    self.assertNotIn(output.encode("utf-8"), persisted)
            finally:
                recovered.close()

    def test_devnet_backend_builds_closed_refund_terminal_plans(self) -> None:
        binding = {
            "capsule_id": hex32(2),
            "artifact_id": hex32(3),
            "tokenizer_root": hex32(4),
            "template_root": hex32(5),
            "runtime_root": hex32(6),
            "sbom_root": hex32(7),
            "execution_profile_id": hex32(8),
            "certificate_valid_until": 10_000,
            "fund_profile_id": hex32(9),
        }
        plan = {"executor_ids": [hex32(10), hex32(11), hex32(12)]}
        job_record = {"finalized_height": 120, "finalized_hash": hex32(13)}
        base = {
            "job_id": hex32(14),
            "receipt_id": hex32(15),
            "settlement_id": hex32(16),
            "binding": binding,
            "quote": {"input_tokens": 3},
        }
        completed = DevnetSettlementBackend._prepare_close(
            {
                **base,
                "terminal_status": "COMPLETED",
                "error_code": None,
                "inference": {
                    "output_tokens": 2,
                    "output_root": hex32(17),
                    "token_history_root": hex32(18),
                },
            },
            plan,
            job_record,
        )
        self.assertEqual(completed["receipt"]["terminal_code"], "complete")
        self.assertEqual(completed["receipt"]["signer_ids"], plan["executor_ids"])

        outcomes = (
            ("CANCELLED", "USER_REQUESTED", "cancelled"),
            ("FAILED", "JOB_DEADLINE_EXPIRED", "deadline"),
            ("FAILED", "EXECUTOR_REJECTED", "rejected"),
            ("NO_QUORUM", "NO_QUORUM", "no_quorum"),
        )
        for status, error_code, expected in outcomes:
            refunded = DevnetSettlementBackend._prepare_close(
                {
                    **base,
                    "terminal_status": status,
                    "error_code": error_code,
                    "inference": {
                        "output_tokens": 0,
                        "output_root": "0" * 64,
                        "token_history_root": "0" * 64,
                    },
                },
                plan,
                job_record,
            )
            self.assertEqual(refunded["receipt"]["terminal_code"], expected)
            self.assertEqual(refunded["receipt"]["paid_amount"], "0")
            self.assertEqual(refunded["receipt"]["refunded_amount"], "0")
            self.assertEqual(refunded["receipt"]["signer_ids"], [])
            self.assertEqual(refunded["receipt"]["control_cluster_ids"], [])
        with self.assertRaisesRegex(PublicSettlementError, "contains output commitments"):
            DevnetSettlementBackend._prepare_close(
                {
                    **base,
                    "terminal_status": "CANCELLED",
                    "error_code": "USER_REQUESTED",
                    "inference": {
                        "output_tokens": 1,
                        "output_root": hex32(17),
                        "token_history_root": hex32(18),
                    },
                },
                plan,
                job_record,
            )

    def test_wwm_openapi_keeps_resolution_and_receipt_schemas_top_level(self) -> None:
        root = Path(__file__).resolve().parents[2]
        contract = json.loads(
            (root / "protocol" / "api" / "openapi-wwm-v2.yaml").read_text(
                encoding="utf-8"
            )
        )
        schemas = contract["components"]["schemas"]
        self.assertTrue(
            {"FinalizedResolution", "StateResponse", "Receipt", "Error"} <= set(schemas)
        )
        resolution = schemas["FinalizedResolution"]["properties"]
        self.assertTrue(
            {
                "state_object_proofs",
                "active",
                "candidates",
                "executors",
                "registry_vector_id",
            }
            <= set(resolution)
        )
        self.assertNotIn("active", resolution["state_object_proofs"])


if __name__ == "__main__":
    unittest.main()
