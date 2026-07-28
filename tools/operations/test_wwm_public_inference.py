from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import threading
import unittest
from unittest.mock import patch
from pathlib import Path

from blake3 import blake3

from tools.operations.wwm_public_inference import (
    CHAIN_ID,
    GENESIS_HASH,
    PROMPT_DOMAIN,
    JOB_DEADLINE_SECONDS,
    ExecutionResult,
    InferenceError,
    InferenceService,
    WorkerdExecutor,
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
    def run(self, job_id, prompt, maximum_output_tokens, on_chunk, abort_code) -> ExecutionResult:
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
    def test_workerd_executor_propagates_abort_with_authenticated_delete(self) -> None:
        submitted = threading.Event()
        cancelled = threading.Event()

        class Headers:
            def __init__(self, content_type: str) -> None:
                self.content_type = content_type

            def get_content_type(self) -> str:
                return self.content_type

        class Response:
            def __init__(self, body: bytes, content_type: str, status: int = 200) -> None:
                self.body = body
                self.headers = Headers(content_type)
                self.status = status

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def read(self, maximum: int) -> bytes:
                return self.body[:maximum]

        class StreamResponse(Response):
            def __init__(self) -> None:
                super().__init__(b"", "text/event-stream")
                self.sent = False

            def readline(self, maximum: int) -> bytes:
                if self.sent:
                    return b""
                if not cancelled.wait(2):
                    raise TimeoutError("executor cancellation was not propagated")
                self.sent = True
                return b'data: {"type":"terminal","code":"cancelled","output_root":null}\n'

        class Tokenizer:
            executable_sha256 = hex32(150)

            @staticmethod
            def tokenize(value: bytes, maximum: int) -> list[int]:
                return [1]

            @staticmethod
            def output_commitment(value: bytes, maximum: int) -> tuple[int, str]:
                raise AssertionError("cancelled output must not be committed")

        def urlopen(request, timeout):
            method = request.get_method()
            if method == "POST" and request.full_url.endswith("/capacity-quotes"):
                return Response(b'{"accepted":true}', "application/json")
            if method == "POST" and request.full_url.endswith("/jobs"):
                submitted.set()
                return Response(
                    json.dumps(
                        {
                            "job_id": hex32(151),
                            "stream": f"/internal/wwm/v1/jobs/{hex32(151)}/stream",
                        },
                        separators=(",", ":"),
                    ).encode("utf-8"),
                    "application/json",
                )
            if method == "GET" and request.full_url.endswith("/stream"):
                return StreamResponse()
            if method == "DELETE" and request.full_url.endswith(hex32(151)):
                cancelled.set()
                return Response(b"", "application/json", status=202)
            raise AssertionError(f"unexpected executor request {method} {request.full_url}")

        executor = WorkerdExecutor(
            origin="http://127.0.0.1:29807",
            token="44" * 32,
            tokenizer=Tokenizer(),
        )
        with patch(
            "tools.operations.wwm_public_inference.urllib.request.urlopen",
            side_effect=urlopen,
        ):
            with self.assertRaises(InferenceError) as raised:
                executor.run(
                    hex32(151),
                    "cancel me",
                    8,
                    lambda chunk, root: self.fail("cancelled execution emitted output"),
                    lambda: "USER_REQUESTED" if submitted.is_set() else None,
                )
        self.assertEqual(raised.exception.code, "USER_REQUESTED")
        self.assertTrue(cancelled.is_set())

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

    def test_duplicate_submission_replays_one_job_without_rerunning(self) -> None:
        class CountingExecutor(ExecutorFixture):
            def __init__(self) -> None:
                self.calls = 0

            def run(self, job_id, prompt, maximum_output_tokens, on_chunk, abort_code):
                self.calls += 1
                return super().run(
                    job_id,
                    prompt,
                    maximum_output_tokens,
                    on_chunk,
                    abort_code,
                )

        prompt = "IDEMPOTENCY_CANARY_f94f0442"
        salt = "22" * 32
        commitment = hashlib.sha256(
            PROMPT_DOMAIN + bytes.fromhex(salt) + prompt.encode("utf-8")
        ).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "inference.sqlite3"
            executor = CountingExecutor()
            service = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=executor,
                start_worker=False,
            )
            try:
                job_id = submit_fixture_job(service, prompt)
                with sqlite3.connect(database) as db:
                    quote_id, deadline_at_ms, queue_depth_at_submit = db.execute(
                        "SELECT quote_id,deadline_at_ms,queue_depth_at_submit FROM inference_jobs WHERE job_id=?",
                        (job_id,),
                    ).fetchone()
                db.close()
                replay = service.post(
                    "/api/wwm/v2/jobs",
                    {
                        "quote_id": quote_id,
                        "prompt": prompt,
                        "prompt_commitment": commitment,
                        "prompt_salt": salt,
                    },
                    "127.0.0.1",
                    "55" * 16,
                ).value
                self.assertEqual(replay["job_id"], job_id)
                self.assertEqual(replay["status"], "QUEUED")
                self.assertEqual(replay["deadline_at_ms"], deadline_at_ms)
                self.assertEqual(replay["queue_depth_at_submit"], queue_depth_at_submit)
                self.assertEqual(queue_depth_at_submit, 1)
                self.assertTrue(replay["replayed"])
                service._execute_job(job_id)
                with sqlite3.connect(database) as db:
                    started_ms = db.execute(
                        "SELECT started_ms FROM inference_jobs WHERE job_id=?",
                        (job_id,),
                    ).fetchone()[0]
                db.close()
                self.assertIsNotNone(started_ms)
                completed = service.post(
                    "/api/wwm/v2/jobs",
                    {
                        "quote_id": quote_id,
                        "prompt": prompt,
                        "prompt_commitment": commitment,
                        "prompt_salt": salt,
                    },
                    "127.0.0.1",
                    "55" * 16,
                ).value
                self.assertEqual(completed["status"], "COMPLETED")
                self.assertEqual(executor.calls, 1)
                with sqlite3.connect(database) as db:
                    self.assertEqual(
                        db.execute("SELECT COUNT(*) FROM inference_jobs").fetchone()[0],
                        1,
                    )
                db.close()
            finally:
                service.close()

    def test_invalid_settlement_proofs_cannot_consume_refund(self) -> None:
        def wrong_model(result: dict) -> None:
            result["job"]["record"]["capsule_id"] = hex32(201)

        def wrong_finality(result: dict) -> None:
            result["settlement"]["finalized_hash"] = "not-a-finalized-hash"

        def wrong_output(result: dict) -> None:
            result["receipt"]["record"]["output_root"] = hex32(202)

        class TamperedSettlement(SettlementFixture):
            def __init__(self, mutate) -> None:
                super().__init__()
                self.mutate = mutate

            def settle(self, request, checkpoint, on_checkpoint) -> dict:
                result = super().settle(request, checkpoint, on_checkpoint)
                self.mutate(result)
                return result

        for name, mutate in (
            ("wrong_model", wrong_model),
            ("wrong_finality", wrong_finality),
            ("wrong_output", wrong_output),
        ):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                database = Path(temporary) / "inference.sqlite3"
                service = InferenceService(
                    database=database,
                    signing_seed=bytes.fromhex("12" * 32),
                    provider=SnapshotFixture(),
                    executor=ExecutorFixture(),
                    settlement_backend=TamperedSettlement(mutate),
                    start_worker=False,
                )
                try:
                    job_id = submit_fixture_job(
                        service,
                        f"INVALID_SETTLEMENT_{name}_CANARY",
                    )
                    service.post(
                        f"/api/wwm/v2/jobs/{job_id}/cancel",
                        {"reason": "USER_REQUESTED"},
                        "127.0.0.1",
                        None,
                    )
                    service._execute_job(job_id)
                    with self.assertRaises(InferenceError) as rejected:
                        service._settle_job(job_id)
                    self.assertEqual(
                        rejected.exception.code,
                        "SETTLEMENT_PROOF_INVALID",
                    )
                    provisional = service.get(
                        f"/api/wwm/v2/jobs/{job_id}/receipt",
                        "",
                        "127.0.0.1",
                    ).value
                    self.assertEqual(provisional["terminal_status"], "CANCELLED")
                    self.assertEqual(provisional["settlement_state"], "PENDING_CHAIN")
                    self.assertEqual(provisional["output_commitment"], "0" * 64)
                    with sqlite3.connect(database) as db:
                        settlement_state, result_json, prompt = db.execute(
                            """
                            SELECT s.state,s.result_json,j.prompt
                            FROM inference_settlements s
                            JOIN inference_jobs j ON j.job_id=s.job_id
                            WHERE s.job_id=?
                            """,
                            (job_id,),
                        ).fetchone()
                    db.close()
                    self.assertEqual(settlement_state, "FINALIZING")
                    self.assertIsNone(result_json)
                    self.assertIsNone(prompt)

                    valid = SettlementFixture()
                    service.settlement_backend = valid
                    service._settle_job(job_id)
                    finalized = service.get(
                        f"/api/wwm/v2/jobs/{job_id}/receipt",
                        "",
                        "127.0.0.1",
                    ).value
                    self.assertEqual(
                        finalized["settlement_state"],
                        "FINALIZED_REFUNDED",
                    )
                    self.assertEqual(finalized["output_commitment"], "0" * 64)
                    events = list(
                        service.stream(f"/api/wwm/v2/jobs/{job_id}/stream", "0")
                    )
                    self.assertEqual(
                        [event["type"] for event in events],
                        ["receipt.completed", "settlement.finalized"],
                    )
                finally:
                    service.close()

    def test_prompt_and_stream_plaintext_never_persist(self) -> None:
        provider = SnapshotFixture()
        prompt = "PROMPT_CANARY_7f04c551"
        output = b"OUTPUT_CANARY_94ba913e"

        class CanaryExecutor:
            def run(self, job_id, observed_prompt, maximum_output_tokens, on_chunk, abort_code):
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

    def test_cancel_cannot_be_overwritten_by_queued_start_claim(self) -> None:
        class CancelDuringClaimClock:
            def __init__(self) -> None:
                self.value = 1_785_207_600_000
                self.callback = None
                self.armed = False

            def __call__(self) -> int:
                self.value += 1
                if self.armed:
                    self.armed = False
                    assert self.callback is not None
                    self.callback()
                return self.value

        with tempfile.TemporaryDirectory() as temporary:
            clock = CancelDuringClaimClock()
            settlement = SettlementFixture()
            service = InferenceService(
                database=Path(temporary) / "inference.sqlite3",
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=ExecutorFixture(),
                settlement_backend=settlement,
                now_ms=clock,
                start_worker=False,
            )
            try:
                job_id = submit_fixture_job(service, "CANCEL_START_RACE_CANARY_954ad63e")
                cancellation = []
                clock.callback = lambda: cancellation.append(
                    service.post(
                        f"/api/wwm/v2/jobs/{job_id}/cancel",
                        {"reason": "USER_REQUESTED"},
                        "127.0.0.1",
                        None,
                    ).value
                )
                clock.armed = True
                service._execute_job(job_id)
                service._settle_job(job_id)
                self.assertEqual(cancellation[0]["status"], "CANCEL_REQUESTED")
                receipt = service.get(
                    f"/api/wwm/v2/jobs/{job_id}/receipt",
                    "",
                    "127.0.0.1",
                ).value
                self.assertEqual(receipt["terminal_status"], "CANCELLED")
                self.assertEqual(receipt["error_code"], "USER_REQUESTED")
                self.assertEqual(receipt["output_tokens"], 0)
                self.assertEqual(receipt["settlement_state"], "FINALIZED_REFUNDED")
            finally:
                service.close()

    def test_cancel_cannot_be_overwritten_by_completion_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            settlement = SettlementFixture()
            service = InferenceService(
                database=Path(temporary) / "inference.sqlite3",
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=ExecutorFixture(),
                settlement_backend=settlement,
                start_worker=False,
            )
            try:
                job_id = submit_fixture_job(
                    service,
                    "CANCEL_COMPLETION_RACE_CANARY_6ab29d70",
                )
                original_sign = service._sign
                cancellation = []

                def sign_after_cancel(value, kind):
                    if kind == "RECEIPT" and not cancellation:
                        cancellation.append(
                            service.post(
                                f"/api/wwm/v2/jobs/{job_id}/cancel",
                                {"reason": "USER_REQUESTED"},
                                "127.0.0.1",
                                None,
                            ).value
                        )
                    return original_sign(value, kind)

                service._sign = sign_after_cancel
                service._execute_job(job_id)
                service._settle_job(job_id)
                self.assertEqual(cancellation[0]["status"], "CANCEL_REQUESTED")
                receipt = service.get(
                    f"/api/wwm/v2/jobs/{job_id}/receipt",
                    "",
                    "127.0.0.1",
                ).value
                self.assertEqual(receipt["terminal_status"], "CANCELLED")
                self.assertEqual(receipt["error_code"], "USER_REQUESTED")
                self.assertEqual(receipt["output_commitment"], "0" * 64)
                self.assertEqual(receipt["settlement_state"], "FINALIZED_REFUNDED")
            finally:
                service.close()

    def test_running_cancel_reaches_executor_and_finalizes_refund(self) -> None:
        class BlockingExecutor:
            def __init__(self) -> None:
                self.started = threading.Event()
                self.poll = threading.Event()
                self.observed_abort: str | None = None

            def run(self, job_id, prompt, maximum_output_tokens, on_chunk, abort_code):
                self.started.set()
                while True:
                    self.observed_abort = abort_code()
                    if self.observed_abort is not None:
                        raise InferenceError(
                            409,
                            self.observed_abort,
                            "Execution control terminated the fixture.",
                        )
                    self.poll.wait(0.01)

        with tempfile.TemporaryDirectory() as temporary:
            executor = BlockingExecutor()
            service = InferenceService(
                database=Path(temporary) / "inference.sqlite3",
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=executor,
                settlement_backend=SettlementFixture(),
            )
            try:
                job_id = submit_fixture_job(service, "CANCEL_RUNNING_CANARY_8e78de98")
                self.assertTrue(executor.started.wait(2))
                cancelled = service.post(
                    f"/api/wwm/v2/jobs/{job_id}/cancel",
                    {"reason": "USER_REQUESTED"},
                    "127.0.0.1",
                    None,
                ).value
                self.assertEqual(cancelled["status"], "CANCEL_REQUESTED")
                events = list(service.stream(f"/api/wwm/v2/jobs/{job_id}/stream", None))
                self.assertEqual(
                    [event["type"] for event in events],
                    ["receipt.completed", "settlement.finalized"],
                )
                self.assertEqual(executor.observed_abort, "USER_REQUESTED")
                receipt = events[-1]["data"]
                self.assertEqual(receipt["terminal_status"], "CANCELLED")
                self.assertEqual(receipt["error_code"], "USER_REQUESTED")
                self.assertEqual(receipt["settlement_state"], "FINALIZED_REFUNDED")
                self.assertEqual(receipt["output_commitment"], "0" * 64)
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

    def test_restart_resumes_pending_settlement_without_rerunning_execution(self) -> None:
        class CountingExecutor(ExecutorFixture):
            def __init__(self) -> None:
                self.calls = 0

            def run(self, job_id, prompt, maximum_output_tokens, on_chunk, abort_code):
                self.calls += 1
                return super().run(
                    job_id,
                    prompt,
                    maximum_output_tokens,
                    on_chunk,
                    abort_code,
                )

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "inference.sqlite3"
            executor = CountingExecutor()
            settlement = SettlementFixture()
            first = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=executor,
                settlement_backend=settlement,
                start_worker=False,
            )
            job_id = submit_fixture_job(first, "SETTLEMENT_RESTART_CANARY_4f87c2f4")
            first._execute_job(job_id)
            first.close()
            self.assertEqual(executor.calls, 1)

            resumed = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=executor,
                settlement_backend=settlement,
            )
            try:
                resumed_events = list(
                    resumed.stream(f"/api/wwm/v2/jobs/{job_id}/stream", "2")
                )
                self.assertEqual(
                    [event["type"] for event in resumed_events],
                    ["settlement.finalized"],
                )
                self.assertEqual(executor.calls, 1)
                self.assertEqual(
                    resumed_events[0]["data"]["settlement_state"],
                    "FINALIZED_PAID",
                )
            finally:
                resumed.close()

            terminal = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=executor,
                settlement_backend=settlement,
                start_worker=False,
            )
            try:
                replayed = list(
                    terminal.stream(f"/api/wwm/v2/jobs/{job_id}/stream", "2")
                )
                self.assertEqual(
                    [event["type"] for event in replayed],
                    ["settlement.finalized"],
                )
                self.assertEqual(executor.calls, 1)
                self.assertEqual(settlement.checkpoints, ["open_finalized"])
            finally:
                terminal.close()

    def test_restart_backfills_deadline_and_metric_columns_for_existing_database(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "inference.sqlite3"
            first = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=ExecutorFixture(),
                start_worker=False,
            )
            job_id = submit_fixture_job(first, "DEADLINE_MIGRATION_CANARY_d80998ce")
            first.close()
            with sqlite3.connect(database) as db:
                created_ms = db.execute(
                    "SELECT created_ms FROM inference_jobs WHERE job_id=?",
                    (job_id,),
                ).fetchone()[0]
                db.execute("ALTER TABLE inference_jobs DROP COLUMN started_ms")
                db.execute("ALTER TABLE inference_jobs DROP COLUMN queue_depth_at_submit")
                db.execute("ALTER TABLE inference_jobs DROP COLUMN deadline_at_ms")
            db.close()

            recovered = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=ExecutorFixture(),
                start_worker=False,
            )
            try:
                with sqlite3.connect(database) as db:
                    deadline_at_ms, queue_depth_at_submit, started_ms = db.execute(
                        "SELECT deadline_at_ms,queue_depth_at_submit,started_ms FROM inference_jobs WHERE job_id=?",
                        (job_id,),
                    ).fetchone()
                db.close()
                self.assertEqual(
                    deadline_at_ms,
                    created_ms + JOB_DEADLINE_SECONDS * 1000,
                )
                self.assertEqual(queue_depth_at_submit, 0)
                self.assertIsNone(started_ms)
                receipt = recovered.get(
                    f"/api/wwm/v2/jobs/{job_id}/receipt",
                    "",
                    "127.0.0.1",
                ).value
                self.assertEqual(receipt["error_code"], "GATEWAY_RESTARTED")
                self.assertEqual(receipt["deadline_at_ms"], deadline_at_ms)
            finally:
                recovered.close()

    def test_worker_disconnect_refunds_once_across_gateway_restart(self) -> None:
        class RestartingExecutor:
            def __init__(self) -> None:
                self.calls = 0

            def run(self, job_id, prompt, maximum_output_tokens, on_chunk, abort_code):
                self.calls += 1
                raise InferenceError(
                    503,
                    "EXECUTOR_UNAVAILABLE",
                    "The private worker restarted during execution.",
                )

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "inference.sqlite3"
            executor = RestartingExecutor()
            settlement = SettlementFixture()
            first = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=executor,
                settlement_backend=settlement,
                start_worker=False,
            )
            job_id = submit_fixture_job(first, "WORKER_RESTART_CANARY_f2707aba")
            first._execute_job(job_id)
            first._settle_job(job_id)
            first.close()
            self.assertEqual(executor.calls, 1)

            recovered = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=executor,
                settlement_backend=settlement,
                start_worker=False,
            )
            try:
                events = list(
                    recovered.stream(f"/api/wwm/v2/jobs/{job_id}/stream", "0")
                )
                self.assertEqual(
                    [event["type"] for event in events],
                    ["receipt.completed", "settlement.finalized"],
                )
                receipt = events[-1]["data"]
                self.assertEqual(receipt["terminal_status"], "FAILED")
                self.assertEqual(receipt["error_code"], "EXECUTOR_UNAVAILABLE")
                self.assertEqual(receipt["settlement_state"], "FINALIZED_REFUNDED")
                self.assertEqual(receipt["output_commitment"], "0" * 64)
                self.assertEqual(executor.calls, 1)
                self.assertEqual(settlement.checkpoints, ["open_finalized"])
            finally:
                recovered.close()

    def test_executor_deadline_failure_clears_prompt_and_refuses_output(self) -> None:
        prompt = "TIMEOUT_CANARY_53da489c"
        clock_ms = [1_000_000]

        class TimeoutExecutor:
            def __init__(self) -> None:
                self.observed_abort: str | None = None

            def run(self, job_id, observed_prompt, maximum_output_tokens, on_chunk, abort_code):
                clock_ms[0] += JOB_DEADLINE_SECONDS * 1000
                self.observed_abort = abort_code()
                raise InferenceError(
                    504,
                    self.observed_abort or "EXECUTION_CONTROL_INVALID",
                    "The bounded inference deadline expired.",
                )

        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "inference.sqlite3"
            settlement = SettlementFixture()
            executor = TimeoutExecutor()
            service = InferenceService(
                database=database,
                signing_seed=bytes.fromhex("12" * 32),
                provider=SnapshotFixture(),
                executor=executor,
                now_ms=lambda: clock_ms[0],
                settlement_backend=settlement,
                start_worker=False,
            )
            try:
                job_id = submit_fixture_job(service, prompt)
                with sqlite3.connect(database) as db:
                    created_ms, deadline_at_ms = db.execute(
                        "SELECT created_ms,deadline_at_ms FROM inference_jobs WHERE job_id=?",
                        (job_id,),
                    ).fetchone()
                db.close()
                self.assertEqual(
                    deadline_at_ms,
                    created_ms + JOB_DEADLINE_SECONDS * 1000,
                )
                service._execute_job(job_id)
                service._settle_job(job_id)
                receipt = service.get(
                    f"/api/wwm/v2/jobs/{job_id}/receipt",
                    "",
                    "127.0.0.1",
                ).value
                self.assertEqual(receipt["terminal_status"], "FAILED")
                self.assertEqual(receipt["error_code"], "JOB_DEADLINE_EXPIRED")
                self.assertEqual(executor.observed_abort, "JOB_DEADLINE_EXPIRED")
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
