from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from blake3 import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from tools.operations import wwm_public_inference as inference


class FixtureProvider:
    def __init__(self):
        self.head_height = 1_000
        self.snapshot_value = inference.StateSnapshot(
            head_height=self.head_height,
            monitor={
                "schema": "noos/wwm-public-testnet-monitor-sample/v1",
                "sample_id": "aa" * 32,
                "signer_key_id": inference.MONITOR_SIGNER_KEY_ID,
                "checks": [
                    {"name": "inference_worker", "ok": True, "detail": {"ready": True}},
                    {"name": "model_resolution", "ok": True, "detail": {"registration_state": "ACTIVE_TESTNET"}},
                ],
            },
            resolution={
                "schema": "noos/finalized-model-resolution/v1",
                "chain_id": inference.CHAIN_ID,
                "genesis_hash": inference.GENESIS_HASH,
                "selector": "bonsai-q1",
                "trust_scope": "LOCAL_FULL_NODE_FINALIZED_STATE",
                "finalized_height": 960,
                "finalized_hash": "bb" * 32,
                "objects_root": "cc" * 32,
                "proof_count": 17,
                "proofs_verified": True,
                "active": {
                    "authorized_config_id": "dd" * 32,
                    "capsule_id": inference.CAPSULE_ID,
                    "artifact_id": inference.ARTIFACT_ID,
                    "artifact_sha256": inference.ARTIFACT_SHA256,
                    "artifact_bytes": inference.MODEL_BYTES,
                    "manifest_root": inference.MANIFEST_ROOT,
                    "runtime_root": inference.RUNTIME_ROOT,
                    "execution_profile_id": inference.EXECUTION_PROFILE_ID,
                    "query_policy_id": inference.QUERY_PROFILE_ID,
                    "availability_certificate_id": inference.AVAILABILITY_CERTIFICATE_ID,
                    "certificate_issued_height": 0,
                    "certificate_valid_until": (1 << 64) - 1,
                    "stripe_count": 454,
                    "custodian_profiles": [
                        {
                            "profile_id": f"{position + 1:064x}",
                            "endpoint_root": f"{position + 101:064x}",
                            "status": 0,
                        }
                        for position in range(12)
                    ],
                    "executor_profile_ids": [f"{position + 201:064x}" for position in range(8)],
                },
            },
        )

    def snapshot(self) -> inference.StateSnapshot:
        return inference.StateSnapshot(
            resolution=self.snapshot_value.resolution,
            monitor=self.snapshot_value.monitor,
            head_height=self.head_height,
        )


class FixtureExecutor:
    def __init__(self):
        self.calls: list[tuple[str, str, int]] = []

    def run(self, job_id: str, prompt: str, maximum_output_tokens: int, on_chunk):
        self.calls.append((job_id, prompt, maximum_output_tokens))
        output = b"grounded"
        on_chunk(output[:4], blake3(output[:4]).hexdigest())
        on_chunk(output[4:], blake3(output).hexdigest())
        history = bytearray(b"NOOS/WWM/LLAMA-TOKEN-HISTORY/V1\0")
        history.extend((1).to_bytes(4, "little"))
        history.extend((42).to_bytes(4, "little"))
        return inference.ExecutionResult(
            output=output,
            output_root=blake3(output).hexdigest(),
            output_tokens=1,
            token_history_root=blake3(bytes(history)).hexdigest(),
            tokenizer_sha256="ee" * 32,
            duration_ms=7,
        )


class BlockingExecutor(FixtureExecutor):
    def __init__(self):
        super().__init__()
        self.started = threading.Event()
        self.release = threading.Event()

    def run(self, job_id: str, prompt: str, maximum_output_tokens: int, on_chunk):
        self.started.set()
        if not self.release.wait(timeout=5):
            raise inference.InferenceError(503, "FIXTURE_TIMEOUT", "fixture timeout")
        return super().run(job_id, prompt, maximum_output_tokens, on_chunk)


class FlakyExecutor(FixtureExecutor):
    def __init__(self):
        super().__init__()
        self.attempts = 0

    def run(self, job_id: str, prompt: str, maximum_output_tokens: int, on_chunk):
        self.attempts += 1
        if self.attempts == 1:
            raise ValueError("unexpected fixture failure")
        return super().run(job_id, prompt, maximum_output_tokens, on_chunk)


class PublicInferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.provider = FixtureProvider()
        self.executor = FixtureExecutor()
        self.service = inference.InferenceService(
            database=Path(self.temp.name) / "inference.sqlite3",
            signing_seed=bytes.fromhex("11" * 32),
            provider=self.provider,
            executor=self.executor,
        )
        self.addCleanup(self.service.close)

    def state(self) -> dict:
        return self.service.get("/api/wwm/v2/state", "", "203.0.113.4").value

    def request(self, prompt: str, nonce: int = 1, maximum: int = 16) -> tuple[dict, str, str]:
        salt = f"{nonce:064x}"
        commitment = hashlib.sha256(
            inference.PROMPT_DOMAIN + bytes.fromhex(salt) + prompt.encode("utf-8")
        ).hexdigest()
        state = self.state()
        active = state["resolution"]["active"]
        return (
            {
                "request_id": f"{nonce:032x}",
                "pin_id": state["resolution"]["pin_id"],
                "capsule_id": active["capsule_id"],
                "execution_profile_id": active["execution_profile_id"],
                "query_profile_id": active["query_profile_id"],
                "prompt_commitment": commitment,
                "input_tokens": max(1, len(prompt) // 4),
                "maximum_output_tokens": maximum,
                "payment": {"mode": "SPONSORED", "authorization": ""},
                "client_nonce": f"{nonce + 100:064x}",
            },
            commitment,
            salt,
        )

    def quote_and_submit(self, prompt: str, nonce: int, client: str = "203.0.113.4") -> tuple[dict, dict]:
        request, commitment, salt = self.request(prompt, nonce)
        quote = self.service.post("/api/wwm/v2/quotes", request, client, None).value
        job = self.service.post(
            "/api/wwm/v2/jobs",
            {
                "quote_id": quote["quote_id"],
                "prompt": prompt,
                "prompt_commitment": commitment,
                "prompt_salt": salt,
            },
            client,
            f"{nonce + 200:032x}",
        ).value
        return quote, job

    def verify_signature(self, value: dict, kind: str) -> None:
        unsigned = dict(value)
        signature = base64.b64decode(unsigned.pop("signature"), validate=True)
        public_key = base64.b64decode(self.service.public_key_base64, validate=True)
        message = inference.SIGNING_DOMAIN + kind.encode("ascii") + b"\0" + inference.canonical_json(unsigned)
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)

    def test_state_is_fail_closed_and_exposes_only_bounded_sponsored_admission(self) -> None:
        state = self.state()
        self.assertEqual(state["schema"], "noos/wwm-gateway/v2")
        self.assertTrue(state["enabled"])
        self.assertFalse(state["production"])
        self.assertEqual(state["promotion_effect"], "NONE")
        self.assertEqual(state["limits"]["prompt_bytes"], 12_000)
        self.assertEqual(state["limits"]["output_tokens"], [8, 16])
        self.assertEqual(state["limits"]["jobs_per_hour_per_client"], 3)
        self.assertEqual(state["limits"]["jobs_per_hour_global"], 24)
        self.assertEqual(state["limits"]["payment_modes"], ["SPONSORED"])
        self.assertEqual(state["resolution"]["proof_source"]["proof_count"], 17)
        self.assertEqual(state["resolution"]["hosting"]["worker"]["source"], "SIGNED_OPERATOR_MONITOR")
        self.assertNotIn("private", json.dumps(state).lower())

    def test_quote_stream_and_receipt_are_bound_signed_and_explicitly_off_chain(self) -> None:
        quote, job = self.quote_and_submit("Name one property of a resilient system.", 1)
        self.assertEqual(quote["maximum_fee_micro_noos"], 0)
        self.assertEqual(quote["payment_reference"], inference.SPONSOR_REFERENCE)
        self.verify_signature(quote, "QUOTE")
        self.assertFalse(job["replayed"])

        path = f"/api/wwm/v2/jobs/{job['job_id']}/stream"
        events = [event for event in self.service.stream(path, None) if event is not None]
        self.assertGreaterEqual(len(events), 2)
        self.assertEqual([event["id"] for event in events], list(range(1, len(events) + 1)))
        for event in events:
            self.verify_signature(event, "STREAM-EVENT")
        self.assertEqual("".join(event["data"].get("delta", "") for event in events), "grounded")
        receipt = events[-1]["data"]
        self.assertEqual(events[-1]["type"], "receipt.completed")
        self.verify_signature(receipt, "RECEIPT")
        self.assertEqual(receipt["terminal_status"], "COMPLETED")
        self.assertEqual(receipt["evidence_state"], "PROVISIONAL_SIGNED")
        self.assertEqual(receipt["execution_scope"], "OFF_CHAIN_INTERACTIVE_TESTNET")
        self.assertEqual(receipt["settlement_state"], "PENDING_CHAIN")
        self.assertIsNone(receipt["chain_anchor"])
        self.assertFalse(receipt["production"])

        fetched = self.service.get(
            f"/api/wwm/v2/jobs/{job['job_id']}/receipt", "", "203.0.113.4"
        ).value
        self.assertEqual(fetched, receipt)
        with self.service._connect() as db:
            stored = db.execute("SELECT prompt FROM inference_jobs WHERE job_id=?", (job["job_id"],)).fetchone()
        self.assertIsNone(stored["prompt"])

    def test_idempotency_replays_only_the_same_bound_job(self) -> None:
        prompt = "Return one short word."
        request, commitment, salt = self.request(prompt, 2)
        quote = self.service.post("/api/wwm/v2/quotes", request, "203.0.113.5", None).value
        body = {
            "quote_id": quote["quote_id"],
            "prompt": prompt,
            "prompt_commitment": commitment,
            "prompt_salt": salt,
        }
        first = self.service.post("/api/wwm/v2/jobs", body, "203.0.113.5", "ab" * 16).value
        replay = self.service.post("/api/wwm/v2/jobs", body, "203.0.113.5", "ab" * 16).value
        self.assertEqual(replay["job_id"], first["job_id"])
        self.assertTrue(replay["replayed"])

        other_request, _, _ = self.request("Different request.", 3)
        other_quote = self.service.post("/api/wwm/v2/quotes", other_request, "203.0.113.5", None).value
        conflict = {**body, "quote_id": other_quote["quote_id"]}
        with self.assertRaisesRegex(inference.InferenceError, "already bound") as raised:
            self.service.post("/api/wwm/v2/jobs", conflict, "203.0.113.5", "ab" * 16)
        self.assertEqual(raised.exception.code, "IDEMPOTENCY_CONFLICT")

    def test_prompt_commitment_output_limit_paid_mode_and_hourly_limit_fail_closed(self) -> None:
        request, commitment, salt = self.request("Bound this prompt.", 4)
        request["maximum_output_tokens"] = 32
        with self.assertRaises(inference.InferenceError) as output_error:
            self.service.post("/api/wwm/v2/quotes", request, "203.0.113.6", None)
        self.assertEqual(output_error.exception.code, "INVALID_OUTPUT_LIMIT")

        request, commitment, salt = self.request("Bound this prompt.", 5)
        request["payment"] = {"mode": "PAID", "authorization": "signed-public-envelope"}
        with self.assertRaises(inference.InferenceError) as payment_error:
            self.service.post("/api/wwm/v2/quotes", request, "203.0.113.6", None)
        self.assertEqual(payment_error.exception.code, "PAYMENT_MODE_UNAVAILABLE")

        request, commitment, salt = self.request("Bound this prompt.", 6)
        quote = self.service.post("/api/wwm/v2/quotes", request, "203.0.113.6", None).value
        with self.assertRaises(inference.InferenceError) as mismatch:
            self.service.post(
                "/api/wwm/v2/jobs",
                {
                    "quote_id": quote["quote_id"],
                    "prompt": "Changed prompt.",
                    "prompt_commitment": commitment,
                    "prompt_salt": salt,
                },
                "203.0.113.6",
                "44" * 16,
            )
        self.assertEqual(mismatch.exception.code, "PROMPT_COMMITMENT_MISMATCH")

        for nonce in range(10, 13):
            _, job = self.quote_and_submit(f"Hourly request {nonce}.", nonce, "203.0.113.7")
            list(self.service.stream(f"/api/wwm/v2/jobs/{job['job_id']}/stream", None))
        request, _, _ = self.request("Fourth request.", 13)
        quote = self.service.post("/api/wwm/v2/quotes", request, "203.0.113.7", None).value
        _, commitment, salt = self.request("Fourth request.", 13)
        with self.assertRaises(inference.InferenceError) as limited:
            self.service.post(
                "/api/wwm/v2/jobs",
                {
                    "quote_id": quote["quote_id"],
                    "prompt": "Fourth request.",
                    "prompt_commitment": commitment,
                    "prompt_salt": salt,
                },
                "203.0.113.7",
                "55" * 16,
            )
        self.assertEqual(limited.exception.code, "JOB_RATE_LIMIT")
        self.assertGreater(limited.exception.retry_after, 0)

    def test_unexpected_executor_failure_is_terminal_and_worker_remains_available(self) -> None:
        self.service.close()
        flaky = FlakyExecutor()
        self.service = inference.InferenceService(
            database=Path(self.temp.name) / "flaky.sqlite3",
            signing_seed=bytes.fromhex("33" * 32),
            provider=self.provider,
            executor=flaky,
        )
        self.addCleanup(self.service.close)
        _, failed_job = self.quote_and_submit("First execution fails.", 20, "203.0.113.20")
        failed_events = [
            event
            for event in self.service.stream(
                f"/api/wwm/v2/jobs/{failed_job['job_id']}/stream",
                None,
            )
            if event is not None
        ]
        failed_receipt = failed_events[-1]["data"]
        self.assertEqual(failed_receipt["terminal_status"], "FAILED")
        self.assertEqual(failed_receipt["error_code"], "INTERNAL_EXECUTION_ERROR")

        _, completed_job = self.quote_and_submit("Second execution succeeds.", 21, "203.0.113.21")
        completed_events = [
            event
            for event in self.service.stream(
                f"/api/wwm/v2/jobs/{completed_job['job_id']}/stream",
                None,
            )
            if event is not None
        ]
        self.assertEqual(completed_events[-1]["data"]["terminal_status"], "COMPLETED")

    def test_global_executor_queue_never_exceeds_one_running_plus_two_waiting(self) -> None:
        self.service.close()
        blocker = BlockingExecutor()
        self.service = inference.InferenceService(
            database=Path(self.temp.name) / "bounded.sqlite3",
            signing_seed=bytes.fromhex("22" * 32),
            provider=self.provider,
            executor=blocker,
        )
        self.addCleanup(self.service.close)
        jobs = []
        for nonce, client in zip(range(30, 33), ["203.0.113.30", "203.0.113.31", "203.0.113.32"]):
            _, job = self.quote_and_submit(f"Queued request {nonce}.", nonce, client)
            jobs.append(job)
            if nonce == 30:
                self.assertTrue(blocker.started.wait(timeout=2))
        request, commitment, salt = self.request("Queue overflow.", 33)
        quote = self.service.post("/api/wwm/v2/quotes", request, "203.0.113.33", None).value
        with self.assertRaises(inference.InferenceError) as full:
            self.service.post(
                "/api/wwm/v2/jobs",
                {
                    "quote_id": quote["quote_id"],
                    "prompt": "Queue overflow.",
                    "prompt_commitment": commitment,
                    "prompt_salt": salt,
                },
                "203.0.113.33",
                "66" * 16,
            )
        self.assertEqual(full.exception.code, "EXECUTOR_QUEUE_FULL")
        blocker.release.set()
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            with self.service._connect() as db:
                remaining = db.execute(
                    "SELECT COUNT(*) FROM inference_jobs WHERE status NOT IN ('COMPLETED','CANCELLED','FAILED','NO_QUORUM')"
                ).fetchone()[0]
            if remaining == 0:
                break
            time.sleep(0.02)
        self.assertEqual(remaining, 0)


if __name__ == "__main__":
    unittest.main()
