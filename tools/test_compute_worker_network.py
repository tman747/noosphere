import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compute_worker
import compute_workload_registry as workload_registry


class ComputeNetworkTests(unittest.TestCase):
    def setUp(self) -> None:
        seed = bytes(range(1, 33))
        chain_id = "01" * 32
        genesis_hash = "02" * 32
        envelope = workload_registry.freeze_registry(
            chain_id=chain_id,
            genesis_hash=genesis_hash,
            sequence=1,
            previous_registry_id=None,
            valid_from_height=0,
            expires_at_height=100,
            activate_at_height=0,
            retire_at_height=100,
            max_units=1_000,
            max_unit_size=1_000,
            max_operations=4_096,
            private_seed=seed,
        )
        self.registry = workload_registry.verify_registry(
            envelope,
            trusted_public_key=workload_registry.public_from_seed(seed),
            expected_chain_id=chain_id,
            expected_genesis_hash=genesis_hash,
            height=1,
        )

    def test_operator_head_is_identity_checked(self) -> None:
        profile = {
            "chain_id": "01" * 32,
            "genesis_hash": "02" * 32,
            "api_base_url": "http://127.0.0.1:18080",
            "_operator_node": "127.0.0.1:18632",
            "_operator_token": "private-token",
        }
        response = io.BytesIO(
            json.dumps(
                {
                    "chain_id": profile["chain_id"],
                    "genesis_hash": profile["genesis_hash"],
                    "unsafe_head": {"height": 4912, "hash": "03" * 32},
                }
            ).encode()
        )
        with patch("urllib.request.urlopen", return_value=response) as request:
            status = compute_worker.live_status(profile)
        self.assertEqual(status["unsafe_head"]["height"], 4912)
        sent = request.call_args.args[0]
        self.assertEqual(sent.get_header("Authorization"), "Bearer private-token")

    def test_receipt_fallback_settles_when_index_record_is_missing(self) -> None:
        profile = {"api_base_url": "http://127.0.0.1:18080"}
        receipt = {
            "receipt": {"txid": "ab" * 32, "status": 0, "fee_charged": "544"},
            "state": {"settled_height": 4914, "status_code": 0},
        }
        with patch.object(
            compute_worker,
            "api_json",
            side_effect=[SystemExit("HTTP Error 404: not found"), receipt],
        ):
            record = compute_worker.settlement_record(profile, "ab" * 32)
        self.assertEqual(record["state"], "INCLUDED")
        self.assertEqual(record["receipt"]["state"]["settled_height"], 4914)

    def test_payload_is_bound_to_on_chain_commitment_and_meter(self) -> None:
        payload = {"seed": 7, "start": 11, "units": 32, "rounds": 64}
        commitment = workload_registry.commit_input(
            self.registry.require_active(0, 1),
            payload,
        )
        job = {
            "workload_kind": 0,
            "input_root": commitment,
            "units": "32",
            "unit_size": "64",
        }
        validated = compute_worker.validate_payload(
            self.registry, job, payload, 1, 2_048
        )
        self.assertEqual(validated[1:], (7, 11, 32, 64))

        tampered = dict(payload, seed=8)
        with self.assertRaisesRegex(ValueError, "commitment mismatch"):
            compute_worker.validate_payload(
                self.registry, job, tampered, 1, 2_048
            )

    def test_unregistered_or_over_budget_workload_is_refused(self) -> None:
        payload = {"seed": 1, "start": 0, "units": 10, "rounds": 10}
        job = {
            "workload_kind": 9,
            "input_root": "00" * 32,
            "units": "10",
            "unit_size": "10",
        }
        with self.assertRaisesRegex(ValueError, "unregistered"):
            compute_worker.validate_payload(
                self.registry, job, payload, 1, 100
            )
        job["workload_kind"] = 0
        with self.assertRaisesRegex(ValueError, "operation budget"):
            compute_worker.validate_payload(
                self.registry, job, payload, 1, 99
            )

    def test_worker_actions_are_signed_only_for_local_payout_identity(self) -> None:
        payout = "ab" * 32
        local_identity = compute_worker.WorkerIdentity(
            chain_id="01" * 32,
            genesis_hash="02" * 32,
            account=3,
            index=4,
            payout_account=payout,
            seed=bytearray(range(32)),
        )
        profile = {
            "chain_id": local_identity.chain_id,
            "genesis_hash": local_identity.genesis_hash,
            "api_base_url": "http://127.0.0.1:18080",
        }
        action = {
            "type": "register_compute_worker",
            "worker": payout,
            "capabilities": 1,
        }
        built = {"tx": "11" * 32, "txid": "22" * 32}
        signed = {"txid": built["txid"], "verifying_key": payout, "witnesses": "33"}
        with (
            patch.object(compute_worker, "cargo_binary", return_value=Path("noos-cli")),
            patch.object(
                compute_worker,
                "live_status",
                return_value={"unsafe_head": {"height": 7}},
            ),
            patch.object(
                compute_worker, "cli_json", side_effect=[built, signed]
            ) as cli,
            patch.object(compute_worker, "checked_status"),
            patch.object(
                compute_worker,
                "api_json",
                return_value={"txid": built["txid"]},
            ),
            patch.object(
                compute_worker,
                "settlement_record",
                return_value={"state": "INCLUDED"},
            ),
        ):
            result = compute_worker.submit_action(profile, local_identity, action)
        self.assertEqual(result["txid"], built["txid"])
        sign_call = cli.call_args_list[1]
        self.assertIn("--seed-stdin", sign_call.args)
        self.assertNotIn(local_identity.seed.hex(), sign_call.args)
        self.assertEqual(sign_call.kwargs["stdin_text"], local_identity.seed.hex() + "\n")

        forged = dict(action, worker="cd" * 32)
        with self.assertRaisesRegex(RuntimeError, "differs from the local payout"):
            compute_worker.submit_action(profile, local_identity, forged)


    def test_dispute_recomputation_reserves_consensus_grain(self) -> None:
        profile = {"chain_id": "01" * 32}
        signer = "ab" * 32
        challenge = compute_worker.transaction_spec(
            profile,
            signer,
            7,
            {
                "type": "challenge_compute_result",
                "requester": signer,
                "job_id": "cd" * 32,
                "seed": 1,
                "start": 0,
            },
        )
        accept = compute_worker.transaction_spec(
            profile,
            signer,
            7,
            {
                "type": "accept_compute_result",
                "requester": signer,
                "job_id": "cd" * 32,
            },
        )
        self.assertEqual(challenge["resource_limits"]["grain_steps"], 1_000_000)
        self.assertEqual(accept["resource_limits"]["grain_steps"], 0)
        compute_worker.require_local_action_actor(
            {"type": "accept_compute_result", "requester": signer, "job_id": "cd" * 32},
            signer,
        )
        compute_worker.require_local_action_actor(
            {"type": "finalize_compute_result", "worker": "ef" * 32, "job_id": "cd" * 32},
            signer,
        )
        with self.assertRaisesRegex(RuntimeError, "differs from the local payout"):
            compute_worker.require_local_action_actor(
                {"type": "challenge_compute_result", "requester": "ef" * 32},
                signer,
            )


if __name__ == "__main__":
    unittest.main()
