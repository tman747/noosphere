import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compute_market
import compute_workload_registry as workload_registry
from compute_worker import compute_root


class ComputeMarketRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        seed = bytes(range(1, 33))
        chain_id = "11" * 32
        genesis_hash = "22" * 32
        envelope = workload_registry.freeze_registry(
            chain_id=chain_id,
            genesis_hash=genesis_hash,
            sequence=1,
            previous_registry_id=None,
            valid_from_height=0,
            expires_at_height=100,
            activate_at_height=0,
            retire_at_height=100,
            max_units=10,
            max_unit_size=20,
            max_operations=100,
            private_seed=seed,
        )
        self.registry = workload_registry.verify_registry(
            envelope,
            trusted_public_key=workload_registry.public_from_seed(seed),
            expected_chain_id=chain_id,
            expected_genesis_hash=genesis_hash,
            height=5,
        )
        profile = {
            "chain_id": chain_id,
            "genesis_hash": genesis_hash,
            "api_base_url": "http://127.0.0.1:18080",
        }
        with patch.object(compute_market, "cargo_binary", return_value=Path("noos-cli")), patch.object(
            compute_market,
            "derive",
            return_value={"verifying_key": "33" * 32},
        ):
            self.market = compute_market.Market(
                profile,
                "01" * 32,
                0,
                0,
                Path(self.temporary.name) / "market.sqlite3",
                "a" * 24,
                self.registry,
            )

    def tearDown(self) -> None:
        self.market.identity.close()
        self.market.db.close()
        self.temporary.cleanup()

    def test_job_open_uses_signed_identity_meter_and_limits(self) -> None:
        self.market.chain = lambda path: {"unsafe_head": {"height": 5}}
        captured: list[dict] = []

        def submit(profile, identity, action):
            captured.append(action)
            return {
                "txid": "44" * 32,
                "built": {"created_compute_jobs": [{"job_id": "55" * 32}]},
            }

        with patch.object(compute_market, "submit_action", side_effect=submit):
            opened = self.market.create_jobs(
                {
                    "shard_count": 1,
                    "units_per_shard": 5,
                    "rounds": 10,
                    "max_price_per_unit": 2,
                    "deadline_blocks": 20,
                    "seed": 7,
                }
            )
        workload = self.registry.require_active(0, 5)
        payload = {"seed": 7, "start": 0, "units": 5, "rounds": 10}
        self.assertEqual(captured[0]["workload_kind"], workload.workload_kind)
        self.assertEqual(captured[0]["input_root"], workload_registry.commit_input(workload, payload))
        self.assertEqual(opened["workload_registry_id"], self.registry.registry_id)
        self.assertEqual(opened["workload_id"], workload.workload_id)

        with patch.object(compute_market, "submit_action") as rejected_submit:
            with self.assertRaisesRegex(ValueError, "signed registry bounds"):
                self.market.create_jobs(
                    {
                        "shard_count": 1,
                        "units_per_shard": 10,
                        "rounds": 11,
                        "seed": 7,
                    }
                )
        rejected_submit.assert_not_called()

    def test_acceptance_recomputes_only_registry_bound_submitted_result(self) -> None:
        job_id = "66" * 32
        payload = {"seed": 7, "start": 0, "units": 2, "rounds": 3}
        workload = self.registry.require_active(0, 5)
        input_root = workload_registry.commit_input(workload, payload)
        expected = compute_root(workload, 7, 0, 2, 3, 1)
        self.market.db.execute(
            "INSERT INTO payloads(job_id,seed,start,units,rounds,created_ms) VALUES(?,?,?,?,?,?)",
            (job_id, 7, 0, 2, 3, 1),
        )
        self.market.db.commit()
        job = {
            "job_id": job_id,
            "state": 2,
            "workload_kind": 0,
            "input_root": input_root,
            "units": "2",
            "unit_size": "3",
            "result_root": expected,
        }
        self.market.chain = lambda path: {"items": [job]}
        with patch.object(
            compute_market,
            "submit_action",
            return_value={"txid": "77" * 32, "state": "INCLUDED"},
        ) as submit:
            accepted = self.market.accept({"job_id": job_id, "result_root": expected})
        self.assertEqual(accepted["workload_id"], workload.workload_id)
        self.assertEqual(submit.call_args.args[2]["type"], "accept_compute_result")

        self.market.chain = lambda path: {"items": [{**job, "input_root": "00" * 32}]}
        with patch.object(compute_market, "submit_action") as rejected_submit:
            with self.assertRaisesRegex(ValueError, "commitment mismatch"):
                self.market.accept({"job_id": job_id, "result_root": expected})
        rejected_submit.assert_not_called()

        invalid = "ff" * 32
        self.market.chain = lambda path: {"items": [{**job, "result_root": invalid}]}
        with patch.object(
            compute_market,
            "submit_action",
            return_value={"txid": "88" * 32, "state": "INCLUDED"},
        ) as submit:
            challenged = self.market.accept({"job_id": job_id, "result_root": invalid})
        action = submit.call_args.args[2]
        self.assertEqual(action["type"], "challenge_compute_result")
        self.assertEqual(action["seed"], 7)
        self.assertEqual(action["start"], 0)
        self.assertEqual(challenged["resolution"], "INVALID_RESULT_REFUNDED_AND_SLASHED")

        self.market.chain = lambda path: {"items": [job]}
        with patch.object(compute_market, "submit_action") as rejected_submit:
            with self.assertRaisesRegex(ValueError, "notification differs"):
                self.market.accept({"job_id": job_id, "result_root": invalid})
        rejected_submit.assert_not_called()

    def test_helper_registration_reserves_available_bond(self) -> None:
        self.market.chain = lambda path: {
            "items": [{
                "worker": self.market.requester,
                "active": 1,
                "bond_available": "50",
                "bond_locked": "20",
            }]
        }
        with patch.object(
            compute_market,
            "submit_action",
            return_value={"txid": "99" * 32, "state": "INCLUDED"},
        ) as submit:
            self.market.ensure_helper_worker(500)
        action = submit.call_args.args[2]
        self.assertEqual(action["type"], "register_compute_worker")
        self.assertEqual(action["bond"], "100020")


if __name__ == "__main__":
    unittest.main()
