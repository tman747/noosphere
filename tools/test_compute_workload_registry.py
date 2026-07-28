import base64
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compute_workload_registry as registry


class WorkloadRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.chain_id = "11" * 32
        self.genesis_hash = "22" * 32
        self.seed = bytes(range(1, 33))
        self.public = registry.public_from_seed(self.seed)
        self.envelope = registry.freeze_registry(
            chain_id=self.chain_id,
            genesis_hash=self.genesis_hash,
            sequence=1,
            previous_registry_id=None,
            valid_from_height=10,
            expires_at_height=100,
            activate_at_height=20,
            retire_at_height=90,
            max_units=10,
            max_unit_size=20,
            max_operations=100,
            private_seed=self.seed,
        )
        self.verified = registry.verify_registry(
            self.envelope,
            trusted_public_key=self.public,
            expected_chain_id=self.chain_id,
            expected_genesis_hash=self.genesis_hash,
            height=20,
        )

    def assert_code(self, code: str, function, *args, **kwargs) -> registry.WorkloadRegistryError:
        with self.assertRaises(registry.WorkloadRegistryError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.code, code)
        return caught.exception

    def valid_payload_and_job(self) -> tuple[dict, dict]:
        payload = {"seed": 7, "start": 11, "units": 5, "rounds": 10}
        workload = self.verified.require_active(0, 20)
        job = {
            "workload_kind": 0,
            "input_root": registry.commit_input(workload, payload),
            "units": "5",
            "unit_size": "10",
        }
        return payload, job

    def test_freeze_round_trip_has_canonical_signed_identities(self) -> None:
        summary = self.verified.summary()
        self.assertEqual(summary["signer_key_id"], registry.sha256(self.public))
        self.assertEqual(summary["registry_id"], registry.registry_identity(self.envelope["body"]))
        workload = self.envelope["body"]["workloads"][0]
        self.assertEqual(workload["workload_id"], registry.workload_identity(workload))
        self.assertEqual(self.envelope["body"]["rejection_vectors"], registry.REJECTION_VECTORS)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            canonical = root / "registry.json"
            canonical.write_bytes(registry.canonical_file(self.envelope))
            loaded = registry.load_registry(
                canonical,
                trusted_public_key=self.public,
                expected_chain_id=self.chain_id,
                expected_genesis_hash=self.genesis_hash,
                height=20,
            )
            self.assertEqual(loaded.summary(), summary)

            noncanonical = root / "pretty.json"
            noncanonical.write_text(json.dumps(self.envelope, indent=2) + "\n", encoding="utf-8")
            self.assert_code(
                "REGISTRY_MALFORMED",
                registry.load_registry,
                noncanonical,
                trusted_public_key=self.public,
                expected_chain_id=self.chain_id,
                expected_genesis_hash=self.genesis_hash,
                height=20,
            )

    def test_sequence_and_lifecycle_are_closed_intervals(self) -> None:
        self.assert_code("WORKLOAD_NOT_ACTIVE", self.verified.require_active, 0, 19)
        self.assertEqual(self.verified.require_active(0, 20).workload_kind, 0)
        self.assertEqual(self.verified.require_active(0, 89).workload_kind, 0)
        self.assert_code("WORKLOAD_RETIRED", self.verified.require_active, 0, 90)
        self.assert_code(
            "REGISTRY_MALFORMED",
            registry.freeze_registry,
            chain_id=self.chain_id,
            genesis_hash=self.genesis_hash,
            sequence=2,
            previous_registry_id=None,
            valid_from_height=10,
            expires_at_height=100,
            activate_at_height=20,
            retire_at_height=90,
            max_units=10,
            max_unit_size=20,
            max_operations=100,
            private_seed=self.seed,
        )

    def test_valid_payload_binds_signed_spec_meter_and_commitment(self) -> None:
        payload, job = self.valid_payload_and_job()
        workload, seed, start, units, rounds = registry.validate_payload(
            self.verified,
            job,
            payload,
            height=20,
            max_operations=100,
        )
        self.assertEqual(workload.workload_id, self.envelope["body"]["workloads"][0]["workload_id"])
        self.assertEqual((seed, start, units, rounds), (7, 11, 5, 10))

    def test_signed_rejection_vectors_are_executable_and_complete(self) -> None:
        payload, job = self.valid_payload_and_job()
        observed: set[str] = set()

        def capture(code: str, function, *args, **kwargs) -> None:
            self.assert_code(code, function, *args, **kwargs)
            observed.add(code)

        capture(
            "WRONG_CHAIN",
            registry.verify_registry,
            self.envelope,
            trusted_public_key=self.public,
            expected_chain_id="33" * 32,
            expected_genesis_hash=self.genesis_hash,
            height=20,
        )
        capture(
            "WRONG_GENESIS",
            registry.verify_registry,
            self.envelope,
            trusted_public_key=self.public,
            expected_chain_id=self.chain_id,
            expected_genesis_hash="44" * 32,
            height=20,
        )
        capture(
            "REGISTRY_NOT_ACTIVE",
            registry.verify_registry,
            self.envelope,
            trusted_public_key=self.public,
            expected_chain_id=self.chain_id,
            expected_genesis_hash=self.genesis_hash,
            height=9,
        )
        capture(
            "REGISTRY_EXPIRED",
            registry.verify_registry,
            self.envelope,
            trusted_public_key=self.public,
            expected_chain_id=self.chain_id,
            expected_genesis_hash=self.genesis_hash,
            height=100,
        )
        capture(
            "UNTRUSTED_SIGNER",
            registry.verify_registry,
            self.envelope,
            trusted_public_key=bytes(reversed(self.public)),
            expected_chain_id=self.chain_id,
            expected_genesis_hash=self.genesis_hash,
            height=20,
        )
        bad_signature = copy.deepcopy(self.envelope)
        signature = bytearray(base64.b64decode(bad_signature["signature"]["signature_base64"]))
        signature[0] ^= 1
        bad_signature["signature"]["signature_base64"] = base64.b64encode(signature).decode("ascii")
        capture(
            "SIGNATURE_INVALID",
            registry.verify_registry,
            bad_signature,
            trusted_public_key=self.public,
            expected_chain_id=self.chain_id,
            expected_genesis_hash=self.genesis_hash,
            height=20,
        )
        capture("UNREGISTERED_WORKLOAD", self.verified.require_active, 1, 20)
        capture("WORKLOAD_NOT_ACTIVE", self.verified.require_active, 0, 19)
        capture("WORKLOAD_RETIRED", self.verified.require_active, 0, 90)

        capture(
            "PAYLOAD_FIELDS",
            registry.validate_payload,
            self.verified,
            job,
            {**payload, "extra": 1},
            height=20,
            max_operations=100,
        )
        capture(
            "PAYLOAD_TYPE",
            registry.validate_payload,
            self.verified,
            job,
            {**payload, "seed": True},
            height=20,
            max_operations=100,
        )
        capture(
            "PAYLOAD_RANGE",
            registry.validate_payload,
            self.verified,
            job,
            {**payload, "seed": 1 << 32},
            height=20,
            max_operations=100,
        )
        capture(
            "WORKLOAD_LIMIT",
            registry.validate_payload,
            self.verified,
            job,
            {**payload, "units": 0},
            height=20,
            max_operations=100,
        )
        over_budget_payload = {"seed": 7, "start": 11, "units": 10, "rounds": 11}
        over_budget_job = {
            "workload_kind": 0,
            "input_root": "00" * 32,
            "units": "10",
            "unit_size": "11",
        }
        capture(
            "REGISTRY_OPERATION_BUDGET",
            registry.validate_payload,
            self.verified,
            over_budget_job,
            over_budget_payload,
            height=20,
            max_operations=200,
        )
        capture(
            "LOCAL_OPERATION_BUDGET",
            registry.validate_payload,
            self.verified,
            job,
            payload,
            height=20,
            max_operations=49,
        )
        capture(
            "METER_MISMATCH",
            registry.validate_payload,
            self.verified,
            {**job, "units": "6"},
            payload,
            height=20,
            max_operations=100,
        )
        capture(
            "INPUT_COMMITMENT_MISMATCH",
            registry.validate_payload,
            self.verified,
            {**job, "input_root": "00" * 32},
            payload,
            height=20,
            max_operations=100,
        )

        declared = {item["code"] for item in self.envelope["body"]["rejection_vectors"]}
        self.assertEqual(observed, declared)


if __name__ == "__main__":
    unittest.main()
