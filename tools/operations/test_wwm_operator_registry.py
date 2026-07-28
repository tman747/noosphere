from __future__ import annotations

import base64
import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.operations import wwm_operator_registry as registry


class OperatorRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    @staticmethod
    def seeds(index: int) -> tuple[bytes, bytes, bytes]:
        return (
            bytes([index]) * 32,
            bytes([index + 32]) * 32,
            bytes([index + 64]) * 32,
        )

    @staticmethod
    def public(seed: bytes) -> str:
        value = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes_raw()
        return base64.b64encode(value).decode("ascii")

    def record(
        self,
        index: int,
        *,
        operator_id: str | None = None,
        valid_from: int = 10,
        expires: int = 1000,
        provider: str | None = None,
        region: str | None = None,
    ) -> tuple[dict[str, object], tuple[bytes, bytes, bytes]]:
        seeds = self.seeds(index)
        identity = Ed25519PrivateKey.from_private_bytes(seeds[0]).public_key().public_bytes_raw()
        stable_id = operator_id or registry.sha256(registry.RECORD_DOMAIN + identity)
        record: dict[str, object] = {
            "record_id": "0" * 64,
            "operator_id": stable_id,
            "organization_root": f"{index + 1:064x}",
            "beneficial_owner_root": f"{index + 2:064x}",
            "control_cluster_id": f"{index + 3:064x}",
            "provider_root": provider or f"{index + 4:064x}",
            "region_id": region or f"{index + 5:064x}",
            "asn": 64512 + index,
            "software_lineage_root": f"{index + 6:064x}",
            "model_publisher_root": f"{index + 7:064x}",
            "identity_public_key_base64": self.public(seeds[0]),
            "operational_public_key_base64": self.public(seeds[1]),
            "revocation_public_key_base64": self.public(seeds[2]),
            "roles": ["custodian", "executor"],
            "capacity": {
                "compute_units": 100,
                "memory_bytes": 64 * 1024**3,
                "storage_bytes": 2 * 1024**4,
                "bandwidth_bps": 1_000_000_000,
            },
            "valid_from_height": valid_from,
            "expires_at_height": expires,
            "incident_contact_root": f"{index + 8:064x}",
        }
        record["record_id"] = registry.record_id(record)
        return record, seeds

    @staticmethod
    def body(
        operator_id: str,
        sequence: int,
        previous: str | None,
        operation: str,
        effective: int,
        **fields: object,
    ) -> dict[str, object]:
        return {
            "operator_id": operator_id,
            "sequence": sequence,
            "previous_entry_id": previous,
            "operation": operation,
            "effective_height": effective,
            **fields,
        }

    def enrollment(self, index: int) -> tuple[dict[str, object], dict[str, object], tuple[bytes, bytes, bytes]]:
        record, seeds = self.record(index)
        body = self.body(
            str(record["operator_id"]),
            1,
            None,
            "ENROLL",
            int(record["valid_from_height"]),
            record=record,
        )
        return registry.sign_body(body, seeds), record, seeds

    def test_enrollment_successor_activation_and_revocation_lifecycle(self) -> None:
        initial, active, active_seeds = self.enrollment(1)
        states: dict[str, registry.OperatorState] = {}
        registry.apply_entry(states, initial)
        operator_id = str(active["operator_id"])
        self.assertEqual(
            registry.active_operational_key(states, operator_id, 20),
            base64.b64decode(str(active["operational_public_key_base64"])),
        )

        successor, successor_seeds = self.record(
            9, operator_id=operator_id, valid_from=50, expires=2000
        )
        publish_body = self.body(
            operator_id,
            2,
            str(initial["body"]["entry_id"]),
            "PUBLISH_SUCCESSOR",
            40,
            successor=successor,
            overlap_until_height=100,
        )
        publish = registry.sign_body(
            publish_body, [active_seeds[0], *successor_seeds]
        )
        registry.apply_entry(states, publish)
        activate_body = self.body(
            operator_id,
            3,
            str(publish["body"]["entry_id"]),
            "ACTIVATE_SUCCESSOR",
            60,
            successor_record_id=successor["record_id"],
        )
        activate = registry.sign_body(
            activate_body, [active_seeds[0], successor_seeds[0]]
        )
        registry.apply_entry(states, activate)
        old_operational = base64.b64decode(str(active["operational_public_key_base64"]))
        new_operational = base64.b64decode(str(successor["operational_public_key_base64"]))
        self.assertNotEqual(old_operational, new_operational)
        self.assertEqual(registry.active_operational_key(states, operator_id, 70), new_operational)

        revoke_body = self.body(
            operator_id,
            4,
            str(activate["body"]["entry_id"]),
            "REVOKE",
            80,
            target_record_id=successor["record_id"],
            reason_root="91" * 32,
        )
        revoke = registry.sign_body(revoke_body, [successor_seeds[2]])
        registry.apply_entry(states, revoke)
        with self.assertRaisesRegex(registry.RegistryError, "no active"):
            registry.active_operational_key(states, operator_id, 80)

    def test_rotation_rejects_stale_missing_and_out_of_overlap_keys(self) -> None:
        initial, active, active_seeds = self.enrollment(2)
        states: dict[str, registry.OperatorState] = {}
        registry.apply_entry(states, initial)
        operator_id = str(active["operator_id"])
        successor, successor_seeds = self.record(
            10, operator_id=operator_id, valid_from=50, expires=2000
        )
        publish = registry.sign_body(
            self.body(
                operator_id,
                2,
                str(initial["body"]["entry_id"]),
                "PUBLISH_SUCCESSOR",
                40,
                successor=successor,
                overlap_until_height=100,
            ),
            [active_seeds[0], *successor_seeds],
        )
        registry.apply_entry(states, publish)
        activation_body = self.body(
            operator_id,
            3,
            str(publish["body"]["entry_id"]),
            "ACTIVATE_SUCCESSOR",
            60,
            successor_record_id=successor["record_id"],
        )
        missing_successor = registry.sign_body(activation_body, [active_seeds[0]])
        with self.assertRaisesRegex(registry.RegistryError, "exact required keys"):
            registry.apply_entry(states, missing_successor)

        late_body = dict(activation_body)
        late_body["effective_height"] = 101
        late = registry.sign_body(late_body, [active_seeds[0], successor_seeds[0]])
        with self.assertRaisesRegex(registry.RegistryError, "outside the overlap"):
            registry.apply_entry(states, late)

        wrong_revoke = registry.sign_body(
            self.body(
                operator_id,
                3,
                str(publish["body"]["entry_id"]),
                "REVOKE",
                70,
                target_record_id=active["record_id"],
                reason_root="92" * 32,
            ),
            [active_seeds[0]],
        )
        with self.assertRaisesRegex(registry.RegistryError, "exact required keys"):
            registry.apply_entry(states, wrong_revoke)

    def test_append_only_ledger_recovers_and_preserves_foreign_lock(self) -> None:
        initial, active, active_seeds = self.enrollment(3)
        ledger = self.root / "operators.jsonl"
        states = registry.append_entry(ledger, initial)
        operator_id = str(active["operator_id"])
        successor, successor_seeds = self.record(
            11, operator_id=operator_id, valid_from=50, expires=2000
        )
        publish = registry.sign_body(
            self.body(
                operator_id,
                2,
                str(initial["body"]["entry_id"]),
                "PUBLISH_SUCCESSOR",
                40,
                successor=successor,
                overlap_until_height=100,
            ),
            [active_seeds[0], *successor_seeds],
        )
        lock = ledger.with_suffix(".jsonl.lock")
        lock.write_text("other-writer", encoding="ascii")
        with self.assertRaisesRegex(registry.RegistryError, "locked"):
            registry.append_entry(ledger, publish)
        self.assertEqual(lock.read_text(encoding="ascii"), "other-writer")
        lock.unlink()
        states = registry.append_entry(ledger, publish)
        entries, recovered = registry.load_ledger(ledger)
        self.assertEqual(len(entries), 2)
        self.assertEqual(states[operator_id].pending, recovered[operator_id].pending)

    def policy(self) -> dict[str, object]:
        return {
            "schema": registry.POLICY_SCHEMA,
            "minimum_members": 3,
            "minimum_distinct_beneficial_owners": 3,
            "minimum_distinct_control_clusters": 3,
            "minimum_distinct_providers": 3,
            "minimum_distinct_regions": 3,
            "minimum_distinct_asns": 3,
            "minimum_distinct_software_lineages": 3,
            "minimum_distinct_model_publishers": 3,
            "maximum_members_per_provider": 1,
            "maximum_members_per_region": 1,
        }

    def test_committee_admission_enforces_every_independence_dimension(self) -> None:
        states: dict[str, registry.OperatorState] = {}
        ids: list[str] = []
        for index in (4, 5, 6):
            entry, record, _ = self.enrollment(index)
            registry.apply_entry(states, entry)
            ids.append(str(record["operator_id"]))
        ids.sort()
        result = registry.admit_committee(states, ids, 20, self.policy())
        self.assertTrue(result["admitted"])
        self.assertEqual(result["distinct"]["providers"], 3)

        clustered: dict[str, registry.OperatorState] = {}
        clustered_ids: list[str] = []
        for index in (12, 13, 14):
            record, seeds = self.record(index, provider="aa" * 32)
            entry = registry.sign_body(
                self.body(
                    str(record["operator_id"]),
                    1,
                    None,
                    "ENROLL",
                    10,
                    record=record,
                ),
                seeds,
            )
            registry.apply_entry(clustered, entry)
            clustered_ids.append(str(record["operator_id"]))
        with self.assertRaisesRegex(registry.RegistryError, "providers diversity"):
            registry.admit_committee(clustered, sorted(clustered_ids), 20, self.policy())

    def test_tampering_and_malformed_identity_fail_closed(self) -> None:
        entry, record, _ = self.enrollment(7)
        tampered = copy.deepcopy(entry)
        tampered["body"]["record"]["capacity"]["compute_units"] = 101
        with self.assertRaisesRegex(registry.RegistryError, "entry id mismatch|record id mismatch"):
            registry.validate_entry_envelope(tampered)

        duplicate_keys = copy.deepcopy(record)
        duplicate_keys["operational_public_key_base64"] = duplicate_keys[
            "identity_public_key_base64"
        ]
        duplicate_keys["record_id"] = registry.record_id(duplicate_keys)
        with self.assertRaisesRegex(registry.RegistryError, "must be distinct"):
            registry.validate_record(duplicate_keys)

        bad_signature = copy.deepcopy(entry)
        bad_signature["signatures"][0]["signature_base64"] = base64.b64encode(bytes(64)).decode("ascii")
        with self.assertRaisesRegex(registry.RegistryError, "signature is invalid"):
            registry.validate_entry_envelope(bad_signature)


if __name__ == "__main__":
    unittest.main()
