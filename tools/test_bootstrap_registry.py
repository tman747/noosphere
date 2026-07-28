import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bootstrap_registry as registry


class BootstrapRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.seed = bytes(range(1, 33))
        self.public = registry.public_from_seed(self.seed)
        self.chain_id = "11" * 32
        self.genesis_hash = "22" * 32
        self.node_ids = [registry.peer_id_from_seed(bytes([value]) * 32) for value in (41, 42, 43, 44)]
        self.nodes = [self.node(index, f"seed-{index}.example") for index in range(3)]
        self.envelope = registry.sign_registry(
            chain_id=self.chain_id,
            genesis_hash=self.genesis_hash,
            sequence=1,
            previous_registry_id=None,
            valid_from_unix_ms=1_000,
            expires_unix_ms=10_000,
            nodes=self.nodes,
            private_seed=self.seed,
        )

    def node(self, index: int, host: str) -> dict:
        node_id = self.node_ids[index]
        return registry.make_node(
            node_id,
            [f"/dns4/{host}/udp/19701/quic-v1/p2p/{node_id}"],
            1_000,
            9_000,
        )

    def test_signed_snapshot_binds_multiple_canonical_peer_addresses(self) -> None:
        verified = registry.verify_registry(
            self.envelope,
            trusted_public_key=self.public,
            expected_chain_id=self.chain_id,
            expected_genesis_hash=self.genesis_hash,
            now_unix_ms=5_000,
        )
        self.assertEqual(verified["body"]["registry_id"], registry.registry_identity(verified["body"]))
        self.assertEqual(len(verified["body"]["nodes"]), 3)
        self.assertEqual(
            [node["node_id"] for node in verified["body"]["nodes"]],
            sorted(self.node_ids[:3]),
        )
        for node_id in self.node_ids:
            self.assertEqual(registry.validate_peer_id(node_id), node_id)

    def test_direct_successor_rotates_stable_identity_and_revokes_explicitly(self) -> None:
        rotated = self.node(0, "seed-0-rotated.example")
        retained = self.node(1, "seed-1.example")
        successor = registry.rotate_registry(
            self.envelope,
            active_nodes=[rotated, retained],
            revoked_node_ids={self.node_ids[2]},
            revoked_at_unix_ms=5_000,
            private_seed=self.seed,
        )
        registry.verify_registry(
            successor,
            trusted_public_key=self.public,
            expected_chain_id=self.chain_id,
            expected_genesis_hash=self.genesis_hash,
            now_unix_ms=5_000,
        )
        registry.verify_transition(self.envelope, successor)
        by_id = {node["node_id"]: node for node in successor["body"]["nodes"]}
        self.assertIn("seed-0-rotated.example", by_id[self.node_ids[0]]["addresses"][0])
        self.assertEqual(by_id[self.node_ids[2]]["status"], "revoked")

        with self.assertRaisesRegex(registry.BootstrapRegistryError, "explicitly revoke"):
            registry.rotate_registry(
                self.envelope,
                active_nodes=[rotated, retained],
                revoked_node_ids=set(),
                revoked_at_unix_ms=5_000,
                private_seed=self.seed,
            )
        with self.assertRaisesRegex(registry.BootstrapRegistryError, "revoked bootstrap"):
            registry.rotate_registry(
                successor,
                active_nodes=[rotated, retained, self.node(2, "seed-2.example")],
                revoked_node_ids=set(),
                revoked_at_unix_ms=6_000,
                private_seed=self.seed,
            )

    def test_wrong_chain_expiry_untrusted_key_and_mutation_fail_closed(self) -> None:
        cases = [
            ({"expected_chain_id": "33" * 32, "now_unix_ms": 5_000}, "wrong chain"),
            ({"expected_chain_id": self.chain_id, "now_unix_ms": 10_000}, "expired"),
        ]
        for overrides, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(registry.BootstrapRegistryError, message):
                    registry.verify_registry(
                        self.envelope,
                        trusted_public_key=self.public,
                        expected_chain_id=overrides["expected_chain_id"],
                        expected_genesis_hash=self.genesis_hash,
                        now_unix_ms=overrides["now_unix_ms"],
                    )
        with self.assertRaisesRegex(registry.BootstrapRegistryError, "pinned trusted key"):
            registry.verify_registry(
                self.envelope,
                trusted_public_key=bytes(reversed(self.public)),
                expected_chain_id=self.chain_id,
                expected_genesis_hash=self.genesis_hash,
                now_unix_ms=5_000,
            )
        mutated = copy.deepcopy(self.envelope)
        mutated["signature"]["signature"] = ("00" if mutated["signature"]["signature"][:2] != "00" else "01") + mutated["signature"]["signature"][2:]
        with self.assertRaisesRegex(registry.BootstrapRegistryError, "signature verification"):
            registry.verify_registry(
                mutated,
                trusted_public_key=self.public,
                expected_chain_id=self.chain_id,
                expected_genesis_hash=self.genesis_hash,
                now_unix_ms=5_000,
            )

    def test_transition_rejects_wrong_predecessor_and_sequence_conflict(self) -> None:
        successor = registry.rotate_registry(
            self.envelope,
            active_nodes=[self.node(0, "seed-0.example"), self.node(1, "seed-1.example")],
            revoked_node_ids={self.node_ids[2]},
            revoked_at_unix_ms=5_000,
            private_seed=self.seed,
        )
        wrong_previous = copy.deepcopy(successor)
        wrong_previous["body"]["previous_registry_id"] = "00" * 32
        wrong_previous = registry.sign_registry(
            chain_id=self.chain_id,
            genesis_hash=self.genesis_hash,
            sequence=2,
            previous_registry_id="00" * 32,
            valid_from_unix_ms=1_000,
            expires_unix_ms=10_000,
            nodes=wrong_previous["body"]["nodes"],
            private_seed=self.seed,
        )
        with self.assertRaisesRegex(registry.BootstrapRegistryError, "direct signed successor"):
            registry.verify_transition(self.envelope, wrong_previous)

        conflict = registry.sign_registry(
            chain_id=self.chain_id,
            genesis_hash=self.genesis_hash,
            sequence=1,
            previous_registry_id=None,
            valid_from_unix_ms=1_000,
            expires_unix_ms=10_000,
            nodes=[self.node(0, "different.example"), self.node(1, "seed-1.example"), self.node(2, "seed-2.example")],
            private_seed=self.seed,
        )
        with self.assertRaisesRegex(registry.BootstrapRegistryError, "conflicting"):
            registry.verify_transition(self.envelope, conflict)


if __name__ == "__main__":
    unittest.main()
