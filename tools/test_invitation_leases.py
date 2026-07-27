import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from invitation_leases import issue_lease, keygen, lease_rows, revoke_lease, verify_lease


class InvitationLeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.seed = self.root / "invite.seed"
        self.database = self.root / "leases.sqlite3"
        self.signing_key = keygen(self.seed)
        self.base = {
            "chain_id": "01" * 32,
            "genesis_hash": "02" * 32,
            "params_sha256": "03" * 32,
            "validator_host": "192.0.2.10",
            "validator_p2p_port": 21701,
            "test_network": True,
        }

    def tearDown(self):
        self.temp.cleanup()
    def witness(self, index):
        return {**self.base, "witness_index": index}


    def test_unique_role_is_signed_expiring_and_revocable(self):
        invite = issue_lease(
            self.database,
            self.seed,
            self.witness(1),
            "witness-1",
            "windows",
            3600,
            now_ms=1_000_000,
        )
        verify_lease(invite, self.database, now_ms=1_000_001)
        self.assertEqual(invite["role"], "witness-1")
        self.assertEqual(len(invite["signature"]), 128)
        with self.assertRaisesRegex(ValueError, "already leased"):
            issue_lease(
                self.database,
                self.seed,
                self.witness(1),
                "witness-1",
                "macos",
                3600,
                now_ms=1_000_002,
            )
        self.assertTrue(revoke_lease(self.database, invite["lease_id"], now_ms=1_000_003))
        with self.assertRaisesRegex(ValueError, "unknown or revoked"):
            verify_lease(invite, self.database, now_ms=1_000_004)
        replacement = issue_lease(
            self.database,
            self.seed,
            self.witness(1),
            "witness-1",
            "macos",
            3600,
            now_ms=1_000_005,
        )
        self.assertNotEqual(replacement["lease_id"], invite["lease_id"])

    def test_tampering_and_expiry_fail_closed(self):
        invite = issue_lease(
            self.database,
            self.seed,
            self.witness(2),
            "witness-2",
            "linux",
            60,
            now_ms=2_000_000,
        )
        tampered = dict(invite)
        tampered["validator_host"] = "198.51.100.20"
        with self.assertRaisesRegex(ValueError, "verification failed"):
            verify_lease(tampered, now_ms=2_000_001, trusted_public_key_hex=self.signing_key)
        with self.assertRaisesRegex(ValueError, "not currently valid"):
            verify_lease(invite, now_ms=2_060_000, trusted_public_key_hex=self.signing_key)
        self.assertEqual(len(lease_rows(self.database)), 1)

    def test_every_voting_role_is_unique_expiring_and_reassignable(self):
        leases = []
        for index in (1, 2, 3):
            lease = issue_lease(
                self.database,
                self.seed,
                self.witness(index),
                f"witness-{index}",
                "linux",
                60,
                now_ms=4_000_000,
            )
            verify_lease(lease, self.database, now_ms=4_000_001)
            leases.append(lease)
        self.assertEqual({lease["role"] for lease in leases}, {"witness-1", "witness-2", "witness-3"})
        replacement = issue_lease(
            self.database,
            self.seed,
            self.witness(3),
            "witness-3",
            "windows",
            60,
            now_ms=4_060_000,
        )
        self.assertNotEqual(replacement["lease_id"], leases[2]["lease_id"])

    def test_role_index_and_trust_anchor_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "does not match"):
            issue_lease(
                self.database,
                self.seed,
                self.witness(2),
                "witness-1",
                "linux",
                60,
                now_ms=5_000_000,
            )
        lease = issue_lease(
            self.database,
            self.seed,
            self.witness(1),
            "witness-1",
            "linux",
            60,
            now_ms=5_000_000,
        )
        with self.assertRaisesRegex(ValueError, "trusted public key"):
            verify_lease(lease, now_ms=5_000_001)
        with self.assertRaisesRegex(ValueError, "not trusted"):
            verify_lease(
                lease,
                now_ms=5_000_001,
                trusted_public_key_hex="09" * 32,
            )

    def test_observer_leases_can_coexist(self):
        first = issue_lease(
            self.database, self.seed, self.base, "observer", "windows", 60, now_ms=3_000_000
        )
        second = issue_lease(
            self.database, self.seed, self.base, "observer", "macos", 60, now_ms=3_000_001
        )
        self.assertNotEqual(first["lease_id"], second["lease_id"])


if __name__ == "__main__":
    unittest.main()
