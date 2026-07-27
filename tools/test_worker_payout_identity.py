import base64
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import worker_payout_identity as identity


CHAIN_ID = "11" * 32
GENESIS_HASH = "22" * 32
PASSWORD = bytearray(b"correct horse battery staple")


def fake_derive(_cli_path: Path, seed: bytearray, account: int, index: int) -> str:
    return hashlib.sha256(
        b"test-worker-payout" + bytes(seed) + account.to_bytes(4, "little") + index.to_bytes(4, "little")
    ).hexdigest()


def deterministic_random(length: int) -> bytes:
    return bytes((length + offset) % 256 for offset in range(length))


class WorkerPayoutIdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.identity_path = self.root / "private" / "worker.identity.json"
        self.cli_path = self.root / "noos-cli"
        self.scrypt_patch = patch.object(identity, "SCRYPT_N", 1 << 12)
        self.scrypt_patch.start()

    def tearDown(self):
        self.scrypt_patch.stop()
        self.temporary.cleanup()

    def create(self):
        return identity.create_identity(
            self.identity_path,
            PASSWORD,
            CHAIN_ID,
            GENESIS_HASH,
            7,
            9,
            self.cli_path,
            random_bytes=deterministic_random,
            derive_account=fake_derive,
        )

    def test_create_open_and_descriptor_never_export_seed(self):
        descriptor = self.create()
        expected_seed = bytearray(deterministic_random(32))
        expected_payout = fake_derive(self.cli_path, expected_seed, 7, 9)
        encoded = self.identity_path.read_text(encoding="utf-8")
        self.assertNotIn(expected_seed.hex(), encoded)
        self.assertNotIn(base64.b64encode(expected_seed).decode("ascii"), encoded)
        self.assertEqual(descriptor["payout_account"], expected_payout)
        self.assertFalse(descriptor["secret_exported"])
        self.assertFalse(descriptor["browser_storage_used"])
        self.assertFalse(descriptor["coordinator_storage_used"])
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.identity_path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(self.identity_path.parent.stat().st_mode), 0o700)

        opened = identity.open_identity(
            self.identity_path,
            PASSWORD,
            CHAIN_ID,
            GENESIS_HASH,
            self.cli_path,
            derive_account=fake_derive,
        )
        seed_reference = opened.seed
        with opened:
            self.assertEqual(opened.seed, expected_seed)
            self.assertEqual(opened.payout_account, expected_payout)
        self.assertEqual(seed_reference, bytearray(32), "seed was not zeroized on close")

    def test_wrong_password_chain_tamper_and_kdf_downgrade_fail_closed(self):
        self.create()
        with self.assertRaisesRegex(identity.IdentityError, "authentication failed"):
            identity.open_identity(
                self.identity_path,
                bytearray(b"wrong password still long"),
                CHAIN_ID,
                GENESIS_HASH,
                self.cli_path,
                derive_account=fake_derive,
            )
        with self.assertRaisesRegex(identity.IdentityError, "different chain"):
            identity.open_identity(
                self.identity_path,
                PASSWORD,
                "33" * 32,
                GENESIS_HASH,
                self.cli_path,
                derive_account=fake_derive,
            )

        original = identity.load_envelope(self.identity_path)
        for name, mutate, expected in (
            (
                "metadata",
                lambda value: value.__setitem__("payout_account", "44" * 32),
                "authentication failed",
            ),
            (
                "ciphertext",
                lambda value: value.__setitem__(
                    "ciphertext_base64",
                    base64.b64encode(
                        bytes([base64.b64decode(value["ciphertext_base64"])[0] ^ 1])
                        + base64.b64decode(value["ciphertext_base64"])[1:]
                    ).decode("ascii"),
                ),
                "authentication failed",
            ),
            (
                "kdf",
                lambda value: value["kdf"].__setitem__("n", 2),
                "KDF policy",
            ),
        ):
            document = copy.deepcopy(original)
            mutate(document)
            path = self.root / f"tampered-{name}.json"
            path.write_bytes(identity.canonical_json(document) + b"\n")
            with self.assertRaisesRegex(identity.IdentityError, expected):
                identity.open_identity(
                    path,
                    PASSWORD,
                    CHAIN_ID,
                    GENESIS_HASH,
                    self.cli_path,
                    derive_account=fake_derive,
                )

    def test_recovery_validates_then_copies_without_overwrite(self):
        descriptor = self.create()
        recovered = self.root / "recovered" / "worker.identity.json"
        result = identity.recover_identity(
            self.identity_path,
            recovered,
            PASSWORD,
            CHAIN_ID,
            GENESIS_HASH,
            self.cli_path,
            derive_account=fake_derive,
        )
        self.assertEqual(result["payout_account"], descriptor["payout_account"])
        self.assertEqual(recovered.read_bytes(), self.identity_path.read_bytes())
        with self.assertRaisesRegex(identity.IdentityError, "refusing to overwrite"):
            identity.recover_identity(
                self.identity_path,
                recovered,
                PASSWORD,
                CHAIN_ID,
                GENESIS_HASH,
                self.cli_path,
                derive_account=fake_derive,
            )

    def test_payout_derivation_uses_stdin_not_process_arguments(self):
        seed = bytearray(range(32))
        payout = "ab" * 32
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=json.dumps({"verifying_key": payout}), stderr=""
        )
        with patch.object(identity.subprocess, "run", return_value=completed) as run:
            self.assertEqual(identity.derive_payout_account(self.cli_path, seed, 3, 5), payout)
        call = run.call_args
        argv = call.args[0]
        self.assertIn("--seed-stdin", argv)
        self.assertNotIn(seed.hex(), argv)
        self.assertEqual(call.kwargs["input"], seed.hex() + "\n")

    def test_noncanonical_and_existing_identity_files_are_rejected(self):
        self.create()
        document = identity.load_envelope(self.identity_path)
        noncanonical = self.root / "noncanonical.json"
        noncanonical.write_text(json.dumps(document, indent=2), encoding="utf-8")
        with self.assertRaisesRegex(identity.IdentityError, "not canonical JSON"):
            identity.load_envelope(noncanonical)
        with self.assertRaisesRegex(identity.IdentityError, "refusing to overwrite"):
            self.create()


if __name__ == "__main__":
    unittest.main()
