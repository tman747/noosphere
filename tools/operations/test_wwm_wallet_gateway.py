from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

import blake3
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from tools.operations import wwm_wallet_gateway as wallet


class WalletServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cli = self.root / "noos-cli"
        self.cli.write_bytes(b"fixture")
        self.ui = self.root / "wallet"
        self.ui.mkdir()
        (self.ui / "index.html").write_text("wallet\n", encoding="utf-8")
        self.db = self.root / "faucet.sqlite3"
        self.service = wallet.WalletService(
            api_base="https://wwm-seed-2.mindchain.network",
            node_rpc="http://127.0.0.1:29652",
            node_token="fixture-token-that-is-longer-than-thirty-two-bytes",
            cli_path=self.cli,
            wallet_root=self.ui,
            faucet_db=self.db,
        )

    @staticmethod
    def public(key: Ed25519PrivateKey) -> str:
        return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()

    def test_envelope_recomputes_txid_and_verifies_the_claimed_account(self) -> None:
        key = Ed25519PrivateKey.generate()
        account = self.public(key)
        tx = "01020304"
        txid = blake3.blake3(b"NOOS/TX/ID/V1" + bytes.fromhex(tx)).hexdigest()
        signature = key.sign(b"NOOS/SIG/TX/V1" + bytes.fromhex(txid)).hex()

        observed_tx, observed_txid, witnesses = self.service._wallet_envelope(
            {"account": account, "tx": tx, "txid": txid, "signature": signature}
        )
        self.assertEqual((observed_tx, observed_txid), (tx, txid))
        self.assertRegex(witnesses, r"^[0-9a-f]+$")

        with self.assertRaisesRegex(wallet.WalletError, "do not match"):
            self.service._wallet_envelope(
                {"account": account, "tx": "01020305", "txid": txid, "signature": signature}
            )
        attacker = Ed25519PrivateKey.generate()
        forged = attacker.sign(b"NOOS/SIG/TX/V1" + bytes.fromhex(txid)).hex()
        with self.assertRaisesRegex(wallet.WalletError, "does not authorize"):
            self.service._wallet_envelope(
                {"account": account, "tx": tx, "txid": txid, "signature": forged}
            )

    def test_transfer_spec_is_identity_bound_and_uses_canonical_balance_actions(self) -> None:
        sender = "11" * 32
        recipient = "22" * 32
        spec = self.service._transfer_spec(sender, recipient, wallet.NOOS_ASSET, 12345, 999)
        self.assertEqual(spec["chain_id"], wallet.CHAIN_ID)
        self.assertEqual(spec["fee_payer"], sender)
        self.assertEqual(spec["account_inputs"], [sender])
        withdraw = bytes.fromhex(spec["actions"][0])
        deposit = bytes.fromhex(spec["actions"][1])
        self.assertEqual(int.from_bytes(withdraw[:2], "little"), 3)
        self.assertEqual(withdraw[2:34].hex(), sender)
        self.assertEqual(int.from_bytes(withdraw[-16:], "little"), 12345)
        self.assertEqual(int.from_bytes(deposit[:2], "little"), 2)
        self.assertEqual(deposit[2:34].hex(), recipient)
        self.assertEqual(int.from_bytes(deposit[-16:], "little"), 12345)

    def test_faucet_limiter_persists_account_and_client_cooldowns(self) -> None:
        now = int(time.time() * 1000)
        first = "11" * 32
        second = "22" * 32
        self.service.limiter.check(first, "203.0.113.1", now)
        self.service.limiter.record(first, "203.0.113.1", now)

        with self.assertRaisesRegex(wallet.WalletError, "already received") as account_error:
            self.service.limiter.check(first, "203.0.113.2", now + 1)
        self.assertEqual(account_error.exception.status, 429)
        with self.assertRaisesRegex(wallet.WalletError, "Please wait") as client_error:
            self.service.limiter.check(second, "203.0.113.1", now + 1)
        self.assertEqual(client_error.exception.status, 429)

        restarted = wallet.FaucetLimiter(self.db)
        with self.assertRaises(wallet.WalletError):
            restarted.check(first, "203.0.113.2", now + 2)
        restarted.check(second, "203.0.113.2", now + 2)

    def test_fixture_faucet_is_exactly_the_genesis_account(self) -> None:
        observed = self.public(self.service.faucet_key)
        self.assertEqual(observed, wallet.FAUCET_ACCOUNT)
        self.assertEqual(wallet.FAUCET_AMOUNT, 1_000_000)


if __name__ == "__main__":
    unittest.main()
