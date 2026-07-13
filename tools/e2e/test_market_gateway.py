from __future__ import annotations

import unittest
from unittest.mock import patch

import market_gateway as gateway


ACCOUNT = "11" * 32
POOL = "22" * 32
MARKET = "33" * 32
OWNER = "44" * 32


class DefiGatewayTests(unittest.TestCase):
    def setUp(self) -> None:
        self.metadata = {"developer_public_id": ACCOUNT, "indexer": "127.0.0.1:1"}

    def capture_action(self, body: dict) -> dict:
        with patch.object(gateway, "submit_actions", return_value={"build": {"txid": "aa" * 32}, "receipt": {"state": {"status_code": 0}}}) as submit:
            result = gateway.defi_action(self.metadata, gateway.Path("noos-cli"), body)
        self.assertEqual(result["txid"], "aa" * 32)
        return submit.call_args.args[2][0]

    def test_liquidity_actions_bind_the_local_signer_and_integer_limits(self) -> None:
        action = self.capture_action({"type": "add_liquidity", "pool_id": POOL, "max_amount_0": "80", "max_amount_1": 40, "min_shares": "10"})
        self.assertEqual(action, {"type": "add_liquidity", "provider": ACCOUNT, "pool_id": POOL, "max_amount_0": "80", "max_amount_1": "40", "min_shares": "10"})
        with self.assertRaisesRegex(ValueError, "max_amount_0"):
            self.capture_action({"type": "add_liquidity", "pool_id": POOL, "max_amount_0": "0", "max_amount_1": "1", "min_shares": "1"})

    def test_credit_actions_cannot_choose_the_signing_owner(self) -> None:
        action = self.capture_action({"type": "borrow_stable", "market_id": MARKET, "owner": OWNER, "amount": "25"})
        self.assertEqual(action["owner"], ACCOUNT)
        self.assertEqual(action["amount"], "25")

    def test_liquidation_rejects_self_and_malformed_ids(self) -> None:
        with self.assertRaisesRegex(ValueError, "self-liquidate"):
            self.capture_action({"type": "liquidate_position", "market_id": MARKET, "owner": ACCOUNT, "repay_amount": "1", "min_collateral_out": "1"})
        with self.assertRaisesRegex(ValueError, "32-byte lowercase hex"):
            self.capture_action({"type": "liquidate_position", "market_id": "BAD", "owner": OWNER, "repay_amount": "1", "min_collateral_out": "1"})

    def test_state_reads_every_consensus_registry(self) -> None:
        paths: list[str] = []
        def fake_request(_addr: str, path: str, *_args, **_kwargs) -> dict:
            paths.append(path)
            return {"items": [{"source": path}]}
        with patch.object(gateway, "request_json", side_effect=fake_request):
            state = gateway.defi_state(self.metadata)
        self.assertEqual(state["account"], ACCOUNT)
        self.assertEqual(paths, [
            "/api/v1/pools", "/api/v1/liquidity-positions", "/api/v1/oracle-feeds",
            "/api/v1/oracle-reports", "/api/v1/lending-markets", "/api/v1/stable-assets",
            "/api/v1/debt-positions",
        ])
        self.assertTrue(all(value for key, value in state.items() if key != "account"))

    def test_unknown_action_fails_before_submission(self) -> None:
        with patch.object(gateway, "submit_actions") as submit:
            with self.assertRaisesRegex(ValueError, "unsupported"):
                gateway.defi_action(self.metadata, gateway.Path("noos-cli"), {"type": "flash_loan"})
        submit.assert_not_called()


if __name__ == "__main__":
    unittest.main()
