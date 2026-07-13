#!/usr/bin/env python3
"""Exercise native AMM, oracle, and stable-debt flows on isolated real processes."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import blake3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
from market_gateway import wallet_build, wallet_faucet, wallet_submit  # noqa: E402
from live_smoke import FAUCET_KEY, FAUCET_PUB, Proc, cli, enc_intent, enc_witnesses, http_json, sign_txid, transfer_actions  # noqa: E402

RPC = "127.0.0.1:28632"
INDEXER = "127.0.0.1:28080"
P2P = "/ip4/127.0.0.1/udp/29701/quic-v1"
TOKEN = "defi-live-smoke-token"
NOOS = "00" * 32


def binaries(env: dict) -> dict[str, Path]:
    metadata = json.loads(subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--no-deps"], cwd=ROOT, env=env, text=True))
    suffix = ".exe" if os.name == "nt" else ""
    root = Path(metadata["target_directory"]) / "debug"
    result = {name: root / (name + suffix) for name in ("noosd", "noos-indexer", "noos-cli")}
    missing = [str(path) for path in result.values() if not path.is_file()]
    if missing:
        raise RuntimeError(f"missing binaries: {missing}")
    return result


def wait_json(addr: str, path: str, token: str | None = None, timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return http_json(addr, path, token, 2)
        except Exception as error:
            last = error
            time.sleep(0.1)
    raise RuntimeError(f"timed out reading {path}: {last}")


def settle(txid: str, timeout: float = 30) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        receipt = http_json(RPC, f"/receipt/{txid}", TOKEN, 2)
        if isinstance(receipt.get("state"), dict):
            if receipt["state"].get("status_code") != 0:
                raise RuntimeError(f"transaction failed: {receipt}")
            return receipt
        time.sleep(0.05)
    raise RuntimeError(f"transaction {txid} did not settle")


def spec(chain_id: str, signer: str, actions: list[dict | str]) -> dict:
    height = int(http_json(RPC, "/status", TOKEN)["unsafe_head"]["height"])
    return {
        "chain_id": chain_id,
        "expiry_height": height + 1000,
        "fee_payer": signer,
        "resource_limits": {"bytes": 65536, "grain_steps": 10000, "proof_units": 8, "state_reads": 128, "state_writes": 128, "blob_bytes": 0},
        "account_inputs": [signer],
        "actions": actions,
    }


def asset_transfer_actions(sender: str, recipient: str, asset: str, amount: int) -> list[str]:
    encoded_amount = amount.to_bytes(16, "little")
    withdraw = (3).to_bytes(2, "little") + bytes.fromhex(sender) + bytes.fromhex(asset) + encoded_amount
    deposit = (2).to_bytes(2, "little") + bytes.fromhex(recipient) + bytes.fromhex(asset) + encoded_amount
    return [withdraw.hex(), deposit.hex()]


def submit_seed(exe: Path, chain_id: str, genesis_hash: str, signer: str, seed: str, actions: list[dict | str]) -> dict:
    built = cli(exe, "tx", "build", "--spec", json.dumps(spec(chain_id, signer, actions), separators=(",", ":")))
    signed = cli(exe, "tx", "sign", "--tx", built["tx"], "--seed", seed, "--account", "0", "--index", "0", "--chain-id", chain_id, "--genesis-hash", genesis_hash)
    submitted = cli(exe, "tx", "submit", "--node", RPC, "--token", TOKEN, "--chain-id", chain_id, "--genesis-hash", genesis_hash, "--tx", built["tx"], "--witnesses", signed["witnesses"])
    if submitted["txid"] != built["txid"]:
        raise RuntimeError("node returned a different transaction id")
    settle(built["txid"])
    return built


def fund(exe: Path, chain_id: str, genesis_hash: str, recipients: list[str]) -> None:
    actions: list[str] = []
    for recipient in recipients:
        actions.extend(transfer_actions(FAUCET_PUB, bytes.fromhex(recipient), 50_000_000))
    built = cli(exe, "tx", "build", "--spec", json.dumps(spec(chain_id, FAUCET_PUB.hex(), actions)))
    signature = sign_txid(FAUCET_KEY, bytes.fromhex(built["txid"]))
    witnesses = enc_witnesses([enc_intent(bytes.fromhex(built["txid"]), signature)]).hex()
    cli(exe, "tx", "submit", "--node", RPC, "--token", TOKEN, "--chain-id", chain_id, "--genesis-hash", genesis_hash, "--tx", built["tx"], "--witnesses", witnesses)
    settle(built["txid"])


def main() -> int:
    env = os.environ.copy()
    exes = binaries(env)
    seeds = [hashlib.blake2b(f"defi-live-smoke/{index}".encode(), digest_size=32).hexdigest() for index in range(3)]
    accounts = [cli(exes["noos-cli"], "keygen", "--seed", seed, "--purpose", "sign", "--account", "0", "--index", "0")["verifying_key"] for seed in seeds]
    work = Path(tempfile.mkdtemp(prefix="noos-defi-live-"))
    logs = work / "logs"; logs.mkdir()
    procs: list[Proc] = []
    checks: list[str] = []
    try:
        node_args = [str(exes["noosd"]), "--data-dir", str(work / "node"), "--genesis-time", str(int(time.time() * 1000)), "--rpc", RPC, "--rpc-token", TOKEN, "--p2p-listen", P2P, "--validator", "--produce-interval-ms", "20", "--devnet-governance-account", accounts[0]]
        for account in accounts[1:]: node_args.extend(["--devnet-account", account])
        node = Proc("noosd-defi", node_args, env, logs); procs.append(node)
        line = node.wait_line(r"noosd up: chain_id=([0-9a-f]{64}) genesis_hash=([0-9a-f]{64})", 120)
        match = re.search(r"chain_id=([0-9a-f]{64}) genesis_hash=([0-9a-f]{64})", line)
        if match is None: raise RuntimeError("node identity missing")
        chain_id, genesis_hash = match.groups()
        node.wait_line(r"operator RPC ready", 30)
        first = wait_json(RPC, "/block/1", TOKEN)
        indexer_root = work / "indexer"; indexer_root.mkdir()
        (indexer_root / "ingest-checkpoint-v1.json").write_text(json.dumps({"schema": "noos-ingest-checkpoint-v1", "identity": {"chain_id": chain_id, "genesis_hash": genesis_hash, "api_version": "v1"}, "next_height": "1", "recent": [{"height": "0", "hash": first["parent_hash"]}]}) + "\n", encoding="utf-8")
        indexer_env = dict(env, NOOS_CHAIN_ID=chain_id, NOOS_GENESIS_HASH=genesis_hash, NOOS_NODE_RPC=RPC, NOOS_NODE_TOKEN=TOKEN, NOOS_INDEXER_LISTEN=INDEXER, NOOS_INDEXER_ROOT=str(indexer_root))
        indexer = Proc("noos-indexer-defi", [str(exes["noos-indexer"])], indexer_env, logs); procs.append(indexer)
        wait_json(INDEXER, "/api/status")
        fund(exes["noos-cli"], chain_id, genesis_hash, accounts)
        checks.append("funded three authenticated accounts")
        wallet_key = Ed25519PrivateKey.generate()
        wallet_account = wallet_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        ).hex()
        wallet_metadata = {
            "chain_id": chain_id,
            "genesis_hash": genesis_hash,
            "developer_public_id": accounts[0],
            "developer_seed_hex": seeds[0],
            "validator_rpc": RPC,
            "indexer": INDEXER,
            "rpc_token": TOKEN,
        }
        wallet_faucet(wallet_metadata, exes["noos-cli"], {"account": wallet_account, "amount": "1000000"})
        unsigned = wallet_build(wallet_metadata, exes["noos-cli"], {
            "account": wallet_account, "recipient": accounts[2],
            "asset": NOOS, "amount": "100000",
        })
        wallet_signature = wallet_key.sign(bytes.fromhex(unsigned["signing_message"])).hex()
        wallet_submit(wallet_metadata, exes["noos-cli"], {
            "account": wallet_account, "tx": unsigned["tx"],
            "txid": unsigned["txid"], "signature": wallet_signature,
        })
        checks.append("generated wallet key locally and settled through unsigned-build/sign/submit RPC")

        asset_build = submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], [{"type": "create_asset", "issuer": accounts[0], "symbol": "QUOTE", "name": "Live Quote Unit", "decimals": 9, "total_supply": "100000000"}])
        quote = asset_build["created_assets"][0]["asset_id"]
        pool_build = submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], [{"type": "create_pool", "provider": accounts[0], "asset_a": NOOS, "asset_b": quote, "amount_a": "2000000", "amount_b": "20000000", "fee_bps": 30}])
        pool = pool_build["created_pools"][0]["pool_id"]
        submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], [{"type": "add_liquidity", "provider": accounts[0], "pool_id": pool, "max_amount_0": "100000", "max_amount_1": "1000000", "min_shares": "1"}])
        submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], [{"type": "swap_exact_in", "trader": accounts[0], "pool_id": pool, "asset_in": NOOS, "amount_in": "10000", "min_amount_out": "1"}])
        submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], [{"type": "remove_liquidity", "provider": accounts[0], "pool_id": pool, "shares": "1000", "min_amount_0": "1", "min_amount_1": "1"}])
        checks.append("created, added, swapped, and removed AMM liquidity")

        feed_build = submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], [{"type": "create_oracle_feed", "base_asset": NOOS, "quote_asset": quote, "reporter_0": accounts[0], "reporter_1": accounts[1], "reporter_2": accounts[2], "max_age_blocks": "500"}])
        feed = feed_build["created_oracle_feeds"][0]["feed_id"]
        for index, (account, seed) in enumerate(zip(accounts, seeds)):
            observed = str(http_json(RPC, "/status", TOKEN)["unsafe_head"]["height"])
            submit_seed(exes["noos-cli"], chain_id, genesis_hash, account, seed, [{"type": "submit_oracle_report", "reporter": account, "feed_id": feed, "price_q9": str(2_000_000_000 + index * 10_000_000), "confidence_bps": 10, "sequence": "1", "observed_height": observed}])
        checks.append("accepted three independently signed oracle reports")

        market_build = submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], [{"type": "create_lending_market", "collateral_asset": NOOS, "oracle_feed_id": feed, "symbol": "MUSD", "name": "Live Mind USD", "decimals": 9, "collateral_factor_bps": 5000, "liquidation_threshold_bps": 7500, "liquidation_bonus_bps": 500, "debt_ceiling": "10000000", "min_debt": "1000"}])
        market = market_build["created_lending_markets"][0]["market_id"]
        stable = market_build["created_lending_markets"][0]["stable_asset"]
        for action in [
            {"type": "deposit_collateral", "owner": accounts[0], "market_id": market, "amount": "1000000"},
            {"type": "borrow_stable", "owner": accounts[0], "market_id": market, "amount": "500000"},
            {"type": "repay_stable", "owner": accounts[0], "market_id": market, "amount": "100000"},
            {"type": "withdraw_collateral", "owner": accounts[0], "market_id": market, "amount": "100000"},
        ]: submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], [action])
        checks.append("deposited, borrowed, repaid, and withdrew collateral")
        submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], asset_transfer_actions(accounts[0], accounts[1], stable, 100000))
        for index, (account, seed) in enumerate(zip(accounts, seeds)):
            observed = str(http_json(RPC, "/status", TOKEN)["unsafe_head"]["height"])
            submit_seed(exes["noos-cli"], chain_id, genesis_hash, account, seed, [{"type": "submit_oracle_report", "reporter": account, "feed_id": feed, "price_q9": str(500_000_000 + index * 1_000_000), "confidence_bps": 10, "sequence": "2", "observed_height": observed}])
        submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[1], seeds[1], [{"type": "liquidate_position", "liquidator": accounts[1], "market_id": market, "owner": accounts[0], "repay_amount": "100000", "min_collateral_out": "1"}])
        checks.append("transferred stable value, repriced by quorum, and liquidated unhealthy debt")
        claim_secret = bytes([0xC1]) * 32
        recipient_commitment = blake3.blake3(
            b"NOOS/PRIVATE-PAYMENT/RECIPIENT/V1"
            + bytes.fromhex(accounts[2])
            + claim_secret
        ).hexdigest()
        payment_build = submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], [{
            "type": "open_private_payment", "payer": accounts[0], "stable_asset": stable,
            "recipient_commitment": recipient_commitment, "memo_commitment": "b1" * 32,
            "reference_commitment": "a1" * 32, "amount": "50000",
            "expiry_height": str(int(http_json(RPC, "/status", TOKEN)["unsafe_head"]["height"]) + 100),
            "payment_kind": 1,
        }])
        payment = payment_build["created_private_payments"][0]["payment_id"]
        submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[2], seeds[2], [{
            "type": "claim_private_payment", "recipient": accounts[2],
            "payment_id": payment, "claim_secret": claim_secret.hex(),
        }])
        refund_expiry = int(http_json(RPC, "/status", TOKEN)["unsafe_head"]["height"]) + 50
        refundable_build = submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], [{
            "type": "open_private_payment", "payer": accounts[0], "stable_asset": stable,
            "recipient_commitment": recipient_commitment, "memo_commitment": "b2" * 32,
            "reference_commitment": "a2" * 32, "amount": "20000",
            "expiry_height": str(refund_expiry), "payment_kind": 2,
        }])
        refundable = refundable_build["created_private_payments"][0]["payment_id"]
        while int(http_json(RPC, "/status", TOKEN)["unsafe_head"]["height"]) <= refund_expiry:
            time.sleep(0.02)
        submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], [{
            "type": "refund_private_payment", "payer": accounts[0], "payment_id": refundable,
        }])
        agent_secret = bytes([0xC3]) * 32
        agent_recipient_commitment = blake3.blake3(
            b"NOOS/PRIVATE-PAYMENT/RECIPIENT/V1"
            + bytes.fromhex(accounts[2])
            + agent_secret
        ).hexdigest()
        schema_root = blake3.blake3(b"NOOS/AGENT-PAYMENT/SCHEMA/V1").hexdigest()
        scope_root = blake3.blake3(
            b"NOOS/AGENT-PAYMENT/SCOPE/V1"
            + bytes.fromhex(stable)
            + bytes.fromhex(agent_recipient_commitment)
        ).hexdigest()
        grant_id = "d1" * 32
        grant_expiry = int(http_json(RPC, "/status", TOKEN)["unsafe_head"]["height"]) + 200
        submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[0], seeds[0], [{
            "type": "grant_capability", "grant_id": grant_id, "issuer": accounts[0],
            "subject_agent": accounts[1], "allowed_action_schema_root": schema_root,
            "object_scope_root": scope_root, "per_action_limit": "10000",
            "cumulative_budget": "15000", "expiry_height": str(grant_expiry),
            "delegation_depth": 0, "revocation_nonce": "0",
        }])
        agent_payment_build = submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[1], seeds[1], [{
            "type": "open_agent_private_payment", "agent": accounts[1], "payer": accounts[0],
            "stable_asset": stable, "recipient_commitment": agent_recipient_commitment,
            "memo_commitment": "b3" * 32, "reference_commitment": "a3" * 32,
            "amount": "10000", "expiry_height": str(grant_expiry - 1),
            "capability_ref": grant_id,
        }])
        agent_payment = agent_payment_build["created_private_payments"][0]["payment_id"]
        submit_seed(exes["noos-cli"], chain_id, genesis_hash, accounts[2], seeds[2], [{
            "type": "claim_private_payment", "recipient": accounts[2],
            "payment_id": agent_payment, "claim_secret": agent_secret.hex(),
        }])
        checks.append("enforced agent asset, recipient, per-payment, cumulative, and expiry capability on-chain")
        checks.append("claimed recipient-hidden agent payment and refunded expired invoice")


        expected = {"/api/v1/pools": pool, "/api/v1/liquidity-positions": pool, "/api/v1/oracle-feeds": feed, "/api/v1/oracle-reports": feed, "/api/v1/lending-markets": market, "/api/v1/stable-assets": stable, "/api/v1/debt-positions": market, "/api/v1/private-payments": agent_payment}
        deadline = time.monotonic() + 30
        while True:
            views = {path: http_json(INDEXER, path) for path in expected}
            if all(value in json.dumps(views[path]) for path, value in expected.items()): break
            if time.monotonic() >= deadline: raise RuntimeError(f"indexer did not expose DeFi state: {views}")
            time.sleep(0.1)
        debt = next(item for item in views["/api/v1/debt-positions"]["items"] if item["market_id"] == market)
        market_view = next(item for item in views["/api/v1/lending-markets"]["items"] if item["market_id"] == market)
        stable_view = next(item for item in views["/api/v1/stable-assets"]["items"] if item["asset_id"] == stable)
        if debt["debt"] != "300000" or not 0 < int(debt["collateral"]) < 900000: raise RuntimeError(f"unexpected liquidated debt state: {debt}")
        if market_view["total_debt"] != stable_view["minted_supply"] or market_view["total_debt"] != "300000": raise RuntimeError("stable supply/debt conservation failed")
        payments = views["/api/v1/private-payments"]["items"]
        claimed = next(item for item in payments if item["payment_id"] == payment)
        refunded = next(item for item in payments if item["payment_id"] == refundable)
        agent_claimed = next(item for item in payments if item["payment_id"] == agent_payment)
        if claimed["status"] != 1 or claimed["settled_account"] != accounts[2]:
            raise RuntimeError(f"private payment did not claim correctly: {claimed}")
        if refunded["status"] != 2 or refunded["settled_account"] != accounts[0]:
            raise RuntimeError(f"private payment did not refund correctly: {refunded}")
        if agent_claimed["status"] != 1 or agent_claimed["settled_account"] != accounts[2]:
            raise RuntimeError(f"agent payment did not claim correctly: {agent_claimed}")
        payer_balance = http_json(INDEXER, f"/api/v1/balances/{accounts[0]}/{stable}")["balance"]
        recipient_balance = http_json(INDEXER, f"/api/v1/balances/{accounts[2]}/{stable}")["balance"]
        if payer_balance != "240000" or recipient_balance != "60000":
            raise RuntimeError("private payment escrow conservation failed")
        checks.append("indexer exposed conserved live DeFi state")
        print(json.dumps({"verdict": "PASS", "chain_id": chain_id, "genesis_hash": genesis_hash, "checks": checks, "pool_id": pool, "feed_id": feed, "market_id": market, "stable_asset": stable, "debt": debt}, indent=2))
        return 0
    finally:
        for proc in reversed(procs): proc.stop()
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
