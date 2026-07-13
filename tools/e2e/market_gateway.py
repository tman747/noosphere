#!/usr/bin/env python3
"""Same-origin local gateway for the Foundry and Current MindChain apps.

This server is a TEST-NETWORK fixture. It signs with the deterministic account
written by local_devnet.py and must never be exposed beyond loopback.
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
from pathlib import Path
import re
import subprocess
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RUNTIME = Path(os.environ.get("NOOS_LOCAL_DEVNET_DIR", "C:/tmp/noosphere-local-devnet"))
STATIC_ROOT = ROOT / "apps" / "mind-market"
NOOS_ASSET = "00" * 32
MAX_BODY = 64 * 1024
TX_LOCK = threading.Lock()
HEX32 = re.compile(r"^[0-9a-f]{64}$")
SYMBOL = re.compile(r"^[A-Z0-9]{1,12}$")


def load_metadata(runtime: Path) -> dict:
    path = runtime / "local-devnet.json"
    if not path.is_file():
        raise RuntimeError(f"local devnet metadata not found: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    for key in (
        "chain_id",
        "genesis_hash",
        "developer_public_id",
        "developer_seed_hex",
        "validator_rpc",
        "indexer",
        "rpc_token",
    ):
        if key not in value:
            raise RuntimeError(f"local devnet metadata missing {key}")
    return value


def locate_cli() -> Path:
    metadata = json.loads(
        subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1", "--no-deps"],
            cwd=ROOT,
            text=True,
        )
    )
    suffix = ".exe" if os.name == "nt" else ""
    path = Path(metadata["target_directory"]) / "debug" / ("noos-cli" + suffix)
    if not path.is_file():
        raise RuntimeError(f"noos-cli binary not found: {path}; run cargo build -p noos-cli")
    return path


def request_json(addr: str, path: str, token: str | None = None, timeout: float = 5) -> dict:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    request = Request(f"http://{addr}{path}", headers=headers)
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read())


def cli_json(exe: Path, *args: str) -> dict:
    completed = subprocess.run(
        [str(exe), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "noos-cli failed"
        raise RuntimeError(detail)
    return json.loads(completed.stdout)


def settled_receipt(metadata: dict, txid: str, deadline_s: float = 45) -> dict:
    deadline = time.monotonic() + deadline_s
    while time.monotonic() < deadline:
        receipt = request_json(
            metadata["validator_rpc"],
            f"/receipt/{txid}",
            metadata["rpc_token"],
        )
        state = receipt.get("state")
        if isinstance(state, dict):
            if state.get("status_code") != 0:
                raise RuntimeError(f"transaction {txid} failed with status {state.get('status_code')}")
            return receipt
        time.sleep(0.4)
    raise RuntimeError(f"transaction {txid} did not settle within {deadline_s}s")


def submit_actions(metadata: dict, exe: Path, actions: list[dict]) -> dict:
    status = request_json(metadata["validator_rpc"], "/status", metadata["rpc_token"])
    height = int(status["unsafe_head"]["height"])
    account = metadata["developer_public_id"]
    spec = {
        "chain_id": metadata["chain_id"],
        "expiry_height": height + 1000,
        "fee_payer": account,
        "resource_limits": {
            "bytes": 65536,
            "grain_steps": 10000,
            "proof_units": 8,
            "state_reads": 128,
            "state_writes": 128,
            "blob_bytes": 0,
        },
        "account_inputs": [account],
        "actions": actions,
    }
    built = cli_json(exe, "tx", "build", "--spec", json.dumps(spec, separators=(",", ":")))
    signed = cli_json(
        exe,
        "tx",
        "sign",
        "--tx",
        built["tx"],
        "--seed",
        metadata["developer_seed_hex"],
        "--account",
        "0",
        "--index",
        "0",
        "--chain-id",
        metadata["chain_id"],
        "--genesis-hash",
        metadata["genesis_hash"],
    )
    submitted = cli_json(
        exe,
        "tx",
        "submit",
        "--node",
        metadata["validator_rpc"],
        "--token",
        metadata["rpc_token"],
        "--chain-id",
        metadata["chain_id"],
        "--genesis-hash",
        metadata["genesis_hash"],
        "--tx",
        built["tx"],
        "--witnesses",
        signed["witnesses"],
    )
    if submitted.get("txid") != built.get("txid"):
        raise RuntimeError("node returned a different transaction id")
    receipt = settled_receipt(metadata, built["txid"])
    return {"build": built, "receipt": receipt}


def integer(value: object, name: str, minimum: int = 0, maximum: int | None = None) -> int:
    try:
        parsed = int(str(value))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{name} must be an integer") from error
    if parsed < minimum or (maximum is not None and parsed > maximum):
        bound = f"{minimum}..{maximum}" if maximum is not None else f">={minimum}"
        raise ValueError(f"{name} must be {bound}")
    return parsed


def launch(metadata: dict, exe: Path, body: dict) -> dict:
    symbol = str(body.get("symbol", "")).strip().upper()
    name = str(body.get("name", "")).strip()
    if not SYMBOL.fullmatch(symbol):
        raise ValueError("symbol must be 1-12 uppercase ASCII letters or digits")
    if not name or len(name.encode("utf-8")) > 64:
        raise ValueError("name must be 1-64 UTF-8 bytes")
    decimals = integer(body.get("decimals"), "decimals", 0, 18)
    supply = integer(body.get("total_supply"), "total_supply", 1)
    initial_noos = integer(body.get("initial_noos"), "initial_noos", 1)
    initial_tokens = integer(body.get("initial_tokens"), "initial_tokens", 1, supply)
    fee_bps = integer(body.get("fee_bps"), "fee_bps", 0, 100)
    account = metadata["developer_public_id"]
    with TX_LOCK:
        created = submit_actions(
            metadata,
            exe,
            [
                {
                    "type": "create_asset",
                    "issuer": account,
                    "symbol": symbol,
                    "name": name,
                    "decimals": decimals,
                    "total_supply": str(supply),
                }
            ],
        )
        asset = created["build"]["created_assets"][0]
        pooled = submit_actions(
            metadata,
            exe,
            [
                {
                    "type": "create_pool",
                    "provider": account,
                    "asset_a": NOOS_ASSET,
                    "asset_b": asset["asset_id"],
                    "amount_a": str(initial_noos),
                    "amount_b": str(initial_tokens),
                    "fee_bps": fee_bps,
                }
            ],
        )
        pool = pooled["build"]["created_pools"][0]
    return {
        "asset": asset,
        "pool": pool,
        "asset_txid": created["build"]["txid"],
        "pool_txid": pooled["build"]["txid"],
        "asset_receipt": created["receipt"],
        "pool_receipt": pooled["receipt"],
    }


def swap(metadata: dict, exe: Path, body: dict) -> dict:
    pool = str(body.get("pool_id", ""))
    asset_in = str(body.get("asset_in", ""))
    if not HEX32.fullmatch(pool) or not HEX32.fullmatch(asset_in):
        raise ValueError("pool_id and asset_in must be 32-byte lowercase hex")
    amount_in = integer(body.get("amount_in"), "amount_in", 1)
    min_out = integer(body.get("min_amount_out"), "min_amount_out", 1)
    account = metadata["developer_public_id"]
    with TX_LOCK:
        result = submit_actions(
            metadata,
            exe,
            [
                {
                    "type": "swap_exact_in",
                    "trader": account,
                    "pool_id": pool,
                    "asset_in": asset_in,
                    "amount_in": str(amount_in),
                    "min_amount_out": str(min_out),
                }
            ],
        )
    return {"txid": result["build"]["txid"], "receipt": result["receipt"]}

def defi_state(metadata: dict) -> dict:
    indexer = metadata["indexer"]
    return {
        "account": metadata["developer_public_id"],
        "pools": request_json(indexer, "/api/v1/pools").get("items", []),
        "liquidity_positions": request_json(
            indexer, "/api/v1/liquidity-positions"
        ).get("items", []),
        "oracle_feeds": request_json(indexer, "/api/v1/oracle-feeds").get("items", []),
        "oracle_reports": request_json(indexer, "/api/v1/oracle-reports").get("items", []),
        "lending_markets": request_json(indexer, "/api/v1/lending-markets").get("items", []),
        "stable_assets": request_json(indexer, "/api/v1/stable-assets").get("items", []),
        "debt_positions": request_json(indexer, "/api/v1/debt-positions").get("items", []),
        "private_payments": request_json(indexer, "/api/v1/private-payments").get("items", []),
    }


def defi_action(metadata: dict, exe: Path, body: dict) -> dict:
    kind = str(body.get("type", ""))
    account = metadata["developer_public_id"]
    action: dict
    if kind == "add_liquidity":
        pool = str(body.get("pool_id", ""))
        if not HEX32.fullmatch(pool):
            raise ValueError("pool_id must be 32-byte lowercase hex")
        action = {
            "type": kind,
            "provider": account,
            "pool_id": pool,
            "max_amount_0": str(integer(body.get("max_amount_0"), "max_amount_0", 1)),
            "max_amount_1": str(integer(body.get("max_amount_1"), "max_amount_1", 1)),
            "min_shares": str(integer(body.get("min_shares"), "min_shares", 1)),
        }
    elif kind == "remove_liquidity":
        pool = str(body.get("pool_id", ""))
        if not HEX32.fullmatch(pool):
            raise ValueError("pool_id must be 32-byte lowercase hex")
        action = {
            "type": kind,
            "provider": account,
            "pool_id": pool,
            "shares": str(integer(body.get("shares"), "shares", 1)),
            "min_amount_0": str(integer(body.get("min_amount_0"), "min_amount_0", 1)),
            "min_amount_1": str(integer(body.get("min_amount_1"), "min_amount_1", 1)),
        }
    elif kind in {"deposit_collateral", "withdraw_collateral", "borrow_stable", "repay_stable"}:
        market = str(body.get("market_id", ""))
        if not HEX32.fullmatch(market):
            raise ValueError("market_id must be 32-byte lowercase hex")
        action = {
            "type": kind,
            "owner": account,
            "market_id": market,
            "amount": str(integer(body.get("amount"), "amount", 1)),
        }
    elif kind == "liquidate_position":
        market = str(body.get("market_id", ""))
        owner = str(body.get("owner", ""))
        if not HEX32.fullmatch(market) or not HEX32.fullmatch(owner):
            raise ValueError("market_id and owner must be 32-byte lowercase hex")
        if owner == account:
            raise ValueError("a position owner cannot self-liquidate")
        action = {
            "type": kind,
            "liquidator": account,
            "market_id": market,
            "owner": owner,
            "repay_amount": str(integer(body.get("repay_amount"), "repay_amount", 1)),
            "min_collateral_out": str(
                integer(body.get("min_collateral_out"), "min_collateral_out", 1)
            ),
        }
    elif kind == "open_private_payment":
        stable = str(body.get("stable_asset", ""))
        recipient_commitment = str(body.get("recipient_commitment", ""))
        memo_commitment = str(body.get("memo_commitment", ""))
        reference_commitment = str(body.get("reference_commitment", ""))
        if not all(HEX32.fullmatch(value) for value in (
            stable, recipient_commitment, memo_commitment, reference_commitment
        )):
            raise ValueError("private payment fields must be 32-byte lowercase hex")
        action = {
            "type": kind,
            "payer": account,
            "stable_asset": stable,
            "recipient_commitment": recipient_commitment,
            "memo_commitment": memo_commitment,
            "reference_commitment": reference_commitment,
            "amount": str(integer(body.get("amount"), "amount", 1)),
            "expiry_height": str(integer(body.get("expiry_height"), "expiry_height", 1)),
            "payment_kind": integer(body.get("payment_kind"), "payment_kind", 0, 3),
        }
    elif kind == "claim_private_payment":
        payment = str(body.get("payment_id", ""))
        secret = str(body.get("claim_secret", ""))
        if not HEX32.fullmatch(payment) or not HEX32.fullmatch(secret):
            raise ValueError("payment_id and claim_secret must be 32-byte lowercase hex")
        action = {
            "type": kind,
            "recipient": account,
            "payment_id": payment,
            "claim_secret": secret,
        }
    elif kind == "refund_private_payment":
        payment = str(body.get("payment_id", ""))
        if not HEX32.fullmatch(payment):
            raise ValueError("payment_id must be 32-byte lowercase hex")
        action = {"type": kind, "payer": account, "payment_id": payment}
    else:
        raise ValueError("unsupported DeFi action")
    with TX_LOCK:
        result = submit_actions(metadata, exe, [action])
    return {"txid": result["build"]["txid"], "receipt": result["receipt"]}



def wallet_build(metadata: dict, exe: Path, body: dict) -> dict:
    account = str(body.get("account", ""))
    recipient = str(body.get("recipient", ""))
    asset = str(body.get("asset", ""))
    if not all(HEX32.fullmatch(value) for value in (account, recipient, asset)):
        raise ValueError("account, recipient, and asset must be 32-byte lowercase hex")
    amount = integer(body.get("amount"), "amount", 1)
    status = request_json(metadata["validator_rpc"], "/status", metadata["rpc_token"])
    spec = {
        "chain_id": metadata["chain_id"],
        "expiry_height": int(status["unsafe_head"]["height"]) + 1000,
        "fee_payer": account,
        "resource_limits": {
            "bytes": 4096,
            "grain_steps": 0,
            "proof_units": 0,
            "state_reads": 32,
            "state_writes": 32,
            "blob_bytes": 0,
        },
        "account_inputs": [account],
        "actions": [
            {"type": "withdraw_from_account", "account_id": account, "asset_id": asset, "amount": str(amount)},
            {"type": "deposit_to_account", "account_id": recipient, "asset_id": asset, "amount": str(amount)},
        ],
    }
    built = cli_json(exe, "tx", "build", "--spec", json.dumps(spec, separators=(",", ":")))
    return {
        "tx": built["tx"],
        "txid": built["txid"],
        "chain_id": metadata["chain_id"],
        "genesis_hash": metadata["genesis_hash"],
        "signing_message": (b"NOOS/SIG/TX/V1" + bytes.fromhex(built["txid"])).hex(),
    }


def _tag(value: int) -> bytes:
    return struct.pack("<H", value)


def _wallet_witness(txid: bytes, signature: bytes) -> str:
    intent = struct.pack("<H", 1)
    intent += _tag(1) + txid
    intent += _tag(2) + bytes([0])
    intent += _tag(3) + bytes([0])
    intent += _tag(4) + struct.pack("<H", 1)
    intent += _tag(5) + struct.pack("<I", len(signature)) + signature
    witnesses = struct.pack("<H", 1)
    witnesses += _tag(1) + struct.pack("<I", 1) + intent
    witnesses += _tag(2) + struct.pack("<I", 0)
    return witnesses.hex()


def wallet_submit(metadata: dict, exe: Path, body: dict) -> dict:
    account = str(body.get("account", ""))
    tx = str(body.get("tx", ""))
    txid = str(body.get("txid", ""))
    signature_hex = str(body.get("signature", ""))
    if not HEX32.fullmatch(account) or not HEX32.fullmatch(txid):
        raise ValueError("account and txid must be 32-byte lowercase hex")
    if not re.fullmatch(r"(?:[0-9a-f]{2})+", tx) or len(signature_hex) != 128 or not re.fullmatch(r"[0-9a-f]+", signature_hex):
        raise ValueError("tx and signature must be canonical lowercase hex")
    signature = bytes.fromhex(signature_hex)
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(account)).verify(
            signature, b"NOOS/SIG/TX/V1" + bytes.fromhex(txid)
        )
    except (ValueError, InvalidSignature) as error:
        raise ValueError("signature does not authorize this transaction id") from error
    submitted = cli_json(
        exe, "tx", "submit",
        "--node", metadata["validator_rpc"], "--token", metadata["rpc_token"],
        "--chain-id", metadata["chain_id"], "--genesis-hash", metadata["genesis_hash"],
        "--tx", tx, "--witnesses", _wallet_witness(bytes.fromhex(txid), signature),
    )
    if submitted.get("txid") != txid:
        raise RuntimeError("node returned a different transaction id")
    return {"txid": txid, "receipt": settled_receipt(metadata, txid)}


def wallet_faucet(metadata: dict, exe: Path, body: dict) -> dict:
    recipient = str(body.get("account", ""))
    if not HEX32.fullmatch(recipient):
        raise ValueError("account must be 32-byte lowercase hex")
    amount = integer(body.get("amount", 1_000_000), "amount", 1, 1_000_000)
    account = metadata["developer_public_id"]
    with TX_LOCK:
        result = submit_actions(metadata, exe, [
            {"type": "withdraw_from_account", "account_id": account, "asset_id": NOOS_ASSET, "amount": str(amount)},
            {"type": "deposit_to_account", "account_id": recipient, "asset_id": NOOS_ASSET, "amount": str(amount)},
        ])
    return {"txid": result["build"]["txid"], "receipt": result["receipt"]}
class Handler(BaseHTTPRequestHandler):
    server_version = "MindMarket/1"

    @property
    def app(self) -> "MarketServer":
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args: object) -> None:
        sys.stderr.write("market-gateway: " + format % args + "\n")

    def send_json(self, status: int, value: dict) -> None:
        encoded = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        try:
            if parsed.path == "/api/config":
                status = request_json(
                    self.app.metadata["validator_rpc"], "/status", self.app.metadata["rpc_token"]
                )
                self.send_json(
                    200,
                    {
                        "chain_id": self.app.metadata["chain_id"],
                        "genesis_hash": self.app.metadata["genesis_hash"],
                        "account": self.app.metadata["developer_public_id"],
                        "noos_asset": NOOS_ASSET,
                        "head": status["unsafe_head"],
                    },
                )
                return
            if parsed.path in ("/api/assets", "/api/pools"):
                suffix = "/api/v1/assets" if parsed.path.endswith("assets") else "/api/v1/pools"
                self.send_json(200, request_json(self.app.metadata["indexer"], suffix))
                return
            if parsed.path == "/api/defi":
                self.send_json(200, defi_state(self.app.metadata))
                return
            if parsed.path == "/api/balance":
                values = parse_qs(parsed.query)
                asset = values.get("asset", [""])[0]
                account = values.get("account", [self.app.metadata["developer_public_id"]])[0]
                if not HEX32.fullmatch(asset) or not HEX32.fullmatch(account):
                    raise ValueError("account and asset must be 32-byte lowercase hex")
                self.send_json(
                    200,
                    request_json(
                        self.app.metadata["indexer"],
                        f"/api/v1/balances/{account}/{asset}",
                    ),
                )
                return
            self.serve_static(parsed.path)
        except (ValueError, RuntimeError) as error:
            self.send_json(400, {"error": str(error)})
        except (HTTPError, URLError, TimeoutError) as error:
            self.send_json(503, {"error": f"chain API unavailable: {error}"})
        except Exception as error:
            self.send_json(500, {"error": str(error)})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                raise ValueError("request body must be 1..65536 bytes")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("request body must be a JSON object")
            if parsed.path == "/api/launch":
                self.send_json(200, launch(self.app.metadata, self.app.cli, body))
                return
            if parsed.path == "/api/swap":
                self.send_json(200, swap(self.app.metadata, self.app.cli, body))
                return
            if parsed.path == "/api/defi/action":
                self.send_json(200, defi_action(self.app.metadata, self.app.cli, body))
                return
            if parsed.path == "/api/wallet/build":
                self.send_json(200, wallet_build(self.app.metadata, self.app.cli, body))
                return
            if parsed.path == "/api/wallet/submit":
                self.send_json(200, wallet_submit(self.app.metadata, self.app.cli, body))
                return
            if parsed.path == "/api/wallet/faucet":
                self.send_json(200, wallet_faucet(self.app.metadata, self.app.cli, body))
                return
            self.send_json(404, {"error": "unknown route"})
        except (ValueError, RuntimeError) as error:
            self.send_json(400, {"error": str(error)})
        except (HTTPError, URLError, TimeoutError) as error:
            self.send_json(503, {"error": f"chain API unavailable: {error}"})
        except Exception as error:
            self.send_json(500, {"error": str(error)})

    def serve_static(self, raw_path: str) -> None:
        aliases = {
            "/": STATIC_ROOT / "index.html",
            "/launch": STATIC_ROOT / "launch" / "index.html",
            "/exchange": STATIC_ROOT / "exchange" / "index.html",
            "/launch/": STATIC_ROOT / "launch" / "index.html",
            "/exchange/": STATIC_ROOT / "exchange" / "index.html",
            "/defi": STATIC_ROOT / "defi" / "index.html",
            "/defi/": STATIC_ROOT / "defi" / "index.html",
            "/wallet": STATIC_ROOT / "wallet" / "index.html",
            "/wallet/": STATIC_ROOT / "wallet" / "index.html",
        }
        target = aliases.get(raw_path)
        if target is None:
            relative = raw_path.lstrip("/")
            target = (STATIC_ROOT / relative).resolve()
            if STATIC_ROOT.resolve() not in target.parents:
                self.send_json(404, {"error": "not found"})
                return
        if not target.is_file():
            self.send_json(404, {"error": "not found"})
            return
        content = target.read_bytes()
        content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type + ("; charset=utf-8" if content_type.startswith("text/") or content_type == "application/javascript" else ""))
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(content)


class MarketServer(ThreadingHTTPServer):
    def __init__(self, address: tuple[str, int], metadata: dict, cli: Path):
        super().__init__(address, Handler)
        self.metadata = metadata
        self.cli = cli


def main() -> int:
    parser = argparse.ArgumentParser(description="Mind Market local application gateway")
    parser.add_argument("--runtime", type=Path, default=DEFAULT_RUNTIME)
    parser.add_argument("--listen", default="127.0.0.1:18100")
    args = parser.parse_args()
    host, port_raw = args.listen.rsplit(":", 1)
    metadata = load_metadata(args.runtime)
    cli = locate_cli()
    server = MarketServer((host, int(port_raw)), metadata, cli)
    print(f"Mind Market ready at http://{host}:{port_raw}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
