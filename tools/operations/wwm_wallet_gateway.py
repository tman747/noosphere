from __future__ import annotations

import ipaddress
import json
import re
import sqlite3
import struct
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from urllib.parse import parse_qs, urlsplit

import blake3
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CHAIN_ID: Final[str] = "0106bef48c350fd9633bac1718f8d9ecb1824c78bd127feee6405c65a63afa8b"
GENESIS_HASH: Final[str] = "8c182c6e9d622f77f082332da1a514ecf061ef4c504b5dde466ca4c93e35167e"
NOOS_ASSET: Final[str] = "00" * 32
FAUCET_ACCOUNT: Final[str] = "c9e967496427ad970fa540f15c274f214c0892aa0a3ce7364b9bb96583cb6b1d"
FAUCET_AMOUNT: Final[int] = 1_000_000
FAUCET_ACCOUNT_COOLDOWN_SECONDS: Final[int] = 3_600
FAUCET_CLIENT_COOLDOWN_SECONDS: Final[int] = 60
FAUCET_DAILY_LIMIT: Final[int] = 500
MAX_BODY_BYTES: Final[int] = 64 * 1024
MAX_UPSTREAM_BYTES: Final[int] = 2 * 1024 * 1024
HEX32 = re.compile(r"^[0-9a-f]{64}$")
HEX_BYTES = re.compile(r"^(?:[0-9a-f]{2})+$")
GET_ROUTES: Final[frozenset[str]] = frozenset(
    {"/api/config", "/api/assets", "/api/defi", "/api/balance", "/api/wallet/health"}
)
POST_ROUTES: Final[frozenset[str]] = frozenset(
    {"/api/wallet/build", "/api/wallet/simulate", "/api/wallet/submit", "/api/wallet/faucet"}
)


class WalletError(RuntimeError):
    def __init__(self, status: int, code: str, message: str, *, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message
        self.retry_after = retry_after


@dataclass(frozen=True)
class WalletReply:
    status: int
    value: dict
    retry_after: int | None = None


class FaucetLimiter:
    def __init__(self, path: Path):
        self.path = path.resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        with self._connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS faucet_claims ("
                "scope TEXT NOT NULL, subject TEXT NOT NULL, claimed_ms INTEGER NOT NULL, "
                "PRIMARY KEY (scope, subject))"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS faucet_events ("
                "event_id INTEGER PRIMARY KEY AUTOINCREMENT, claimed_ms INTEGER NOT NULL)"
            )
            db.execute("CREATE INDEX IF NOT EXISTS faucet_events_claimed_ms ON faucet_events(claimed_ms)")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    def check(self, account: str, client: str, now_ms: int) -> None:
        day_start = now_ms - 86_400_000
        with self._lock, self._connect() as db:
            account_row = db.execute(
                "SELECT claimed_ms FROM faucet_claims WHERE scope = 'account' AND subject = ?",
                (account,),
            ).fetchone()
            if account_row is not None:
                remaining_ms = int(account_row[0]) + FAUCET_ACCOUNT_COOLDOWN_SECONDS * 1000 - now_ms
                if remaining_ms > 0:
                    retry = max(1, (remaining_ms + 999) // 1000)
                    raise WalletError(429, "FAUCET_ACCOUNT_COOLDOWN", "This wallet already received recent test funds.", retry_after=retry)
            client_row = db.execute(
                "SELECT claimed_ms FROM faucet_claims WHERE scope = 'client' AND subject = ?",
                (client,),
            ).fetchone()
            if client_row is not None:
                remaining_ms = int(client_row[0]) + FAUCET_CLIENT_COOLDOWN_SECONDS * 1000 - now_ms
                if remaining_ms > 0:
                    retry = max(1, (remaining_ms + 999) // 1000)
                    raise WalletError(429, "FAUCET_CLIENT_COOLDOWN", "Please wait before funding another wallet.", retry_after=retry)
            daily = db.execute(
                "SELECT COUNT(*) FROM faucet_events WHERE claimed_ms >= ?", (day_start,)
            ).fetchone()
            if daily is not None and int(daily[0]) >= FAUCET_DAILY_LIMIT:
                raise WalletError(429, "FAUCET_DAILY_LIMIT", "The public test faucet reached its daily safety limit.", retry_after=3_600)

    def record(self, account: str, client: str, now_ms: int) -> None:
        with self._lock, self._connect() as db:
            db.execute(
                "INSERT INTO faucet_claims(scope, subject, claimed_ms) VALUES('account', ?, ?) "
                "ON CONFLICT(scope, subject) DO UPDATE SET claimed_ms = excluded.claimed_ms",
                (account, now_ms),
            )
            db.execute(
                "INSERT INTO faucet_claims(scope, subject, claimed_ms) VALUES('client', ?, ?) "
                "ON CONFLICT(scope, subject) DO UPDATE SET claimed_ms = excluded.claimed_ms",
                (client, now_ms),
            )
            db.execute("INSERT INTO faucet_events(claimed_ms) VALUES(?)", (now_ms,))
            db.execute("DELETE FROM faucet_events WHERE claimed_ms < ?", (now_ms - 86_400_000,))


class WalletService:
    def __init__(
        self,
        *,
        api_base: str,
        node_rpc: str,
        node_token: str,
        cli_path: Path,
        wallet_root: Path,
        faucet_db: Path,
    ):
        parsed = urlsplit(api_base)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username
            or parsed.password
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or parsed.port not in {None, 443}
        ):
            raise WalletError(500, "INVALID_WALLET_API", "Wallet API must be an exact HTTPS origin.")
        self.api_base = api_base.rstrip("/")
        self.node_rpc = node_rpc.rstrip("/")
        self.node_token = node_token
        self.cli_path = cli_path.resolve(strict=True)
        self.wallet_root = wallet_root.resolve(strict=True)
        if not self.cli_path.is_file():
            raise WalletError(500, "MISSING_WALLET_CLI", "Wallet transaction builder is unavailable.")
        if not self.wallet_root.is_dir():
            raise WalletError(500, "MISSING_WALLET_UI", "Wallet application files are unavailable.")
        self.limiter = FaucetLimiter(faucet_db)
        self.faucet_lock = threading.Lock()
        self.work_slots = threading.BoundedSemaphore(4)
        fixture_seed = blake3.blake3(b"noos-devnet-1/faucet/0").digest()
        self.faucet_key = Ed25519PrivateKey.from_private_bytes(fixture_seed)
        faucet_public = self.faucet_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        if faucet_public != FAUCET_ACCOUNT:
            raise WalletError(500, "FAUCET_IDENTITY_MISMATCH", "Test faucet identity does not match genesis.")

    @staticmethod
    def is_get_route(path: str) -> bool:
        return path in GET_ROUTES

    @staticmethod
    def is_post_route(path: str) -> bool:
        return path in POST_ROUTES

    @staticmethod
    def client_key(value: str) -> str:
        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            return "invalid-client"

    def get(self, path: str, query: str) -> WalletReply:
        if path == "/api/config":
            if query:
                raise WalletError(400, "INVALID_QUERY", "This endpoint does not accept a query string.")
            status = self._status()
            return WalletReply(
                200,
                {
                    "schema": "noos/public-testnet-wallet-config/v1",
                    "environment": "public-testnet",
                    "production": False,
                    "chain_id": CHAIN_ID,
                    "genesis_hash": GENESIS_HASH,
                    "faucet_account": FAUCET_ACCOUNT,
                    "noos_asset": NOOS_ASSET,
                    "head": status["unsafe_head"],
                },
            )
        if path == "/api/assets":
            return WalletReply(200, {"items": []})
        if path == "/api/defi":
            return WalletReply(200, {"stable_assets": [], "lending_markets": [], "stable_safety": []})
        if path == "/api/balance":
            values = parse_qs(query, keep_blank_values=True)
            account = self._single_query(values, "account")
            asset = self._single_query(values, "asset")
            self._hex32(account, "account")
            self._hex32(asset, "asset")
            balance = self._api_json("GET", f"/api/v1/balances/{account}/{asset}")
            if balance is None:
                balance = {"account": account, "asset": asset, "balance": "0"}
            return WalletReply(200, balance)
        if path == "/api/wallet/health":
            if query:
                raise WalletError(400, "INVALID_QUERY", "This endpoint does not accept a query string.")
            status = self._status()
            return WalletReply(
                200,
                {
                    "schema": "noos/public-testnet-wallet-health/v1",
                    "status": "ok",
                    "environment": "public-testnet",
                    "production": False,
                    "chain_id": CHAIN_ID,
                    "genesis_hash": GENESIS_HASH,
                    "unsafe_head": status["unsafe_head"],
                    "faucet": {
                        "amount_micro_noos_test": str(FAUCET_AMOUNT),
                        "account_cooldown_seconds": FAUCET_ACCOUNT_COOLDOWN_SECONDS,
                        "client_cooldown_seconds": FAUCET_CLIENT_COOLDOWN_SECONDS,
                    },
                },
            )
        raise WalletError(404, "NOT_FOUND", "Wallet route not found.")

    def post(self, path: str, body: dict, client: str) -> WalletReply:
        if path == "/api/wallet/build":
            return WalletReply(200, self._build_transfer(body))
        if path == "/api/wallet/simulate":
            account = self._hex32(body.get("account", ""), "account")
            self._wait_operator_account(account)
            tx, txid, witnesses = self._wallet_envelope(body)
            result = self._operator_json("/simulate_tx", {"tx": tx, "witnesses": witnesses})
            if result.get("txid") != txid:
                raise WalletError(502, "SIMULATION_TXID_MISMATCH", "Validator simulated a different transaction.")
            return WalletReply(200, result)
        if path == "/api/wallet/submit":
            tx, txid, witnesses = self._wallet_envelope(body)
            record = self._submit_and_wait(tx, txid, witnesses)
            return WalletReply(200, {"txid": txid, "receipt": record})
        if path == "/api/wallet/faucet":
            return WalletReply(200, self._faucet(body, self.client_key(client)))
        raise WalletError(404, "NOT_FOUND", "Wallet route not found.")

    @staticmethod
    def _single_query(values: dict[str, list[str]], name: str) -> str:
        selected = values.get(name)
        if selected is None or len(selected) != 1:
            raise WalletError(400, "INVALID_QUERY", f"Query parameter {name} is required exactly once.")
        return selected[0]

    @staticmethod
    def _hex32(value: object, name: str) -> str:
        rendered = str(value)
        if HEX32.fullmatch(rendered) is None:
            raise WalletError(400, "INVALID_HEX32", f"{name} must be 32-byte lowercase hex.")
        return rendered

    @staticmethod
    def _integer(value: object, name: str, minimum: int, maximum: int) -> int:
        rendered = str(value)
        if not rendered.isascii() or not rendered.isdigit():
            raise WalletError(400, "INVALID_INTEGER", f"{name} must be a canonical unsigned integer.")
        parsed = int(rendered)
        if not minimum <= parsed <= maximum:
            raise WalletError(400, "INTEGER_OUT_OF_RANGE", f"{name} is outside the accepted range.")
        return parsed

    def _status(self) -> dict:
        status = self._api_json("GET", "/api/status")
        if status is None or status.get("chain_id") != CHAIN_ID or status.get("genesis_hash") != GENESIS_HASH:
            raise WalletError(502, "WRONG_CHAIN_IDENTITY", "Wallet API returned the wrong chain identity.")
        if status.get("api_version") != "v1" or status.get("protocol_version") != "v1":
            raise WalletError(502, "UNSUPPORTED_PROTOCOL", "Wallet API protocol version is unsupported.")
        return status

    def _build_transfer(self, body: dict) -> dict:
        account = self._hex32(body.get("account", ""), "account")
        recipient = self._hex32(body.get("recipient", ""), "recipient")
        asset = self._hex32(body.get("asset", ""), "asset")
        if asset != NOOS_ASSET:
            raise WalletError(400, "UNSUPPORTED_ASSET", "This public mobile pilot sends only valueless NOOS_TEST.")
        amount = self._integer(body.get("amount", ""), "amount", 1, (1 << 128) - 1)
        status = self._status()
        spec = self._transfer_spec(account, recipient, asset, amount, int(status["unsafe_head"]["height"]) + 1_000)
        built = self._cli_json("tx", "build", "--spec", json.dumps(spec, separators=(",", ":")))
        tx = str(built.get("tx", ""))
        txid = str(built.get("txid", ""))
        self._validate_built(tx, txid)
        return {
            "tx": tx,
            "txid": txid,
            "chain_id": CHAIN_ID,
            "genesis_hash": GENESIS_HASH,
            "signing_message": (b"NOOS/SIG/TX/V1" + bytes.fromhex(txid)).hex(),
        }

    @staticmethod
    def _transfer_spec(account: str, recipient: str, asset: str, amount: int, expiry_height: int) -> dict:
        return {
            "chain_id": CHAIN_ID,
            "format_version": 1,
            "expiry_height": expiry_height,
            "fee_payer": account,
            "fee_authorization": None,
            "resource_limits": {
                "bytes": 4096,
                "grain_steps": 0,
                "proof_units": 0,
                "state_reads": 64,
                "state_writes": 64,
                "blob_bytes": 0,
            },
            "note_inputs": [],
            "account_inputs": [account],
            "object_access_list": [],
            "actions": [
                (struct.pack("<H", 3) + bytes.fromhex(account) + bytes.fromhex(asset) + amount.to_bytes(16, "little")).hex(),
                (struct.pack("<H", 2) + bytes.fromhex(recipient) + bytes.fromhex(asset) + amount.to_bytes(16, "little")).hex(),
            ],
            "outputs": [],
            "evidence_refs": [],
            "lock_reveals": [],
        }

    @staticmethod
    def _validate_built(tx: str, txid: str) -> None:
        if HEX_BYTES.fullmatch(tx) is None or HEX32.fullmatch(txid) is None:
            raise WalletError(502, "MALFORMED_BUILDER_OUTPUT", "Transaction builder returned malformed canonical data.")
        computed = blake3.blake3(b"NOOS/TX/ID/V1" + bytes.fromhex(tx)).hexdigest()
        if computed != txid:
            raise WalletError(502, "BUILDER_TXID_MISMATCH", "Transaction builder returned a mismatched transaction ID.")

    def _wallet_envelope(self, body: dict) -> tuple[str, str, str]:
        account = self._hex32(body.get("account", ""), "account")
        txid = self._hex32(body.get("txid", ""), "txid")
        tx = str(body.get("tx", ""))
        signature_hex = str(body.get("signature", ""))
        if HEX_BYTES.fullmatch(tx) is None or len(tx) > MAX_BODY_BYTES * 2:
            raise WalletError(400, "INVALID_TRANSACTION", "Transaction must be bounded canonical lowercase hex.")
        computed = blake3.blake3(b"NOOS/TX/ID/V1" + bytes.fromhex(tx)).hexdigest()
        if computed != txid:
            raise WalletError(400, "TXID_MISMATCH", "Transaction bytes do not match the signed transaction ID.")
        if len(signature_hex) != 128 or HEX_BYTES.fullmatch(signature_hex) is None:
            raise WalletError(400, "INVALID_SIGNATURE", "Signature must be 64-byte lowercase hex.")
        signature = bytes.fromhex(signature_hex)
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(account)).verify(
                signature, b"NOOS/SIG/TX/V1" + bytes.fromhex(txid)
            )
        except (ValueError, InvalidSignature) as error:
            raise WalletError(400, "INVALID_SIGNATURE", "Signature does not authorize this transaction.") from error
        return tx, txid, self._wallet_witness(bytes.fromhex(txid), signature)

    @staticmethod
    def _wallet_witness(txid: bytes, signature: bytes) -> str:
        tag = lambda value: struct.pack("<H", value)
        intent = struct.pack("<H", 1)
        intent += tag(1) + txid
        intent += tag(2) + bytes([0])
        intent += tag(3) + bytes([0])
        intent += tag(4) + struct.pack("<H", 1)
        intent += tag(5) + struct.pack("<I", len(signature)) + signature
        witnesses = struct.pack("<H", 1)
        witnesses += tag(1) + struct.pack("<I", 1) + intent
        witnesses += tag(2) + struct.pack("<I", 0)
        return witnesses.hex()

    def _faucet(self, body: dict, client: str) -> dict:
        account = self._hex32(body.get("account", ""), "account")
        amount = self._integer(body.get("amount", FAUCET_AMOUNT), "amount", FAUCET_AMOUNT, FAUCET_AMOUNT)
        if not self.faucet_lock.acquire(blocking=False):
            raise WalletError(429, "FAUCET_BUSY", "Another faucet transfer is settling. Try again shortly.", retry_after=15)
        try:
            now_ms = int(time.time() * 1000)
            self.limiter.check(account, client, now_ms)
            status = self._status()
            spec = self._transfer_spec(
                FAUCET_ACCOUNT,
                account,
                NOOS_ASSET,
                amount,
                int(status["unsafe_head"]["height"]) + 1_000,
            )
            built = self._cli_json("tx", "build", "--spec", json.dumps(spec, separators=(",", ":")))
            tx = str(built.get("tx", ""))
            txid = str(built.get("txid", ""))
            self._validate_built(tx, txid)
            signature = self.faucet_key.sign(b"NOOS/SIG/TX/V1" + bytes.fromhex(txid))
            witnesses = self._wallet_witness(bytes.fromhex(txid), signature)
            record = self._submit_and_wait(tx, txid, witnesses)
            self.limiter.record(account, client, int(time.time() * 1000))
            return {"txid": txid, "receipt": record, "amount": str(amount), "asset": NOOS_ASSET}
        finally:
            self.faucet_lock.release()

    def _submit_and_wait(self, tx: str, txid: str, witnesses: str) -> dict:
        accepted = self._api_json("POST", "/api/v1/transactions", {"tx": tx, "witnesses": witnesses})
        if accepted is None or accepted.get("txid") != txid:
            raise WalletError(502, "SUBMISSION_TXID_MISMATCH", "Transaction API accepted a different transaction ID.")
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            record = self._api_json("GET", f"/api/v1/transactions/{txid}", allow_not_found=True)
            if record is not None:
                state = record.get("state")
                if state in {"INCLUDED", "JUSTIFIED", "FINALIZED"}:
                    return record
                if state in {"REJECTED", "REVERTED"}:
                    raise WalletError(409, "TRANSACTION_REJECTED", f"Transaction entered {state} state.")
            time.sleep(0.4)
        raise WalletError(504, "SETTLEMENT_TIMEOUT", "Transaction was accepted but did not settle within 90 seconds.")

    def _cli_json(self, *args: str) -> dict:
        if not self.work_slots.acquire(blocking=False):
            raise WalletError(503, "WALLET_BUILDER_BUSY", "Wallet transaction builder is busy.", retry_after=2)
        try:
            try:
                completed = subprocess.run(
                    [str(self.cli_path), *args],
                    capture_output=True,
                    text=True,
                    timeout=15,
                    check=False,
                )
            except subprocess.TimeoutExpired as error:
                raise WalletError(504, "WALLET_BUILDER_TIMEOUT", "Wallet transaction builder timed out.") from error
            if completed.returncode != 0:
                detail = completed.stderr.strip() or completed.stdout.strip() or "wallet transaction builder failed"
                raise WalletError(400, "WALLET_BUILD_REJECTED", detail[:512])
            try:
                value = json.loads(completed.stdout)
            except json.JSONDecodeError as error:
                raise WalletError(502, "MALFORMED_BUILDER_OUTPUT", "Wallet transaction builder returned malformed JSON.") from error
            if not isinstance(value, dict):
                raise WalletError(502, "MALFORMED_BUILDER_OUTPUT", "Wallet transaction builder returned a non-object.")
            return value
        finally:
            self.work_slots.release()

    def _wait_operator_account(self, account: str) -> None:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            request = urllib.request.Request(
                self.node_rpc + f"/account/{account}",
                method="GET",
                headers={
                    "Accept": "application/json",
                    "Authorization": "Bearer " + self.node_token,
                    "User-Agent": "mindchain-public-wallet/1",
                },
            )
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    response.read(MAX_UPSTREAM_BYTES + 1)
                return
            except urllib.error.HTTPError as error:
                error.read(16_384)
                if error.code != 404:
                    raise WalletError(503, "VALIDATOR_UNAVAILABLE", "Validator account view is unavailable.") from error
            except (urllib.error.URLError, TimeoutError, OSError) as error:
                raise WalletError(503, "VALIDATOR_UNAVAILABLE", "Validator account view is unavailable.") from error
            time.sleep(0.25)
        raise WalletError(503, "VALIDATOR_CATCHING_UP", "Validator is still indexing this newly funded wallet. Retry shortly.", retry_after=3)

    def _operator_json(self, path: str, value: dict) -> dict:
        encoded = json.dumps(value, separators=(",", ":")).encode()
        request = urllib.request.Request(
            self.node_rpc + path,
            data=encoded,
            method="POST",
            headers={
                "Accept": "application/json",
                "Authorization": "Bearer " + self.node_token,
                "Content-Type": "application/json",
                "User-Agent": "mindchain-public-wallet/1",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read(MAX_UPSTREAM_BYTES + 1)
        except urllib.error.HTTPError as error:
            detail = self._error_detail(error.read(16_384))
            raise WalletError(400, "SIMULATION_REJECTED", detail) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise WalletError(503, "VALIDATOR_UNAVAILABLE", "Validator simulation service is unavailable.") from error
        if len(raw) > MAX_UPSTREAM_BYTES:
            raise WalletError(502, "UPSTREAM_TOO_LARGE", "Validator response exceeded the wallet bound.")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as error:
            raise WalletError(502, "MALFORMED_UPSTREAM", "Validator returned malformed JSON.") from error
        if not isinstance(parsed, dict):
            raise WalletError(502, "MALFORMED_UPSTREAM", "Validator returned a non-object.")
        return parsed

    def _api_json(
        self,
        method: str,
        path: str,
        value: dict | None = None,
        *,
        allow_not_found: bool = False,
    ) -> dict | None:
        encoded = None if value is None else json.dumps(value, separators=(",", ":")).encode()
        headers = {
            "Accept": "application/vnd.noos.v1+json, application/json",
            "Cache-Control": "no-cache",
            "User-Agent": "mindchain-public-wallet/1",
        }
        if encoded is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(self.api_base + path, data=encoded, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=15) as response:
                raw = response.read(MAX_UPSTREAM_BYTES + 1)
        except urllib.error.HTTPError as error:
            raw = error.read(16_384)
            if allow_not_found and error.code == 404:
                return None
            status = error.code if error.code in {400, 409, 413, 415, 422, 429} else 502
            raise WalletError(status, "CHAIN_API_REJECTED", self._error_detail(raw)) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise WalletError(503, "CHAIN_API_UNAVAILABLE", "Public testnet API is unavailable.") from error
        if len(raw) > MAX_UPSTREAM_BYTES:
            raise WalletError(502, "UPSTREAM_TOO_LARGE", "Public testnet response exceeded the wallet bound.")
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as error:
            raise WalletError(502, "MALFORMED_UPSTREAM", "Public testnet returned malformed JSON.") from error
        if not isinstance(parsed, dict):
            raise WalletError(502, "MALFORMED_UPSTREAM", "Public testnet returned a non-object.")
        return parsed

    @staticmethod
    def _error_detail(raw: bytes) -> str:
        try:
            parsed = json.loads(raw)
            error = parsed.get("error") if isinstance(parsed, dict) else None
            if isinstance(error, dict):
                return str(error.get("detail") or error.get("message") or error.get("code") or "request rejected")[:512]
            if isinstance(error, str):
                return error[:512]
        except json.JSONDecodeError:
            pass
        rendered = raw.decode("utf-8", "replace").strip()
        return rendered[:512] or "request rejected"
