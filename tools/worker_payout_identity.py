#!/usr/bin/env python3
"""Create, inspect, and recover a local encrypted compute-worker payout identity."""
from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass, field
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wallet_transfer import cargo_binary, load_profile  # noqa: E402

SCHEMA = "noos/worker-payout-identity/v1"
SECRET_SCHEMA = "noos/worker-payout-secret/v1"
AAD_DOMAIN = b"NOOS/WORKER/PAYOUT-IDENTITY/AAD/V1\0"
HEX32 = re.compile(r"^[0-9a-f]{64}$")
MAX_IDENTITY_BYTES = 1_048_576
MIN_PASSWORD_BYTES = 12
MAX_PASSWORD_BYTES = 1_024
SCRYPT_N = 1 << 17
SCRYPT_R = 8
SCRYPT_P = 1
KDF_FIELDS = {"name", "salt_base64", "length", "n", "r", "p"}
AEAD_FIELDS = {"name", "nonce_base64"}
ENVELOPE_FIELDS = {
    "schema",
    "chain_id",
    "genesis_hash",
    "account",
    "index",
    "payout_account",
    "kdf",
    "aead",
    "ciphertext_base64",
}
SECRET_FIELDS = {
    "schema",
    "chain_id",
    "genesis_hash",
    "account",
    "index",
    "payout_account",
    "seed_base64",
}


class IdentityError(RuntimeError):
    """The local identity is malformed, unauthenticated, or unsafe."""


@dataclass
class WorkerIdentity:
    chain_id: str
    genesis_hash: str
    account: int
    index: int
    payout_account: str
    seed: bytearray = field(repr=False)

    def descriptor(self, identity_file: Path) -> dict:
        return {
            "schema": SCHEMA,
            "chain_id": self.chain_id,
            "genesis_hash": self.genesis_hash,
            "account": self.account,
            "index": self.index,
            "payout_account": self.payout_account,
            "identity_file_sha256": hashlib.sha256(identity_file.read_bytes()).hexdigest(),
            "custody": "LOCAL_PASSWORD_ENCRYPTED",
            "recovery_portable": True,
            "secret_exported": False,
            "browser_storage_used": False,
            "coordinator_storage_used": False,
        }

    def close(self) -> None:
        self.seed[:] = b"\x00" * len(self.seed)

    def __enter__(self) -> "WorkerIdentity":
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _decode_base64(value: object, size: int, field_name: str) -> bytes:
    if not isinstance(value, str):
        raise IdentityError(f"{field_name} is malformed")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise IdentityError(f"{field_name} is malformed") from error
    if len(decoded) != size:
        raise IdentityError(f"{field_name} has the wrong length")
    return decoded


def _validate_password(password: bytes | bytearray) -> None:
    if not MIN_PASSWORD_BYTES <= len(password) <= MAX_PASSWORD_BYTES:
        raise IdentityError("identity password must contain 12 to 1024 UTF-8 bytes")


def read_password(path: Path | None, prompt: str = "Worker identity password: ") -> bytearray:
    if path is None:
        value = getpass.getpass(prompt).encode("utf-8")
    else:
        if path.is_symlink() or not path.is_file():
            raise IdentityError("password file is missing or a symlink")
        if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise IdentityError("password file must not be accessible by group or other")
        if path.stat().st_size > MAX_PASSWORD_BYTES + 2:
            raise IdentityError("password file is unbounded")
        value = path.read_bytes()
        if len(value) > MAX_PASSWORD_BYTES + 2:
            raise IdentityError("password file changed while being read")
        value = value.rstrip(b"\r\n")
    _validate_password(value)
    return bytearray(value)


def _derive_key(password: bytes | bytearray, salt: bytes) -> bytearray:
    _validate_password(password)
    return bytearray(
        Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P).derive(
            bytes(password)
        )
    )


def derive_payout_account(
    cli_path: Path, seed: bytearray, account: int, index: int
) -> str:
    seed_stdin = seed.hex() + "\n"
    completed = subprocess.run(
        [
            str(cli_path),
            "keygen",
            "--seed-stdin",
            "--purpose",
            "sign",
            "--account",
            str(account),
            "--index",
            str(index),
        ],
        text=True,
        input=seed_stdin,
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or "noos-cli failed"
        raise IdentityError(f"payout derivation failed: {detail}")
    try:
        value = json.loads(completed.stdout)
        payout = value["verifying_key"]
    except (json.JSONDecodeError, KeyError, TypeError) as error:
        raise IdentityError("payout derivation returned malformed JSON") from error
    if not isinstance(payout, str) or HEX32.fullmatch(payout) is None:
        raise IdentityError("payout derivation returned a malformed account")
    return payout


def _metadata(
    chain_id: str,
    genesis_hash: str,
    account: int,
    index: int,
    payout_account: str,
    salt: bytes,
    nonce: bytes,
) -> dict:
    return {
        "schema": SCHEMA,
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "account": account,
        "index": index,
        "payout_account": payout_account,
        "kdf": {
            "name": "SCRYPT",
            "salt_base64": base64.b64encode(salt).decode("ascii"),
            "length": 32,
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
        },
        "aead": {
            "name": "AES-256-GCM",
            "nonce_base64": base64.b64encode(nonce).decode("ascii"),
        },
    }


def _validate_public_fields(
    chain_id: object,
    genesis_hash: object,
    account: object,
    index: object,
    payout_account: object,
) -> tuple[str, str, int, int, str]:
    if not isinstance(chain_id, str) or HEX32.fullmatch(chain_id) is None:
        raise IdentityError("identity chain_id is malformed")
    if not isinstance(genesis_hash, str) or HEX32.fullmatch(genesis_hash) is None:
        raise IdentityError("identity genesis_hash is malformed")
    if (
        not isinstance(account, int)
        or isinstance(account, bool)
        or not 0 <= account < 1 << 31
        or not isinstance(index, int)
        or isinstance(index, bool)
        or not 0 <= index < 1 << 31
    ):
        raise IdentityError("identity derivation path is malformed")
    if (
        not isinstance(payout_account, str)
        or HEX32.fullmatch(payout_account) is None
        or payout_account == "0" * 64
    ):
        raise IdentityError("identity payout account is malformed")
    return chain_id, genesis_hash, account, index, payout_account


def _validate_envelope(document: object) -> tuple[dict, bytes, bytes, bytes]:
    if not isinstance(document, dict) or set(document) != ENVELOPE_FIELDS:
        raise IdentityError("identity envelope fields are malformed")
    if document.get("schema") != SCHEMA:
        raise IdentityError("identity schema is unsupported")
    _validate_public_fields(
        document.get("chain_id"),
        document.get("genesis_hash"),
        document.get("account"),
        document.get("index"),
        document.get("payout_account"),
    )
    kdf = document.get("kdf")
    aead = document.get("aead")
    if (
        not isinstance(kdf, dict)
        or set(kdf) != KDF_FIELDS
        or kdf.get("name") != "SCRYPT"
        or kdf.get("length") != 32
        or kdf.get("n") != SCRYPT_N
        or kdf.get("r") != SCRYPT_R
        or kdf.get("p") != SCRYPT_P
    ):
        raise IdentityError("identity KDF policy is malformed or downgraded")
    if (
        not isinstance(aead, dict)
        or set(aead) != AEAD_FIELDS
        or aead.get("name") != "AES-256-GCM"
    ):
        raise IdentityError("identity AEAD policy is malformed or downgraded")
    salt = _decode_base64(kdf.get("salt_base64"), 16, "KDF salt")
    nonce = _decode_base64(aead.get("nonce_base64"), 12, "AEAD nonce")
    ciphertext_value = document.get("ciphertext_base64")
    if not isinstance(ciphertext_value, str):
        raise IdentityError("identity ciphertext is malformed")
    try:
        ciphertext = base64.b64decode(ciphertext_value, validate=True)
    except (ValueError, TypeError) as error:
        raise IdentityError("identity ciphertext is malformed") from error
    if not 16 < len(ciphertext) <= 4_096:
        raise IdentityError("identity ciphertext is empty or unbounded")
    metadata = {key: value for key, value in document.items() if key != "ciphertext_base64"}
    return metadata, salt, nonce, ciphertext


def _write_private(path: Path, document: dict) -> None:
    encoded = canonical_json(document) + b"\n"
    if len(encoded) > MAX_IDENTITY_BYTES:
        raise IdentityError("identity envelope is unbounded")
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError as error:
        raise IdentityError(f"cannot secure identity directory: {error}") from error
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise IdentityError(f"refusing to overwrite identity file: {path}") from error
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(path, 0o600)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def load_envelope(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise IdentityError("identity file is missing or a symlink")
    if path.stat().st_size > MAX_IDENTITY_BYTES:
        raise IdentityError("identity file is unbounded")
    encoded = path.read_bytes()
    if not encoded or len(encoded) > MAX_IDENTITY_BYTES:
        raise IdentityError("identity file changed while being read")
    try:
        document = json.loads(encoded)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise IdentityError("identity file is not canonical JSON") from error
    _validate_envelope(document)
    if encoded != canonical_json(document) + b"\n":
        raise IdentityError("identity file is not canonical JSON")
    return document


def create_identity(
    path: Path,
    password: bytes | bytearray,
    chain_id: str,
    genesis_hash: str,
    account: int,
    index: int,
    cli_path: Path,
    *,
    random_bytes: Callable[[int], bytes] = secrets.token_bytes,
    derive_account: Callable[[Path, bytearray, int, int], str] = derive_payout_account,
) -> dict:
    _validate_password(password)
    _validate_public_fields(chain_id, genesis_hash, account, index, "1" * 64)
    seed = bytearray(random_bytes(32))
    if len(seed) != 32:
        seed[:] = b"\x00" * len(seed)
        raise IdentityError("OS CSPRNG returned the wrong seed length")
    try:
        payout_account = derive_account(cli_path, seed, account, index)
        _validate_public_fields(chain_id, genesis_hash, account, index, payout_account)
        salt = random_bytes(16)
        nonce = random_bytes(12)
        if len(salt) != 16 or len(nonce) != 12:
            raise IdentityError("OS CSPRNG returned the wrong nonce length")
        metadata = _metadata(
            chain_id, genesis_hash, account, index, payout_account, salt, nonce
        )
        secret = {
            "schema": SECRET_SCHEMA,
            "chain_id": chain_id,
            "genesis_hash": genesis_hash,
            "account": account,
            "index": index,
            "payout_account": payout_account,
            "seed_base64": base64.b64encode(seed).decode("ascii"),
        }
        key = _derive_key(password, salt)
        try:
            ciphertext = AESGCM(bytes(key)).encrypt(
                nonce, canonical_json(secret), AAD_DOMAIN + canonical_json(metadata)
            )
        finally:
            key[:] = b"\x00" * len(key)
        document = {
            **metadata,
            "ciphertext_base64": base64.b64encode(ciphertext).decode("ascii"),
        }
        _write_private(path, document)
        with WorkerIdentity(
            chain_id, genesis_hash, account, index, payout_account, bytearray(seed)
        ) as identity:
            return identity.descriptor(path)
    finally:
        seed[:] = b"\x00" * len(seed)


def open_identity(
    path: Path,
    password: bytes | bytearray,
    expected_chain_id: str,
    expected_genesis_hash: str,
    cli_path: Path,
    *,
    derive_account: Callable[[Path, bytearray, int, int], str] = derive_payout_account,
) -> WorkerIdentity:
    _validate_password(password)
    document = load_envelope(path)
    metadata, salt, nonce, ciphertext = _validate_envelope(document)
    chain_id, genesis_hash, account, index, payout_account = _validate_public_fields(
        document["chain_id"],
        document["genesis_hash"],
        document["account"],
        document["index"],
        document["payout_account"],
    )
    if chain_id != expected_chain_id or genesis_hash != expected_genesis_hash:
        raise IdentityError("worker identity belongs to a different chain or genesis")
    key = _derive_key(password, salt)
    try:
        plaintext = bytearray(
            AESGCM(bytes(key)).decrypt(
                nonce, ciphertext, AAD_DOMAIN + canonical_json(metadata)
            )
        )
    except InvalidTag as error:
        raise IdentityError("worker identity authentication failed") from error
    finally:
        key[:] = b"\x00" * len(key)
    try:
        secret = json.loads(plaintext)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise IdentityError("worker identity secret payload is malformed") from error
    finally:
        plaintext[:] = b"\x00" * len(plaintext)
    if not isinstance(secret, dict) or set(secret) != SECRET_FIELDS:
        raise IdentityError("worker identity secret fields are malformed")
    if (
        secret.get("schema") != SECRET_SCHEMA
        or secret.get("chain_id") != chain_id
        or secret.get("genesis_hash") != genesis_hash
        or secret.get("account") != account
        or secret.get("index") != index
        or secret.get("payout_account") != payout_account
    ):
        raise IdentityError("worker identity public and encrypted records differ")
    seed = bytearray(_decode_base64(secret.get("seed_base64"), 32, "worker seed"))
    derived = derive_account(cli_path, seed, account, index)
    if derived != payout_account:
        seed[:] = b"\x00" * len(seed)
        raise IdentityError("worker identity payout derivation differs")
    return WorkerIdentity(chain_id, genesis_hash, account, index, payout_account, seed)


def recover_identity(
    recovery_path: Path,
    destination: Path,
    password: bytes | bytearray,
    expected_chain_id: str,
    expected_genesis_hash: str,
    cli_path: Path,
    *,
    derive_account: Callable[[Path, bytearray, int, int], str] = derive_payout_account,
) -> dict:
    document = load_envelope(recovery_path)
    with open_identity(
        recovery_path,
        password,
        expected_chain_id,
        expected_genesis_hash,
        cli_path,
        derive_account=derive_account,
    ) as identity:
        _write_private(destination, document)
        return identity.descriptor(destination)


def _profile_identity(path: str) -> tuple[str, str]:
    profile = load_profile(path)
    return str(profile["chain_id"]), str(profile["genesis_hash"])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("create", "inspect", "recover"):
        command = commands.add_parser(name)
        command.add_argument("--profile", required=True)
        command.add_argument("--password-file", type=Path)
        if name == "create":
            command.add_argument("--out", type=Path, required=True)
            command.add_argument("--account", type=int, default=0)
            command.add_argument("--index", type=int, default=0)
        elif name == "inspect":
            command.add_argument("--identity", type=Path, required=True)
        else:
            command.add_argument("--recovery", type=Path, required=True)
            command.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    password = read_password(args.password_file)
    try:
        chain_id, genesis_hash = _profile_identity(args.profile)
        cli_path = cargo_binary("noos-cli")
        if args.command == "create":
            result = create_identity(
                args.out,
                password,
                chain_id,
                genesis_hash,
                args.account,
                args.index,
                cli_path,
            )
        elif args.command == "inspect":
            with open_identity(
                args.identity, password, chain_id, genesis_hash, cli_path
            ) as identity:
                result = identity.descriptor(args.identity)
        else:
            result = recover_identity(
                args.recovery,
                args.out,
                password,
                chain_id,
                genesis_hash,
                cli_path,
            )
    finally:
        password[:] = b"\x00" * len(password)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except IdentityError as error:
        raise SystemExit(f"worker payout identity: {error}") from error
