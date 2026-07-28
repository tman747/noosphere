#!/usr/bin/env python3
"""Publish and verify signed, monotonic MindChain bootstrap snapshots."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "noos/bootstrap-registry/v1"
REGISTRY_ID_DOMAIN = b"NOOS/BOOTSTRAP/REGISTRY-ID/V1\0"
SIGNATURE_DOMAIN = b"NOOS/SIG/BOOTSTRAP-REGISTRY/V1\0"
MAX_REGISTRY_BYTES = 1024 * 1024
UINT64_MAX = (1 << 64) - 1
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BASE58_INDEX = {character: index for index, character in enumerate(BASE58_ALPHABET)}
ROOT_FIELDS = {"schema", "body", "signature"}
BODY_FIELDS = {
    "registry_id",
    "chain_id",
    "genesis_hash",
    "sequence",
    "previous_registry_id",
    "valid_from_unix_ms",
    "expires_unix_ms",
    "nodes",
}
NODE_FIELDS = {
    "node_id",
    "addresses",
    "valid_from_unix_ms",
    "expires_unix_ms",
    "status",
    "revoked_at_unix_ms",
}
SIGNATURE_FIELDS = {"algorithm", "key_id", "public_key", "signature"}


class BootstrapRegistryError(ValueError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_file(value: object) -> bytes:
    return canonical_json(value) + b"\n"


def sha256(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part)
    return digest.hexdigest()


def uint(value: Any, field: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= UINT64_MAX:
        raise BootstrapRegistryError(f"{field} must be a u64 no smaller than {minimum}")
    return value


def hex32(value: Any, field: str) -> str:
    if not isinstance(value, str) or not HEX64.fullmatch(value):
        raise BootstrapRegistryError(f"{field} must be 32-byte lowercase hex")
    return value


def b58encode(value: bytes) -> str:
    zeros = len(value) - len(value.lstrip(b"\0"))
    number = int.from_bytes(value, "big")
    encoded = ""
    while number:
        number, remainder = divmod(number, 58)
        encoded = BASE58_ALPHABET[remainder] + encoded
    return "1" * zeros + encoded


def b58decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise BootstrapRegistryError("bootstrap node_id must be base58btc text")
    number = 0
    for character in value:
        try:
            digit = BASE58_INDEX[character]
        except KeyError as error:
            raise BootstrapRegistryError("bootstrap node_id is not base58btc") from error
        number = number * 58 + digit
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeros = len(value) - len(value.lstrip("1"))
    result = b"\0" * zeros + decoded
    if b58encode(result) != value:
        raise BootstrapRegistryError("bootstrap node_id is not canonical base58btc")
    return result


def validate_peer_id(value: Any) -> str:
    if not isinstance(value, str):
        raise BootstrapRegistryError("bootstrap node_id must be text")
    decoded = b58decode(value)
    if len(decoded) != 38 or decoded[:6] != b"\x00\x24\x08\x01\x12\x20":
        raise BootstrapRegistryError("bootstrap node_id must be an inline Ed25519 PeerId")
    return value


def peer_id_from_ed25519_public(public: bytes) -> str:
    if len(public) != 32:
        raise BootstrapRegistryError("Ed25519 public key must contain 32 bytes")
    return b58encode(b"\x00\x24\x08\x01\x12\x20" + public)


def peer_id_from_seed(seed: bytes) -> str:
    return peer_id_from_ed25519_public(
        Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
    )


def read_private_seed(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise BootstrapRegistryError(f"cannot read bootstrap private key: {error}") from error
    stripped = raw.strip()
    if len(raw) == 32:
        seed = raw
    elif len(stripped) == 64:
        try:
            seed = bytes.fromhex(stripped.decode("ascii"))
        except (UnicodeDecodeError, ValueError) as error:
            raise BootstrapRegistryError("bootstrap private key must be 32 raw bytes or lowercase hex64") from error
        if seed.hex().encode("ascii") != stripped:
            raise BootstrapRegistryError("bootstrap private key hex is not canonical lowercase")
    else:
        raise BootstrapRegistryError("bootstrap private key must be 32 raw bytes or lowercase hex64")
    if seed == bytes(32):
        raise BootstrapRegistryError("all-zero bootstrap private key is forbidden")
    return seed


def read_public_key(path: Path) -> bytes:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise BootstrapRegistryError(f"cannot read trusted bootstrap key: {error}") from error
    if len(raw) == 32:
        return raw
    stripped = raw.strip()
    if len(stripped) != 64:
        raise BootstrapRegistryError("trusted bootstrap key must be 32 raw bytes or lowercase hex64")
    try:
        public = bytes.fromhex(stripped.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as error:
        raise BootstrapRegistryError("trusted bootstrap key must be 32 raw bytes or lowercase hex64") from error
    if public.hex().encode("ascii") != stripped:
        raise BootstrapRegistryError("trusted bootstrap key hex is not canonical lowercase")
    return public


def public_from_seed(seed: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def validate_address(address: Any, node_id: str) -> str:
    if not isinstance(address, str) or not address.isascii():
        raise BootstrapRegistryError("bootstrap address must be ASCII text")
    allowed_family = address.startswith(("/ip4/", "/ip6/", "/dns4/", "/dns6/"))
    if not allowed_family or "/udp/" not in address or not address.endswith(f"/quic-v1/p2p/{node_id}"):
        raise BootstrapRegistryError("bootstrap address must be an IP/DNS QUIC multiaddr bound to node_id")
    fields = address.split("/")
    if "" not in fields[:1] or any(not field for field in fields[1:]):
        raise BootstrapRegistryError("bootstrap address is malformed")
    try:
        udp_index = fields.index("udp")
        port = int(fields[udp_index + 1])
    except (ValueError, IndexError) as error:
        raise BootstrapRegistryError("bootstrap address has no valid UDP port") from error
    if not 1 <= port <= 65535:
        raise BootstrapRegistryError("bootstrap address UDP port is out of range")
    return address


def validate_node(value: Any, registry_valid_from: int, registry_expires: int) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != NODE_FIELDS:
        raise BootstrapRegistryError("bootstrap node fields are malformed")
    node_id = validate_peer_id(value["node_id"])
    addresses = value["addresses"]
    if (
        not isinstance(addresses, list)
        or not 1 <= len(addresses) <= 4
        or addresses != sorted(set(addresses))
    ):
        raise BootstrapRegistryError("bootstrap addresses must contain one to four sorted unique values")
    for address in addresses:
        validate_address(address, node_id)
    valid_from = uint(value["valid_from_unix_ms"], "node valid_from_unix_ms")
    expires = uint(value["expires_unix_ms"], "node expires_unix_ms")
    if valid_from < registry_valid_from or expires > registry_expires or valid_from >= expires:
        raise BootstrapRegistryError("bootstrap node validity lies outside the registry interval")
    status = value["status"]
    revoked_at = value["revoked_at_unix_ms"]
    if status == "active" and revoked_at is not None:
        raise BootstrapRegistryError("active bootstrap cannot have a revocation time")
    if status == "revoked":
        revoked = uint(revoked_at, "node revoked_at_unix_ms")
        if not valid_from <= revoked < expires:
            raise BootstrapRegistryError("bootstrap revocation time is outside its valid interval")
    elif status != "active":
        raise BootstrapRegistryError("bootstrap node status must be active or revoked")
    return value


def registry_identity(body: dict[str, Any]) -> str:
    payload = dict(body)
    payload.pop("registry_id", None)
    return sha256(REGISTRY_ID_DOMAIN, canonical_json(payload))


def make_node(
    node_id: str,
    addresses: list[str],
    valid_from_unix_ms: int,
    expires_unix_ms: int,
) -> dict[str, Any]:
    value = {
        "node_id": validate_peer_id(node_id),
        "addresses": sorted(set(addresses)),
        "valid_from_unix_ms": valid_from_unix_ms,
        "expires_unix_ms": expires_unix_ms,
        "status": "active",
        "revoked_at_unix_ms": None,
    }
    return validate_node(value, valid_from_unix_ms, expires_unix_ms)


def sign_registry(
    *,
    chain_id: str,
    genesis_hash: str,
    sequence: int,
    previous_registry_id: str | None,
    valid_from_unix_ms: int,
    expires_unix_ms: int,
    nodes: list[dict[str, Any]],
    private_seed: bytes,
) -> dict[str, Any]:
    hex32(chain_id, "chain_id")
    hex32(genesis_hash, "genesis_hash")
    sequence = uint(sequence, "sequence", minimum=1)
    valid_from = uint(valid_from_unix_ms, "valid_from_unix_ms")
    expires = uint(expires_unix_ms, "expires_unix_ms", minimum=1)
    if valid_from >= expires:
        raise BootstrapRegistryError("bootstrap registry validity interval is empty")
    if sequence == 1 and previous_registry_id is not None:
        raise BootstrapRegistryError("sequence one cannot name a previous registry")
    if sequence > 1:
        hex32(previous_registry_id, "previous_registry_id")
    if len(private_seed) != 32 or private_seed == bytes(32):
        raise BootstrapRegistryError("bootstrap private key must contain 32 nonzero bytes")
    if not 2 <= len(nodes) <= 32:
        raise BootstrapRegistryError("bootstrap registry must contain two to thirty-two nodes")
    if any(not isinstance(node, dict) for node in nodes):
        raise BootstrapRegistryError("bootstrap node must be an object")
    for node in nodes:
        validate_node(node, valid_from, expires)
    ordered_nodes = sorted(nodes, key=lambda node: node["node_id"])
    if len({node["node_id"] for node in ordered_nodes}) != len(ordered_nodes):
        raise BootstrapRegistryError("bootstrap node ids must be unique")
    if sum(node["status"] == "active" for node in ordered_nodes) < 2:
        raise BootstrapRegistryError("bootstrap registry must retain at least two active nodes")
    body: dict[str, Any] = {
        "registry_id": "",
        "chain_id": chain_id,
        "genesis_hash": genesis_hash,
        "sequence": sequence,
        "previous_registry_id": previous_registry_id,
        "valid_from_unix_ms": valid_from,
        "expires_unix_ms": expires,
        "nodes": ordered_nodes,
    }
    body["registry_id"] = registry_identity(body)
    private = Ed25519PrivateKey.from_private_bytes(private_seed)
    public = public_from_seed(private_seed)
    signature = private.sign(SIGNATURE_DOMAIN + canonical_json(body))
    return {
        "schema": SCHEMA,
        "body": body,
        "signature": {
            "algorithm": "ed25519",
            "key_id": sha256(public),
            "public_key": public.hex(),
            "signature": signature.hex(),
        },
    }


def verify_registry(
    envelope: Any,
    *,
    trusted_public_key: bytes,
    expected_chain_id: str,
    expected_genesis_hash: str,
    now_unix_ms: int | None,
) -> dict[str, Any]:
    hex32(expected_chain_id, "expected chain_id")
    hex32(expected_genesis_hash, "expected genesis_hash")
    if len(trusted_public_key) != 32:
        raise BootstrapRegistryError("trusted bootstrap key must contain 32 bytes")
    if not isinstance(envelope, dict) or set(envelope) != ROOT_FIELDS or envelope.get("schema") != SCHEMA:
        raise BootstrapRegistryError("bootstrap registry envelope is malformed")
    body = envelope["body"]
    if not isinstance(body, dict) or set(body) != BODY_FIELDS:
        raise BootstrapRegistryError("bootstrap registry body fields are malformed")
    if hex32(body["registry_id"], "registry_id") != registry_identity(body):
        raise BootstrapRegistryError("bootstrap registry_id does not match its canonical body")
    chain_id = hex32(body["chain_id"], "chain_id")
    genesis_hash = hex32(body["genesis_hash"], "genesis_hash")
    if chain_id != expected_chain_id:
        raise BootstrapRegistryError("bootstrap registry is bound to the wrong chain")
    if genesis_hash != expected_genesis_hash:
        raise BootstrapRegistryError("bootstrap registry is bound to the wrong genesis")
    sequence = uint(body["sequence"], "sequence", minimum=1)
    previous = body["previous_registry_id"]
    if sequence == 1 and previous is not None:
        raise BootstrapRegistryError("sequence one cannot name a previous registry")
    if sequence > 1:
        hex32(previous, "previous_registry_id")
    valid_from = uint(body["valid_from_unix_ms"], "valid_from_unix_ms")
    expires = uint(body["expires_unix_ms"], "expires_unix_ms", minimum=1)
    if valid_from >= expires:
        raise BootstrapRegistryError("bootstrap registry validity interval is empty")
    nodes = body["nodes"]
    if not isinstance(nodes, list) or not 2 <= len(nodes) <= 32:
        raise BootstrapRegistryError("bootstrap registry must contain two to thirty-two nodes")
    if any(not isinstance(node, dict) for node in nodes):
        raise BootstrapRegistryError("bootstrap node must be an object")
    node_ids = [node.get("node_id") for node in nodes]
    if (
        any(not isinstance(node_id, str) for node_id in node_ids)
        or node_ids != sorted(set(node_ids))
    ):
        raise BootstrapRegistryError("bootstrap nodes must be sorted and unique")
    for node in nodes:
        validate_node(node, valid_from, expires)
    if sum(node["status"] == "active" for node in nodes) < 2:
        raise BootstrapRegistryError("bootstrap registry must retain at least two active nodes")
    signature = envelope["signature"]
    if not isinstance(signature, dict) or set(signature) != SIGNATURE_FIELDS or signature.get("algorithm") != "ed25519":
        raise BootstrapRegistryError("bootstrap signature envelope is malformed")
    public_hex = hex32(signature["public_key"], "public_key")
    public = bytes.fromhex(public_hex)
    if public != trusted_public_key:
        raise BootstrapRegistryError("bootstrap registry signer is not the pinned trusted key")
    if hex32(signature["key_id"], "key_id") != sha256(public):
        raise BootstrapRegistryError("bootstrap registry signer key_id is invalid")
    signature_hex = signature["signature"]
    if not isinstance(signature_hex, str) or not HEX128.fullmatch(signature_hex):
        raise BootstrapRegistryError("bootstrap signature must be 64-byte lowercase hex")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            bytes.fromhex(signature_hex),
            SIGNATURE_DOMAIN + canonical_json(body),
        )
    except (InvalidSignature, ValueError) as error:
        raise BootstrapRegistryError("bootstrap registry signature verification failed") from error
    if now_unix_ms is not None:
        now = uint(now_unix_ms, "now_unix_ms")
        if now < valid_from:
            raise BootstrapRegistryError("bootstrap registry is not valid yet")
        if now >= expires:
            raise BootstrapRegistryError("bootstrap registry has expired")
        active = [
            node
            for node in nodes
            if node["status"] == "active"
            and node["valid_from_unix_ms"] <= now < node["expires_unix_ms"]
        ]
        if len(active) < 2:
            raise BootstrapRegistryError("fewer than two bootstrap nodes are active at the current time")
    return envelope


def verify_transition(previous: dict[str, Any], successor: dict[str, Any]) -> None:
    old = previous["body"]
    new = successor["body"]
    if old["chain_id"] != new["chain_id"] or old["genesis_hash"] != new["genesis_hash"]:
        raise BootstrapRegistryError("bootstrap rotation changes protocol identity")
    if new["sequence"] == old["sequence"]:
        if new["registry_id"] == old["registry_id"]:
            return
        raise BootstrapRegistryError("conflicting bootstrap registries share one sequence")
    if new["sequence"] != old["sequence"] + 1 or new["previous_registry_id"] != old["registry_id"]:
        raise BootstrapRegistryError("bootstrap rotation is not the direct signed successor")
    old_nodes = {node["node_id"]: node for node in old["nodes"]}
    new_nodes = {node["node_id"]: node for node in new["nodes"]}
    for node_id, old_node in old_nodes.items():
        if node_id not in new_nodes:
            raise BootstrapRegistryError(f"bootstrap rotation silently removes node {node_id}; explicit revocation is required")
        if old_node["status"] == "revoked" and new_nodes[node_id] != old_node:
            raise BootstrapRegistryError(f"bootstrap rotation rewrites or reactivates revoked node {node_id}")


def read_registry_envelope(path: Path) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise BootstrapRegistryError(f"cannot read bootstrap registry: {error}") from error
    if not 1 <= len(raw) <= MAX_REGISTRY_BYTES:
        raise BootstrapRegistryError("bootstrap registry file size is outside bounds")
    try:
        return json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BootstrapRegistryError("bootstrap registry is not valid UTF-8 JSON") from error


def load_registry(
    path: Path,
    *,
    trusted_public_key: bytes,
    expected_chain_id: str,
    expected_genesis_hash: str,
    now_unix_ms: int | None,
) -> dict[str, Any]:
    envelope = read_registry_envelope(path)
    return verify_registry(
        envelope,
        trusted_public_key=trusted_public_key,
        expected_chain_id=expected_chain_id,
        expected_genesis_hash=expected_genesis_hash,
        now_unix_ms=now_unix_ms,
    )


def parse_node_argument(value: str) -> tuple[str, list[str]]:
    node_id, separator, encoded_addresses = value.partition("=")
    if not separator or not encoded_addresses:
        raise BootstrapRegistryError("--node must be NODE_ID=ADDR[,ADDR]")
    validate_peer_id(node_id)
    addresses = encoded_addresses.split(",")
    if len(addresses) != len(set(addresses)):
        raise BootstrapRegistryError("--node addresses must be unique")
    for address in addresses:
        validate_address(address, node_id)
    return node_id, sorted(addresses)


def nodes_from_arguments(values: list[str], valid_from: int, expires: int) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for value in values:
        node_id, addresses = parse_node_argument(value)
        if node_id in seen:
            raise BootstrapRegistryError("--node repeats one node_id")
        seen.add(node_id)
        nodes.append(make_node(node_id, addresses, valid_from, expires))
    return nodes


def rotate_registry(
    previous: dict[str, Any],
    *,
    active_nodes: list[dict[str, Any]],
    revoked_node_ids: set[str],
    revoked_at_unix_ms: int,
    private_seed: bytes,
) -> dict[str, Any]:
    old = previous["body"]
    active = {node["node_id"]: node for node in active_nodes}
    if active.keys() & revoked_node_ids:
        raise BootstrapRegistryError("one bootstrap cannot be active and revoked in the same rotation")
    old_nodes = {node["node_id"]: node for node in old["nodes"]}
    result: list[dict[str, Any]] = []
    for node_id, old_node in old_nodes.items():
        if old_node["status"] == "revoked":
            if node_id in active or node_id in revoked_node_ids:
                raise BootstrapRegistryError("a revoked bootstrap cannot be changed or reactivated")
            result.append(old_node)
        elif node_id in active:
            replacement = dict(active.pop(node_id))
            replacement["valid_from_unix_ms"] = old_node["valid_from_unix_ms"]
            replacement["expires_unix_ms"] = old_node["expires_unix_ms"]
            result.append(replacement)
        elif node_id in revoked_node_ids:
            revoked = dict(old_node)
            revoked["status"] = "revoked"
            revoked["revoked_at_unix_ms"] = revoked_at_unix_ms
            result.append(revoked)
        else:
            raise BootstrapRegistryError(f"rotation must retain or explicitly revoke bootstrap {node_id}")
    result.extend(active.values())
    successor = sign_registry(
        chain_id=old["chain_id"],
        genesis_hash=old["genesis_hash"],
        sequence=old["sequence"] + 1,
        previous_registry_id=old["registry_id"],
        valid_from_unix_ms=old["valid_from_unix_ms"],
        expires_unix_ms=old["expires_unix_ms"],
        nodes=result,
        private_seed=private_seed,
    )
    verify_transition(previous, successor)
    return successor


def write_new(path: Path, value: bytes, label: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
    except FileExistsError as error:
        raise BootstrapRegistryError(f"{label} already exists: {path}") from error
    except OSError as error:
        raise BootstrapRegistryError(f"cannot write {label}: {error}") from error


def summary(envelope: dict[str, Any], now_unix_ms: int | None) -> dict[str, Any]:
    body = envelope["body"]
    nodes = body["nodes"]
    return {
        "schema": SCHEMA,
        "registry_id": body["registry_id"],
        "sequence": body["sequence"],
        "previous_registry_id": body["previous_registry_id"],
        "chain_id": body["chain_id"],
        "genesis_hash": body["genesis_hash"],
        "valid_from_unix_ms": body["valid_from_unix_ms"],
        "expires_unix_ms": body["expires_unix_ms"],
        "signer_key_id": envelope["signature"]["key_id"],
        "active_node_ids": [
            node["node_id"]
            for node in nodes
            if node["status"] == "active"
            and (now_unix_ms is None or node["valid_from_unix_ms"] <= now_unix_ms < node["expires_unix_ms"])
        ],
        "revoked_node_ids": [node["node_id"] for node in nodes if node["status"] == "revoked"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("keygen", help="generate an offline registry signing key")
    keygen.add_argument("--private-key", type=Path, required=True)
    keygen.add_argument("--public-key", type=Path, required=True)

    freeze = commands.add_parser("freeze", help="freeze the first signed bootstrap snapshot")
    freeze.add_argument("--chain-id", required=True)
    freeze.add_argument("--genesis-hash", required=True)
    freeze.add_argument("--private-key", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    freeze.add_argument("--valid-from-unix-ms", type=int, required=True)
    freeze.add_argument("--expires-unix-ms", type=int, required=True)
    freeze.add_argument("--node", action="append", default=[], required=True)

    rotate = commands.add_parser("rotate", help="publish a direct address rotation/revocation successor")
    rotate.add_argument("--previous", type=Path, required=True)
    rotate.add_argument("--private-key", type=Path, required=True)
    rotate.add_argument("--output", type=Path, required=True)
    rotate.add_argument("--now-unix-ms", type=int, required=True)
    rotate.add_argument("--node", action="append", default=[])
    rotate.add_argument("--revoke", action="append", default=[])

    verify = commands.add_parser("verify", help="verify identity, signature, lifetime, and optional predecessor")
    verify.add_argument("--registry", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--chain-id", required=True)
    verify.add_argument("--genesis-hash", required=True)
    verify.add_argument("--now-unix-ms", type=int, required=True)
    verify.add_argument("--previous", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "keygen":
            seed = os.urandom(32)
            public = public_from_seed(seed)
            write_new(args.private_key, seed, "bootstrap private key")
            try:
                os.chmod(args.private_key, 0o600)
            except OSError:
                pass
            write_new(args.public_key, public.hex().encode("ascii") + b"\n", "bootstrap public key")
            result = {"public_key": public.hex(), "key_id": sha256(public)}
        elif args.command == "freeze":
            seed = read_private_seed(args.private_key)
            nodes = nodes_from_arguments(args.node, args.valid_from_unix_ms, args.expires_unix_ms)
            envelope = sign_registry(
                chain_id=args.chain_id,
                genesis_hash=args.genesis_hash,
                sequence=1,
                previous_registry_id=None,
                valid_from_unix_ms=args.valid_from_unix_ms,
                expires_unix_ms=args.expires_unix_ms,
                nodes=nodes,
                private_seed=seed,
            )
            write_new(args.output, canonical_file(envelope), "bootstrap registry")
            result = summary(envelope, args.valid_from_unix_ms)
        elif args.command == "rotate":
            seed = read_private_seed(args.private_key)
            public = public_from_seed(seed)
            previous_envelope = read_registry_envelope(args.previous)
            previous_body = (
                previous_envelope.get("body")
                if isinstance(previous_envelope, dict)
                else None
            )
            if not isinstance(previous_body, dict):
                raise BootstrapRegistryError("previous bootstrap registry body is malformed")
            previous = verify_registry(
                previous_envelope,
                trusted_public_key=public,
                expected_chain_id=hex32(previous_body.get("chain_id"), "chain_id"),
                expected_genesis_hash=hex32(
                    previous_body.get("genesis_hash"), "genesis_hash"
                ),
                now_unix_ms=None,
            )
            old = previous["body"]
            active_nodes = nodes_from_arguments(args.node, old["valid_from_unix_ms"], old["expires_unix_ms"])
            revoked = {validate_peer_id(node_id) for node_id in args.revoke}
            envelope = rotate_registry(
                previous,
                active_nodes=active_nodes,
                revoked_node_ids=revoked,
                revoked_at_unix_ms=args.now_unix_ms,
                private_seed=seed,
            )
            verify_registry(
                envelope,
                trusted_public_key=public,
                expected_chain_id=old["chain_id"],
                expected_genesis_hash=old["genesis_hash"],
                now_unix_ms=args.now_unix_ms,
            )
            write_new(args.output, canonical_file(envelope), "bootstrap registry")
            result = summary(envelope, args.now_unix_ms)
        else:
            public = read_public_key(args.public_key)
            envelope = load_registry(
                args.registry,
                trusted_public_key=public,
                expected_chain_id=args.chain_id,
                expected_genesis_hash=args.genesis_hash,
                now_unix_ms=args.now_unix_ms,
            )
            if args.previous:
                predecessor = load_registry(
                    args.previous,
                    trusted_public_key=public,
                    expected_chain_id=args.chain_id,
                    expected_genesis_hash=args.genesis_hash,
                    now_unix_ms=None,
                )
                verify_transition(predecessor, envelope)
            result = summary(envelope, args.now_unix_ms)
    except (BootstrapRegistryError, OSError, json.JSONDecodeError, KeyError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
