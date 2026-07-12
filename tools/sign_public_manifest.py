#!/usr/bin/env python3
"""Sign an exact MindChain public-network manifest with an offline Ed25519 seed file."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SCHEMA = "noos/public-network-manifest/v1"
DOMAIN = b"NOOS/PUBLIC/NETWORK/MANIFEST/V1\0"


def canonical_payload(manifest: dict) -> bytes:
    payload = dict(manifest)
    payload.pop("signature", None)
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def read_seed(path: Path) -> bytes:
    text = path.read_text(encoding="ascii").strip()
    try:
        seed = bytes.fromhex(text)
    except ValueError as error:
        raise SystemExit("manifest signing seed file must contain lowercase hex") from error
    if len(seed) != 32 or text != seed.hex():
        raise SystemExit("manifest signing seed file must contain exactly 32 lowercase bytes")
    return seed


def sign_manifest(source: Path, seed_path: Path, output: Path) -> dict:
    manifest = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise SystemExit("unsupported public manifest schema")
    private = Ed25519PrivateKey.from_private_bytes(read_seed(seed_path))
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    manifest["signing_key"] = public.hex()
    manifest["signature"] = private.sign(DOMAIN + canonical_payload(manifest)).hex()
    encoded = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(encoded, encoding="utf-8", newline="\n")
    os.replace(temporary, output)
    return {
        "schema": "noos/public-network-manifest-signing-evidence/v1",
        "manifest": output.name,
        "sha256": hashlib.sha256(output.read_bytes()).hexdigest(),
        "signing_key": public.hex(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True)
    parser.add_argument("--seed-file", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    evidence = sign_manifest(Path(args.input), Path(args.seed_file), Path(args.output))
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
