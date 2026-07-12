#!/usr/bin/env python3
"""Build a role-specific double-click MindChain LAN invitation bundle."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from invitation_leases import issue_lease

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=("windows", "macos"), required=True)
    parser.add_argument("--noosd", required=True)
    parser.add_argument("--noos-cli")
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--validator-host", required=True)
    parser.add_argument("--witness-index", type=int, choices=(1, 2, 3), required=True)
    parser.add_argument("--local-p2p-port", type=int, default=19702)
    parser.add_argument("--compute-market-url", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--lease-database")
    parser.add_argument("--lease-seed-file")
    parser.add_argument("--lease-ttl-seconds", type=int, default=86400)
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    profile_path = Path(args.profile).resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    if manifest.get("schema") != "noos/lan-testnet/v1":
        raise SystemExit("unsupported LAN manifest")
    params = Path(manifest["params"])
    if not params.is_absolute():
        params = ROOT / params
    if sha256(params) != manifest["params_sha256"]:
        raise SystemExit("LAN parameter checksum mismatch")
    node = Path(args.noosd).resolve()
    if not node.is_file():
        raise SystemExit(f"node binary not found: {node}")
    cli = Path(args.noos_cli).resolve() if args.noos_cli else None
    if cli is not None and not cli.is_file():
        raise SystemExit(f"CLI binary not found: {cli}")
    if bool(args.lease_database) != bool(args.lease_seed_file):
        raise SystemExit("--lease-database and --lease-seed-file must be supplied together")
    if args.lease_database and cli is None:
        raise SystemExit("--noos-cli is required for a signed invitation bundle")

    invite = {
        "schema": "noos/one-click-invite/v1",
        "chain_id": profile["chain_id"],
        "genesis_hash": profile["genesis_hash"],
        "genesis_time_ms": manifest["genesis_time_ms"],
        "params_sha256": manifest["params_sha256"],
        "validator_host": args.validator_host,
        "validator_p2p_port": manifest["ports"]["p2p"],
        "local_p2p_port": args.local_p2p_port,
        "witness_index": args.witness_index,
        "wallet_accounts": manifest["wallet_accounts"],
        "public_api_url": profile["api_base_url"],
        "compute_market_url": args.compute_market_url,
        "test_network": True,
    }
    if args.lease_database:
        invite = issue_lease(
            Path(args.lease_database).resolve(),
            Path(args.lease_seed_file).resolve(),
            invite,
            f"witness-{args.witness_index}",
            args.platform,
            args.lease_ttl_seconds,
        )

    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="mindchain-join-") as temp_name:
        temp = Path(temp_name)
        shutil.copy2(params, temp / "devnet-parameters.toml")
        (temp / "invite.json").write_text(
            json.dumps(invite, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if invite.get("signing_key"):
            (temp / "trusted-invitation-key.txt").write_text(
                str(invite["signing_key"]) + "\n", encoding="ascii", newline="\n"
            )
        if args.platform == "windows":
            shutil.copy2(node, temp / "noosd.exe")
            if cli is not None:
                shutil.copy2(cli, temp / "noos-cli.exe")
            shutil.copy2(ROOT / "tools/operator_onboard.ps1", temp / "operator_onboard.ps1")
            (temp / "JOIN MINDCHAIN.cmd").write_text(
                '@echo off\r\npowershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0operator_onboard.ps1" -BundleRoot "%~dp0"\r\n',
                encoding="ascii",
            )
        else:
            shutil.copy2(node, temp / "noosd")
            if cli is not None:
                shutil.copy2(cli, temp / "noos-cli")
            shutil.copy2(ROOT / "tools/operator_onboard.command", temp / "JOIN MINDCHAIN.command")
            shutil.copy2(ROOT / "tools/node_status_dashboard.py", temp / "node_status_dashboard.py")
        members = sorted(path for path in temp.iterdir() if path.is_file())
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in members:
                info = zipfile.ZipInfo(path.name)
                info.compress_type = zipfile.ZIP_DEFLATED
                executable = path.suffix in {".command", ".cmd", ".ps1"} or path.name in {"noosd", "noos-cli"}
                info.external_attr = (0o755 if executable else 0o644) << 16
                archive.writestr(info, path.read_bytes())
    evidence = {
        "schema": "noos/one-click-bundle-evidence/v1",
        "platform": args.platform,
        "bundle": output.name,
        "sha256": sha256(output),
        "node_sha256": sha256(node),
        "cli_sha256": sha256(cli) if cli is not None else None,
        "chain_id": invite["chain_id"],
        "genesis_hash": invite["genesis_hash"],
        "witness_index": args.witness_index,
        "lease_id": invite.get("lease_id"),
        "lease_expires_unix_ms": invite.get("expires_unix_ms"),
        "lease_signing_key": invite.get("signing_key"),
    }
    output.with_suffix(output.suffix + ".json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(evidence, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
