#!/usr/bin/env python3
"""Aggregate artifact, policy, runtime, and upgrade checks into one release verdict."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "operations"))
import validator_upgrade


class ReadinessError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    resolved = root.resolve()
    if candidate != resolved and resolved not in candidate.parents:
        raise ReadinessError(f"path escapes bundle: {relative}")
    return candidate


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReadinessError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise ReadinessError(f"{path} must contain a JSON object")
    return value


def verify_candidate_bundle(bundle_dir: Path, production: bool) -> dict[str, Any]:
    manifest_path = bundle_dir / "bundle-manifest.json"
    manifest = read_json(manifest_path)
    if manifest.get("schema") != "noos/repro-candidate-bundle/v1":
        raise ReadinessError("unsupported candidate bundle schema")
    status = manifest.get("candidate_status")
    if status not in {"SMOKE_ONLY", "CANDIDATE_ONLY"}:
        raise ReadinessError("candidate status is invalid")
    if production and status != "CANDIDATE_ONLY":
        raise ReadinessError("smoke-only bundle cannot enter production readiness")
    if manifest.get("promotion_effect") != "NONE" or manifest.get("independent_builder_evidence") is not False:
        raise ReadinessError("candidate boundary fields are invalid")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise ReadinessError("candidate manifest has no files")
    actual: dict[str, str] = {}
    for relative, expected in sorted(files.items()):
        if not isinstance(relative, str) or Path(relative).is_absolute():
            raise ReadinessError("candidate file paths must be relative")
        validator_upgrade.validate_hex32(expected, f"digest for {relative}")
        path = safe_path(bundle_dir, relative)
        if not path.is_file():
            raise ReadinessError(f"candidate file is missing: {relative}")
        digest = sha256_file(path)
        if digest != expected:
            raise ReadinessError(f"candidate file hash mismatch: {relative}")
        actual[relative] = digest
    sums_path = bundle_dir / "SHA256SUMS"
    if sha256_file(sums_path) != manifest.get("checksums_sha256"):
        raise ReadinessError("SHA256SUMS digest differs from candidate manifest")
    sums: dict[str, str] = {}
    for line in sums_path.read_text("ascii").splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2:
            raise ReadinessError("malformed SHA256SUMS line")
        validator_upgrade.validate_hex32(parts[0], "SHA256SUMS digest")
        if parts[1] in sums:
            raise ReadinessError(f"duplicate SHA256SUMS path: {parts[1]}")
        sums[parts[1]] = parts[0]
    if sums != actual:
        raise ReadinessError("SHA256SUMS does not exactly cover candidate files")
    required = {"build-details.json", "sbom.cdx.json", "provenance.intoto.jsonl"}
    if not required.issubset(actual):
        raise ReadinessError("candidate lacks build details, SBOM, or provenance")
    return manifest


def verify_promotion_ledger(path: Path) -> dict[str, Any]:
    ledger = read_json(path)
    gates = ledger.get("gates")
    if not isinstance(gates, list) or not gates:
        raise ReadinessError("promotion ledger contains no gates")
    blocked: list[str] = []
    for gate in gates:
        if not isinstance(gate, dict):
            raise ReadinessError("promotion gate row is malformed")
        gate_name = str(gate.get("gate", "UNKNOWN"))
        if gate.get("state") != "PASS":
            blocked.append(f"{gate_name}:{gate.get('state', 'MISSING')}")
        requirements = gate.get("requirements", [])
        if not isinstance(requirements, list):
            raise ReadinessError(f"{gate_name} requirements are malformed")
        for requirement in requirements:
            if requirement.get("status") != "SATISFIED" or requirement.get("verdict") != "PASS":
                blocked.append(str(requirement.get("requirement_id", f"{gate_name}:UNKNOWN")))
    return {"pass": not blocked, "blocked": sorted(set(blocked)), "gate_count": len(gates)}


def get_json(url: str, token: str | None = None, timeout: float = 4.0) -> dict[str, Any]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read())
    except (OSError, URLError, json.JSONDecodeError) as error:
        raise ReadinessError(f"runtime endpoint unavailable: {url}: {error}") from error
    if not isinstance(value, dict):
        raise ReadinessError(f"runtime endpoint returned non-object: {url}")
    return value


def checkpoint_height(value: Any) -> int:
    if not isinstance(value, dict):
        raise ReadinessError("runtime head is malformed")
    try:
        return int(value["height"])
    except (KeyError, TypeError, ValueError) as error:
        raise ReadinessError("runtime head lacks height") from error


def verify_runtime(node_rpc: str, node_token: str, indexer_url: str, chain_id: str, genesis_hash: str, max_indexer_lag: int) -> dict[str, Any]:
    node = get_json(f"http://{node_rpc}/status", node_token)
    indexer = get_json(indexer_url.rstrip("/") + "/api/status")
    for name, value in (("node", node), ("indexer", indexer)):
        if value.get("chain_id") != chain_id or value.get("genesis_hash") != genesis_hash:
            raise ReadinessError(f"{name} runtime identity differs from release")
    if node.get("observer") is True:
        raise ReadinessError("release validator is running in observer mode")
    if indexer.get("ready") is not True:
        raise ReadinessError(f"indexer is not ready: {indexer.get('readiness')}")
    node_height = checkpoint_height(node.get("unsafe_head"))
    indexer_height = checkpoint_height(indexer.get("unsafe_head"))
    lag = max(0, node_height - indexer_height)
    if lag > max_indexer_lag:
        raise ReadinessError(f"indexer lag {lag} exceeds limit {max_indexer_lag}")
    return {"node_height": node_height, "indexer_height": indexer_height, "indexer_lag": lag}


def verify_upgrade(manifest_path: Path, keyring_path: Path, candidate: dict[str, Any], production: bool) -> dict[str, Any]:
    manifest = validator_upgrade.read_json(manifest_path)
    validator_upgrade.verify_manifest(manifest, validator_upgrade.read_json(keyring_path))
    candidate_hashes = set(candidate["files"].values())
    artifact_hashes = set(manifest["artifacts"].values())
    if not artifact_hashes.issubset(candidate_hashes):
        raise ReadinessError("upgrade artifacts are not byte-identical members of the candidate bundle")
    if production and manifest["chain_id"] == "00" * 32:
        raise ReadinessError("production upgrade cannot target the zero chain identity")
    return {
        "release_id": manifest["release_id"],
        "activation_height": manifest["activation_height"],
        "chain_id": manifest["chain_id"],
        "genesis_hash": manifest["genesis_hash"],
        "artifact_count": len(manifest["artifacts"]),
        "throughput": manifest["throughput"],
    }


def git_source_state() -> dict[str, Any]:
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, timeout=10)
    tree = subprocess.run(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, capture_output=True, text=True, timeout=10)
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, capture_output=True, text=True, timeout=10)
    if any(command.returncode != 0 for command in (revision, tree, dirty)):
        raise ReadinessError("cannot resolve repository source state")
    return {
        "revision": revision.stdout.strip(),
        "tree": tree.stdout.strip(),
        "clean": not dirty.stdout.strip(),
    }


def verify_full_release(args: argparse.Namespace) -> str:
    required = {
        "release_manifest": args.release_manifest,
        "release_keyring": args.release_keyring,
        "final_freeze": args.final_freeze,
        "final_freeze_signatures": args.final_freeze_signatures,
        "repro_assurance": args.repro_assurance,
    }
    missing = [name for name, value in required.items() if value is None]
    if missing:
        raise ReadinessError("production readiness requires " + ", ".join(missing))
    command = [
        sys.executable,
        str(ROOT / "tools" / "gates" / "verify_release.py"),
        str(args.release_manifest),
        "--keyring", str(args.release_keyring),
        "--final-freeze", str(args.final_freeze),
        "--final-freeze-signatures", str(args.final_freeze_signatures),
        "--repro-assurance", str(args.repro_assurance),
    ]
    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=120)
    output = (completed.stdout + completed.stderr).strip()
    if completed.returncode != 0 or "RESULT verify_release=PASS" not in output:
        raise ReadinessError(f"full release verification did not pass: {output}")
    return output


def assess(args: argparse.Namespace) -> tuple[int, dict[str, Any]]:
    production = args.mode == "production"
    checks: dict[str, Any] = {}
    failures: list[str] = []
    blockers: list[str] = []
    candidate: dict[str, Any] | None = None
    upgrade: dict[str, Any] | None = None

    try:
        candidate = verify_candidate_bundle(args.bundle_dir, production)
        checks["candidate_bundle"] = {"status": "PASS", "candidate_status": candidate["candidate_status"], "file_count": len(candidate["files"])}
    except (ReadinessError, validator_upgrade.UpgradeError, OSError) as error:
        failures.append(str(error))
        checks["candidate_bundle"] = {"status": "FAIL", "reason": str(error)}

    try:
        source = git_source_state()
        source_binding = candidate.get("source", {}) if candidate else {}
        if candidate and (source_binding.get("revision") != source["revision"] or source_binding.get("tree") != source["tree"]):
            raise ReadinessError("candidate source revision/tree differs from checkout")
        if production and not source["clean"]:
            raise ReadinessError("production readiness requires a clean checkout")
        checks["source"] = {"status": "PASS", **source}
    except ReadinessError as error:
        failures.append(str(error))
        checks["source"] = {"status": "FAIL", "reason": str(error)}

    try:
        promotion = verify_promotion_ledger(args.promotion_ledger)
        checks["promotion"] = {"status": "PASS" if promotion["pass"] else "BLOCKED", **promotion}
        if production and not promotion["pass"]:
            blockers.extend(promotion["blocked"])
    except ReadinessError as error:
        failures.append(str(error))
        checks["promotion"] = {"status": "FAIL", "reason": str(error)}

    if args.upgrade_manifest and args.upgrade_keyring and candidate:
        try:
            upgrade = verify_upgrade(args.upgrade_manifest, args.upgrade_keyring, candidate, production)
            checks["upgrade"] = {"status": "PASS", **upgrade}
        except (ReadinessError, validator_upgrade.UpgradeError) as error:
            failures.append(str(error))
            checks["upgrade"] = {"status": "FAIL", "reason": str(error)}
    elif production:
        failures.append("production readiness requires signed upgrade manifest and keyring")
        checks["upgrade"] = {"status": "FAIL", "reason": failures[-1]}
    else:
        checks["upgrade"] = {"status": "NOT_REQUESTED"}

    if args.node_rpc and args.node_token and args.indexer_url and upgrade:
        try:
            runtime = verify_runtime(args.node_rpc, args.node_token, args.indexer_url, upgrade["chain_id"], upgrade["genesis_hash"], args.max_indexer_lag)
            if upgrade["activation_height"] - runtime["node_height"] < args.minimum_activation_lead:
                raise ReadinessError("signed activation height lacks the required operational lead")
            checks["runtime"] = {"status": "PASS", **runtime}
        except ReadinessError as error:
            failures.append(str(error))
            checks["runtime"] = {"status": "FAIL", "reason": str(error)}
    elif production:
        failures.append("production readiness requires node, token, and indexer endpoints")
        checks["runtime"] = {"status": "FAIL", "reason": failures[-1]}
    else:
        checks["runtime"] = {"status": "NOT_REQUESTED"}

    if production:
        try:
            checks["release_manifest"] = {"status": "PASS", "output": verify_full_release(args)}
        except ReadinessError as error:
            failures.append(str(error))
            checks["release_manifest"] = {"status": "FAIL", "reason": str(error)}
    else:
        checks["release_manifest"] = {"status": "NOT_REQUIRED"}

    if failures:
        verdict, code = "FAIL", 1
    elif blockers:
        verdict, code = "BLOCKED", 2
    else:
        verdict, code = ("PRODUCTION_READY" if production else "CANDIDATE_READY"), 0
    report = {
        "schema": "noos/release-readiness-report/v1",
        "mode": args.mode,
        "verdict": verdict,
        "failures": failures,
        "blockers": sorted(set(blockers)),
        "checks": checks,
    }
    return code, report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fail-closed NOOSPHERE release readiness aggregator")
    parser.add_argument("--mode", choices=("candidate", "production"), default="candidate")
    parser.add_argument("--bundle-dir", type=Path, required=True)
    parser.add_argument("--promotion-ledger", type=Path, default=ROOT / "protocol" / "release" / "promotion-blockers.json")
    parser.add_argument("--upgrade-manifest", type=Path)
    parser.add_argument("--upgrade-keyring", type=Path)
    parser.add_argument("--node-rpc")
    parser.add_argument("--node-token")
    parser.add_argument("--indexer-url")
    parser.add_argument("--max-indexer-lag", type=int, default=2)
    parser.add_argument("--minimum-activation-lead", type=int, default=64)
    parser.add_argument("--release-manifest", type=Path)
    parser.add_argument("--release-keyring", type=Path)
    parser.add_argument("--final-freeze", type=Path)
    parser.add_argument("--final-freeze-signatures", type=Path)
    parser.add_argument("--repro-assurance", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.max_indexer_lag < 0 or args.minimum_activation_lead < 1:
        print("RESULT release_readiness=FAIL reason=invalid lag or activation lead", file=sys.stderr)
        return 1
    code, report = assess(args)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(canonical_json(report))
    print(f"RESULT release_readiness={report['verdict']} failures={len(report['failures'])} blockers={len(report['blockers'])} out={args.out}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
