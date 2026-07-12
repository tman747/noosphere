#!/usr/bin/env python3
"""Deterministic release builds and external reproducibility attestation checks.

Building on one machine, including multiple clean directories or CI matrix jobs
under one control plane, is smoke evidence only.  The qualifying verifier needs
detached Ed25519 signatures from two externally controlled builder identities;
it never edits the promotion ledger or changes a registry claim state.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "protocol/release/repro-policy-v1.toml"
POLICY_SIGNATURES = ROOT / "protocol/release/repro-policy-v1.signatures.json"
TOOLCHAINS = ROOT / "protocol/release/repro-toolchains-v1.json"
REQUIRED_TARGETS = {"windows-x86_64", "linux-x86_64", "linux-aarch64"}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TARGETS = {
    "windows-x86_64": {
        "os": "windows", "arch": "x86_64", "rust": "x86_64-pc-windows-msvc",
        "goos": "windows", "goarch": "amd64", "suffix": ".exe",
    },
    "linux-x86_64": {
        "os": "linux", "arch": "x86_64", "rust": "x86_64-unknown-linux-gnu",
        "goos": "linux", "goarch": "amd64", "suffix": "",
    },
    "linux-aarch64": {
        "os": "linux", "arch": "aarch64", "rust": "aarch64-unknown-linux-gnu",
        "goos": "linux", "goarch": "arm64", "suffix": "", "native": True,
    },
}


class AssuranceError(ValueError):
    """A stable, user-readable fail-closed assurance error."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_repository_output(path: Path) -> Path:
    resolved = path.resolve()
    root = ROOT.resolve()
    if resolved == root or root not in resolved.parents:
        raise AssuranceError(f"output must be a child of the repository: {path}")
    return resolved


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AssuranceError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AssuranceError(f"{path}: top level must be an object")
    return value


def command(args: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> str:
    completed = subprocess.run(args, cwd=cwd, env=env, check=True, text=True, capture_output=True)
    return completed.stdout.strip()


def git_value(*args: str) -> str:
    return command(["git", *args])


def source_identity(revision: str | None = None) -> dict[str, Any]:
    revision = revision or git_value("rev-parse", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise AssuranceError("source revision must be a full lowercase Git commit")
    try:
        tree = git_value("rev-parse", f"{revision}^{{tree}}")
        epoch = int(git_value("show", "-s", "--format=%ct", revision))
    except (subprocess.CalledProcessError, ValueError) as exc:
        raise AssuranceError(f"cannot resolve source revision {revision}") from exc
    return {"revision": revision, "tree": tree, "source_date_epoch": epoch}


def load_toolchains() -> dict[str, Any]:
    data = load_json(TOOLCHAINS)
    if data.get("schema") != "noos/repro-toolchains/v1":
        raise AssuranceError("wrong repro toolchain lock schema")
    if set(data.get("targets", {})) != REQUIRED_TARGETS:
        raise AssuranceError("toolchain lock does not cover the exact required target set")
    return data


def verify_policy_signatures() -> list[str]:
    """Verify the frozen policy. Missing signatures are a blocker, never evidence."""
    errors: list[str] = []
    raw = POLICY.read_bytes()
    policy = tomllib.loads(raw.decode("utf-8"))
    if policy.get("state") != "SIGNED":
        errors.append("policy state is not SIGNED")
    if policy.get("post_build_normalization") != "forbidden":
        errors.append("post-build normalization is not forbidden")
    if not POLICY_SIGNATURES.is_file():
        errors.append("detached policy signature record missing")
        return errors
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        records = load_json(POLICY_SIGNATURES)
        roles: set[str] = set()
        for record in records.get("signatures", []):
            key = Ed25519PublicKey.from_public_bytes(base64.b64decode(record["public_key_base64"], validate=True))
            key.verify(base64.b64decode(record["signature_base64"], validate=True), raw)
            roles.add(record["role"])
        for role in policy["signature_policy"]["required_roles"]:
            if role not in roles:
                errors.append(f"missing valid policy signature role {role}")
    except Exception as exc:  # cryptography exposes several backend exceptions
        errors.append(f"policy signature verification failed: {exc}")
    return errors


def _host() -> tuple[str, str]:
    host_os = "windows" if os.name == "nt" else "linux" if sys.platform.startswith("linux") else sys.platform
    machine = platform.machine().lower()
    host_arch = "aarch64" if machine in {"aarch64", "arm64"} else "x86_64" if machine in {"amd64", "x86_64"} else machine
    return host_os, host_arch


def _version_line(args: list[str]) -> str:
    return command(args).splitlines()[0]


def verify_installed_toolchains(lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    expected = lock["toolchains"]
    observed = {
        "rustc": _version_line(["rustc", "--version"]),
        "cargo": _version_line(["cargo", "--version"]),
        "go": _version_line(["go", "version"]),
    }
    for name in ("rustc", "cargo"):
        if observed[name] != expected[name]["version_output"]:
            errors.append(f"{name} mismatch: expected {expected[name]['version_output']!r}, got {observed[name]!r}")
    expected_go_prefix = f"go version go{expected['go']['version']} "
    if not observed["go"].startswith(expected_go_prefix):
        errors.append(f"go mismatch: expected {expected_go_prefix!r} with a host suffix, got {observed['go']!r}")
    return errors


def locked_toolchain_identities(lock: dict[str, Any]) -> dict[str, str]:
    return {
        "rustc": lock["toolchains"]["rustc"]["version_output"],
        "cargo": lock["toolchains"]["cargo"]["version_output"],
        "go": f"go{lock['toolchains']['go']['version']}",
    }


def deterministic_environment(root: Path, target_dir: Path, target: str, epoch: int) -> dict[str, str]:
    """Create a small deterministic environment; timestamp normalization is pre-build only."""
    keep = ("PATH", "SystemRoot", "COMSPEC", "PATHEXT", "TEMP", "TMP", "HOME", "USERPROFILE", "CARGO_HOME", "RUSTUP_HOME")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    cfg = TARGETS[target]
    env.update({
        "CARGO_HOME": env.get("CARGO_HOME", str(Path.home() / ".cargo")),
        "RUSTUP_HOME": env.get("RUSTUP_HOME", str(Path.home() / ".rustup")),
        "CARGO_TARGET_DIR": str(target_dir),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "SOURCE_DATE_EPOCH": str(epoch),
        "TZ": "UTC",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "ZERO_AR_DATE": "1",
        "GOPROXY": "off",
        "GOSUMDB": "off",
        "GOENV": "off",
        "GOOS": cfg["goos"],
        "GOARCH": cfg["goarch"],
        "CGO_ENABLED": "0",
        "GOFLAGS": "-mod=readonly -trimpath -buildvcs=false",
        "GOCACHE": str(target_dir / "go-build-cache"),
    })
    rustflags = [f"--remap-path-prefix={root}=/workspace/noosphere", "-C", "debuginfo=0"]
    if target == "windows-x86_64":
        windows = load_toolchains()["targets"][target]
        msvc_version = windows.get("msvc_tools_version")
        sdk_version = windows.get("windows_sdk_version")
        if not isinstance(msvc_version, str) or not isinstance(sdk_version, str):
            raise AssuranceError("Windows target lacks pinned MSVC/SDK versions")
        vs_root = Path("C:/Program Files (x86)/Microsoft Visual Studio/2022/BuildTools")
        msvc_root = vs_root / "VC" / "Tools" / "MSVC" / msvc_version
        sdk_root = Path("C:/Program Files (x86)/Windows Kits/10")
        msvc_lib = msvc_root / "lib" / "x64"
        sdk_lib = sdk_root / "Lib" / sdk_version
        library_paths = [msvc_lib, sdk_lib / "ucrt" / "x64", sdk_lib / "um" / "x64"]
        binary_paths = [msvc_root / "bin" / "Hostx64" / "x64", sdk_root / "bin" / sdk_version / "x64"]
        sdk_include = sdk_root / "Include" / sdk_version
        include_paths = [
            msvc_root / "include",
            sdk_include / "ucrt",
            sdk_include / "shared",
            sdk_include / "um",
            sdk_include / "winrt",
        ]
        missing = [
            str(path)
            for path in (*library_paths, *binary_paths, *include_paths)
            if not path.is_dir()
        ]
        if missing:
            raise AssuranceError(f"pinned Windows toolchain directories missing: {missing}")
        env["LIB"] = os.pathsep.join(str(path) for path in library_paths)
        env["INCLUDE"] = os.pathsep.join(str(path) for path in include_paths)
        env["PATH"] = os.pathsep.join([*(str(path) for path in binary_paths), env.get("PATH", "")])
        env["VCINSTALLDIR"] = str(vs_root / "VC") + os.sep
        env["VCToolsInstallDir"] = str(msvc_root) + os.sep
        env["VCToolsVersion"] = msvc_version
        env["WindowsSdkDir"] = str(sdk_root) + os.sep
        env["WindowsSDKVersion"] = sdk_version + os.sep
        rust_sysroot = Path(command(["rustc", "--print", "sysroot"]).strip())
        rust_lld = rust_sysroot / "lib" / "rustlib" / "x86_64-pc-windows-msvc" / "bin" / "rust-lld.exe"
        if not rust_lld.is_file():
            raise AssuranceError(f"pinned Rust linker missing: {rust_lld}")
        env["CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER"] = str(rust_lld)
        rustflags.extend(["-C", "link-arg=/Brepro", "-C", "link-arg=/PDBALTPATH:noos-transition.pdb"])
    # Unit-separator encoding preserves path arguments even when an external
    # builder checks the repository out below a directory containing spaces.
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(rustflags)
    return env


def build_target(target: str, out: Path, *, revision: str | None = None, smoke: bool = False) -> dict[str, Any]:
    if target not in TARGETS:
        raise AssuranceError(f"unsupported target {target!r}")
    cfg = TARGETS[target]
    host_os, host_arch = _host()
    if host_os != cfg["os"] or (cfg.get("native") and host_arch != cfg["arch"]):
        raise AssuranceError(f"{target} requires a native {cfg['os']}/{cfg['arch']} runner; observed {host_os}/{host_arch}")
    identity = source_identity(revision)
    locks = load_toolchains()
    toolchain_errors = verify_installed_toolchains(locks)
    policy_errors = verify_policy_signatures()
    if toolchain_errors or (policy_errors and not smoke):
        raise AssuranceError("; ".join(toolchain_errors + ([] if smoke else policy_errors)))

    out = safe_repository_output(out)
    out.mkdir(parents=True, exist_ok=True)
    target_dir = out / ".cargo-target"
    env = deterministic_environment(ROOT, target_dir, target, identity["source_date_epoch"])
    subprocess.run(
        ["cargo", "build", "--locked", "--offline", "--frozen", "--release", "--target", cfg["rust"],
         "-p", "noos-lumen", "--bin", "noos-transition"],
        cwd=ROOT, env=env, check=True,
    )
    subprocess.run(["go", "mod", "verify"], cwd=ROOT / "go", env=env, check=True)
    suffix = cfg["suffix"]
    rust_output = target_dir / cfg["rust"] / "release" / f"noos-transition{suffix}"
    artifacts = out / "artifacts"
    artifacts.mkdir(exist_ok=True)
    shutil.copyfile(rust_output, artifacts / f"noos-transition-rust{suffix}")
    for name, package in (("noos-transition-go", "./cmd/noos-transition"), ("noos-verify", "./cmd/noos-verify")):
        destination = artifacts / f"{name}{suffix}"
        destination.unlink(missing_ok=True)
        subprocess.run(["go", "build", "-o", str(destination), package], cwd=ROOT / "go", env=env, check=True)

    binary_hashes = {f"artifacts/{path.name}": sha256_file(path) for path in sorted(artifacts.iterdir()) if path.is_file()}
    result = {
        "schema": "noos/repro-build-details/v1",
        "evidence_class": "same-machine-smoke" if smoke else "candidate-build-not-independent-attestation",
        "target": target,
        "host": {"os": host_os, "architecture": host_arch},
        "source": identity,
        "toolchain_lock_sha256": sha256_file(TOOLCHAINS),
        "toolchains": locked_toolchain_identities(locks),
        "dependency_locks": {"Cargo.lock": sha256_file(ROOT / "Cargo.lock"), "go/go.sum": sha256_file(ROOT / "go/go.sum")},
        "deterministic_environment": locks["deterministic_environment"],
        "post_build_normalization": "forbidden-and-not-performed",
        "offline_build": True,
        "binary_hashes": binary_hashes,
        "policy_signature_errors": policy_errors,
        "toolchain_errors": toolchain_errors,
    }
    (out / "build-details.json").write_bytes(canonical_json(result))
    shutil.rmtree(target_dir)
    return result


def _trusted_builders(
    path: Path,
    allow_test_keys: bool,
    blockers: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    trust = load_json(path)
    if trust.get("schema") != "noos/trusted-repro-builders/v1":
        raise AssuranceError("wrong trusted builder schema")
    result: dict[str, dict[str, Any]] = {}
    for record in trust.get("builders", []):
        key_id = record.get("key_id")
        if not isinstance(key_id, str) or key_id in result:
            raise AssuranceError("trusted builder key_id missing or duplicated")
        if record.get("public_key_base64") == "EXTERNAL_INPUT_REQUIRED":
            if blockers is not None:
                blockers.append(f"trusted builder {key_id}: external public key is required")
            continue
        try:
            public = base64.b64decode(record["public_key_base64"], validate=True)
        except Exception as exc:
            raise AssuranceError(f"trusted builder {key_id}: invalid public key encoding") from exc
        if len(public) != 32 or sha256_bytes(public) != key_id:
            raise AssuranceError(f"trusted builder {key_id}: key_id must equal SHA-256 of the raw Ed25519 public key")
        if record.get("test_only") and not allow_test_keys:
            continue
        result[key_id] = record
    return result


def _required_binary_names(target: str) -> set[str]:
    suffix = ".exe" if target == "windows-x86_64" else ""
    return {f"artifacts/{name}{suffix}" for name in ("noos-transition-rust", "noos-transition-go", "noos-verify")}


def _validate_attestation(payload: dict[str, Any], trust: dict[str, Any], expected_source: dict[str, Any], lock: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if payload.get("schema") != "noos/repro-build-attestation/v1":
        errors.append("wrong attestation schema")
    builder = payload.get("builder", {})
    for field in ("operator", "control_plane_identity", "host_identity", "toolchain_installation"):
        if not isinstance(builder.get(field), str) or not builder[field]:
            errors.append(f"builder.{field} missing")
        elif builder[field] != trust.get(field):
            errors.append(f"builder.{field} does not match trust record")
    if trust.get("external_to_release_owner") is not True:
        errors.append("builder is not declared external to release owner")
    target = payload.get("build", {}).get("target")
    if target not in REQUIRED_TARGETS or target not in set(trust.get("authorized_targets", [])):
        errors.append("target is not authorized for builder")
    build = payload.get("build", {})
    if build.get("source_revision") != expected_source["revision"]:
        errors.append("source revision mismatch")
    if build.get("source_tree") != expected_source["tree"]:
        errors.append("source tree mismatch")
    if build.get("source_date_epoch") != expected_source["source_date_epoch"]:
        errors.append("normalized source timestamp mismatch")
    if build.get("toolchain_lock_sha256") != sha256_file(TOOLCHAINS):
        errors.append("toolchain lock mismatch")
    expected_tools = locked_toolchain_identities(lock)
    if build.get("toolchains") != expected_tools:
        errors.append("pinned toolchain set mismatch")
    if target == "linux-aarch64" and build.get("host_architecture") != "aarch64":
        errors.append("linux-aarch64 attestation is not from a native aarch64 host")
    hashes = payload.get("artifact_hashes")
    if not isinstance(hashes, dict) or not hashes:
        errors.append("artifact hash set missing")
    elif any(not isinstance(name, str) or not HEX64.fullmatch(str(digest)) for name, digest in hashes.items()):
        errors.append("artifact hash set malformed")
    elif set(hashes) != _required_binary_names(str(target)):
        errors.append("artifact hash set does not exactly cover required release binaries")
    return errors


def verify_attestation_set(
    attestations: Path,
    trusted_builders: Path,
    expected_revision: str,
    *,
    allow_test_keys: bool = False,
) -> dict[str, Any]:
    """Verify signatures, bindings, byte equality, and two-builder coverage.

    `allow_test_keys` exists solely for mutation tests. It permanently changes
    the result to SMOKE_ONLY and can never yield a qualifying verdict.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover
        raise AssuranceError("cryptography package with Ed25519 support is required") from exc

    errors: list[str] = []
    trust = _trusted_builders(trusted_builders, allow_test_keys, errors)
    locks = load_toolchains()
    expected_source = source_identity(expected_revision)
    policy_signature_errors = verify_policy_signatures()
    if not allow_test_keys:
        errors.extend(policy_signature_errors)
    accepted: list[dict[str, Any]] = []
    payload_paths = sorted(attestations.glob("*.attestation.json"))
    if not payload_paths:
        errors.append("no external builder attestations supplied")
    for payload_path in payload_paths:
        signature_path = payload_path.with_name(payload_path.name.replace(".attestation.json", ".signature.json"))
        try:
            payload = load_json(payload_path)
            signature = load_json(signature_path)
            key_id = signature.get("key_id")
            record = trust.get(key_id)
            if record is None:
                raise AssuranceError(f"untrusted or production-ineligible key {key_id!r}")
            raw = canonical_json(payload)
            if signature.get("schema") != "noos/detached-ed25519-signature/v1" or signature.get("algorithm") != "ed25519":
                raise AssuranceError("wrong detached signature schema/algorithm")
            if signature.get("payload_sha256") != sha256_bytes(raw):
                raise AssuranceError("detached signature payload digest mismatch")
            public = base64.b64decode(record["public_key_base64"], validate=True)
            Ed25519PublicKey.from_public_bytes(public).verify(base64.b64decode(signature["signature_base64"], validate=True), raw)
            item_errors = _validate_attestation(payload, record, expected_source, locks)
            if item_errors:
                raise AssuranceError("; ".join(item_errors))
            accepted.append({"path": payload_path.name, "key_id": key_id, "payload": payload, "trust": record})
        except Exception as exc:
            errors.append(f"{payload_path.name}: {exc}")

    # All accepted builders must bind one source tree and compare raw bytes per target.
    trees = {item["payload"]["build"]["source_tree"] for item in accepted}
    if len(trees) > 1:
        errors.append("source tree mismatch between builders")
    by_target: dict[str, list[dict[str, Any]]] = {target: [] for target in REQUIRED_TARGETS}
    for item in accepted:
        by_target[item["payload"]["build"]["target"]].append(item)
    for target, items in sorted(by_target.items()):
        hash_sets = {canonical_json(item["payload"]["artifact_hashes"]) for item in items}
        if len(items) < 2:
            errors.append(f"{target}: fewer than two signed external builders")
        if len(hash_sets) > 1:
            errors.append(f"{target}: raw binary hash comparison mismatch")

    coverage: dict[str, set[str]] = {}
    for item in accepted:
        coverage.setdefault(item["key_id"], set()).add(item["payload"]["build"]["target"])
    complete_keys = sorted(key for key, targets in coverage.items() if targets == REQUIRED_TARGETS)
    complete = [next(item for item in accepted if item["key_id"] == key) for key in complete_keys]
    for field in ("operator", "control_plane_identity", "host_identity", "toolchain_installation"):
        values = {item["payload"]["builder"][field] for item in complete}
        if len(values) < 2:
            errors.append(f"complete builders do not have two distinct {field} values")
    if len(complete_keys) < 2:
        errors.append("two externally signed builder identities must each cover every required target")

    report = {
        "schema": "noos/repro-assurance-report/v1",
        "promotion_ledger_mutation": "PROHIBITED",
        "registry_claim_state_mutation": "PROHIBITED",
        "expected_revision": expected_revision,
        "required_targets": sorted(REQUIRED_TARGETS),
        "accepted_attestations": [{"path": item["path"], "key_id": item["key_id"], "target": item["payload"]["build"]["target"]} for item in accepted],
        "complete_external_builder_identities": complete_keys,
        "comparison_law": "raw_bytes_witnessed_by_sha256",
        "policy_sha256": sha256_file(POLICY),
        "policy_signature_errors": policy_signature_errors,
        "errors": sorted(set(errors)),
    }
    if errors:
        report["verdict"] = "EXTERNAL_BLOCKED"
    elif allow_test_keys:
        report["verdict"] = "SMOKE_ONLY_TEST_KEYS"
        report["errors"] = ["test keys are not production signatures and cannot satisfy the external builder gate"]
    else:
        report["verdict"] = "QUALIFYING_EXTERNAL_ATTESTATIONS_VERIFIED"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="build one native target with locked offline dependencies")
    build.add_argument("--target", choices=sorted(REQUIRED_TARGETS), required=True)
    build.add_argument("--out", required=True)
    build.add_argument("--revision")
    build.add_argument("--smoke", action="store_true", help="allow unsigned policy/toolchain mismatch; output is smoke-only")
    verify = sub.add_parser("verify-attestations", help="verify an external two-builder attestation quorum")
    verify.add_argument("--attestations", required=True)
    verify.add_argument("--trusted-builders", required=True)
    verify.add_argument("--revision", required=True)
    verify.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            result = build_target(args.target, ROOT / args.out, revision=args.revision, smoke=args.smoke)
            print(f"RESULT repro_build={'SMOKE_ONLY' if args.smoke else 'CANDIDATE_BUILT'} target={args.target} binaries={len(result['binary_hashes'])}")
            return 0
        report = verify_attestation_set(Path(args.attestations), Path(args.trusted_builders), args.revision)
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(canonical_json(report))
        print(f"RESULT repro_assurance={report['verdict']} accepted={len(report['accepted_attestations'])} report={out}")
        return 0 if report["verdict"] == "QUALIFYING_EXTERNAL_ATTESTATIONS_VERIFIED" else 2
    except (AssuranceError, OSError, subprocess.CalledProcessError) as exc:
        print(f"RESULT repro_build=FAIL reason={exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
