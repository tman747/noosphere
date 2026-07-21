#!/usr/bin/env python3
"""Seal and verify one exact-revision public-testnet runtime bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

ROOT: Final[Path] = Path(__file__).resolve().parents[2]
SCHEMA: Final[str] = "noos/wwm-public-testnet-release-bundle/v1"
MANIFEST_NAME: Final[str] = "release-manifest.json"
HEX40: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{40}$")
HEX64: Final[re.Pattern[str]] = re.compile(r"^[0-9a-f]{64}$")
TARGET: Final[str] = "x86_64-unknown-linux-gnu"
SEMVER_BASE_TEXT: Final[str] = (
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
)
SEMVER_BASE: Final[re.Pattern[str]] = re.compile(rf"^{SEMVER_BASE_TEXT}$")
REVISION_RELEASE: Final[re.Pattern[str]] = re.compile(
    rf"^({SEMVER_BASE_TEXT})\+git\.([0-9a-f]{{40}})$"
)
BOUNDARY: Final[dict[str, object]] = {
    "environment": "public-testnet",
    "production": False,
    "production_capable": False,
    "promotion_effect": "NONE",
    "evidence_class": "OWNER_CONTROLLED_TESTNET_RELEASE",
    "independent_reproduction": False,
}
ROLLOUT: Final[dict[str, object]] = {
    "order": [
        "observer-read-gateway",
        "witness-3",
        "witness-2",
        "witness-1",
        "producer-witness-0",
    ],
    "minimum_finality_quorum": 3,
    "rollback_artifact_required": True,
    "durable_state_deletion_permitted": False,
    "process_rss_limit_bytes": {
        "observer-read-gateway": 6 * 1024**3,
        "witness-3": 5 * 1024**3,
        "witness-2": 5 * 1024**3,
        "witness-1": 6 * 1024**3,
        "producer-witness-0": 14 * 1024**3,
    },
    "stop_conditions": [
        "chain_or_genesis_mismatch",
        "height_regression",
        "finality_quorum_loss",
        "finalized_checkpoint_divergence",
        "host_memory_envelope_exceeded",
    ],
}


class ReleaseBundleError(RuntimeError):
    pass


@dataclass(frozen=True)
class BinaryComponent:
    package: str
    binary: str
    revision_probe: bool


BINARIES: Final[tuple[BinaryComponent, ...]] = (
    BinaryComponent("noos-node", "noosd", True),
    BinaryComponent("noos-indexer", "noos-indexer", True),
    BinaryComponent("noos-workerd", "noos-workerd", True),
    BinaryComponent("noos-cli", "noos-cli", False),
    BinaryComponent("noos-mind-gateway", "noos-web-capacityd", False),
    BinaryComponent("noos-artifact-service", "noos-artifact-service", False),
)
REQUIRED_BINARY_PATHS: Final[frozenset[str]] = frozenset(
    f"bin/{component.binary}" for component in BINARIES
)
REVISION_PROBE_PATHS: Final[frozenset[str]] = frozenset(
    f"bin/{component.binary}" for component in BINARIES if component.revision_probe
)
API_CONTRACT_FILES: Final[tuple[str, ...]] = (
    "protocol/api/openapi-v1.yaml",
    "protocol/api/vectors/negative.json",
    "protocol/api/vectors/positive.json",
)
RUNTIME_PATHS: Final[tuple[str, ...]] = (
    "apps/mind-market/wallet",
    "deploy/wwm/public-testnet.json",
    "deploy/wwm/run-public-testnet.ps1",
    "deploy/wwm/systemd",
    "protocol/api",
    "protocol/genesis/devnet-parameters.toml",
    "site",
    "tools/network_dashboard.py",
    "tools/operations/wwm_hosted_model_demo.py",
    "tools/operations/wwm_neural_publisher.py",
    "tools/operations/wwm_public_gateway.py",
    "tools/operations/wwm_public_inference.py",
    "tools/operations/wwm_public_testnet_monitor.py",
    "tools/operations/wwm_release_bundle.py",
    "tools/operations/wwm_static_bundle_server.py",
    "tools/operations/wwm_wallet_gateway.py",
)
MANIFEST_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "bundle_id",
        "boundary",
        "source",
        "toolchain",
        "chain_binding",
        "api_contract",
        "build",
        "files",
        "version_probes",
        "rollout",
    }
)


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def run_capture(arguments: list[str], *, cwd: Path = ROOT) -> str:
    try:
        completed = subprocess.run(
            arguments,
            cwd=cwd,
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReleaseBundleError(f"cannot execute {arguments[0]}: {error}") from error
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip() or f"exit {completed.returncode}"
        raise ReleaseBundleError(f"{' '.join(arguments)} failed: {detail}")
    return completed.stdout.strip()


def git_text(*arguments: str) -> str:
    return run_capture(["git", *arguments])


def source_identity(requested_revision: str | None = None) -> dict[str, object]:
    revision = git_text("rev-parse", "HEAD")
    if not HEX40.fullmatch(revision):
        raise ReleaseBundleError("repository HEAD is not a full lowercase Git revision")
    if requested_revision is not None and requested_revision != revision:
        raise ReleaseBundleError("requested revision is not the checked-out HEAD")
    tracked_changes = git_text("status", "--porcelain", "--untracked-files=no")
    if tracked_changes:
        raise ReleaseBundleError("tracked source tree is dirty; commit before sealing a release")
    tree = git_text("rev-parse", "HEAD^{tree}")
    if not HEX40.fullmatch(tree):
        raise ReleaseBundleError("repository tree is not a full lowercase Git object id")
    raw_epoch = git_text("show", "-s", "--format=%ct", "HEAD")
    try:
        source_date_epoch = int(raw_epoch)
    except ValueError as error:
        raise ReleaseBundleError("source commit timestamp is invalid") from error
    if source_date_epoch < 1:
        raise ReleaseBundleError("source commit timestamp must be positive")
    return {
        "revision": revision,
        "tree": tree,
        "source_date_epoch": source_date_epoch,
    }


def pinned_rust_version() -> str:
    try:
        document = (ROOT / "rust-toolchain.toml").read_text(encoding="utf-8")
    except OSError as error:
        raise ReleaseBundleError("rust-toolchain.toml is unreadable") from error
    matches = re.findall(
        r'^channel\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$',
        document,
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        raise ReleaseBundleError("pinned Rust channel is not one exact stable version")
    return matches[0]


def package_version(package: str) -> str:
    manifest = ROOT / "crates" / package / "Cargo.toml"
    try:
        document = manifest.read_text(encoding="utf-8")
    except OSError as error:
        raise ReleaseBundleError(f"package manifest is unreadable: {package}") from error
    section = re.search(
        r"(?ms)^\[package\]\s*$\n(.*?)(?=^\[|\Z)",
        document,
    )
    if section is None:
        raise ReleaseBundleError(f"package manifest has no package section: {package}")
    versions = re.findall(
        r'^version\s*=\s*"([^"]+)"\s*$',
        section.group(1),
        flags=re.MULTILINE,
    )
    if len(versions) != 1 or SEMVER_BASE.fullmatch(versions[0]) is None:
        raise ReleaseBundleError(f"package version is not one canonical base SemVer: {package}")
    return versions[0]


def revision_bound_release_version(revision: str) -> str:
    versions = {
        package_version(component.package)
        for component in BINARIES
        if component.revision_probe
    }
    if len(versions) != 1:
        raise ReleaseBundleError("revision-probed packages do not share one base version")
    return f"{versions.pop()}+git.{revision}"


def toolchain_identity() -> dict[str, str]:
    expected = pinned_rust_version()
    rustc_verbose = run_capture(["rustc", "-Vv"])
    if f"release: {expected}" not in rustc_verbose or f"host: {TARGET}" not in rustc_verbose:
        raise ReleaseBundleError("installed Rust compiler differs from the pinned Linux toolchain")
    cargo_version = run_capture(["cargo", "-V"])
    return {
        "rustc_verbose": rustc_verbose,
        "cargo_version": cargo_version,
        "rust_toolchain_sha256": sha256_file(ROOT / "rust-toolchain.toml"),
        "cargo_lock_sha256": sha256_file(ROOT / "Cargo.lock"),
    }


def tracked_runtime_files() -> list[Path]:
    try:
        completed = subprocess.run(
            ["git", "ls-files", "-z", "--", *RUNTIME_PATHS],
            cwd=ROOT,
            check=False,
            capture_output=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReleaseBundleError(f"cannot enumerate tracked runtime files: {error}") from error
    if completed.returncode != 0:
        raise ReleaseBundleError("git ls-files failed while enumerating runtime files")
    paths = [ROOT / os.fsdecode(raw) for raw in completed.stdout.split(b"\0") if raw]
    if not paths:
        raise ReleaseBundleError("release bundle contains no tracked runtime files")
    for path in paths:
        if not path.is_file() or path.is_symlink():
            raise ReleaseBundleError(f"runtime source is missing or symbolic: {path}")
    return sorted(paths)


def safe_bundle_path(bundle_root: Path, relative: str) -> Path:
    if not relative or Path(relative).is_absolute() or "\\" in relative:
        raise ReleaseBundleError(f"bundle path is not canonical: {relative!r}")
    candidate = (bundle_root / relative).resolve()
    try:
        candidate.relative_to(bundle_root.resolve())
    except ValueError as error:
        raise ReleaseBundleError(f"bundle path escapes its root: {relative!r}") from error
    if candidate == bundle_root.resolve():
        raise ReleaseBundleError("bundle file path cannot name the bundle root")
    return candidate

def frozen_root(root: Path, relative_paths: tuple[str, ...]) -> str:
    digest = hashlib.sha256()
    for relative in sorted(relative_paths):
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(safe_bundle_path(root, relative).read_bytes()).digest())
    return digest.hexdigest()


def api_contract_identity(root: Path) -> dict[str, str]:
    manifest_path = safe_bundle_path(root, "protocol/api/contract-root-v1.json")
    try:
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseBundleError("frozen API contract root is unreadable") from error
    files = document.get("files") if isinstance(document, dict) else None
    if (
        not isinstance(files, dict)
        or set(files) != set(API_CONTRACT_FILES)
        or document.get("contract") != "NOOS/API/V1"
    ):
        raise ReleaseBundleError("frozen API contract file set or identity is invalid")
    for relative, expected in files.items():
        path = safe_bundle_path(root, relative)
        if (
            not path.is_file()
            or path.is_symlink()
            or not isinstance(expected, str)
            or HEX64.fullmatch(expected) is None
            or sha256_file(path) != expected
        ):
            raise ReleaseBundleError(f"frozen API contract hash mismatch: {relative}")
    vector_paths = tuple(
        relative for relative in API_CONTRACT_FILES if relative != "protocol/api/openapi-v1.yaml"
    )
    vector_root = frozen_root(root, vector_paths)
    contract_root = frozen_root(root, API_CONTRACT_FILES)
    if (
        document.get("vector_root") != vector_root
        or document.get("contract_root") != contract_root
    ):
        raise ReleaseBundleError("frozen API aggregate roots are invalid")
    return {
        "contract": "NOOS/API/V1",
        "vector_root": vector_root,
        "contract_root": contract_root,
    }


def file_entry(path: Path, relative: str, component: str) -> dict[str, object]:
    return {
        "path": relative,
        "component": component,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def manifest_bundle_id(manifest: dict[str, Any]) -> str:
    payload = dict(manifest)
    payload.pop("bundle_id", None)
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def build_binary(
    component: BinaryComponent,
    target_dir: Path,
    environment: dict[str, str],
) -> Path:
    command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "-p",
        component.package,
        "--bin",
        component.binary,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            check=False,
            timeout=3600,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise ReleaseBundleError(f"cannot build {component.binary}: {error}") from error
    if completed.returncode != 0:
        raise ReleaseBundleError(f"locked release build failed for {component.binary}")
    path = target_dir / "release" / component.binary
    if not path.is_file() or path.is_symlink():
        raise ReleaseBundleError(f"release binary is missing or symbolic: {component.binary}")
    return path


def copy_file(source: Path, destination: Path, *, executable: bool) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)
    destination.chmod(0o755 if executable else 0o644)


def build_bundle(
    output: Path,
    *,
    requested_revision: str | None = None,
    target_dir: Path | None = None,
) -> dict[str, Any]:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"}:
        raise ReleaseBundleError("public-testnet release bundles must be sealed on Linux x86_64")
    identity = source_identity(requested_revision)
    toolchain = toolchain_identity()
    output = output.resolve()
    if output.exists() and any(output.iterdir()):
        raise ReleaseBundleError("output directory must be absent or empty")
    output.mkdir(parents=True, exist_ok=True)
    cargo_target = (target_dir or output.parent / f".{output.name}-cargo-target").resolve()
    if cargo_target == output or output in cargo_target.parents:
        raise ReleaseBundleError("Cargo target directory cannot be inside the release bundle")
    cargo_target.mkdir(parents=True, exist_ok=True)

    revision = str(identity["revision"])
    release_version = revision_bound_release_version(revision)
    environment = os.environ.copy()
    environment.update(
        {
            "CARGO_INCREMENTAL": "0",
            "CARGO_TARGET_DIR": str(cargo_target),
            "NOOS_SOURCE_REVISION": revision,
            "NOOS_RELEASE_VERSION": release_version,
            "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
        }
    )

    entries: list[dict[str, object]] = []
    probes: dict[str, str] = {}
    for component in BINARIES:
        binary = build_binary(component, cargo_target, environment)
        relative = f"bin/{component.binary}"
        destination = safe_bundle_path(output, relative)
        copy_file(binary, destination, executable=True)
        entries.append(file_entry(destination, relative, component.package))
        if component.revision_probe:
            result = run_capture([str(destination), "--version"], cwd=output)
            expected = (
                f"{component.binary} {release_version} source_revision={revision}"
            )
            if result != expected:
                raise ReleaseBundleError(
                    f"{component.binary} does not report the exact sealed release identity"
                )
            probes[relative] = result

    for source in tracked_runtime_files():
        relative = source.relative_to(ROOT).as_posix()
        destination = safe_bundle_path(output, relative)
        executable = source.suffix in {".py", ".sh"} or os.access(source, os.X_OK)
        copy_file(source, destination, executable=executable)
        entries.append(file_entry(destination, relative, "runtime-source"))

    deployment = json.loads(
        (ROOT / "deploy" / "wwm" / "public-testnet.json").read_text(encoding="utf-8")
    )
    chain_binding = deployment.get("chain_binding")
    if (
        not isinstance(chain_binding, dict)
        or not HEX64.fullmatch(str(chain_binding.get("chain_id", "")))
        or not HEX64.fullmatch(str(chain_binding.get("genesis_hash", "")))
    ):
        raise ReleaseBundleError("public-testnet chain binding is malformed")

    api_contract = api_contract_identity(ROOT)

    manifest: dict[str, Any] = {
        "schema": SCHEMA,
        "bundle_id": "",
        "boundary": BOUNDARY,
        "source": identity,
        "toolchain": toolchain,
        "chain_binding": chain_binding,
        "api_contract": api_contract,
        "build": {
            "target": TARGET,
            "profile": "release",
            "cargo_locked": True,
            "incremental": False,
            "source_revision_env": revision,
            "release_version_env": release_version,
        },
        "files": sorted(entries, key=lambda entry: str(entry["path"])),
        "version_probes": probes,
        "rollout": ROLLOUT,
    }
    manifest["bundle_id"] = manifest_bundle_id(manifest)
    (output / MANIFEST_NAME).write_bytes(canonical_json(manifest) + b"\n")
    verify_bundle(output)
    return manifest


def read_manifest(bundle_root: Path) -> dict[str, Any]:
    try:
        value = json.loads((bundle_root / MANIFEST_NAME).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseBundleError(f"release manifest is unreadable: {error}") from error
    if not isinstance(value, dict):
        raise ReleaseBundleError("release manifest must be a JSON object")
    return value


def verify_bundle(bundle_root: Path) -> dict[str, Any]:
    bundle_root = bundle_root.resolve()
    if not bundle_root.is_dir():
        raise ReleaseBundleError("release bundle root does not exist")
    manifest = read_manifest(bundle_root)
    if set(manifest) != MANIFEST_KEYS or manifest.get("schema") != SCHEMA:
        raise ReleaseBundleError("release manifest schema or fields are invalid")
    if manifest.get("boundary") != BOUNDARY:
        raise ReleaseBundleError("release boundary is not fail-closed testnet evidence")
    if manifest.get("rollout") != ROLLOUT:
        raise ReleaseBundleError("release rollout policy is not exact")
    source = manifest.get("source")
    if (
        not isinstance(source, dict)
        or set(source) != {"revision", "tree", "source_date_epoch"}
        or not HEX40.fullmatch(str(source.get("revision", "")))
        or not HEX40.fullmatch(str(source.get("tree", "")))
        or not isinstance(source.get("source_date_epoch"), int)
        or source["source_date_epoch"] < 1
    ):
        raise ReleaseBundleError("release source identity is invalid")
    bundle_id = manifest.get("bundle_id")
    if not isinstance(bundle_id, str) or not HEX64.fullmatch(bundle_id):
        raise ReleaseBundleError("release bundle id is invalid")
    if manifest_bundle_id(manifest) != bundle_id:
        raise ReleaseBundleError("release bundle id does not match canonical manifest content")

    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        raise ReleaseBundleError("release manifest has no files")
    expected_paths: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "component",
            "bytes",
            "sha256",
        }:
            raise ReleaseBundleError("release file entry is malformed")
        relative = entry.get("path")
        if not isinstance(relative, str) or relative in expected_paths:
            raise ReleaseBundleError("release file path is invalid or duplicated")
        path = safe_bundle_path(bundle_root, relative)
        if not path.is_file() or path.is_symlink():
            raise ReleaseBundleError(f"release file is missing or symbolic: {relative}")
        if (
            not isinstance(entry.get("bytes"), int)
            or entry["bytes"] < 0
            or path.stat().st_size != entry["bytes"]
            or not isinstance(entry.get("sha256"), str)
            or not HEX64.fullmatch(entry["sha256"])
            or sha256_file(path) != entry["sha256"]
        ):
            raise ReleaseBundleError(f"release file evidence mismatch: {relative}")
        expected_paths.add(relative)

    if not REQUIRED_BINARY_PATHS.issubset(expected_paths):
        raise ReleaseBundleError("release bundle omits a required public-testnet binary")
    actual_paths = {
        path.relative_to(bundle_root).as_posix()
        for path in bundle_root.rglob("*")
        if path.is_file() and path.name != MANIFEST_NAME
    }
    if actual_paths != expected_paths:
        raise ReleaseBundleError("release bundle contains unmanifested or missing files")
    if manifest.get("api_contract") != api_contract_identity(bundle_root):
        raise ReleaseBundleError("release API contract identity is invalid")

    revision = source["revision"]
    build = manifest.get("build")
    release_version = build.get("release_version_env") if isinstance(build, dict) else None
    release_match = (
        REVISION_RELEASE.fullmatch(release_version)
        if isinstance(release_version, str)
        else None
    )
    if (
        release_match is None
        or release_match.group(2) != revision
        or build
        != {
            "target": TARGET,
            "profile": "release",
            "cargo_locked": True,
            "incremental": False,
            "source_revision_env": revision,
            "release_version_env": release_version,
        }
    ):
        raise ReleaseBundleError("release build settings are not exact and locked")

    probes = manifest.get("version_probes")
    if not isinstance(probes, dict) or set(probes) != REVISION_PROBE_PATHS:
        raise ReleaseBundleError("release version probes do not cover revision-bound binaries")
    for relative, output in probes.items():
        expected = (
            f"{Path(relative).name} {release_version} source_revision={revision}"
        )
        if output != expected:
            raise ReleaseBundleError(
                f"release version probe is not exact and revision-bound: {relative}"
            )
    chain = manifest.get("chain_binding")
    if (
        not isinstance(chain, dict)
        or set(chain) != {"chain_id", "genesis_hash"}
        or not HEX64.fullmatch(str(chain.get("chain_id", "")))
        or not HEX64.fullmatch(str(chain.get("genesis_hash", "")))
    ):
        raise ReleaseBundleError("release chain binding is invalid")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Seal or verify an exact-revision WWM public-testnet release bundle"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("--out", type=Path, required=True)
    build_parser.add_argument("--revision")
    build_parser.add_argument("--target-dir", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--bundle", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "build":
            manifest = build_bundle(
                args.out,
                requested_revision=args.revision,
                target_dir=args.target_dir,
            )
        else:
            manifest = verify_bundle(args.bundle)
    except (ReleaseBundleError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"RESULT wwm_release_bundle=FAIL reason={error}", file=sys.stderr)
        return 1
    print(
        "RESULT wwm_release_bundle=PASS "
        f"bundle_id={manifest['bundle_id']} revision={manifest['source']['revision']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
