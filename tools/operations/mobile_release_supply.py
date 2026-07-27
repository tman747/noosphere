from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "noos/mobile-release-subject-manifest/v1"
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
LABEL = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
REQUIRED_LABELS = {
    "android-linux",
    "android-windows",
    "ios",
    "native-windows",
    "native-macos",
}
MAX_FILES = 20_000
MAX_FILE_BYTES = 2 * 1024 * 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024 * 1024


class SupplyError(RuntimeError):
    pass


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    try:
        if not path.is_file() or path.stat().st_size > 16 * 1024 * 1024:
            raise SupplyError(f"JSON subject is missing or oversized: {path}")
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SupplyError(f"cannot load JSON subject {path}: {error}") from error
    if not isinstance(value, dict):
        raise SupplyError(f"JSON subject must contain an object: {path}")
    return value


def safe_relative(value: str) -> PurePosixPath:
    pure = PurePosixPath(value)
    if pure.is_absolute() or not pure.parts or ".." in pure.parts or "\\" in value:
        raise SupplyError(f"unsafe mobile subject path: {value}")
    return pure


def inventory(root: Path, label: str) -> list[dict[str, Any]]:
    if not root.is_dir():
        raise SupplyError(f"mobile artifact directory does not exist: {root}")
    files: list[Path] = []
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise SupplyError(f"mobile artifact contains a symlink: {path}")
        if not path.is_file():
            continue
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise SupplyError(f"mobile artifact exceeds the per-file bound: {path}")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise SupplyError("mobile artifact inventory exceeds the total byte bound")
        files.append(path)
        if len(files) > MAX_FILES:
            raise SupplyError("mobile artifact inventory exceeds the file-count bound")
    if not files:
        raise SupplyError(f"mobile artifact directory is empty: {root}")
    return [
        {
            "label": label,
            "path": path.relative_to(root).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        }
        for path in files
    ]


def locate_manifest(root: Path, filename: str) -> Path:
    matches = [path for path in root.rglob(filename) if path.is_file()]
    if len(matches) != 1:
        raise SupplyError(f"expected exactly one {filename} below {root}")
    return matches[0]


def resolve_downloaded_subject(root: Path, manifest_path: str) -> Path:
    pure = safe_relative(manifest_path)
    candidates = [root / Path(*pure.parts)]
    if pure.parts[:2] == ("wallet", "mobile"):
        candidates.append(root / Path(*pure.parts[2:]))
    matches = [candidate for candidate in candidates if candidate.is_file()]
    if len(matches) != 1:
        raise SupplyError(f"manifested subject is missing or ambiguous: {manifest_path}")
    return matches[0]


def validate_binding_manifest(root: Path, platform_name: str, revision: str) -> dict[str, Any]:
    filename = f"{platform_name}-bindings.manifest.json"
    path = locate_manifest(root, filename)
    document = load_json(path)
    expected_version = f"0.1.0+git.{revision}"
    required = {
        "schema",
        "platform",
        "profile",
        "crate",
        "crate_version",
        "source_revision",
        "release_version",
        "files",
    }
    if (
        set(document) != required
        or document.get("schema") != "noos/mobile-wallet-bindings/v2"
        or document.get("platform") != platform_name
        or document.get("profile") != "release"
        or document.get("crate") != "noos-wallet-sdk"
        or document.get("source_revision") != revision
        or document.get("release_version") != expected_version
        or not isinstance(document.get("crate_version"), str)
        or not document["crate_version"]
    ):
        raise SupplyError(f"{platform_name} binding manifest identity is malformed")
    entries = document["files"]
    if not isinstance(entries, list) or not entries:
        raise SupplyError(f"{platform_name} binding manifest is empty")
    seen: set[str] = set()
    package_suffixes = {"android": {".apk", ".aar", ".so", ".kt"}, "ios": {".a", ".swift", ".h"}}
    observed_suffixes: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"path", "bytes", "sha256"}:
            raise SupplyError(f"{platform_name} binding descriptor is malformed")
        relative = entry["path"]
        if not isinstance(relative, str) or relative in seen:
            raise SupplyError(f"{platform_name} binding path is malformed or duplicated")
        seen.add(relative)
        subject = resolve_downloaded_subject(root, relative)
        if (
            not isinstance(entry["bytes"], int)
            or isinstance(entry["bytes"], bool)
            or subject.stat().st_size != entry["bytes"]
            or not isinstance(entry["sha256"], str)
            or not HEX64.fullmatch(entry["sha256"])
            or sha256_file(subject) != entry["sha256"]
        ):
            raise SupplyError(f"manifested mobile subject integrity mismatch: {relative}")
        observed_suffixes.add(subject.suffix.lower())
    if not package_suffixes[platform_name] <= observed_suffixes:
        missing = sorted(package_suffixes[platform_name] - observed_suffixes)
        raise SupplyError(f"{platform_name} release subject classes are missing: {missing}")
    return {
        "path": path.relative_to(root).as_posix(),
        "sha256": sha256_file(path),
        "crate_version": document["crate_version"],
        "release_version": document["release_version"],
        "subject_count": len(entries),
    }


def android_comparison(
    linux_manifest_root: Path, windows_manifest_root: Path
) -> dict[str, Any]:
    linux = load_json(locate_manifest(linux_manifest_root, "android-bindings.manifest.json"))
    windows = load_json(locate_manifest(windows_manifest_root, "android-bindings.manifest.json"))
    linux_rows = {entry["path"]: entry for entry in linux["files"]}
    windows_rows = {entry["path"]: entry for entry in windows["files"]}
    paths = sorted(set(linux_rows) | set(windows_rows))
    rows = []
    for path in paths:
        left = linux_rows.get(path)
        right = windows_rows.get(path)
        rows.append(
            {
                "path": path,
                "linux_sha256": None if left is None else left["sha256"],
                "windows_sha256": None if right is None else right["sha256"],
                "byte_equal": left is not None
                and right is not None
                and left["bytes"] == right["bytes"]
                and left["sha256"] == right["sha256"],
            }
        )
    return {
        "schema": "noos/mobile-cross-builder-comparison/v1",
        "builders": ["github-ubuntu-24.04", "github-windows-2025"],
        "independent_builders": False,
        "normalized": False,
        "all_subjects_equal": bool(rows) and all(row["byte_equal"] for row in rows),
        "subjects": rows,
    }


def manifest_id(body: dict[str, Any]) -> str:
    payload = dict(body)
    payload.pop("manifest_id", None)
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def seal(inputs: dict[str, Path], output: Path, revision: str) -> dict[str, Any]:
    if not HEX40.fullmatch(revision):
        raise SupplyError("mobile release revision must be lowercase hex40")
    if set(inputs) != REQUIRED_LABELS:
        raise SupplyError("mobile release input labels are incomplete")
    if output.exists():
        raise SupplyError("mobile release output already exists")
    inventories = {label: inventory(path, label) for label, path in sorted(inputs.items())}
    bindings = {
        "android-linux": validate_binding_manifest(inputs["android-linux"], "android", revision),
        "android-windows": validate_binding_manifest(inputs["android-windows"], "android", revision),
        "ios": validate_binding_manifest(inputs["ios"], "ios", revision),
    }
    native_requirements = {
        "native-windows": {".exe"},
        "native-macos": {""},
    }
    for label, suffixes in native_requirements.items():
        observed = {Path(row["path"]).suffix.lower() for row in inventories[label]}
        if not suffixes <= observed:
            raise SupplyError(f"{label} native binary subjects are missing")
    all_subjects = [row for rows in inventories.values() for row in rows]
    all_subjects.sort(key=lambda row: (row["label"], row["path"]))
    body = {
        "manifest_id": "0" * 64,
        "source_revision": revision,
        "release_version": f"0.1.0+git.{revision}",
        "subjects": all_subjects,
        "binding_manifests": bindings,
        "android_cross_builder_comparison": android_comparison(
            inputs["android-linux"], inputs["android-windows"]
        ),
        "attestation": {
            "mode": "GITHUB_OIDC_DSSE_EXTERNAL",
            "subjects": ["subject-manifest.json", "SHA256SUMS"],
            "embedded_signature": False,
        },
        "production": False,
        "promotion_effect": "NONE",
        "independent_reproduction_claimed": False,
    }
    body["manifest_id"] = manifest_id(body)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        sums = "".join(
            f"{row['sha256']}  {row['label']}/{row['path']}\n" for row in all_subjects
        )
        (temporary / "SHA256SUMS").write_text(sums, encoding="ascii", newline="\n")
        document = {"schema": SCHEMA, "body": body}
        (temporary / "subject-manifest.json").write_bytes(canonical_json(document) + b"\n")
        verify(temporary / "subject-manifest.json", temporary / "SHA256SUMS")
        os.replace(temporary, output)
        return document
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def verify(manifest_path: Path, checksums_path: Path) -> dict[str, Any]:
    document = load_json(manifest_path)
    if set(document) != {"schema", "body"} or document.get("schema") != SCHEMA:
        raise SupplyError("mobile release subject manifest envelope is malformed")
    body = document["body"]
    if not isinstance(body, dict) or set(body) != {
        "manifest_id",
        "source_revision",
        "release_version",
        "subjects",
        "binding_manifests",
        "android_cross_builder_comparison",
        "attestation",
        "production",
        "promotion_effect",
        "independent_reproduction_claimed",
    }:
        raise SupplyError("mobile release subject manifest body is malformed")
    revision = body["source_revision"]
    if (
        not isinstance(revision, str)
        or not HEX40.fullmatch(revision)
        or body["release_version"] != f"0.1.0+git.{revision}"
        or body["manifest_id"] != manifest_id(body)
    ):
        raise SupplyError("mobile release subject manifest identity is invalid")
    if body["production"] is not False or body["promotion_effect"] != "NONE" or body["independent_reproduction_claimed"] is not False:
        raise SupplyError("mobile release subject manifest crosses an assurance boundary")
    subjects = body["subjects"]
    if not isinstance(subjects, list) or not subjects or len(subjects) > MAX_FILES:
        raise SupplyError("mobile release subject inventory is malformed")
    lines: list[str] = []
    prior: tuple[str, str] | None = None
    for row in subjects:
        if not isinstance(row, dict) or set(row) != {"label", "path", "bytes", "sha256"}:
            raise SupplyError("mobile release subject descriptor is malformed")
        if row["label"] not in REQUIRED_LABELS or not isinstance(row["path"], str):
            raise SupplyError("mobile release subject label or path is invalid")
        safe_relative(row["path"])
        key = (row["label"], row["path"])
        if prior is not None and key <= prior:
            raise SupplyError("mobile release subject inventory is unsorted or duplicated")
        prior = key
        if not isinstance(row["bytes"], int) or isinstance(row["bytes"], bool) or row["bytes"] < 0 or not isinstance(row["sha256"], str) or not HEX64.fullmatch(row["sha256"]):
            raise SupplyError("mobile release subject size or hash is invalid")
        lines.append(f"{row['sha256']}  {row['label']}/{row['path']}\n")
    try:
        observed = checksums_path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError) as error:
        raise SupplyError(f"cannot read mobile SHA256SUMS: {error}") from error
    if observed != "".join(lines):
        raise SupplyError("mobile SHA256SUMS does not exactly cover subject descriptors")
    if set(body["binding_manifests"]) != {"android-linux", "android-windows", "ios"}:
        raise SupplyError("mobile binding manifest inventory is incomplete")
    comparison = body["android_cross_builder_comparison"]
    if not isinstance(comparison, dict) or comparison.get("schema") != "noos/mobile-cross-builder-comparison/v1" or comparison.get("independent_builders") is not False or comparison.get("normalized") is not False:
        raise SupplyError("Android cross-builder comparison is malformed or overstated")
    if body["attestation"] != {
        "mode": "GITHUB_OIDC_DSSE_EXTERNAL",
        "subjects": ["subject-manifest.json", "SHA256SUMS"],
        "embedded_signature": False,
    }:
        raise SupplyError("mobile release attestation contract is malformed")
    return body


def parse_inputs(values: list[str]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for value in values:
        label, separator, raw_path = value.partition("=")
        if not separator or not LABEL.fullmatch(label) or label in result or not raw_path:
            raise SupplyError(f"mobile release input must be unique label=path: {value}")
        result[label] = Path(raw_path).resolve()
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Seal and verify exact-revision mobile release subjects")
    subparsers = parser.add_subparsers(dest="command", required=True)
    seal_parser = subparsers.add_parser("seal")
    seal_parser.add_argument("--revision", required=True)
    seal_parser.add_argument("--input", action="append", default=[], required=True)
    seal_parser.add_argument("--output", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("--manifest", type=Path, required=True)
    verify_parser.add_argument("--checksums", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "seal":
            value = seal(parse_inputs(args.input), args.output, args.revision)
        else:
            value = verify(args.manifest, args.checksums)
    except SupplyError as error:
        print(f"mobile release supply failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
