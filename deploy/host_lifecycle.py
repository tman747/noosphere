#!/usr/bin/env python3
"""Signed, monotonic MindChain host releases with hardened systemd services."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
import plistlib
import platform as runtime_platform
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

MANIFEST_SCHEMA = "noos/mindchain-host-release/v1"
ROLLBACK_SCHEMA = "noos/mindchain-host-rollback-authorization/v1"
SECURITY_SCHEMA = "noos/mindchain-host-security-state/v1"
POINTER_SCHEMA = "noos/mindchain-host-current-release/v1"
UNINSTALL_SCHEMA = "noos/mindchain-host-uninstall-record/v1"
MANIFEST_DOMAIN = b"NOOS/SIG/MINDCHAIN-HOST-RELEASE/V1\0"
ROLLBACK_DOMAIN = b"NOOS/SIG/MINDCHAIN-HOST-ROLLBACK/V1\0"
RELEASE_ID_DOMAIN = b"NOOS/MINDCHAIN-HOST-RELEASE-ID/V1\0"
ROLLBACK_ID_DOMAIN = b"NOOS/MINDCHAIN-HOST-ROLLBACK-ID/V1\0"
SERVICE_ORDER = ("producer", "node", "indexer", "gateway", "dashboard")
SERVICE_DEPENDENCIES = {
    "producer": (),
    "node": (),
    "indexer": ("node",),
    "gateway": ("indexer",),
    "dashboard": ("gateway", "indexer"),
}
SUPPORTED_TARGETS = {
    "linux": {"x86_64", "aarch64"},
    "macos": {"x86_64", "aarch64", "universal2"},
    "windows": {"x86_64", "aarch64"},
}
SERVICE_PACKAGE_DIRECTORIES = {
    "linux": "systemd",
    "macos": "launchd",
    "windows": "task-scheduler",
}
BODY_FIELDS = {
    "release_id",
    "release_sequence",
    "version",
    "source_revision",
    "chain_id",
    "genesis_hash",
    "platform",
    "arch",
    "release_signer_key_id",
    "rollback_signer_key_id",
    "rollback_public_key_base64",
    "artifacts",
    "services",
}
ARTIFACT_FIELDS = {"path", "sha256", "executable"}
SERVICE_FIELDS = {"name", "artifact", "argv", "dependencies", "private_config"}
SIGNATURE_FIELDS = {"suite", "domain", "key_id", "public_key_base64", "signature_base64"}
ROLLBACK_BODY_FIELDS = {
    "authorization_id",
    "current_release_id",
    "target_release_id",
    "authorized_at_utc",
    "expires_at_utc",
    "reason",
    "signer_key_id",
}
SECURITY_FIELDS = {
    "schema",
    "trust_key_id",
    "highest_release_sequence",
    "platform",
    "arch",
    "current_release_id",
    "previous_release_id",
    "installed_release_ids",
    "used_rollback_authorization_ids",
    "events",
}
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")
ENV_KEY = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_ARTIFACTS = 256
MAX_ARTIFACT_BYTES = 16 * 1024 * 1024 * 1024
MAX_PRIVATE_CONFIG_BYTES = 64 * 1024
MAX_EVENTS = 4096


class HostLifecycleError(RuntimeError):
    """The release, lifecycle state, or service package is unsafe."""


def remove_tree(path: Path, *, ignore_errors: bool = False) -> None:
    """Remove an immutable release tree on POSIX and Windows."""
    if not path.exists():
        return

    def make_writable_and_retry(function: Any, value: str, exception_info: Any) -> None:
        try:
            os.chmod(value, 0o700)
            function(value)
        except OSError:
            if not ignore_errors:
                raise exception_info[1]

    shutil.rmtree(path, onerror=make_writable_and_retry)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path, maximum_bytes: int = MAX_ARTIFACT_BYTES) -> str:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise HostLifecycleError(f"cannot stat artifact {path}: {error}") from error
    if not 0 <= size <= maximum_bytes:
        raise HostLifecycleError(f"artifact {path} exceeds its byte bound")
    digest = hashlib.sha256()
    try:
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as error:
        raise HostLifecycleError(f"cannot hash artifact {path}: {error}") from error
    return digest.hexdigest()


def load_object(path: Path, maximum_bytes: int = MAX_MANIFEST_BYTES) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise HostLifecycleError(f"cannot read {path}: {error}") from error
    if not payload or len(payload) > maximum_bytes:
        raise HostLifecycleError(f"{path} is empty or exceeds {maximum_bytes} bytes")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise HostLifecycleError(f"{path} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise HostLifecycleError(f"{path} must contain one JSON object")
    return value


def atomic_write(path: Path, value: Mapping[str, Any], mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_json(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    except OSError as error:
        raise HostLifecycleError(f"cannot atomically write {path}: {error}") from error
    finally:
        temporary.unlink(missing_ok=True)


def atomic_create(path: Path, value: Mapping[str, Any], mode: int = 0o600) -> None:
    if path.exists():
        raise HostLifecycleError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = canonical_json(value) + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as error:
        raise HostLifecycleError(f"refusing to overwrite {path}") from error
    except OSError as error:
        path.unlink(missing_ok=True)
        raise HostLifecycleError(f"cannot create {path}: {error}") from error


def parse_utc(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or UTC.fullmatch(value) is None:
        raise HostLifecycleError(f"{field} must be UTC text with second precision")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError as error:
        raise HostLifecycleError(f"{field} is not a real UTC timestamp") from error


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_seed(path: Path) -> bytes:
    try:
        seed = path.read_bytes()
    except OSError as error:
        raise HostLifecycleError(f"cannot read Ed25519 seed: {error}") from error
    if len(seed) != 32 or seed == bytes(32):
        raise HostLifecycleError("Ed25519 seed must contain 32 nonzero raw bytes")
    return seed


def public_identity(private: Ed25519PrivateKey) -> tuple[str, str]:
    public = private.public_key().public_bytes_raw()
    return base64.b64encode(public).decode("ascii"), sha256_bytes(public)


def decode_public(value: Any) -> bytes:
    try:
        public = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise HostLifecycleError("public key is not canonical base64") from error
    if len(public) != 32:
        raise HostLifecycleError("Ed25519 public key must contain 32 bytes")
    return public


def decode_signature(value: Any) -> bytes:
    try:
        signature = base64.b64decode(value, validate=True)
    except (TypeError, ValueError) as error:
        raise HostLifecycleError("signature is not canonical base64") from error
    if len(signature) != 64:
        raise HostLifecycleError("Ed25519 signature must contain 64 bytes")
    return signature


def signature_record(
    private: Ed25519PrivateKey, domain: bytes, body: Mapping[str, Any]
) -> dict[str, str]:
    public, key_id = public_identity(private)
    return {
        "suite": "ed25519",
        "domain": domain[:-1].decode("ascii"),
        "key_id": key_id,
        "public_key_base64": public,
        "signature_base64": base64.b64encode(
            private.sign(domain + canonical_json(body))
        ).decode("ascii"),
    }


def verify_signature(
    record: Any, domain: bytes, body: Mapping[str, Any], expected_key_id: str
) -> None:
    if not isinstance(record, dict) or set(record) != SIGNATURE_FIELDS:
        raise HostLifecycleError("signature record fields are malformed")
    if record.get("suite") != "ed25519" or record.get("domain") != domain[:-1].decode(
        "ascii"
    ):
        raise HostLifecycleError("signature suite or domain is invalid")
    public = decode_public(record.get("public_key_base64"))
    if sha256_bytes(public) != expected_key_id or record.get("key_id") != expected_key_id:
        raise HostLifecycleError("signature differs from the configured trust anchor")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            decode_signature(record.get("signature_base64")),
            domain + canonical_json(body),
        )
    except InvalidSignature as error:
        raise HostLifecycleError("Ed25519 signature is forged or invalid") from error


def safe_relative(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise HostLifecycleError(f"{field} must be a nonempty POSIX relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise HostLifecycleError(f"{field} escapes its release root")
    return path.as_posix()


def runtime_target() -> tuple[str, str]:
    system = {
        "Linux": "linux",
        "Darwin": "macos",
        "Windows": "windows",
    }.get(runtime_platform.system())
    machine = {
        "amd64": "x86_64",
        "x86_64": "x86_64",
        "arm64": "aarch64",
        "aarch64": "aarch64",
    }.get(runtime_platform.machine().lower())
    if system is None or machine is None:
        raise HostLifecycleError("local runtime platform/architecture is unsupported")
    return system, machine


def require_runtime_target(body: Mapping[str, Any]) -> None:
    local_platform, local_arch = runtime_target()
    target_arch = body["arch"]
    arch_matches = target_arch == local_arch or (
        body["platform"] == "macos" and target_arch == "universal2"
    )
    if body["platform"] != local_platform or not arch_matches:
        raise HostLifecycleError(
            "signed release targets a different runtime platform/architecture"
        )


def release_id(body: Mapping[str, Any]) -> str:
    unsigned = {key: value for key, value in body.items() if key != "release_id"}
    return sha256_bytes(RELEASE_ID_DOMAIN + canonical_json(unsigned))


def rollback_id(body: Mapping[str, Any]) -> str:
    unsigned = {
        key: value for key, value in body.items() if key != "authorization_id"
    }
    return sha256_bytes(ROLLBACK_ID_DOMAIN + canonical_json(unsigned))


def validate_manifest_body(body: Any) -> dict[str, Any]:
    if not isinstance(body, dict) or set(body) != BODY_FIELDS:
        raise HostLifecycleError("host release body fields are malformed")
    for field in (
        "release_id",
        "chain_id",
        "genesis_hash",
        "release_signer_key_id",
        "rollback_signer_key_id",
    ):
        if not isinstance(body.get(field), str) or HEX64.fullmatch(body[field]) is None:
            raise HostLifecycleError(f"{field} must be lowercase hex64")
    if body["release_id"] != release_id(body):
        raise HostLifecycleError("release_id does not match the canonical release body")
    sequence = body.get("release_sequence")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise HostLifecycleError("release_sequence must be a positive integer")
    if not isinstance(body.get("version"), str) or VERSION.fullmatch(body["version"]) is None:
        raise HostLifecycleError("release version is malformed")
    if not isinstance(body.get("source_revision"), str) or HEX40.fullmatch(
        body["source_revision"]
    ) is None:
        raise HostLifecycleError("source_revision must be lowercase Git hex40")
    platform = body.get("platform")
    arch = body.get("arch")
    if platform not in SUPPORTED_TARGETS or arch not in SUPPORTED_TARGETS[platform]:
        raise HostLifecycleError(
            "host release platform/architecture is unsupported; expected "
            "linux x86_64/aarch64, macos x86_64/aarch64/universal2, or "
            "windows x86_64/aarch64"
        )
    rollback_public = decode_public(body.get("rollback_public_key_base64"))
    if sha256_bytes(rollback_public) != body["rollback_signer_key_id"]:
        raise HostLifecycleError("rollback key does not match rollback_signer_key_id")

    artifacts = body.get("artifacts")
    if not isinstance(artifacts, list) or not 5 <= len(artifacts) <= MAX_ARTIFACTS:
        raise HostLifecycleError("host release artifact list is missing or unbounded")
    artifact_paths: set[str] = set()
    executable_paths: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != ARTIFACT_FIELDS:
            raise HostLifecycleError("artifact fields are malformed")
        path = safe_relative(artifact.get("path"), "artifact path")
        if path in artifact_paths:
            raise HostLifecycleError("artifact path is duplicated")
        artifact_paths.add(path)
        if not isinstance(artifact.get("sha256"), str) or HEX64.fullmatch(
            artifact["sha256"]
        ) is None:
            raise HostLifecycleError("artifact SHA-256 is malformed")
        if not isinstance(artifact.get("executable"), bool):
            raise HostLifecycleError("artifact executable flag must be boolean")
        if artifact["executable"]:
            executable_paths.add(path)
    if artifacts != sorted(artifacts, key=lambda row: row["path"]):
        raise HostLifecycleError("artifacts must be sorted by path")

    services = body.get("services")
    if (
        not isinstance(services, list)
        or tuple(row.get("name") for row in services if isinstance(row, dict))
        != SERVICE_ORDER
    ):
        raise HostLifecycleError("host release must define the fixed service order")
    for service in services:
        if not isinstance(service, dict) or set(service) != SERVICE_FIELDS:
            raise HostLifecycleError("service fields are malformed")
        name = service["name"]
        artifact = safe_relative(service.get("artifact"), f"{name} artifact")
        if artifact not in executable_paths:
            raise HostLifecycleError(f"{name} does not reference an executable artifact")
        if tuple(service.get("dependencies", ())) != SERVICE_DEPENDENCIES[name]:
            raise HostLifecycleError(f"{name} dependencies differ from the fixed service DAG")
        if service.get("private_config") != f"{name}.env":
            raise HostLifecycleError(f"{name} private configuration filename is not canonical")
        argv = service.get("argv")
        if (
            not isinstance(argv, list)
            or len(argv) > 128
            or any(
                not isinstance(item, str)
                or not item
                or "\x00" in item
                or "\n" in item
                or re.search(r"(?i)(password|secret|token|private[-_]?key|seed)", item)
                for item in argv
            )
        ):
            raise HostLifecycleError(f"{name} argv is malformed, unbounded, or contains a secret")
    return body


def freeze_manifest(
    unsigned_path: Path, release_seed_path: Path, output: Path
) -> dict[str, Any]:
    unsigned = load_object(unsigned_path)
    if set(unsigned) != {"schema", "body"} or unsigned.get("schema") != MANIFEST_SCHEMA:
        raise HostLifecycleError("unsigned host release envelope is malformed")
    body = validate_manifest_body(unsigned.get("body"))
    private = Ed25519PrivateKey.from_private_bytes(load_seed(release_seed_path))
    _, key_id = public_identity(private)
    if body["release_signer_key_id"] != key_id:
        raise HostLifecycleError("release seed differs from release_signer_key_id")
    envelope = {
        "schema": MANIFEST_SCHEMA,
        "body": body,
        "signature": signature_record(private, MANIFEST_DOMAIN, body),
    }
    atomic_create(output, envelope, 0o644)
    return envelope


def verify_manifest(document: Any, expected_key_id: str) -> dict[str, Any]:
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "body", "signature"}
        or document.get("schema") != MANIFEST_SCHEMA
    ):
        raise HostLifecycleError("signed host release envelope is malformed")
    body = validate_manifest_body(document.get("body"))
    if body["release_signer_key_id"] != expected_key_id:
        raise HostLifecycleError("manifest embeds a different release trust anchor")
    verify_signature(document.get("signature"), MANIFEST_DOMAIN, body, expected_key_id)
    return body


def validate_private_config(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise HostLifecycleError(f"private configuration is missing or a symlink: {path}")
    try:
        payload = path.read_bytes()
    except OSError as error:
        raise HostLifecycleError(f"cannot read private configuration {path}: {error}") from error
    if not payload or len(payload) > MAX_PRIVATE_CONFIG_BYTES or b"\x00" in payload:
        raise HostLifecycleError(
            f"private configuration {path} is empty or unbounded"
        )
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise HostLifecycleError(f"private configuration {path} is not UTF-8") from error
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    keys: set[str] = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator != "=" or ENV_KEY.fullmatch(key) is None or not value:
            raise HostLifecycleError(f"private configuration {path} has a malformed entry")
        if key in keys:
            raise HostLifecycleError(f"private configuration {path} duplicates {key}")
        keys.add(key)
    if not keys:
        raise HostLifecycleError(f"private configuration {path} contains no values")
    return text.encode("utf-8")


def ensure_separate_roots(install_root: Path, state_root: Path, private_root: Path) -> None:
    roots = [install_root.resolve(), state_root.resolve(), private_root.resolve()]
    for index, first in enumerate(roots):
        for second in roots[index + 1 :]:
            try:
                first.relative_to(second)
                nested = True
            except ValueError:
                try:
                    second.relative_to(first)
                    nested = True
                except ValueError:
                    nested = False
            if nested:
                raise HostLifecycleError("install, durable-state, and private roots must be separate")


def systemd_quote(value: str) -> str:
    if "\x00" in value or "\n" in value:
        raise HostLifecycleError("systemd argument contains a forbidden byte")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def service_user(name: str) -> str:
    return f"mindchain-{name}"


def render_unit(
    service: Mapping[str, Any], release_root: Path, state_root: Path, private_root: Path
) -> str:
    name = service["name"]
    dependencies = [f"mindchain-{item}.service" for item in service["dependencies"]]
    after = ["network-online.target", *dependencies]
    wants = ["network-online.target", *dependencies]
    executable = release_root / PurePosixPath(service["artifact"])
    command = " ".join(
        [systemd_quote(str(executable)), *(systemd_quote(item) for item in service["argv"])]
    )
    return "\n".join(
        [
            "[Unit]",
            f"Description=MindChain {name}",
            f"After={' '.join(after)}",
            f"Wants={' '.join(wants)}",
            "StartLimitIntervalSec=300",
            "StartLimitBurst=5",
            "",
            "[Service]",
            "Type=simple",
            f"User={service_user(name)}",
            f"Group={service_user(name)}",
            f"WorkingDirectory={systemd_quote(str(state_root / name))}",
            f"EnvironmentFile={systemd_quote(str(private_root / service['private_config']))}",
            f"ExecStart={command}",
            "Restart=on-failure",
            "RestartSec=5s",
            "TimeoutStopSec=30s",
            "KillSignal=SIGTERM",
            "UMask=0077",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            "PrivateDevices=true",
            "ProtectSystem=strict",
            "ProtectHome=true",
            "ProtectClock=true",
            "ProtectControlGroups=true",
            "ProtectKernelLogs=true",
            "ProtectKernelModules=true",
            "ProtectKernelTunables=true",
            "RestrictSUIDSGID=true",
            "RestrictRealtime=true",
            "LockPersonality=true",
            "CapabilityBoundingSet=",
            "AmbientCapabilities=",
            "RestrictNamespaces=true",
            "SystemCallArchitectures=native",
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
            f"ReadOnlyPaths={systemd_quote(str(release_root))}",
            f"ReadWritePaths={systemd_quote(str(state_root / name))}",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        ]
    )


def shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def render_activation_scripts(
    services: list[dict[str, Any]], units_root: Path, state_root: Path, private_root: Path
) -> tuple[str, str]:
    install_lines = ["#!/bin/sh", "set -eu", 'test "$(id -u)" -eq 0 || { echo "root required" >&2; exit 1; }']
    for service in services:
        name = service["name"]
        user = service_user(name)
        install_lines.extend(
            [
                f"id -u {shell_quote(user)} >/dev/null 2>&1 || useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin {shell_quote(user)}",
                f"install -d -o {shell_quote(user)} -g {shell_quote(user)} -m 0700 {shell_quote(str(state_root / name))}",
                f"chown {shell_quote(user)}:{shell_quote(user)} {shell_quote(str(private_root / service['private_config']))}",
                f"chmod 0600 {shell_quote(str(private_root / service['private_config']))}",
                f"install -o root -g root -m 0644 {shell_quote(str(units_root / f'mindchain-{name}.service'))} {shell_quote(f'/etc/systemd/system/mindchain-{name}.service')}",
            ]
        )
    install_lines.extend(
        [
            "systemctl daemon-reload",
            "systemctl enable --now "
            + " ".join(f"mindchain-{name}.service" for name in SERVICE_ORDER),
            "",
        ]
    )
    remove_lines = [
        "#!/bin/sh",
        "set -eu",
        'test "$(id -u)" -eq 0 || { echo "root required" >&2; exit 1; }',
        "systemctl disable --now "
        + " ".join(f"mindchain-{name}.service" for name in reversed(SERVICE_ORDER))
        + " || true",
    ]
    remove_lines.extend(
        f"rm -f {shell_quote(f'/etc/systemd/system/mindchain-{name}.service')}"
        for name in SERVICE_ORDER
    )
    remove_lines.extend(["systemctl daemon-reload", ""])
    return "\n".join(install_lines), "\n".join(remove_lines)


def powershell_quote(value: str) -> str:
    if "\x00" in value or "\r" in value or "\n" in value:
        raise HostLifecycleError("PowerShell argument contains a forbidden byte")
    return "'" + value.replace("'", "''") + "'"


def render_posix_env_launcher(
    service: Mapping[str, Any],
    release_root: Path,
    private_root: Path,
) -> str:
    executable = release_root.joinpath(*PurePosixPath(service["artifact"]).parts)
    command = " ".join(
        [shell_quote(str(executable)), *(shell_quote(item) for item in service["argv"])]
    )
    private_path = private_root / service["private_config"]
    return "\n".join(
        [
            "#!/bin/sh",
            "set -eu",
            "while IFS= read -r line || [ -n \"$line\" ]; do",
            "    case \"$line\" in ''|'#'*) continue ;; esac",
            "    key=${line%%=*}",
            "    value=${line#*=}",
            "    export \"$key=$value\"",
            f"done < {shell_quote(str(private_path))}",
            f"exec {command}",
            "",
        ]
    )


def render_launchd_plist(
    service: Mapping[str, Any], package_root: Path, state_root: Path
) -> str:
    name = service["name"]
    state = state_root / name
    document = {
        "KeepAlive": {"SuccessfulExit": False},
        "Label": f"org.mindchain.{name}",
        "ProcessType": "Background",
        "ProgramArguments": [str(package_root / f"run-{name}.sh")],
        "RunAtLoad": True,
        "StandardErrorPath": str(state / "stderr.log"),
        "StandardOutPath": str(state / "stdout.log"),
        "ThrottleInterval": 5,
        "Umask": 0o077,
        "WorkingDirectory": str(state),
    }
    return plistlib.dumps(
        document, fmt=plistlib.FMT_XML, sort_keys=True
    ).decode("utf-8")


def render_launchd_activation_scripts(
    services: list[dict[str, Any]],
    package_root: Path,
    state_root: Path,
    private_root: Path,
) -> tuple[str, str]:
    activate = [
        "#!/bin/sh",
        "set -eu",
        'DOMAIN="gui/$(id -u)"',
        'AGENT_ROOT="$HOME/Library/LaunchAgents"',
        'install -d -m 0700 "$AGENT_ROOT"',
    ]
    for service in services:
        name = service["name"]
        label = f"org.mindchain.{name}"
        plist_name = f"{label}.plist"
        activate.extend(
            [
                f"install -d -m 0700 {shell_quote(str(state_root / name))}",
                f"chmod 0600 {shell_quote(str(private_root / service['private_config']))}",
                f"launchctl bootout \"$DOMAIN/{label}\" >/dev/null 2>&1 || true",
                f"install -m 0600 {shell_quote(str(package_root / plist_name))} \"$AGENT_ROOT/{plist_name}\"",
                f"launchctl bootstrap \"$DOMAIN\" \"$AGENT_ROOT/{plist_name}\"",
                f"launchctl kickstart -k \"$DOMAIN/{label}\"",
            ]
        )
    activate.append("")
    deactivate = [
        "#!/bin/sh",
        "set -eu",
        'DOMAIN="gui/$(id -u)"',
        'AGENT_ROOT="$HOME/Library/LaunchAgents"',
    ]
    for name in reversed(SERVICE_ORDER):
        label = f"org.mindchain.{name}"
        plist_name = f"{label}.plist"
        deactivate.extend(
            [
                f"launchctl bootout \"$DOMAIN/{label}\" >/dev/null 2>&1 || true",
                f"rm -f \"$AGENT_ROOT/{plist_name}\"",
            ]
        )
    deactivate.append("")
    return "\n".join(activate), "\n".join(deactivate)


def render_powershell_env_launcher(
    service: Mapping[str, Any],
    release_root: Path,
    private_root: Path,
) -> str:
    executable = release_root.joinpath(*PurePosixPath(service["artifact"]).parts)
    arguments = ", ".join(powershell_quote(item) for item in service["argv"])
    return "\n".join(
        [
            "#Requires -Version 5.1",
            "$ErrorActionPreference = 'Stop'",
            f"$PrivateConfig = {powershell_quote(str(private_root / service['private_config']))}",
            "foreach ($Line in [System.IO.File]::ReadAllLines($PrivateConfig, [System.Text.Encoding]::UTF8)) {",
            "    if ([String]::IsNullOrEmpty($Line) -or $Line.StartsWith('#')) { continue }",
            "    $Separator = $Line.IndexOf('=')",
            "    if ($Separator -le 0) { throw 'private configuration entry is malformed' }",
            "    $Key = $Line.Substring(0, $Separator)",
            "    $Value = $Line.Substring($Separator + 1)",
            "    if ($Key -notmatch '^[A-Z][A-Z0-9_]{0,63}$' -or [String]::IsNullOrEmpty($Value)) {",
            "        throw 'private configuration entry is malformed'",
            "    }",
            "    [Environment]::SetEnvironmentVariable($Key, $Value, [EnvironmentVariableTarget]::Process)",
            "}",
            f"$Arguments = @({arguments})",
            f"& {powershell_quote(str(executable))} @Arguments",
            "exit $LASTEXITCODE",
            "",
        ]
    )


def render_windows_activation_scripts(
    services: list[dict[str, Any]],
    package_root: Path,
    state_root: Path,
    private_root: Path,
) -> tuple[str, str]:
    activate = [
        "#Requires -Version 5.1",
        "$ErrorActionPreference = 'Stop'",
        "$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()",
        "$Trigger = New-ScheduledTaskTrigger -AtLogOn -User $Identity.Name",
        "$Principal = New-ScheduledTaskPrincipal -UserId $Identity.Name -LogonType Interactive -RunLevel Limited",
        "$Settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew",
    ]
    for service in services:
        name = service["name"]
        runner = package_root / f"run-{name}.ps1"
        state = state_root / name
        private = private_root / service["private_config"]
        dependencies = ",".join(service["dependencies"]) or "none"
        activate.extend(
            [
                f"$StatePath = {powershell_quote(str(state))}",
                "New-Item -ItemType Directory -Path $StatePath -Force | Out-Null",
                "& icacls.exe $StatePath /inheritance:r /grant:r ('*' + $Identity.User.Value + ':(OI)(CI)F') | Out-Null",
                "if ($LASTEXITCODE -ne 0) { throw 'failed to restrict durable state ACL' }",
                f"$PrivatePath = {powershell_quote(str(private))}",
                "& icacls.exe $PrivatePath /inheritance:r /grant:r ('*' + $Identity.User.Value + ':F') | Out-Null",
                "if ($LASTEXITCODE -ne 0) { throw 'failed to restrict private configuration ACL' }",
                f"$Runner = {powershell_quote(str(runner))}",
                "$RunnerArguments = '-NoProfile -NonInteractive -ExecutionPolicy RemoteSigned -File \"' + $Runner + '\"'",
                "$Action = New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'powershell.exe') -Argument $RunnerArguments",
                f"Register-ScheduledTask -TaskName {powershell_quote(f'MindChain-{name}')} -Action $Action -Trigger $Trigger -Settings $Settings -Principal $Principal -Description {powershell_quote(f'MindChain {name}; dependencies={dependencies}')} -Force | Out-Null",
            ]
        )
    activate.extend(
        f"Start-ScheduledTask -TaskName {powershell_quote(f'MindChain-{name}')}"
        for name in SERVICE_ORDER
    )
    activate.append("")
    deactivate = [
        "#Requires -Version 5.1",
        "$ErrorActionPreference = 'Stop'",
    ]
    deactivate.extend(
        f"Unregister-ScheduledTask -TaskName {powershell_quote(f'MindChain-{name}')} -Confirm:$false -ErrorAction SilentlyContinue"
        for name in reversed(SERVICE_ORDER)
    )
    deactivate.append("")
    return "\n".join(activate), "\n".join(deactivate)


def windows_task_descriptor(
    service: Mapping[str, Any], package_root: Path
) -> dict[str, Any]:
    name = service["name"]
    return {
        "schema": "noos/mindchain-windows-autostart-task/v1",
        "service": name,
        "task_name": f"MindChain-{name}",
        "trigger": "CURRENT_USER_LOGON",
        "run_level": "LIMITED",
        "dependencies": service["dependencies"],
        "runner": str(package_root / f"run-{name}.ps1"),
        "restart_count": 5,
        "restart_interval_seconds": 60,
    }


def build_release_tree(
    body: Mapping[str, Any], envelope: Mapping[str, Any], source_root: Path, destination: Path
) -> None:
    if destination.exists():
        raise HostLifecycleError(f"release destination already exists: {destination}")
    destination.mkdir(parents=True)
    try:
        for artifact in body["artifacts"]:
            relative = PurePosixPath(artifact["path"])
            source = source_root.joinpath(*relative.parts)
            if source.is_symlink() or not source.is_file():
                raise HostLifecycleError(f"artifact is missing or a symlink: {source}")
            if sha256_file(source) != artifact["sha256"]:
                raise HostLifecycleError(f"artifact checksum differs: {artifact['path']}")
            target = destination.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            os.chmod(target, 0o555 if artifact["executable"] else 0o444)
        manifest_path = destination / "release-manifest.json"
        manifest_path.write_bytes(canonical_json(envelope) + b"\n")
        os.chmod(manifest_path, 0o444)
    except BaseException:
        remove_tree(destination, ignore_errors=True)
        raise


def verify_release_tree(body: Mapping[str, Any], release_root: Path) -> None:
    for artifact in body["artifacts"]:
        path = release_root.joinpath(*PurePosixPath(artifact["path"]).parts)
        if path.is_symlink() or not path.is_file() or sha256_file(path) != artifact["sha256"]:
            raise HostLifecycleError(f"installed artifact is missing or corrupt: {artifact['path']}")


def security_path(state_root: Path) -> Path:
    return state_root / "host-control" / "security.json"


def load_security(state_root: Path) -> dict[str, Any] | None:
    path = security_path(state_root)
    if not path.exists():
        return None
    state = load_object(path)
    if not isinstance(state, dict) or set(state) != SECURITY_FIELDS or state.get("schema") != SECURITY_SCHEMA:
        raise HostLifecycleError("host security state fields are malformed")
    if not isinstance(state.get("trust_key_id"), str) or HEX64.fullmatch(state["trust_key_id"]) is None:
        raise HostLifecycleError("host security trust key is malformed")
    highest = state.get("highest_release_sequence")
    if not isinstance(highest, int) or isinstance(highest, bool) or highest < 1:
        raise HostLifecycleError("host highest release sequence is malformed")
    platform = state.get("platform")
    arch = state.get("arch")
    if platform not in SUPPORTED_TARGETS or arch not in SUPPORTED_TARGETS[platform]:
        raise HostLifecycleError("host security platform/architecture is malformed")
    for field in ("current_release_id", "previous_release_id"):
        value = state.get(field)
        if value is not None and (not isinstance(value, str) or HEX64.fullmatch(value) is None):
            raise HostLifecycleError(f"host {field} is malformed")
    installed = state.get("installed_release_ids")
    used = state.get("used_rollback_authorization_ids")
    events = state.get("events")
    if (
        not isinstance(installed, list)
        or installed != list(dict.fromkeys(installed))
        or any(not isinstance(value, str) or HEX64.fullmatch(value) is None for value in installed)
        or not isinstance(used, list)
        or used != list(dict.fromkeys(used))
        or any(not isinstance(value, str) or HEX64.fullmatch(value) is None for value in used)
        or not isinstance(events, list)
        or len(events) > MAX_EVENTS
    ):
        raise HostLifecycleError("host security history is malformed or unbounded")
    return state


def append_event(state: dict[str, Any], action: str, release: str, now: datetime) -> None:
    if len(state["events"]) >= MAX_EVENTS:
        raise HostLifecycleError("host lifecycle event ledger is full")
    state["events"].append(
        {
            "sequence": len(state["events"]) + 1,
            "action": action,
            "release_id": release,
            "observed_at_utc": format_utc(now),
        }
    )


def prepare_private_and_state(
    services: list[dict[str, Any]], private_source: Path, private_root: Path, state_root: Path
) -> None:
    private_root.mkdir(parents=True, exist_ok=True)
    state_root.mkdir(parents=True, exist_ok=True)
    for service in services:
        name = service["name"]
        source = private_source / service["private_config"]
        payload = validate_private_config(source)
        target = private_root / service["private_config"]
        if target.exists():
            if validate_private_config(target) != payload:
                raise HostLifecycleError(
                    f"private configuration mutation for {name} requires an explicit credential rotation"
                )
        else:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        (state_root / name).mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(state_root / name, 0o700)
            os.chmod(target, 0o600)
        except OSError as error:
            raise HostLifecycleError(f"cannot secure private/state path for {name}: {error}") from error


def render_service_package(
    body: Mapping[str, Any],
    install_root: Path,
    state_root: Path,
    private_root: Path,
) -> Path:
    release_root = install_root / "releases" / body["release_id"]
    platform = body["platform"]
    package_name = SERVICE_PACKAGE_DIRECTORIES[platform]
    package_root = install_root / package_name
    stage = install_root / f".{package_name}-stage-{body['release_id']}"
    if stage.exists():
        remove_tree(stage)
    stage.mkdir(parents=True)

    if platform == "linux":
        for service in body["services"]:
            (stage / f"mindchain-{service['name']}.service").write_text(
                render_unit(service, release_root, state_root, private_root),
                encoding="utf-8",
            )
        activate, deactivate = render_activation_scripts(
            body["services"], package_root, state_root, private_root
        )
        (stage / "activate-systemd.sh").write_text(
            activate, encoding="utf-8", newline="\n"
        )
        (stage / "deactivate-systemd.sh").write_text(
            deactivate, encoding="utf-8", newline="\n"
        )
    elif platform == "macos":
        for service in body["services"]:
            name = service["name"]
            (stage / f"run-{name}.sh").write_text(
                render_posix_env_launcher(service, release_root, private_root),
                encoding="utf-8",
                newline="\n",
            )
            (stage / f"org.mindchain.{name}.plist").write_text(
                render_launchd_plist(service, package_root, state_root),
                encoding="utf-8",
                newline="\n",
            )
        activate, deactivate = render_launchd_activation_scripts(
            body["services"], package_root, state_root, private_root
        )
        (stage / "activate-launchd.sh").write_text(
            activate, encoding="utf-8", newline="\n"
        )
        (stage / "deactivate-launchd.sh").write_text(
            deactivate, encoding="utf-8", newline="\n"
        )
    else:
        for service in body["services"]:
            name = service["name"]
            (stage / f"run-{name}.ps1").write_text(
                render_powershell_env_launcher(service, release_root, private_root),
                encoding="utf-8",
                newline="\n",
            )
            (stage / f"mindchain-{name}.task.json").write_bytes(
                canonical_json(windows_task_descriptor(service, package_root)) + b"\n"
            )
        activate, deactivate = render_windows_activation_scripts(
            body["services"], package_root, state_root, private_root
        )
        (stage / "activate-tasks.ps1").write_text(
            activate, encoding="utf-8", newline="\n"
        )
        (stage / "deactivate-tasks.ps1").write_text(
            deactivate, encoding="utf-8", newline="\n"
        )

    for path in stage.iterdir():
        os.chmod(path, 0o555 if path.suffix == ".sh" else 0o444)
    backup = install_root / f".{package_name}-prior"
    if backup.exists():
        remove_tree(backup)
    if package_root.exists():
        os.replace(package_root, backup)
    try:
        os.replace(stage, package_root)
    except BaseException:
        if backup.exists() and not package_root.exists():
            os.replace(backup, package_root)
        raise
    remove_tree(backup, ignore_errors=True)
    return package_root


def write_pointer(install_root: Path, body: Mapping[str, Any]) -> None:
    atomic_write(
        install_root / "current.json",
        {
            "schema": POINTER_SCHEMA,
            "release_id": body["release_id"],
            "release_sequence": body["release_sequence"],
            "release_root": str(install_root / "releases" / body["release_id"]),
        },
        0o644,
    )


def install_release(
    manifest: Mapping[str, Any],
    expected_key_id: str,
    source_root: Path,
    private_source: Path,
    install_root: Path,
    state_root: Path,
    private_root: Path,
    *,
    now: datetime | None = None,
    enforce_runtime_target: bool = True,
) -> dict[str, Any]:
    observed_now = now or datetime.now(timezone.utc)
    ensure_separate_roots(install_root, state_root, private_root)
    body = verify_manifest(manifest, expected_key_id)
    if enforce_runtime_target:
        require_runtime_target(body)
    security = load_security(state_root)
    reinstall = False
    if security is None:
        security = {
            "schema": SECURITY_SCHEMA,
            "trust_key_id": expected_key_id,
            "highest_release_sequence": body["release_sequence"],
            "platform": body["platform"],
            "arch": body["arch"],
            "current_release_id": None,
            "previous_release_id": None,
            "installed_release_ids": [],
            "used_rollback_authorization_ids": [],
            "events": [],
        }
    else:
        if security["trust_key_id"] != expected_key_id:
            raise HostLifecycleError("release trust anchor changed across update")
        if (security["platform"], security["arch"]) != (
            body["platform"],
            body["arch"],
        ):
            raise HostLifecycleError(
                "release platform/architecture changed across update"
            )
        current = security["current_release_id"]
        if current is None and body["release_id"] in security["installed_release_ids"] and body["release_sequence"] == security["highest_release_sequence"]:
            reinstall = True
        elif body["release_sequence"] <= security["highest_release_sequence"]:
            raise HostLifecycleError("signed release is a replay or downgrade")
    prepare_private_and_state(body["services"], private_source, private_root, state_root)
    install_root.mkdir(parents=True, exist_ok=True)
    releases = install_root / "releases"
    releases.mkdir(exist_ok=True)
    target = releases / body["release_id"]
    if target.exists():
        stored = load_object(target / "release-manifest.json")
        stored_body = verify_manifest(stored, expected_key_id)
        if stored_body != body:
            raise HostLifecycleError("existing release directory conflicts with signed manifest")
        verify_release_tree(body, target)
    else:
        stage = releases / f".{body['release_id']}.stage"
        if stage.exists():
            remove_tree(stage)
        build_release_tree(body, manifest, source_root, stage)
        os.replace(stage, target)
    previous = security["current_release_id"]
    security["previous_release_id"] = previous
    security["current_release_id"] = body["release_id"]
    security["highest_release_sequence"] = max(
        security["highest_release_sequence"], body["release_sequence"]
    )
    if body["release_id"] not in security["installed_release_ids"]:
        security["installed_release_ids"].append(body["release_id"])
    append_event(
        security,
        "REINSTALL" if reinstall else "INSTALL",
        body["release_id"],
        observed_now,
    )
    package = render_service_package(body, install_root, state_root, private_root)
    write_pointer(install_root, body)
    atomic_write(security_path(state_root), security)
    return {
        "release_id": body["release_id"],
        "release_sequence": body["release_sequence"],
        "previous_release_id": previous,
        "platform": body["platform"],
        "service_package_directory": str(package),
        "service_package_files": sorted(path.name for path in package.iterdir()),
        "state_preserved": True,
        "private_config_preserved": True,
        "action": "REINSTALL" if reinstall else "INSTALL",
    }


def repair_release(
    manifest: Mapping[str, Any],
    expected_key_id: str,
    source_root: Path,
    private_source: Path,
    install_root: Path,
    state_root: Path,
    private_root: Path,
    *,
    now: datetime | None = None,
    enforce_runtime_target: bool = True,
) -> dict[str, Any]:
    observed_now = now or datetime.now(timezone.utc)
    ensure_separate_roots(install_root, state_root, private_root)
    body = verify_manifest(manifest, expected_key_id)
    if enforce_runtime_target:
        require_runtime_target(body)
    security = load_security(state_root)
    if security is None or security["current_release_id"] != body["release_id"]:
        raise HostLifecycleError("repair manifest is not the current installed release")
    if security["trust_key_id"] != expected_key_id:
        raise HostLifecycleError("repair trust anchor differs from durable state")
    prepare_private_and_state(body["services"], private_source, private_root, state_root)
    releases = install_root / "releases"
    target = releases / body["release_id"]
    stage = releases / f".{body['release_id']}.repair"
    backup = releases / f".{body['release_id']}.corrupt"
    for path in (stage, backup):
        if path.exists():
            remove_tree(path)
    build_release_tree(body, manifest, source_root, stage)
    if target.exists():
        os.replace(target, backup)
    try:
        os.replace(stage, target)
    except BaseException:
        if backup.exists() and not target.exists():
            os.replace(backup, target)
        raise
    remove_tree(backup, ignore_errors=True)
    verify_release_tree(body, target)
    append_event(security, "REPAIR", body["release_id"], observed_now)
    package = render_service_package(body, install_root, state_root, private_root)
    write_pointer(install_root, body)
    atomic_write(security_path(state_root), security)
    return {
        "release_id": body["release_id"],
        "platform": body["platform"],
        "service_package_directory": str(package),
        "action": "REPAIR",
        "state_preserved": True,
        "private_config_preserved": True,
    }


def authorize_rollback(
    current_manifest: Mapping[str, Any],
    target_release_id: str,
    rollback_seed_path: Path,
    output: Path,
    authorized_at: datetime,
    expires_at: datetime,
    reason: str,
) -> dict[str, Any]:
    current_body = validate_manifest_body(current_manifest.get("body"))
    if not isinstance(target_release_id, str) or HEX64.fullmatch(target_release_id) is None:
        raise HostLifecycleError("rollback target release id is malformed")
    if target_release_id == current_body["release_id"]:
        raise HostLifecycleError("rollback target equals the current release")
    if authorized_at >= expires_at:
        raise HostLifecycleError("rollback authorization interval is empty")
    if not isinstance(reason, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 ._:-]{0,255}", reason):
        raise HostLifecycleError("rollback reason is malformed or unbounded")
    private = Ed25519PrivateKey.from_private_bytes(load_seed(rollback_seed_path))
    _, key_id = public_identity(private)
    if key_id != current_body["rollback_signer_key_id"]:
        raise HostLifecycleError("rollback seed differs from the current release policy")
    body: dict[str, Any] = {
        "authorization_id": "",
        "current_release_id": current_body["release_id"],
        "target_release_id": target_release_id,
        "authorized_at_utc": format_utc(authorized_at),
        "expires_at_utc": format_utc(expires_at),
        "reason": reason,
        "signer_key_id": key_id,
    }
    body["authorization_id"] = rollback_id(body)
    envelope = {
        "schema": ROLLBACK_SCHEMA,
        "body": body,
        "signature": signature_record(private, ROLLBACK_DOMAIN, body),
    }
    atomic_create(output, envelope)
    return envelope


def verify_rollback_authorization(
    document: Any, current_body: Mapping[str, Any], target_release_id: str, now: datetime
) -> dict[str, Any]:
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "body", "signature"}
        or document.get("schema") != ROLLBACK_SCHEMA
    ):
        raise HostLifecycleError("rollback authorization envelope is malformed")
    body = document.get("body")
    if not isinstance(body, dict) or set(body) != ROLLBACK_BODY_FIELDS:
        raise HostLifecycleError("rollback authorization body fields are malformed")
    for field in ("authorization_id", "current_release_id", "target_release_id", "signer_key_id"):
        if not isinstance(body.get(field), str) or HEX64.fullmatch(body[field]) is None:
            raise HostLifecycleError(f"rollback {field} is malformed")
    if body["authorization_id"] != rollback_id(body):
        raise HostLifecycleError("rollback authorization id does not match its body")
    if body["current_release_id"] != current_body["release_id"] or body["target_release_id"] != target_release_id:
        raise HostLifecycleError("rollback authorization does not bind the direct transition")
    if body["signer_key_id"] != current_body["rollback_signer_key_id"]:
        raise HostLifecycleError("rollback authorization uses the wrong policy key")
    if not isinstance(body.get("reason"), str) or not re.fullmatch(
        r"[A-Za-z0-9][A-Za-z0-9 ._:-]{0,255}", body["reason"]
    ):
        raise HostLifecycleError("rollback reason is malformed")
    authorized = parse_utc(body.get("authorized_at_utc"), "authorized_at_utc")
    expires = parse_utc(body.get("expires_at_utc"), "expires_at_utc")
    if authorized >= expires or now < authorized or now > expires:
        raise HostLifecycleError("rollback authorization is not currently valid")
    public = decode_public(current_body["rollback_public_key_base64"])
    if sha256_bytes(public) != body["signer_key_id"]:
        raise HostLifecycleError("rollback public key differs from the signed release")
    verify_signature(document.get("signature"), ROLLBACK_DOMAIN, body, body["signer_key_id"])
    return body


def load_stored_manifest(install_root: Path, release_id_value: str) -> dict[str, Any]:
    return load_object(
        install_root / "releases" / release_id_value / "release-manifest.json"
    )


def rollback_release(
    authorization: Mapping[str, Any],
    install_root: Path,
    state_root: Path,
    private_root: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    observed_now = now or datetime.now(timezone.utc)
    security = load_security(state_root)
    if security is None or security["current_release_id"] is None:
        raise HostLifecycleError("no installed current release can be rolled back")
    current_id = security["current_release_id"]
    target_id = security["previous_release_id"]
    if target_id is None or target_id not in security["installed_release_ids"]:
        raise HostLifecycleError("rollback target is not the direct installed predecessor")
    current_manifest = load_stored_manifest(install_root, current_id)
    current_body = verify_manifest(current_manifest, security["trust_key_id"])
    target_manifest = load_stored_manifest(install_root, target_id)
    target_body = verify_manifest(target_manifest, security["trust_key_id"])
    auth_body = verify_rollback_authorization(
        authorization, current_body, target_id, observed_now
    )
    if auth_body["authorization_id"] in security["used_rollback_authorization_ids"]:
        raise HostLifecycleError("rollback authorization has already been consumed")
    verify_release_tree(target_body, install_root / "releases" / target_id)
    old_current = current_id
    security["current_release_id"] = target_id
    security["previous_release_id"] = old_current
    security["used_rollback_authorization_ids"].append(auth_body["authorization_id"])
    append_event(security, "ROLLBACK", target_id, observed_now)
    package = render_service_package(
        target_body, install_root, state_root, private_root
    )
    write_pointer(install_root, target_body)
    atomic_write(security_path(state_root), security)
    return {
        "action": "ROLLBACK",
        "release_id": target_id,
        "rolled_back_from": old_current,
        "authorization_id": auth_body["authorization_id"],
        "platform": target_body["platform"],
        "service_package_directory": str(package),
        "state_preserved": True,
        "private_config_preserved": True,
    }


def uninstall_host(
    install_root: Path,
    state_root: Path,
    private_root: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    observed_now = now or datetime.now(timezone.utc)
    ensure_separate_roots(install_root, state_root, private_root)
    security = load_security(state_root)
    if security is None or security["current_release_id"] is None:
        raise HostLifecycleError("no installed host release can be uninstalled")
    current = security["current_release_id"]
    lifecycle_digest = sha256_file(security_path(state_root), MAX_MANIFEST_BYTES)
    append_event(security, "UNINSTALL", current, observed_now)
    security["current_release_id"] = None
    security["previous_release_id"] = None
    atomic_write(security_path(state_root), security)
    if install_root.exists():
        remove_tree(install_root)
    record = {
        "schema": UNINSTALL_SCHEMA,
        "release_id": current,
        "uninstalled_at_utc": format_utc(observed_now),
        "pre_uninstall_security_sha256": lifecycle_digest,
        "state_root": str(state_root.resolve()),
        "private_root": str(private_root.resolve()),
        "state_preserved": state_root.exists(),
        "private_config_preserved": private_root.exists(),
    }
    atomic_write(state_root / "host-control" / "last-uninstall.json", record)
    return record


def keygen(path: Path) -> dict[str, str]:
    if path.exists():
        raise HostLifecycleError(f"refusing to overwrite {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    private = Ed25519PrivateKey.generate()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(private.private_bytes_raw())
        stream.flush()
        os.fsync(stream.fileno())
    public, key_id = public_identity(private)
    return {"key_id": key_id, "public_key_base64": public}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("keygen")
    generate.add_argument("--out", type=Path, required=True)
    freeze = subparsers.add_parser("freeze")
    freeze.add_argument("--unsigned", type=Path, required=True)
    freeze.add_argument("--release-seed", type=Path, required=True)
    freeze.add_argument("--out", type=Path, required=True)
    for name in ("install", "repair"):
        command = subparsers.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--release-key-id", required=True)
        command.add_argument("--source", type=Path, required=True)
        command.add_argument("--private-source", type=Path, required=True)
        command.add_argument("--install-root", type=Path, required=True)
        command.add_argument("--state-root", type=Path, required=True)
        command.add_argument("--private-root", type=Path, required=True)
    authorize = subparsers.add_parser("authorize-rollback")
    authorize.add_argument("--current-manifest", type=Path, required=True)
    authorize.add_argument("--target-release-id", required=True)
    authorize.add_argument("--rollback-seed", type=Path, required=True)
    authorize.add_argument("--authorized-at", required=True)
    authorize.add_argument("--expires-at", required=True)
    authorize.add_argument("--reason", required=True)
    authorize.add_argument("--out", type=Path, required=True)
    rollback = subparsers.add_parser("rollback")
    rollback.add_argument("--authorization", type=Path, required=True)
    rollback.add_argument("--install-root", type=Path, required=True)
    rollback.add_argument("--state-root", type=Path, required=True)
    rollback.add_argument("--private-root", type=Path, required=True)
    uninstall = subparsers.add_parser("uninstall")
    uninstall.add_argument("--install-root", type=Path, required=True)
    uninstall.add_argument("--state-root", type=Path, required=True)
    uninstall.add_argument("--private-root", type=Path, required=True)
    verify = subparsers.add_parser("verify")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--release-key-id", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "keygen":
            result = keygen(args.out)
        elif args.command == "freeze":
            result = freeze_manifest(args.unsigned, args.release_seed, args.out)
        elif args.command in {"install", "repair"}:
            manifest = load_object(args.manifest)
            function = install_release if args.command == "install" else repair_release
            result = function(
                manifest,
                args.release_key_id,
                args.source,
                args.private_source,
                args.install_root,
                args.state_root,
                args.private_root,
            )
        elif args.command == "authorize-rollback":
            result = authorize_rollback(
                load_object(args.current_manifest),
                args.target_release_id,
                args.rollback_seed,
                args.out,
                parse_utc(args.authorized_at, "authorized_at"),
                parse_utc(args.expires_at, "expires_at"),
                args.reason,
            )
        elif args.command == "rollback":
            result = rollback_release(
                load_object(args.authorization),
                args.install_root,
                args.state_root,
                args.private_root,
            )
        elif args.command == "uninstall":
            result = uninstall_host(
                args.install_root, args.state_root, args.private_root
            )
        else:
            result = verify_manifest(
                load_object(args.manifest), args.release_key_id
            )
    except HostLifecycleError as error:
        print(f"RESULT host_lifecycle=FAIL reason={error}", file=os.sys.stderr)
        return 1
    print(canonical_json(result).decode("utf-8"))
    print(f"RESULT host_lifecycle=PASS command={args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
