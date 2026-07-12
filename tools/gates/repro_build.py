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
import contextlib
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python 3.10 compatibility
    import tomli as tomllib

ROOT = Path(__file__).resolve().parents[2]
POLICY = ROOT / "protocol/release/repro-policy-v1.toml"
POLICY_SIGNATURES = ROOT / "protocol/release/repro-policy-v1.signatures.json"
TOOLCHAINS = ROOT / "protocol/release/repro-toolchains-v1.json"
GO_MODULE = ROOT / "go"
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


def _command_failure(exc: subprocess.CalledProcessError, cwd: Path) -> AssuranceError:
    stderr = (exc.stderr or "").strip() if isinstance(exc.stderr, str) else ""
    stdout = (exc.stdout or "").strip() if isinstance(exc.stdout, str) else ""
    detail = stderr or stdout or "no stdout/stderr captured"
    rendered = subprocess.list2cmdline([str(part) for part in exc.cmd]) if isinstance(exc.cmd, (list, tuple)) else str(exc.cmd)
    return AssuranceError(f"command failed (exit {exc.returncode}, cwd={cwd}): {rendered}; stderr={detail}")


def command(args: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> str:
    try:
        completed = subprocess.run(args, cwd=cwd, env=env, check=True, text=True, capture_output=True)
    except subprocess.CalledProcessError as exc:
        raise _command_failure(exc, cwd) from exc
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

BUILD_INPUT_NAMES = {
    "Cargo.toml", "Cargo.lock", "build.rs", "rust-toolchain", "rust-toolchain.toml",
    "go.mod", "go.sum", "go.work", "go.work.sum", "Makefile", "CMakeLists.txt",
}
BUILD_INPUT_SUFFIXES = {".rs", ".go", ".c", ".cc", ".cpp", ".h", ".hpp", ".s", ".S", ".asm", ".toml"}
AMBIENT_BUILD_VARIABLES = {
    "RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_TARGET_DIR",
    "CARGO_CONFIG", "CARGO_HOME", "GOENV", "GOFLAGS", "GOWORK", "GOMODCACHE", "GOCACHE",
    "CC", "CXX", "AR", "LD", "PKG_CONFIG", "PKG_CONFIG_PATH",
}


def _is_build_input(relative: str) -> bool:
    path = Path(relative)
    lowered = relative.replace("\\", "/").lower()
    return (
        path.name in BUILD_INPUT_NAMES
        or path.suffix in BUILD_INPUT_SUFFIXES
        or lowered.startswith(("tools/", "scripts/", ".github/workflows/"))
    )


def validate_build_source(root: Path, revision: str, environ: Mapping[str, str] | None = None) -> None:
    """Reject caller-selected source/configuration before invoking a compiler."""
    env = os.environ if environ is None else environ
    ambient = sorted(name for name in AMBIENT_BUILD_VARIABLES if env.get(name))
    if ambient:
        raise AssuranceError("ambient build-affecting environment is forbidden: " + ", ".join(ambient))
    head = command(["git", "rev-parse", "HEAD"], cwd=root)
    if head != revision:
        raise AssuranceError(f"checkout HEAD {head} does not equal requested revision {revision}")
    porcelain = command(
        ["git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"],
        cwd=root,
    )
    violations: list[str] = []
    for line in porcelain.splitlines():
        if len(line) < 4:
            continue
        state, relative = line[:2], line[3:].split(" -> ")[-1]
        normalized = relative.replace("\\", "/")
        if state == "!!":
            if normalized.lower() in {".cargo/config", ".cargo/config.toml"}:
                violations.append(f"ignored Cargo configuration {normalized}")
        elif state == "??":
            if _is_build_input(normalized):
                violations.append(f"untracked build input {normalized}")
        else:
            violations.append(f"tracked/staged source change {normalized}")
    for config in (root / ".cargo/config", root / ".cargo/config.toml"):
        if config.exists() and f"ignored Cargo configuration {config.relative_to(root).as_posix()}" not in violations:
            violations.append(f"repository Cargo configuration {config.relative_to(root).as_posix()}")
    if violations:
        raise AssuranceError("source checkout is not hermetic: " + "; ".join(sorted(violations)))


@contextlib.contextmanager
def materialized_revision(revision: str) -> Iterator[Path]:
    """Yield a detached, clean checkout containing exactly ``revision``."""
    validate_build_source(ROOT, revision)
    with tempfile.TemporaryDirectory(prefix="noos-repro-source-") as directory:
        checkout = Path(directory) / "source"
        try:
            command(["git", "worktree", "add", "--detach", str(checkout), revision], cwd=ROOT)
            if command(["git", "rev-parse", "HEAD"], cwd=checkout) != revision:
                raise AssuranceError("isolated source checkout resolved the wrong HEAD")
            if command(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=checkout):
                raise AssuranceError("isolated source checkout is dirty")
            yield checkout
        finally:
            if checkout.exists():
                subprocess.run(
                    ["git", "worktree", "remove", "--force", str(checkout)],
                    cwd=ROOT, text=True, capture_output=True, check=False,
                )


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


def installed_toolchain_provenance() -> dict[str, dict[str, str]]:
    observed: dict[str, dict[str, str]] = {}
    for name, args in (
        ("rustc", ["rustc", "--version"]),
        ("cargo", ["cargo", "--version"]),
        ("go", ["go", "version"]),
    ):
        executable = shutil.which(args[0])
        if executable is None:
            raise AssuranceError(f"required toolchain executable is not on PATH: {args[0]}")
        resolved = Path(executable).resolve()
        observed[name] = {
            "path": str(resolved),
            "sha256": sha256_file(resolved),
            "version_output": _version_line(args),
        }
    return observed


def verify_installed_toolchains(lock: dict[str, Any], observed: dict[str, dict[str, str]]) -> list[str]:
    errors: list[str] = []
    expected = lock["toolchains"]
    for name in ("rustc", "cargo"):
        actual = observed[name]["version_output"]
        if actual != expected[name]["version_output"]:
            errors.append(f"{name} mismatch: expected {expected[name]['version_output']!r}, got {actual!r}")
    expected_go_prefix = f"go version go{expected['go']['version']} "
    actual_go = observed["go"]["version_output"]
    if not actual_go.startswith(expected_go_prefix):
        errors.append(f"go mismatch: expected {expected_go_prefix!r} with a host suffix, got {actual_go!r}")
    return errors


def locked_toolchain_identities(lock: dict[str, Any]) -> dict[str, str]:
    return {
        "rustc": lock["toolchains"]["rustc"]["version_output"],
        "cargo": lock["toolchains"]["cargo"]["version_output"],
        "go": f"go{lock['toolchains']['go']['version']}",
    }


def _required_environment(environ: Mapping[str, str], names: tuple[str, ...]) -> dict[str, str]:
    missing = [name for name in names if not environ.get(name)]
    if missing:
        raise AssuranceError(f"explicit Windows toolchain environment missing: {missing}")
    return {name: environ[name] for name in names}


def windows_file_version(path: Path) -> str:
    """Read a Windows PE fixed file version without trusting command output."""
    if os.name != "nt":
        raise AssuranceError("Windows PE version validation requires a Windows host")
    import ctypes
    from ctypes import wintypes

    class FixedFileInfo(ctypes.Structure):
        _fields_ = [
            ("signature", wintypes.DWORD), ("struct_version", wintypes.DWORD),
            ("file_version_ms", wintypes.DWORD), ("file_version_ls", wintypes.DWORD),
            ("product_version_ms", wintypes.DWORD), ("product_version_ls", wintypes.DWORD),
            ("file_flags_mask", wintypes.DWORD), ("file_flags", wintypes.DWORD),
            ("file_os", wintypes.DWORD), ("file_type", wintypes.DWORD),
            ("file_subtype", wintypes.DWORD), ("file_date_ms", wintypes.DWORD),
            ("file_date_ls", wintypes.DWORD),
        ]

    size = ctypes.windll.version.GetFileVersionInfoSizeW(str(path), None)
    if not size:
        raise AssuranceError(f"Windows binary has no readable file version: {path}")
    buffer = ctypes.create_string_buffer(size)
    if not ctypes.windll.version.GetFileVersionInfoW(str(path), 0, size, buffer):
        raise AssuranceError(f"cannot read Windows file version: {path}")
    pointer = ctypes.c_void_p()
    length = wintypes.UINT()
    if not ctypes.windll.version.VerQueryValueW(buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)):
        raise AssuranceError(f"Windows file version record missing: {path}")
    info = ctypes.cast(pointer, ctypes.POINTER(FixedFileInfo)).contents
    if info.signature != 0xFEEF04BD:
        raise AssuranceError(f"Windows file version signature invalid: {path}")
    return ".".join(str(value) for value in (
        info.file_version_ms >> 16, info.file_version_ms & 0xFFFF,
        info.file_version_ls >> 16, info.file_version_ls & 0xFFFF,
    ))


def resolve_windows_toolchain(
    lock: dict[str, Any], environ: Mapping[str, str] | None = None,
    *, file_version_reader: Callable[[Path], str] = windows_file_version,
) -> dict[str, Any]:
    """Validate an explicitly discovered Windows toolchain against the lock.

    CI and independent builders discover their own installation roots.  This
    function accepts no path aliases or implicit machine-local fallbacks.
    """
    environ = os.environ if environ is None else environ
    values = _required_environment(environ, (
        "NOOS_MSVC_ROOT", "NOOS_MSVC_TOOLS_VERSION",
        "NOOS_WINDOWS_SDK_ROOT", "NOOS_WINDOWS_SDK_VERSION",
    ))
    expected = lock["targets"]["windows-x86_64"]
    for env_name, lock_name in (
        ("NOOS_MSVC_TOOLS_VERSION", "msvc_tools_version"),
        ("NOOS_WINDOWS_SDK_VERSION", "windows_sdk_version"),
    ):
        if values[env_name] != expected.get(lock_name):
            raise AssuranceError(
                f"{env_name} mismatch: expected {expected.get(lock_name)!r}, got {values[env_name]!r}"
            )

    msvc_root = Path(values["NOOS_MSVC_ROOT"]).resolve()
    sdk_root = Path(values["NOOS_WINDOWS_SDK_ROOT"]).resolve()
    if msvc_root.name != expected["msvc_tools_version"]:
        raise AssuranceError(
            f"MSVC root does not end in locked version {expected['msvc_tools_version']!r}: {msvc_root}"
        )
    sdk_version = expected["windows_sdk_version"]
    msvc_bin = msvc_root / "bin" / "Hostx64" / "x64"
    sdk_bin = sdk_root / "bin" / sdk_version / "x64"
    library_paths = [
        msvc_root / "lib" / "x64",
        sdk_root / "Lib" / sdk_version / "ucrt" / "x64",
        sdk_root / "Lib" / sdk_version / "um" / "x64",
    ]
    sdk_include = sdk_root / "Include" / sdk_version
    include_paths = [
        msvc_root / "include", sdk_include / "ucrt", sdk_include / "shared",
        sdk_include / "um", sdk_include / "winrt",
    ]
    binaries = {
        "cl.exe": msvc_bin / "cl.exe",
        "link.exe": msvc_bin / "link.exe",
        "rc.exe": sdk_bin / "rc.exe",
    }
    required_files = {
        **binaries,
        "ucrt.lib": library_paths[1] / "ucrt.lib",
        "kernel32.lib": library_paths[2] / "kernel32.lib",
    }
    missing_dirs = [str(path) for path in (*library_paths, msvc_bin, sdk_bin, *include_paths) if not path.is_dir()]
    missing_files = [str(path) for path in required_files.values() if not path.is_file()]
    if missing_dirs or missing_files:
        raise AssuranceError(
            f"locked Windows toolchain incomplete: missing_directories={missing_dirs}; missing_files={missing_files}"
        )
    binary_file_versions = {name: file_version_reader(path) for name, path in sorted(binaries.items())}
    expected_versions = {
        "cl.exe": expected["msvc_binary_file_version"],
        "link.exe": expected["msvc_binary_file_version"],
        "rc.exe": expected["windows_sdk_rc_file_version"],
    }
    if binary_file_versions != expected_versions:
        raise AssuranceError(
            f"Windows toolchain binary version mismatch: expected {expected_versions}, got {binary_file_versions}"
        )
    return {
        "msvc_tools_version": expected["msvc_tools_version"],
        "msvc_component": expected["msvc_component"],
        "windows_sdk_version": sdk_version,
        "windows_sdk_component": expected["windows_sdk_component"],
        "msvc_root": str(msvc_root),
        "windows_sdk_root": str(sdk_root),
        "binary_paths": {name: str(path.resolve()) for name, path in sorted(binaries.items())},
        "binary_file_versions": binary_file_versions,
        "binary_sha256": {name: sha256_file(path) for name, path in sorted(binaries.items())},
        "_library_paths": library_paths,
        "_binary_paths": [msvc_bin, sdk_bin],
        "_include_paths": include_paths,
    }


def windows_toolchain_provenance(resolved: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in resolved.items() if not key.startswith("_")}


def deterministic_environment(
    root: Path, target_dir: Path, target: str, epoch: int,
    *, windows_toolchain: dict[str, Any] | None = None,
) -> dict[str, str]:
    """Create a closed build environment with repository-independent homes."""
    keep = ("PATH", "SystemRoot", "COMSPEC", "PATHEXT", "TEMP", "TMP", "RUSTUP_HOME")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    cfg = TARGETS[target]
    cargo_home = target_dir / "cargo-home"
    go_home = target_dir / "go-home"
    cargo_home.mkdir(parents=True, exist_ok=True)
    go_home.mkdir(parents=True, exist_ok=True)
    # The build is offline. Dependency caches must be provisioned into these
    # explicit homes by the release runner; no user/global configuration is read.
    env.update({
        "HOME": str(target_dir / "home"),
        "USERPROFILE": str(target_dir / "home"),
        "CARGO_HOME": str(cargo_home),
        "CARGO_TARGET_DIR": str(target_dir / "cargo-target"),
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
        "GO111MODULE": "on",
        "GOOS": cfg["goos"],
        "GOARCH": cfg["goarch"],
        "CGO_ENABLED": "0",
        "GOFLAGS": "-mod=readonly -trimpath -buildvcs=false",
        "GOCACHE": str(target_dir / "go-build-cache"),
        "GOMODCACHE": str(go_home / "pkg/mod"),
    })
    rustflags = [f"--remap-path-prefix={root}=/workspace/noosphere", "-C", "debuginfo=0"]
    if target == "windows-x86_64":
        windows_toolchain = windows_toolchain or resolve_windows_toolchain(load_toolchains())
        msvc_root = Path(windows_toolchain["msvc_root"])
        sdk_root = Path(windows_toolchain["windows_sdk_root"])
        env["LIB"] = os.pathsep.join(str(path) for path in windows_toolchain["_library_paths"])
        env["INCLUDE"] = os.pathsep.join(str(path) for path in windows_toolchain["_include_paths"])
        env["PATH"] = os.pathsep.join([*(str(path) for path in windows_toolchain["_binary_paths"]), env.get("PATH", "")])
        env["VCINSTALLDIR"] = str(msvc_root.parents[2]) + os.sep
        env["VCToolsInstallDir"] = str(msvc_root) + os.sep
        env["VCToolsVersion"] = windows_toolchain["msvc_tools_version"]
        env["UniversalCRTSdkDir"] = str(sdk_root) + os.sep
        env["UCRTVersion"] = windows_toolchain["windows_sdk_version"]
        env["WindowsSdkDir"] = str(sdk_root) + os.sep
        env["WindowsSDKVersion"] = windows_toolchain["windows_sdk_version"] + os.sep
        rust_sysroot = Path(command(["rustc", "--print", "sysroot"], env=env).strip())
        rust_lld = rust_sysroot / "lib" / "rustlib" / "x86_64-pc-windows-msvc" / "bin" / "rust-lld.exe"
        if not rust_lld.is_file():
            raise AssuranceError(f"pinned Rust linker missing: {rust_lld}")
        windows_toolchain["rust_linker_path"] = str(rust_lld.resolve())
        windows_toolchain["rust_linker_sha256"] = sha256_file(rust_lld)
        env["CARGO_TARGET_X86_64_PC_WINDOWS_MSVC_LINKER"] = str(rust_lld)
        rustflags.extend(["-C", "link-arg=/Brepro", "-C", "link-arg=/PDBALTPATH:noos-transition.pdb"])
    env["CARGO_ENCODED_RUSTFLAGS"] = "\x1f".join(rustflags)
    return env


def go_modules(env: dict[str, str], module_root: Path = GO_MODULE) -> list[dict[str, str]]:
    """Read the complete, already-downloaded module graph without network access."""
    args = ["go", "list", "-mod=readonly", "-m", "-json", "all"]
    try:
        completed = subprocess.run(
            args, cwd=module_root, env=env, check=True, text=True, capture_output=True,
        )
    except subprocess.CalledProcessError as exc:
        raise _command_failure(exc, module_root) from exc
    decoder = json.JSONDecoder()
    text = completed.stdout
    offset = 0
    modules: list[dict[str, str]] = []
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset == len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        modules.append({"path": value["Path"], "version": value.get("Version", "workspace")})
    return sorted(modules, key=lambda module: (module["path"], module["version"]))


def build_target(target: str, out: Path, *, revision: str | None = None, smoke: bool = False) -> dict[str, Any]:
    if target not in TARGETS:
        raise AssuranceError(f"unsupported target {target!r}")
    cfg = TARGETS[target]
    host_os, host_arch = _host()
    if host_os != cfg["os"] or host_arch != cfg["arch"]:
        raise AssuranceError(f"{target} requires a native {cfg['os']}/{cfg['arch']} runner; observed {host_os}/{host_arch}")
    identity = source_identity(revision)
    locks = load_toolchains()
    installed_toolchains = installed_toolchain_provenance()
    toolchain_errors = verify_installed_toolchains(locks, installed_toolchains)
    policy_errors = verify_policy_signatures()
    if toolchain_errors or (policy_errors and not smoke):
        raise AssuranceError("; ".join(toolchain_errors + ([] if smoke else policy_errors)))

    out = safe_repository_output(out)
    out.mkdir(parents=True, exist_ok=True)
    target_dir = out / ".controlled-build"
    windows_toolchain = resolve_windows_toolchain(locks) if target == "windows-x86_64" else None
    with materialized_revision(identity["revision"]) as source_root:
        source_go = source_root / "go"
        env = deterministic_environment(
            source_root, target_dir, target, identity["source_date_epoch"], windows_toolchain=windows_toolchain,
        )
        subprocess.run(["go", "mod", "verify"], cwd=source_go, env=env, check=True)
        module_count = len(go_modules(env, source_go))
        subprocess.run(
            ["cargo", "build", "--locked", "--offline", "--frozen", "--release", "--target", cfg["rust"],
             "-p", "noos-lumen", "--bin", "noos-transition"],
            cwd=source_root, env=env, check=True,
        )
        suffix = cfg["suffix"]
        rust_output = Path(env["CARGO_TARGET_DIR"]) / cfg["rust"] / "release" / f"noos-transition{suffix}"
        artifacts = out / "artifacts"
        artifacts.mkdir(exist_ok=True)
        shutil.copyfile(rust_output, artifacts / f"noos-transition-rust{suffix}")
        for name, package in (("noos-transition-go", "./cmd/noos-transition"), ("noos-verify", "./cmd/noos-verify")):
            destination = artifacts / f"{name}{suffix}"
            destination.unlink(missing_ok=True)
            subprocess.run(["go", "build", "-o", str(destination), package], cwd=source_go, env=env, check=True)

        binary_hashes = {f"artifacts/{path.name}": sha256_file(path) for path in sorted(artifacts.iterdir()) if path.is_file()}
        result = {
            "schema": "noos/repro-build-details/v1",
            "evidence_class": "same-machine-smoke" if smoke else "candidate-build-not-independent-attestation",
            "target": target,
            "host": {"os": host_os, "architecture": host_arch},
            "source": identity,
            "toolchain_lock_sha256": sha256_file(source_root / "protocol/release/repro-toolchains-v1.json"),
            "toolchains": locked_toolchain_identities(locks),
            "installed_toolchain_provenance": installed_toolchains,
            "windows_toolchain_provenance": windows_toolchain_provenance(windows_toolchain) if windows_toolchain else None,
            "dependency_locks": {
                "Cargo.lock": sha256_file(source_root / "Cargo.lock"),
                "go/go.mod": sha256_file(source_go / "go.mod"),
                "go/go.sum": sha256_file(source_go / "go.sum"),
            },
            "go_module_provenance": {
                "module_root": "go",
                "locked_download_command": "go mod download all",
                "offline_list_command": "go list -mod=readonly -m -json all",
                "offline_graph_verified": True,
                "module_count": module_count,
            },
            "deterministic_environment": locks["deterministic_environment"],
            "post_build_normalization": "forbidden-and-not-performed",
            "offline_build": True,
            "binary_hashes": binary_hashes,
            "policy_signature_errors": policy_errors,
            "toolchain_errors": toolchain_errors,
        }
    (out / "build-details.json").write_bytes(canonical_json(result))
    shutil.rmtree(target_dir, ignore_errors=True)
    return result


def authenticated_repro_binding(
    trusted_builders: Path,
    keyring_path: Path,
    final_freeze_path: Path,
    final_freeze_signatures_path: Path,
    *,
    allow_test_keys: bool = False,
) -> tuple[str, str]:
    """Derive revision and roster digest only from a verified final freeze."""
    genesis_tools = ROOT / "tools/genesis"
    if str(genesis_tools) not in sys.path:
        sys.path.insert(0, str(genesis_tools))
    try:
        from production_authorization import (
            DOMAIN_FINAL_FREEZE, FINAL_ROLES, canonical_json as authorization_json,
            file_sha256, load_keyring, read_json, verify_detached_signatures,
        )
        keyring, keyring_doc = load_keyring(keyring_path, test_mode=allow_test_keys)
        freeze = read_json(final_freeze_path)
        revision = freeze.get("exact_revision")
        if keyring_doc.get("exact_revision") != revision:
            raise AssuranceError("final freeze/keyring revision mismatch")
        if freeze.get("role_keyring_sha256") != file_sha256(keyring_path):
            raise AssuranceError("final freeze does not pin supplied role keyring bytes")
        roster_digest = freeze.get("trusted_repro_builders_sha256")
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision):
            raise AssuranceError("final freeze exact revision is invalid")
        if not isinstance(roster_digest, str) or not HEX64.fullmatch(roster_digest):
            raise AssuranceError("final freeze does not pin trusted reproducibility builders")
        verify_detached_signatures(
            authorization_json(freeze), read_json(final_freeze_signatures_path),
            DOMAIN_FINAL_FREEZE, revision, FINAL_ROLES, keyring,
        )
        if sha256_file(trusted_builders) != roster_digest:
            raise AssuranceError("trusted builder roster does not match signed final freeze")
        return revision, roster_digest
    except AssuranceError:
        raise
    except Exception as exc:
        raise AssuranceError(f"signed reproducibility trust verification failed: {exc}") from exc


def _trusted_builders(
    path: Path,
    allow_test_keys: bool,
    externally_pinned_sha256: str,
    expected_revision: str,
    blockers: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    if not HEX64.fullmatch(externally_pinned_sha256) or sha256_file(path) != externally_pinned_sha256:
        raise AssuranceError("trusted builder roster does not match externally supplied trust root")
    trust = load_json(path)
    if trust.get("schema") != "noos/trusted-repro-builders/v1":
        raise AssuranceError("wrong trusted builder schema")
    if trust.get("exact_revision") != expected_revision:
        if trust.get("exact_revision") == "OWNER_BLOCKED" and blockers is not None:
            blockers.append("trusted builder roster exact revision is external/owner blocked")
        else:
            raise AssuranceError("trusted builder roster is not bound to exact source revision")
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
    if build.get("trusted_repro_builders_sha256") != expected_source["trusted_repro_builders_sha256"]:
        errors.append("trusted builder roster digest mismatch")
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


def _verify_attestation_set_pinned(
    attestations: Path,
    trusted_builders: Path,
    expected_revision: str,
    *,
    trusted_builders_sha256: str,
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
    trust = _trusted_builders(
        trusted_builders, allow_test_keys, trusted_builders_sha256, expected_revision, errors,
    )
    locks = load_toolchains()
    expected_source = source_identity(expected_revision)
    expected_source["trusted_repro_builders_sha256"] = trusted_builders_sha256
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
            accepted.append({"path": payload_path.name, "key_id": key_id, "payload_sha256": signature["payload_sha256"], "payload": payload, "trust": record})
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

    agreed_artifacts = {
        target: (dict(sorted(items[0]["payload"]["artifact_hashes"].items())) if items else {})
        for target, items in sorted(by_target.items())
    }
    report = {
        "schema": "noos/repro-assurance-report/v2",
        "promotion_ledger_mutation": "PROHIBITED",
        "registry_claim_state_mutation": "PROHIBITED",
        "source": expected_source,
        "trusted_repro_builders_sha256": trusted_builders_sha256,
        "required_targets": sorted(REQUIRED_TARGETS),
        "artifact_hashes_by_target": agreed_artifacts,
        "toolchain_lock_sha256": sha256_file(TOOLCHAINS),
        "toolchains": locked_toolchain_identities(locks),
        "accepted_attestations": [
            {
                "path": item["path"], "key_id": item["key_id"],
                "target": item["payload"]["build"]["target"],
                "signed_payload_sha256": item["payload_sha256"],
                "artifact_hashes_sha256": sha256_bytes(canonical_json(item["payload"]["artifact_hashes"])),
            }
            for item in accepted
        ],
        "builder_artifact_hashes": [
            {
                "key_id": item["key_id"],
                "target": item["payload"]["build"]["target"],
                "artifact_hashes": dict(sorted(item["payload"]["artifact_hashes"].items())),
            }
            for item in accepted
        ],
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


def verify_attestation_set(
    attestations: Path,
    trusted_builders: Path,
    keyring: Path,
    final_freeze: Path,
    final_freeze_signatures: Path,
    *,
    allow_test_keys: bool = False,
) -> dict[str, Any]:
    revision, roster_digest = authenticated_repro_binding(
        trusted_builders, keyring, final_freeze, final_freeze_signatures,
        allow_test_keys=allow_test_keys,
    )
    return _verify_attestation_set_pinned(
        attestations, trusted_builders, revision,
        trusted_builders_sha256=roster_digest, allow_test_keys=allow_test_keys,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    build = sub.add_parser("build", help="build one native target with locked offline dependencies")
    build.add_argument("--target", choices=sorted(REQUIRED_TARGETS), required=True)
    build.add_argument("--out", required=True)
    build.add_argument("--revision")
    build.add_argument("--smoke", action="store_true", help="allow unsigned policy only; toolchain mismatches still fail and output is smoke-only")
    sub.add_parser("validate-windows-toolchain", help="validate explicit NOOS_MSVC/SDK roots against the lock")
    verify = sub.add_parser("verify-attestations", help="verify an external two-builder attestation quorum")
    verify.add_argument("--attestations", required=True)
    verify.add_argument("--trusted-builders", required=True)
    verify.add_argument("--keyring", required=True)
    verify.add_argument("--final-freeze", required=True)
    verify.add_argument("--final-freeze-signatures", required=True)
    verify.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate-windows-toolchain":
            resolved = resolve_windows_toolchain(load_toolchains())
            print(canonical_json(windows_toolchain_provenance(resolved)).decode("utf-8"), end="")
            print("RESULT windows_toolchain=VALID")
            return 0
        if args.command == "build":
            result = build_target(args.target, ROOT / args.out, revision=args.revision, smoke=args.smoke)
            print(f"RESULT repro_build={'SMOKE_ONLY' if args.smoke else 'CANDIDATE_BUILT'} target={args.target} binaries={len(result['binary_hashes'])}")
            return 0
        report = verify_attestation_set(
            Path(args.attestations), Path(args.trusted_builders), Path(args.keyring),
            Path(args.final_freeze), Path(args.final_freeze_signatures),
        )
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
