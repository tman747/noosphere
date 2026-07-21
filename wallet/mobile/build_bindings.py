#!/usr/bin/env python3
"""Build and package the UniFFI wallet core for Android or Apple mobile targets."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Final

ROOT: Final[Path] = Path(__file__).resolve().parents[2]
SDK_CRATE: Final[str] = "noos-wallet-sdk"
ANDROID_TARGETS: Final[tuple[tuple[str, str], ...]] = (
    ("aarch64-linux-android", "arm64-v8a"),
    ("armv7-linux-androideabi", "armeabi-v7a"),
    ("x86_64-linux-android", "x86_64"),
)
APPLE_TARGETS: Final[tuple[str, ...]] = (
    "aarch64-apple-ios",
    "aarch64-apple-ios-sim",
    "x86_64-apple-ios",
)


class BuildError(RuntimeError):
    pass


def run(argv: list[str], *, env: dict[str, str] | None = None) -> None:
    print("+", subprocess.list2cmdline(argv), flush=True)
    completed = subprocess.run(argv, cwd=ROOT, env=env, check=False)
    if completed.returncode != 0:
        raise BuildError(f"command failed with exit code {completed.returncode}: {argv[0]}")


def output(argv: list[str]) -> str:
    completed = subprocess.run(
        argv,
        cwd=ROOT,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
    )
    if completed.returncode != 0:
        raise BuildError(completed.stderr.strip() or f"command failed: {argv[0]}")
    return completed.stdout.strip()


def cargo_metadata() -> dict[str, object]:
    return json.loads(output(["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"]))


def target_directory() -> Path:
    value = cargo_metadata().get("target_directory")
    if not isinstance(value, str) or not value:
        raise BuildError("cargo metadata did not return target_directory")
    return Path(value).resolve()


def host_library(profile: str) -> Path:
    suffixes = (".dll",) if os.name == "nt" else ((".dylib",) if sys.platform == "darwin" else (".so",))
    target = target_directory()
    candidates: list[Path] = []
    for directory in (target / profile, target / profile / "deps"):
        if not directory.is_dir():
            continue
        for suffix in suffixes:
            candidates.extend(directory.glob(f"*noos_wallet_sdk*{suffix}"))
    files = [path for path in candidates if path.is_file()]
    if not files:
        raise BuildError(f"host UniFFI library was not found below {target / profile}")
    return max(files, key=lambda path: path.stat().st_mtime_ns)


def build_host(profile: str) -> Path:
    argv = ["cargo", "build", "--locked", "-p", SDK_CRATE]
    if profile == "release":
        argv.append("--release")
    run(argv)
    return host_library(profile)


def generate_bindings(library: Path, language: str, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    run(
        [
            "cargo",
            "run",
            "--locked",
            "-p",
            SDK_CRATE,
            "--features",
            "bindgen",
            "--bin",
            "noos-wallet-sdk-bindgen",
            "--",
            "generate",
            "--library",
            str(library),
            "--language",
            language,
            "--out-dir",
            str(destination),
            "--no-format",
        ]
    )


def normalized_generated_source(path: Path) -> list[str]:
    if not path.is_file():
        raise BuildError(f"generated binding is missing: {path}")
    lines = [line.rstrip() for line in path.read_text(encoding="utf-8").splitlines()]
    while lines and not lines[-1]:
        lines.pop()
    return lines


def verify_bindings(profile: str) -> None:
    library = build_host(profile)
    bindings = (
        (
            "kotlin",
            Path("org/noosphere/wallet/core/noos_wallet_sdk.kt"),
            ROOT
            / "wallet"
            / "mobile"
            / "android"
            / "core"
            / "src"
            / "main"
            / "java"
            / "org"
            / "noosphere"
            / "wallet"
            / "core"
            / "noos_wallet_sdk.kt",
        ),
        (
            "swift",
            Path("MindChainWalletCore.swift"),
            ROOT / "wallet" / "mobile" / "ios" / "CoreBindings" / "MindChainWalletCore.swift",
        ),
        (
            "swift",
            Path("MindChainWalletCoreFFI.h"),
            ROOT / "wallet" / "mobile" / "ios" / "CoreBindings" / "MindChainWalletCoreFFI.h",
        ),
        (
            "swift",
            Path("MindChainWalletCoreFFI.modulemap"),
            ROOT
            / "wallet"
            / "mobile"
            / "ios"
            / "CoreBindings"
            / "MindChainWalletCoreFFI.modulemap",
        ),
    )
    with tempfile.TemporaryDirectory(prefix="noos-wallet-bindings-") as temporary:
        generated_roots = {
            language: Path(temporary) / language for language in ("kotlin", "swift")
        }
        for language, destination in generated_roots.items():
            generate_bindings(library, language, destination)

        drifted: list[str] = []
        for language, relative_path, committed_path in bindings:
            generated_path = generated_roots[language] / relative_path
            generated_lines = normalized_generated_source(generated_path)
            committed_lines = normalized_generated_source(committed_path)
            if generated_lines == committed_lines:
                continue
            display_path = committed_path.relative_to(ROOT).as_posix()
            drifted.append(display_path)
            difference = "\n".join(
                difflib.unified_diff(
                    committed_lines,
                    generated_lines,
                    fromfile=display_path,
                    tofile=f"generated/{language}/{relative_path.as_posix()}",
                    lineterm="",
                )
            )
            print(difference, file=sys.stderr)

    if drifted:
        raise BuildError(
            "generated bindings differ from committed sources: " + ", ".join(drifted)
        )
    print("verified committed Kotlin and Swift bindings")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(platform_name: str, files: list[Path], profile: str) -> None:
    root = ROOT / "wallet" / "mobile"
    entries = []
    for path in sorted(files):
        entries.append(
            {
                "path": path.relative_to(ROOT).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
        )
    manifest = {
        "schema": "noos/mobile-wallet-bindings/v1",
        "platform": platform_name,
        "profile": profile,
        "crate": SDK_CRATE,
        "files": entries,
    }
    destination = root / f"{platform_name}-bindings.manifest.json"
    destination.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"wrote {destination}")


def build_android(profile: str, ndk_home: Path) -> None:
    if not ndk_home.is_dir():
        raise BuildError(f"Android NDK directory does not exist: {ndk_home}")
    run(["rustup", "target", "add", *(target for target, _ in ANDROID_TARGETS)])
    output(["cargo", "ndk", "--version"])
    native_root = ROOT / "wallet" / "mobile" / "android" / "core" / "src" / "main" / "jniLibs"
    argv = ["cargo", "ndk"]
    for _, abi in ANDROID_TARGETS:
        argv.extend(["-t", abi])
    argv.extend(["-o", str(native_root), "build", "-p", SDK_CRATE])
    if profile == "release":
        argv.append("--release")
    environment = os.environ.copy()
    environment["ANDROID_NDK_HOME"] = str(ndk_home)
    run(argv, env=environment)

    library = build_host(profile)
    kotlin_root = (
        ROOT
        / "wallet"
        / "mobile"
        / "android"
        / "core"
        / "src"
        / "main"
        / "java"
    )
    generate_bindings(library, "kotlin", kotlin_root)
    generated = kotlin_root / "org" / "noosphere" / "wallet" / "core" / "noos_wallet_sdk.kt"
    android_runtime = kotlin_root / "org" / "noosphere" / "wallet" / "core" / "MobileNodeSynchronizer.kt"
    wallet_transport = kotlin_root / "org" / "noosphere" / "wallet" / "core" / "WalletApiTransport.kt"
    android_root = ROOT / "wallet" / "mobile" / "android"
    android_app = android_root / "app"
    native_files = [native_root / abi / "libnoos_wallet_sdk.so" for _, abi in ANDROID_TARGETS]
    app_files = [
        *android_app.rglob("*.kt"),
        *android_app.rglob("*.json"),
        *android_app.rglob("*.xml"),
        android_app / "build.gradle.kts",
    ]
    missing = [
        path
        for path in [generated, android_runtime, wallet_transport, *native_files, *app_files]
        if not path.is_file()
    ]
    if missing:
        raise BuildError(f"Android binding or application outputs are missing: {missing}")
    gradle = android_root / ("gradlew.bat" if os.name == "nt" else "gradlew")
    variant = "Release" if profile == "release" else "Debug"
    run(
        [
            str(gradle),
            "-p",
            str(android_root),
            f":security:assemble{variant}",
            f":core:assemble{variant}",
            f":app:assemble{variant}",
            f":app:lint{variant}",
        ]
    )
    write_manifest(
        "android",
        [generated, android_runtime, wallet_transport, *native_files, *app_files],
        profile,
    )


def require_darwin() -> None:
    if platform.system() != "Darwin":
        raise BuildError("Apple bindings require macOS with Xcode and the iOS SDK")
    for binary in ("xcodebuild", "xcrun", "lipo"):
        if shutil.which(binary) is None:
            raise BuildError(f"required Apple build tool is missing: {binary}")


def build_ios(profile: str) -> None:
    require_darwin()
    run(["rustup", "target", "add", *APPLE_TARGETS])
    library = build_host(profile)
    bindings = ROOT / "wallet" / "mobile" / "ios" / "CoreBindings"
    generate_bindings(library, "swift", bindings)

    profile_flag = "--release" if profile == "release" else None
    for target in APPLE_TARGETS:
        argv = ["cargo", "build", "-p", SDK_CRATE, "--target", target]
        if profile_flag is not None:
            argv.append(profile_flag)
        run(argv)

    target = target_directory()
    device = target / "aarch64-apple-ios" / profile / "libnoos_wallet_sdk.a"
    simulator_arm = target / "aarch64-apple-ios-sim" / profile / "libnoos_wallet_sdk.a"
    simulator_x64 = target / "x86_64-apple-ios" / profile / "libnoos_wallet_sdk.a"
    for path in (device, simulator_arm, simulator_x64):
        if not path.is_file():
            raise BuildError(f"Apple static library is missing: {path}")

    artifacts = ROOT / "wallet" / "mobile" / "ios" / "Artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    simulator = artifacts / "libnoos_wallet_sdk-simulator.a"
    run(["lipo", "-create", str(simulator_arm), str(simulator_x64), "-output", str(simulator)])

    headers = artifacts / "include"
    headers.mkdir(parents=True, exist_ok=True)
    shutil.copy2(bindings / "MindChainWalletCoreFFI.h", headers / "MindChainWalletCoreFFI.h")
    module_map = (bindings / "MindChainWalletCoreFFI.modulemap").read_text(encoding="utf-8")
    (headers / "module.modulemap").write_text(module_map, encoding="utf-8", newline="\n")
    framework = artifacts / "MindChainWalletCoreNative.xcframework"
    if framework.exists():
        shutil.rmtree(framework)
    run(
        [
            "xcodebuild",
            "-create-xcframework",
            "-library",
            str(device),
            "-headers",
            str(headers),
            "-library",
            str(simulator),
            "-headers",
            str(headers),
            "-output",
            str(framework),
        ]
    )
    app_root = ROOT / "wallet" / "mobile" / "ios" / "App"
    app_spec = app_root / "project.yml"
    if shutil.which("xcodegen") is None:
        raise BuildError("xcodegen is required to generate and verify the iOS application project")
    run(["xcodegen", "generate", "--spec", str(app_spec)])
    app_project = app_root / "MindChainWalletMobile.xcodeproj"
    if not app_project.is_dir():
        raise BuildError("xcodegen did not produce the MindChain iOS project")
    derived_data = artifacts / "AppDerivedData"
    run(
        [
            "xcodebuild",
            "-project",
            str(app_project),
            "-scheme",
            "MindChainWallet",
            "-configuration",
            "Release",
            "-sdk",
            "iphonesimulator",
            "-destination",
            "generic/platform=iOS Simulator",
            "-derivedDataPath",
            str(derived_data),
            "CODE_SIGNING_ALLOWED=NO",
            "build",
        ]
    )
    app_files = [
        app_spec,
        *app_root.rglob("*.swift"),
        *app_root.rglob("*.plist"),
        *app_root.rglob("*.entitlements"),
        *app_root.rglob("*.json"),
        *app_root.rglob("*.png"),
    ]

    swift_source = bindings / "MindChainWalletCore.swift"
    info_plist = framework / "Info.plist"
    if not swift_source.is_file() or not info_plist.is_file():
        raise BuildError("Apple binding package is incomplete")
    package_files = [
        swift_source,
        bindings / "MobileNodeSynchronizer.swift",
        bindings / "MindChainWalletCoreFFI.h",
        info_plist,
        *app_files,
    ]
    package_files.extend(path for path in framework.rglob("*.a") if path.is_file())
    write_manifest("ios", package_files, profile)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("platform", choices=("android", "ios", "verify"))
    parser.add_argument("--profile", choices=("debug", "release"), default="release")
    parser.add_argument(
        "--ndk-home",
        type=Path,
        default=Path(os.environ.get("ANDROID_NDK_HOME", os.environ.get("ANDROID_NDK_ROOT", ""))),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        if args.platform == "android":
            build_android(args.profile, args.ndk_home.expanduser().resolve())
        elif args.platform == "ios":
            build_ios(args.profile)
        else:
            verify_bindings(args.profile)
    except (BuildError, OSError, ValueError, json.JSONDecodeError) as error:
        print(f"mobile wallet binding build failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
