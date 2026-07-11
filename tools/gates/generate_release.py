#!/usr/bin/env python3
"""Create a deterministic, downloadable candidate release bundle for one target.

The bundle contains real binaries, checksums, CycloneDX SBOM, SLSA/in-toto
provenance, and an unsigned external-attestation request.  It deliberately does
not claim independent reproduction, a production signature, or gate passage.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/gates"))
import repro_build


def cargo_packages() -> list[dict[str, str]]:
    packages: list[dict[str, str]] = []
    current: dict[str, str] | None = None
    for raw in (ROOT / "Cargo.lock").read_text("utf-8").splitlines():
        line = raw.strip()
        if line == "[[package]]":
            current = {}
            packages.append(current)
        elif line.startswith("["):
            current = None
        elif current is not None and " = " in line:
            key, value = line.split(" = ", 1)
            if key in {"name", "version", "source", "checksum"} and value.startswith('"') and value.endswith('"'):
                current[key] = value[1:-1]
    if any("name" not in package or "version" not in package for package in packages):
        raise repro_build.AssuranceError("Cargo.lock contains an incomplete package row")
    return sorted(packages, key=lambda package: (package["name"], package["version"], package.get("source", "")))


def go_modules(env: dict[str, str]) -> list[dict[str, str]]:
    completed = subprocess.run(
        ["go", "list", "-mod=readonly", "-m", "-json", "all"],
        cwd=ROOT / "go", env=env, check=True, text=True, capture_output=True,
    )
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


def deterministic_uuid(payload: bytes) -> str:
    digest = repro_build.sha256_bytes(payload)
    return f"urn:uuid:{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-{digest[20:32]}"


def create_bundle(target: str, out: Path, version: str, *, smoke: bool, revision: str | None = None) -> dict[str, Any]:
    out = repro_build.safe_repository_output(out)
    if out.exists():
        for child in out.iterdir():
            if child.name != ".cargo-target":
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
    out.mkdir(parents=True, exist_ok=True)
    details = repro_build.build_target(target, out, revision=revision, smoke=smoke)
    identity = details["source"]
    env = repro_build.deterministic_environment(ROOT, out / ".metadata-target", target, identity["source_date_epoch"])
    binary_hashes = details["binary_hashes"]

    components: list[dict[str, Any]] = [
        {"type": "file", "name": name, "version": version, "hashes": [{"alg": "SHA-256", "content": digest}]}
        for name, digest in sorted(binary_hashes.items())
    ]
    for package in cargo_packages():
        component: dict[str, Any] = {
            "type": "library", "name": package["name"], "version": package["version"],
            "purl": f"pkg:cargo/{package['name']}@{package['version']}",
            "properties": [{"name": "noos:workspace", "value": "false" if "source" in package else "true"}],
        }
        if "checksum" in package:
            component["hashes"] = [{"alg": "SHA-256", "content": package["checksum"]}]
        components.append(component)
    for module in go_modules(env):
        components.append({
            "type": "library", "name": module["path"], "version": module["version"],
            "purl": f"pkg:golang/{module['path']}@{module['version']}",
        })
    component_bytes = repro_build.canonical_json(components)
    sbom = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": deterministic_uuid(component_bytes), "version": 1,
        "metadata": {"component": {"type": "application", "name": "noosphere", "version": version}},
        "components": components,
    }
    (out / "sbom.cdx.json").write_bytes(repro_build.canonical_json(sbom))

    subjects = [{"name": name, "digest": {"sha256": digest}} for name, digest in sorted(binary_hashes.items())]
    provenance = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": subjects,
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://mindchain.network/noos/repro-build/v1",
                "externalParameters": {"target": target, "locked": True, "offline": True},
                "internalParameters": {
                    "sourceDateEpoch": identity["source_date_epoch"],
                    "pathRemap": "/workspace/noosphere",
                    "postBuildNormalization": "forbidden-and-not-performed",
                },
                "resolvedDependencies": [
                    {"uri": "git+https://github.com/mindchain/noosphere", "digest": {"gitCommit": identity["revision"], "gitTree": identity["tree"]}},
                    {"uri": "Cargo.lock", "digest": {"sha256": repro_build.sha256_file(ROOT / "Cargo.lock")}},
                    {"uri": "go/go.sum", "digest": {"sha256": repro_build.sha256_file(ROOT / "go/go.sum")}},
                    {"uri": "protocol/release/repro-toolchains-v1.json", "digest": {"sha256": repro_build.sha256_file(repro_build.TOOLCHAINS)}},
                ],
            },
            "runDetails": {
                "builder": {"id": "github-actions-candidate-single-control-plane" if not smoke else "local-same-machine-smoke"},
                "metadata": {"independentBuilderEvidence": False, "evidenceClass": "smoke-only"},
            },
        },
    }
    (out / "provenance.intoto.jsonl").write_bytes(repro_build.canonical_json(provenance))

    covered = {
        **binary_hashes,
        "build-details.json": repro_build.sha256_file(out / "build-details.json"),
        "sbom.cdx.json": repro_build.sha256_file(out / "sbom.cdx.json"),
        "provenance.intoto.jsonl": repro_build.sha256_file(out / "provenance.intoto.jsonl"),
    }
    checksums = "".join(f"{digest}  {name}\n" for name, digest in sorted(covered.items()))
    (out / "SHA256SUMS").write_text(checksums, encoding="ascii", newline="\n")
    manifest = {
        "schema": "noos/repro-candidate-bundle/v1",
        "evidence_class": "public-candidate-smoke-not-independent-reproduction",
        "release_version": version,
        "target": target,
        "source": identity,
        "toolchain_lock_sha256": repro_build.sha256_file(repro_build.TOOLCHAINS),
        "files": covered,
        "checksums_sha256": repro_build.sha256_file(out / "SHA256SUMS"),
        "external_builder_gate": "EXTERNAL_BLOCKED",
        "promotion_ledger_mutation": "PROHIBITED",
    }
    (out / "bundle-manifest.json").write_bytes(repro_build.canonical_json(manifest))
    request = {
        "schema": "noos/external-attestation-request/v1",
        "not_an_attestation": True,
        "not_a_signature": True,
        "target": target,
        "source_revision": identity["revision"],
        "source_tree": identity["tree"],
        "toolchain_lock_sha256": repro_build.sha256_file(repro_build.TOOLCHAINS),
        "candidate_bundle_manifest_sha256": repro_build.sha256_file(out / "bundle-manifest.json"),
        "instructions": "Rebuild from the bound source with an externally controlled pinned installation; sign your own canonical attestation payload with a registered external Ed25519 key.",
    }
    (out / "external-attestation-request.json").write_bytes(repro_build.canonical_json(request))
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", choices=sorted(repro_build.REQUIRED_TARGETS), required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--version", default="0.1.0-dev")
    parser.add_argument("--revision")
    parser.add_argument("--smoke", action="store_true", help="permit unsigned policy locally; bundle remains smoke-only")
    args = parser.parse_args(argv)
    try:
        result = create_bundle(args.target, ROOT / args.out, args.version, smoke=args.smoke, revision=args.revision)
    except (repro_build.AssuranceError, OSError, subprocess.CalledProcessError) as exc:
        print(f"RESULT generate_release=FAIL reason={exc}", file=sys.stderr)
        return 1
    print(f"RESULT generate_release={'SMOKE_ONLY' if args.smoke else 'CANDIDATE_ONLY'} target={args.target} files={len(result['files'])} out={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
