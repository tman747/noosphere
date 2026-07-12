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
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools/gates"))
import repro_build

BUILDER_PROFILES = {
    "local-builder": "local-single-builder-control-plane",
    "github-hosted-owner-smoke": "github-actions-owner-controlled-smoke-control-plane",
}


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
    return repro_build.go_modules(env)


def deterministic_uuid(payload: bytes) -> str:
    digest = repro_build.sha256_bytes(payload)
    return f"urn:uuid:{digest[:8]}-{digest[8:12]}-4{digest[13:16]}-8{digest[17:20]}-{digest[20:32]}"


def candidate_boundary(smoke: bool, builder_profile: str) -> dict[str, Any]:
    if builder_profile not in BUILDER_PROFILES:
        raise repro_build.AssuranceError(f"unknown builder profile {builder_profile!r}")
    if builder_profile == "github-hosted-owner-smoke" and not smoke:
        raise repro_build.AssuranceError("GitHub-hosted owner candidates must remain --smoke")
    return {
        "candidate_status": "SMOKE_ONLY" if smoke else "CANDIDATE_ONLY",
        "evidence_class": "public-candidate-smoke-not-independent-reproduction" if smoke else "candidate-not-independent-reproduction",
        "control_plane": BUILDER_PROFILES[builder_profile],
        "independent_builder_evidence": False,
        "external_builder_gate": "EXTERNAL_BLOCKED",
        "promotion_effect": "NONE",
        "promotion_ledger_mutation": "PROHIBITED",
    }


def create_bundle(
    target: str, out: Path, version: str, *, smoke: bool,
    revision: str | None = None, builder_profile: str = "local-builder",
) -> dict[str, Any]:
    out = repro_build.safe_repository_output(out)
    if out.exists():
        for child in out.iterdir():
            if child.name not in {".cargo-target", ".controlled-build"}:
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
    out.mkdir(parents=True, exist_ok=True)
    details = repro_build.build_target(target, out, revision=revision, smoke=smoke)
    identity = details["source"]
    boundary = candidate_boundary(smoke, builder_profile)
    metadata_target = out / ".metadata-target"
    env = repro_build.deterministic_environment(ROOT, metadata_target, target, identity["source_date_epoch"])
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
    try:
        modules = go_modules(env)
    finally:
        if metadata_target.exists():
            shutil.rmtree(metadata_target)
    for module in modules:
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
                    "toolchainProvenance": {
                        "installed": details["installed_toolchain_provenance"],
                        "windows": details["windows_toolchain_provenance"],
                    },
                },
                "resolvedDependencies": [
                    {"uri": "git+https://github.com/mindchain/noosphere", "digest": {"gitCommit": identity["revision"], "gitTree": identity["tree"]}},
                    {"uri": "Cargo.lock", "digest": {"sha256": repro_build.sha256_file(ROOT / "Cargo.lock")}},
                    {"uri": "go/go.mod", "digest": {"sha256": repro_build.sha256_file(ROOT / "go/go.mod")}},
                    {"uri": "go/go.sum", "digest": {"sha256": repro_build.sha256_file(ROOT / "go/go.sum")}},
                    {"uri": "protocol/release/repro-toolchains-v1.json", "digest": {"sha256": repro_build.sha256_file(repro_build.TOOLCHAINS)}},
                ],
            },
            "runDetails": {
                "builder": {"id": boundary["control_plane"]},
                "metadata": {
                    "candidateStatus": boundary["candidate_status"],
                    "independentBuilderEvidence": False,
                    "evidenceClass": boundary["evidence_class"],
                    "promotionEffect": "NONE",
                },
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
        **boundary,
        "release_version": version,
        "target": target,
        "source": identity,
        "toolchain_lock_sha256": repro_build.sha256_file(repro_build.TOOLCHAINS),
        "toolchain_provenance": {
            "installed": details["installed_toolchain_provenance"],
            "windows": details["windows_toolchain_provenance"],
        },
        "files": covered,
        "checksums_sha256": repro_build.sha256_file(out / "SHA256SUMS"),
    }
    (out / "bundle-manifest.json").write_bytes(repro_build.canonical_json(manifest))
    request = {
        "schema": "noos/external-attestation-request/v1",
        "not_an_attestation": True,
        "not_a_signature": True,
        "candidate_status": boundary["candidate_status"],
        "promotion_effect": "NONE",
        "external_builder_gate": "EXTERNAL_BLOCKED",
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
    parser.add_argument("--builder-profile", choices=sorted(BUILDER_PROFILES), default="local-builder")
    args = parser.parse_args(argv)
    try:
        result = create_bundle(
            args.target, ROOT / args.out, args.version, smoke=args.smoke,
            revision=args.revision, builder_profile=args.builder_profile,
        )
    except (repro_build.AssuranceError, OSError) as exc:
        print(f"RESULT generate_release=FAIL reason={exc}", file=sys.stderr)
        return 1
    print(f"RESULT generate_release={'SMOKE_ONLY' if args.smoke else 'CANDIDATE_ONLY'} target={args.target} files={len(result['files'])} out={args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
