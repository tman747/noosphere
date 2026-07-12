#!/usr/bin/env python3
"""Build a deterministic, exact-revision independent-audit handoff bundle."""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import subprocess
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from common import (
    ROOT,
    AuditError,
    canonical_bytes,
    git,
    git_blob,
    git_entry,
    git_paths,
    git_tree,
    materialize_bundle,
    resolve_revision,
    sha256_bytes,
    sha256_file,
    verify_bundle_against_git,
)

SUPPORT_PATHS = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "go/go.mod",
    "go/go.sum",
    "protocol/claims/registry.json",
    "protocol/claims/registry.schema.json",
    "protocol/release/promotion-blockers.json",
    "protocol/release/promotion-blockers-schema-v1.json",
    "protocol/release/repro-policy-v1.toml",
    "protocol/spec/precedence.md",
    "protocol/spec/genesis-identity-v1.md",
    "protocol/audit/audit-scope-v1.json",
    "protocol/audit/severity-taxonomy-v1.json",
    "protocol/audit/finding-lifecycle-v1.json",
    "protocol/audit/audit-report-schema-v1.json",
    "tools/audit/common.py",
    "tools/audit/build_handoff.py",
    "tools/audit/ingest_report.py",
    "tools/audit/verify_handoff.py",
    "tools/audit/test_audit_system.py",
]

RISC0_TCB_PATHS = {
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "crates/noos-jet/Cargo.toml",
    "crates/noos-jet/src/risc0.rs",
    "crates/noos-jet/src/vectors.rs",
    "crates/noos-jet/src/bin/jet-risc0-vec.rs",
    "crates/noos-jet/risc0-methods/Cargo.toml",
    "crates/noos-jet/risc0-methods/Cargo.lock",
    "crates/noos-jet/risc0-methods/build.rs",
    "crates/noos-jet/risc0-methods/rebuild-guest.ps1",
    "crates/noos-jet/risc0-methods/src/lib.rs",
    "crates/noos-jet/risc0-methods/src/bin/risc0-method-id.rs",
    "crates/noos-jet/risc0-methods/guest/Cargo.toml",
    "crates/noos-jet/risc0-methods/guest/src/main.rs",
    "crates/noos-jet/risc0-methods/shared/Cargo.toml",
    "crates/noos-jet/risc0-methods/shared/src/lib.rs",
    "crates/noos-jet/risc0-methods/artifacts/jet_proof.bin",
    "protocol/vectors/jet/jet-risc0-proof-v1.json",
}


def load_blob_json(revision: str, path: str) -> dict:
    try:
        value = json.loads(git_blob(revision, path).decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"invalid JSON at {path} in {revision}: {exc}") from exc
    if not isinstance(value, dict):
        raise AuditError(f"{path} is not a JSON object")
    return value


def matching_paths(paths: list[str], patterns: list[str]) -> list[str]:
    return sorted({path for path in paths for pattern in patterns if fnmatch.fnmatchcase(path, pattern)})


def validate_scope(scope: dict, registry: dict, paths: list[str]) -> None:
    if scope.get("schema_version") != 1 or scope.get("scope_id") != "NOOS-INDEPENDENT-AUDIT-SCOPE-V1":
        raise AuditError("wrong audit scope schema or id")
    if scope.get("subject", {}).get("automation_independence_claim") is not False:
        raise AuditError("audit scope must not claim automation is independent")
    workstreams = scope.get("workstreams")
    if not isinstance(workstreams, list) or {item.get("id") for item in workstreams} != {
        "consensus", "networking", "state-transition", "cryptography-cryptanalysis", "economics", "operations"
    }:
        raise AuditError("audit scope does not contain the six mandatory workstreams")
    rows = {row.get("claim_id"): row for row in registry.get("claims", [])}
    for workstream in workstreams:
        for claim_id in workstream.get("claim_ids", []):
            if claim_id not in rows:
                raise AuditError(f"scope references missing claim: {claim_id}")
        for pattern in workstream.get("source_globs", []):
            if not matching_paths(paths, [pattern]):
                raise AuditError(f"scope source glob matches no tracked file: {pattern}")

    crypto = next(item for item in workstreams if item["id"] == "cryptography-cryptanalysis")
    crypto_paths = set(matching_paths(paths, crypto["source_globs"])) | set(SUPPORT_PATHS)
    missing_tcb = sorted(RISC0_TCB_PATHS - crypto_paths)
    if missing_tcb:
        raise AuditError("cryptography scope omits RISC Zero proving TCB: " + ", ".join(missing_tcb))
    method_roots = {
        path.rsplit("/", 1)[0]
        for path in paths
        if path.startswith("crates/noos-jet/") and path.endswith("-methods/Cargo.toml")
    }
    declared = scope.get("proving_backends")
    if not isinstance(declared, list) or {item.get("root") for item in declared if isinstance(item, dict)} != method_roots:
        raise AuditError("every tracked proving-method backend must have exactly one scope declaration")
    for backend in declared:
        required = {"id", "root", "host_verifier", "method_artifact", "method_id_source", "proof_vectors", "rebuild_script"}
        if set(backend) != required or any(not isinstance(backend[key], str) or not backend[key] for key in required):
            raise AuditError("proving backend declaration has missing or unknown fields")
        backend_paths = {backend[key] for key in required - {"id", "root"}}
        tracked_under_root = {path for path in paths if path.startswith(backend["root"] + "/")}
        if not backend_paths <= set(paths) or not tracked_under_root <= crypto_paths:
            raise AuditError(f"proving backend is incomplete in cryptography scope: {backend['id']}")


def _expected_risc0_method_id(method_source: bytes) -> list[int]:
    text = method_source.decode("utf-8")
    match = re.search(r"JET_PROOF_ID\s*:\s*\[u32;\s*8\]\s*=\s*\[(.*?)\];", text, re.S)
    if not match:
        raise AuditError("cannot locate JET_PROOF_ID in packaged method source")
    words = [int(token.replace("_", "")) for token in re.findall(r"\d[\d_]*", match.group(1))]
    if len(words) != 8 or any(word > 0xFFFF_FFFF for word in words):
        raise AuditError("packaged JET_PROOF_ID is not eight u32 words")
    return words


def verify_risc0_method_binding(revision: str) -> list[int]:
    artifact = git_blob(revision, "crates/noos-jet/risc0-methods/artifacts/jet_proof.bin")
    expected = _expected_risc0_method_id(git_blob(revision, "crates/noos-jet/risc0-methods/src/lib.rs"))
    vector = load_blob_json(revision, "protocol/vectors/jet/jet-risc0-proof-v1.json")
    if vector.get("method_id_words") != expected or not vector.get("cases"):
        raise AuditError("RISC Zero proof vector is missing or disagrees with host method id")
    with tempfile.TemporaryDirectory(prefix="noos-risc0-method-id-") as temporary:
        artifact_path = Path(temporary) / "jet_proof.bin"
        artifact_path.write_bytes(artifact)
        cargo_args = [
            "cargo", "run", "--quiet", "--locked",
            "--manifest-path", "crates/noos-jet/risc0-methods/Cargo.toml",
            "--bin", "risc0-method-id", "--",
        ]
        if os.name == "nt":
            def wsl_path(path: Path) -> str:
                converted = subprocess.run(
                    ["wsl.exe", "-e", "wslpath", "-a", str(path)],
                    text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
                if converted.returncode:
                    raise AuditError("cannot map method-id input into trusted WSL environment")
                return converted.stdout.strip()

            command = [
                "wsl.exe", "-e", "bash", "-lc",
                "cd " + shlex.quote(wsl_path(ROOT)) + " && "
                + " ".join(shlex.quote(arg) for arg in [*cargo_args, wsl_path(artifact_path)]),
            ]
        else:
            command = [*cargo_args, str(artifact_path)]
        completed = subprocess.run(
            command,
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    if completed.returncode:
        raise AuditError("independent RISC Zero method-id computation failed: " + completed.stderr[-1000:].strip())
    try:
        computed = [int(word) for word in completed.stdout.strip().split(",")]
    except ValueError as exc:
        raise AuditError("independent RISC Zero method-id tool emitted invalid output") from exc
    if computed != expected:
        raise AuditError(f"RISC Zero method artifact/id mismatch computed={computed} expected={expected}")
    return computed


def source_manifest_and_inventory(revision: str, scope: dict, registry: dict, paths: list[str]) -> tuple[dict, dict, dict[str, bytes]]:
    rows = {row["claim_id"]: row for row in registry["claims"]}
    workstream_files: dict[str, list[str]] = {}
    all_source_paths: set[str] = set()
    for workstream in scope["workstreams"]:
        matched = matching_paths(paths, workstream["source_globs"])
        workstream_files[workstream["id"]] = matched
        all_source_paths.update(matched)

    included_paths = sorted(all_source_paths | {path for path in SUPPORT_PATHS if path in paths})
    missing_support = sorted(set(SUPPORT_PATHS) - set(included_paths))
    if missing_support:
        raise AuditError("required support paths missing from revision: " + ", ".join(missing_support))

    blobs: dict[str, bytes] = {}
    entries: list[dict] = []
    for path in included_paths:
        data = git_blob(revision, path)
        mode, object_type, object_id = git_entry(revision, path)
        if object_type != "blob":
            raise AuditError(f"audited path is not a Git blob: {path}")
        archive_path = ("source/" if path in all_source_paths else "reference/") + path
        blobs[archive_path] = data
        workstreams = sorted(key for key, values in workstream_files.items() if path in values)
        entries.append({
            "path": path,
            "archive_path": archive_path,
            "git_mode": mode,
            "git_type": object_type,
            "git_blob": object_id,
            "sha256": sha256_bytes(data),
            "bytes": len(data),
            "role": "audited_source" if path in all_source_paths else "normative_or_tooling_reference",
            "workstreams": workstreams,
        })

    source_manifest = {
        "schema_version": 2,
        "manifest_kind": "noosphere-audit-source-manifest",
        "source_revision": revision,
        "source_tree": git_tree(revision),
        "hash_algorithm": "sha256",
        "entries": entries,
    }

    threats: list[dict] = []
    for workstream in scope["workstreams"]:
        source_refs = workstream_files[workstream["id"]]
        for claim_id in workstream["claim_ids"]:
            row = rows[claim_id]
            claim_projection = {
                key: row.get(key)
                for key in (
                    "claim_id", "mechanism_id", "claim", "protected_property", "adversary", "metric",
                    "pass_threshold", "kill_threshold", "scope", "lifecycle", "result",
                    "local_implementation_state", "local_evidence_state", "owner_blockers", "external_blockers",
                )
            }
            threats.append({
                "threat_id": f"TM-{workstream['id'].upper()}-{claim_id}",
                "workstream_id": workstream["id"],
                "claim_id": claim_id,
                "claim_row_sha256": sha256_bytes(canonical_bytes(row)),
                "protected_property": row.get("protected_property"),
                "adversary": row.get("adversary"),
                "kill_threshold": row.get("kill_threshold"),
                "registered_state": {
                    "lifecycle": row.get("lifecycle"),
                    "result": row.get("result"),
                    "local_implementation_state": row.get("local_implementation_state"),
                    "local_evidence_state": row.get("local_evidence_state"),
                    "owner_blockers": row.get("owner_blockers", []),
                    "external_blockers": row.get("external_blockers", []),
                },
                "source_refs": source_refs,
                "registry_projection": claim_projection,
            })
    threat_inventory = {
        "schema_version": 1,
        "inventory_kind": "noosphere-source-and-registry-derived-threat-model",
        "source_revision": revision,
        "derivation": "Claim threats are copied from protected_property/adversary/kill_threshold fields; source refs are resolved from scope globs against the exact Git tree. No audit finding or verdict is generated.",
        "claim_registry_sha256": sha256_bytes(git_blob(revision, "protocol/claims/registry.json")),
        "threats": threats,
    }
    return source_manifest, threat_inventory, blobs


def templates(bundle_id: str, revision: str, binding: dict, scope: dict) -> dict[str, bytes]:
    report = {
        "schema_version": 1,
        "report_kind": "noosphere-independent-audit-report",
        "report_id": "EXTERNAL_AUDITOR_REQUIRED",
        "binding": {
            "bundle_id": bundle_id,
            "source_revision": revision,
            **binding,
            "bundle_manifest_sha256": "REPLACE_WITH_SHA256_OF_BUNDLE_MANIFEST_JSON",
        },
        "issued_at": "REPLACE_WITH_REAL_UTC_TIMESTAMP",
        "expires_at": "REPLACE_WITH_REAL_UTC_TIMESTAMP_NO_MORE_THAN_90_DAYS_AFTER_ISSUE",
        "auditor": {"organization_id": "EXTERNAL_AUDITOR_REQUIRED", "signing_key_id": "EXTERNAL_AUDITOR_KEY_SHA256_REQUIRED"},
        "scope": {"workstream_ids": [item["id"] for item in scope["workstreams"]], "scope_exceptions": []},
        "attachments": {"auditor-independence.json": "REPLACE_WITH_SHA256"},
        "findings": [],
        "limitations": [],
    }
    independence = {
        "schema_version": 1,
        "declaration_kind": "noosphere-auditor-independence-declaration",
        "bundle_id": bundle_id,
        "source_revision": revision,
        "auditor_organization_id": "EXTERNAL_AUDITOR_REQUIRED",
        "signing_key_id": "EXTERNAL_AUDITOR_KEY_SHA256_REQUIRED",
        "declarants": [{"legal_name": "HUMAN_DECLARANT_REQUIRED", "role": "AUDIT_ROLE_REQUIRED"}],
        "declarations": {
            "source_authorship": False,
            "subject_employment_or_control": False,
            "material_financial_interest": False,
            "conclusion_controlled_by_subject": False,
            "undisclosed_conflicts": False,
        },
        "disclosed_relationships": [],
        "machine_verification_limit": "The ingest gate validates this signed declaration and registered identity separation; it does not establish that automation is an independent human auditor.",
    }
    roster = {
        "schema_version": 1,
        "roster_kind": "noosphere-external-auditor-roster",
        "bundle_id": bundle_id,
        "source_revision": revision,
        "entries": [],
        "external_input_required": "Populate with independently selected auditor organization, Ed25519 public key, authorized workstreams, and real validity interval. Project/self-authored identities are refused.",
    }
    signature = {
        "schema_version": 1,
        "signature_kind": "noosphere-detached-audit-report-signature",
        "algorithm": "ed25519",
        "signed_file": "audit-report.json",
        "signed_file_sha256": "REPLACE_WITH_SHA256",
        "public_key_base64": "EXTERNAL_AUDITOR_PUBLIC_KEY_REQUIRED",
        "signature_base64": "EXTERNAL_AUDITOR_SIGNATURE_REQUIRED",
        "key_use": "EXTERNAL_AUDITOR_REPORT_SIGNING_NOT_A_TEST_KEY",
    }
    instructions = f"""# Independent auditor handoff\n\nThis bundle targets exact Git revision `{revision}` and bundle `{bundle_id}`. It is a handoff, not an audit verdict, launch approval, or statement that an external audit is complete. Its timestamps are commit/package metadata and never evidence of elapsed public-testnet, Quiet Week, canary, or other real public time.\n\n1. Obtain the repository/worktree or trusted Git object database independently. Run `python tools/audit/verify_handoff.py <bundle.zip> --repo <trusted-repository> --revision {revision}`. A bundle cannot establish its own revision trust root.\n2. Verify `bundle-manifest.json`, every listed SHA-256, every packaged source byte/mode/blob against `<revision>:<path>`, and independently recompute the packaged RISC Zero method ID.\n3. Use `audit-scope.json`, `threat-model-inventory.json`, and the six workstream source trees. Record all scope exceptions.\n4. Obtain an external auditor-roster entry for the report key. A self-declared random key is not sufficient.\n5. Complete `auditor-independence.json`; declarations are signed assertions, not machine proof of human independence.\n6. Complete `audit-report.json`. Findings are append-only hash-chained events under `finding-lifecycle.json`. Waivers and risk acceptance never close a finding. An S1 must end in auditor-authored `resolved_verified`.\n7. Hash every attachment into the report, then sign the exact raw `audit-report.json` bytes with detached Ed25519 and complete `audit-report.signature.json`.\n8. Run `python tools/audit/ingest_report.py --bundle <bundle.zip> --submission <directory> --auditor-roster <external-roster.json> --as-of <real-current-UTC-time>`. Acceptance means evidence-package integrity only; it cannot pass G3/G5 or edit claim state.\n\nNo private key is included. Any keys created by the deterministic test suite are ephemeral and explicitly test-only; they are not production signatures.\n"""
    return {
        "templates/audit-report.template.json": canonical_bytes(report),
        "templates/auditor-independence.template.json": canonical_bytes(independence),
        "templates/auditor-roster.template.json": canonical_bytes(roster),
        "templates/audit-report.signature.template.json": canonical_bytes(signature),
        "AUDITOR-INSTRUCTIONS.md": instructions.encode("utf-8"),
    }


def write_bundle(revision: str, output: Path) -> tuple[str, str]:
    paths = git_paths(revision)
    scope = load_blob_json(revision, "protocol/audit/audit-scope-v1.json")
    registry = load_blob_json(revision, "protocol/claims/registry.json")
    validate_scope(scope, registry, paths)
    method_id = verify_risc0_method_binding(revision)
    source_manifest, threat_inventory, blobs = source_manifest_and_inventory(revision, scope, registry, paths)
    scope_bytes = canonical_bytes(scope)
    source_manifest_bytes = canonical_bytes(source_manifest)
    threat_inventory_bytes = canonical_bytes(threat_inventory)
    binding = {
        "scope_sha256": sha256_bytes(scope_bytes),
        "source_manifest_sha256": sha256_bytes(source_manifest_bytes),
        "threat_inventory_sha256": sha256_bytes(threat_inventory_bytes),
    }
    identity = {"source_revision": revision, **binding}
    bundle_id = "sha256:" + sha256_bytes(canonical_bytes(identity))
    blobs.update({
        "audit-scope.json": scope_bytes,
        "source-manifest.json": source_manifest_bytes,
        "threat-model-inventory.json": threat_inventory_bytes,
        "severity-taxonomy.json": git_blob(revision, "protocol/audit/severity-taxonomy-v1.json"),
        "finding-lifecycle.json": git_blob(revision, "protocol/audit/finding-lifecycle-v1.json"),
        "audit-report-schema.json": git_blob(revision, "protocol/audit/audit-report-schema-v1.json"),
    })
    blobs.update(templates(bundle_id, revision, binding, scope))
    commit_time = str(git("show", "-s", "--format=%cI", revision))

    with tempfile.TemporaryDirectory(prefix="noos-audit-build-") as temporary:
        root = Path(temporary)
        for relative, data in blobs.items():
            path = root / Path(*PurePosixPath(relative).parts)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        files = {relative: sha256_bytes(data) for relative, data in sorted(blobs.items())}
        manifest = {
            "schema_version": 1,
            "bundle_kind": "noosphere-independent-audit-handoff",
            "bundle_id": bundle_id,
            "source_revision": revision,
            "source_tree": git_tree(revision),
            "source_revision_commit_time": commit_time,
            "time_basis": "Git commit metadata only; not elapsed public time, Quiet Week, public testnet, canary, or launch-duration evidence.",
            "binding": binding,
            "verified_proving_artifacts": {
                "risc0-jet-proof": {
                    "artifact": "crates/noos-jet/risc0-methods/artifacts/jet_proof.bin",
                    "method_id_words": method_id,
                    "computation": "risc0-binfmt-3.0.4 compute_image_id",
                }
            },
            "files": files,
            "status": "READY_FOR_EXTERNAL_AUDITOR_HANDOFF",
            "external_audit_complete": False,
            "promotion_effect": "none",
            "registry_claim_states_modified": False,
            "test_or_fixture_keys_accepted": False,
            "independence_limit": "The software verifies signed declarations and identity separation. It does not make automation an independent human auditor.",
        }
        (root / "bundle-manifest.json").write_bytes(canonical_bytes(manifest))

        output.parent.mkdir(parents=True, exist_ok=True)
        if output.exists():
            output.unlink()
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for path in sorted(root.rglob("*")):
                if path.is_file():
                    relative = path.relative_to(root).as_posix()
                    info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
                    info.compress_type = zipfile.ZIP_DEFLATED
                    info.external_attr = 0o100644 << 16
                    archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)

    with materialize_bundle(output) as (root, verified):
        if verified["bundle_id"] != bundle_id:
            raise AuditError("post-build bundle verification returned a different id")
        verify_bundle_against_git(root, verified, ROOT, revision)
    digest = sha256_file(output)
    output.with_suffix(output.suffix + ".sha256").write_text(f"{digest}  {output.name}\n", encoding="ascii")
    return bundle_id, digest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", default="HEAD", help="exact target commit or revision resolved to a commit")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        revision = resolve_revision(args.revision)
        bundle_id, digest = write_bundle(revision, args.output.resolve())
    except AuditError as exc:
        print(f"RESULT audit_handoff=FAIL error={exc}")
        return 1
    print(f"RESULT audit_handoff=READY source_revision={revision} bundle_id={bundle_id} sha256={digest}")
    print("NOTICE external_audit_complete=false promotion_effect=none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
