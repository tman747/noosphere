#!/usr/bin/env python3
"""Build a deterministic, exact-revision independent-audit handoff bundle."""
from __future__ import annotations

import argparse
import fnmatch
import json
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

from common import (
    ROOT,
    AuditError,
    canonical_bytes,
    git,
    git_blob,
    git_paths,
    materialize_bundle,
    resolve_revision,
    sha256_bytes,
    sha256_file,
)

SUPPORT_PATHS = [
    "Cargo.toml",
    "Cargo.lock",
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
        archive_path = ("source/" if path in all_source_paths else "reference/") + path
        blobs[archive_path] = data
        workstreams = sorted(key for key, values in workstream_files.items() if path in values)
        entries.append({
            "path": path,
            "archive_path": archive_path,
            "sha256": sha256_bytes(data),
            "bytes": len(data),
            "role": "audited_source" if path in all_source_paths else "normative_or_tooling_reference",
            "workstreams": workstreams,
        })

    source_manifest = {
        "schema_version": 1,
        "manifest_kind": "noosphere-audit-source-manifest",
        "source_revision": revision,
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
    instructions = f"""# Independent auditor handoff\n\nThis bundle targets exact Git revision `{revision}` and bundle `{bundle_id}`. It is a handoff, not an audit verdict, launch approval, or statement that an external audit is complete. Its timestamps are commit/package metadata and never evidence of elapsed public-testnet, Quiet Week, canary, or other real public time.\n\n1. Verify `bundle-manifest.json`, every listed SHA-256, and the source revision independently.\n2. Use `audit-scope.json`, `threat-model-inventory.json`, and the six workstream source trees. Record all scope exceptions.\n3. Obtain an external auditor-roster entry for the report key. A self-declared random key is not sufficient.\n4. Complete `auditor-independence.json`; declarations are signed assertions, not machine proof of human independence.\n5. Complete `audit-report.json`. Findings are append-only hash-chained events under `finding-lifecycle.json`. Waivers and risk acceptance never close a finding. An S1 must end in auditor-authored `resolved_verified`.\n6. Hash every attachment into the report, then sign the exact raw `audit-report.json` bytes with detached Ed25519 and complete `audit-report.signature.json`.\n7. Run `python tools/audit/ingest_report.py --bundle <bundle.zip> --submission <directory> --auditor-roster <external-roster.json> --as-of <real-current-UTC-time>`. Acceptance means evidence-package integrity only; it cannot pass G3/G5 or edit claim state.\n\nNo private key is included. Any keys created by the deterministic test suite are ephemeral and explicitly test-only; they are not production signatures.\n"""
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
            "source_revision_commit_time": commit_time,
            "time_basis": "Git commit metadata only; not elapsed public time, Quiet Week, public testnet, canary, or launch-duration evidence.",
            "binding": binding,
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

    with materialize_bundle(output) as (_, verified):
        if verified["bundle_id"] != bundle_id:
            raise AuditError("post-build bundle verification returned a different id")
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
