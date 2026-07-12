#!/usr/bin/env python3
"""Verify and optionally retain an external audit report without promoting any gate."""
from __future__ import annotations

import argparse
import base64
import json
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

from common import (
    AuditError,
    atomic_append_only_write,
    canonical_bytes,
    materialize_bundle,
    parse_time,
    read_json,
    safe_member,
    sha256_bytes,
    sha256_file,
    verify_ed25519,
)

REPORT_KEYS = {
    "schema_version", "report_kind", "report_id", "binding", "issued_at", "expires_at",
    "auditor", "scope", "attachments", "findings", "limitations",
}
EVENT_STATES = {"open", "acknowledged", "remediation_submitted", "retest_failed", "resolved_verified"}
TRANSITIONS = {
    "open": {"acknowledged", "remediation_submitted"},
    "acknowledged": {"remediation_submitted"},
    "remediation_submitted": {"retest_failed", "resolved_verified"},
    "retest_failed": {"remediation_submitted"},
    "resolved_verified": set(),
}
DECLARATIONS = {
    "source_authorship", "subject_employment_or_control", "material_financial_interest",
    "conclusion_controlled_by_subject", "undisclosed_conflicts",
}
PRODUCTION_KEY_USE = "EXTERNAL_AUDITOR_REPORT_SIGNING"
TEST_KEY_USE = "TEST_ONLY_NOT_PRODUCTION_SIGNATURE"


def require_exact_keys(value: dict, required: set[str], label: str) -> None:
    missing = sorted(required - set(value))
    extra = sorted(set(value) - required)
    if missing:
        raise AuditError(f"{label} missing fields: {', '.join(missing)}")
    if extra:
        raise AuditError(f"{label} has unknown fields: {', '.join(extra)}")


def validate_signature(submission: Path, allow_test_keys: bool) -> tuple[dict, dict, bytes, str]:
    report_path = submission / "audit-report.json"
    signature_path = submission / "audit-report.signature.json"
    if not report_path.is_file() or not signature_path.is_file():
        raise AuditError("submission requires audit-report.json and audit-report.signature.json")
    report_bytes = report_path.read_bytes()
    signature = read_json(signature_path, "detached report signature")
    require_exact_keys(signature, {
        "schema_version", "signature_kind", "algorithm", "signed_file", "signed_file_sha256",
        "public_key_base64", "signature_base64", "key_use",
    }, "detached report signature")
    if signature.get("schema_version") != 1 or signature.get("signature_kind") != "noosphere-detached-audit-report-signature":
        raise AuditError("wrong detached signature schema or kind")
    if signature.get("algorithm") != "ed25519" or signature.get("signed_file") != "audit-report.json":
        raise AuditError("only detached Ed25519 over audit-report.json is accepted")
    report_hash = sha256_bytes(report_bytes)
    if signature.get("signed_file_sha256") != report_hash:
        raise AuditError("detached signature report hash mismatch")
    allowed_key_use = TEST_KEY_USE if allow_test_keys else PRODUCTION_KEY_USE
    if signature.get("key_use") != allowed_key_use:
        raise AuditError(f"signature key_use must be {allowed_key_use}")
    key_id = verify_ed25519(signature["public_key_base64"], signature["signature_base64"], report_bytes)
    try:
        report = json.loads(report_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError(f"signed audit report is not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(report, dict):
        raise AuditError("signed audit report must be a JSON object")
    return report, signature, report_bytes, key_id


def validate_roster(roster: dict, manifest: dict, key_id: str, public_key_base64: str, auditor: dict,
                    workstreams: set[str], as_of: datetime, allow_test_keys: bool) -> dict:
    if roster.get("schema_version") != 1 or roster.get("roster_kind") != "noosphere-external-auditor-roster":
        raise AuditError("wrong external auditor roster schema or kind")
    if roster.get("bundle_id") != manifest["bundle_id"] or roster.get("source_revision") != manifest["source_revision"]:
        raise AuditError("external auditor roster is not bound to this bundle and revision")
    candidates = [entry for entry in roster.get("entries", []) if isinstance(entry, dict) and entry.get("signing_key_id") == key_id]
    if len(candidates) != 1:
        raise AuditError("report signing key is not uniquely registered by the external auditor roster")
    entry = candidates[0]
    if entry.get("public_key_base64") != public_key_base64:
        raise AuditError("auditor roster public key does not match the report signature")
    if entry.get("organization_id") != auditor.get("organization_id"):
        raise AuditError("auditor organization does not match its roster entry")
    allowed_key_use = TEST_KEY_USE if allow_test_keys else PRODUCTION_KEY_USE
    if entry.get("key_use") != allowed_key_use:
        raise AuditError(f"auditor roster key_use must be {allowed_key_use}")
    if entry.get("relationship_to_subject") != "independent_external":
        raise AuditError("auditor roster does not declare an independent external relationship")
    authorized = set(entry.get("authorized_workstreams", []))
    if not workstreams <= authorized:
        raise AuditError("report includes a workstream not authorized by the auditor roster")
    valid_from = parse_time(entry.get("valid_from"), "auditor roster valid_from")
    valid_until = parse_time(entry.get("valid_until"), "auditor roster valid_until")
    if valid_from > as_of or as_of > valid_until:
        raise AuditError("auditor roster entry is not valid at ingest time")
    return entry


def validate_attachments(submission: Path, report: dict) -> dict:
    attachments = report.get("attachments")
    if not isinstance(attachments, dict) or "auditor-independence.json" not in attachments:
        raise AuditError("report must hash auditor-independence.json as an attachment")
    expected_files = {"audit-report.json", "audit-report.signature.json", *attachments.keys()}
    actual_files = {path.relative_to(submission).as_posix() for path in submission.rglob("*") if path.is_file()}
    if actual_files != expected_files:
        missing = sorted(expected_files - actual_files)
        unbound = sorted(actual_files - expected_files)
        raise AuditError(f"submission file set mismatch missing={missing} unbound={unbound}")
    for relative, expected in sorted(attachments.items()):
        member = safe_member(relative)
        if not isinstance(expected, str) or len(expected) != 64:
            raise AuditError(f"invalid attachment hash: {relative}")
        path = submission / Path(*member.parts)
        if sha256_file(path) != expected:
            raise AuditError(f"attachment hash mismatch: {relative}")
    return read_json(submission / "auditor-independence.json", "auditor independence declaration")


def validate_independence(declaration: dict, manifest: dict, scope: dict, auditor: dict, key_id: str) -> None:
    if declaration.get("schema_version") != 1 or declaration.get("declaration_kind") != "noosphere-auditor-independence-declaration":
        raise AuditError("wrong auditor independence declaration schema or kind")
    if declaration.get("bundle_id") != manifest["bundle_id"] or declaration.get("source_revision") != manifest["source_revision"]:
        raise AuditError("auditor independence declaration is not bound to this bundle and revision")
    organization_id = auditor.get("organization_id")
    if declaration.get("auditor_organization_id") != organization_id or declaration.get("signing_key_id") != key_id:
        raise AuditError("auditor independence declaration identity does not match the signed report")
    subject_ids = set(scope.get("subject", {}).get("organization_ids", []))
    if organization_id in subject_ids:
        raise AuditError("self-authored report refused: auditor organization is a subject organization")
    declarants = declaration.get("declarants")
    if not isinstance(declarants, list) or not declarants or any(not item.get("legal_name") or not item.get("role") for item in declarants if isinstance(item, dict)):
        raise AuditError("auditor independence declaration requires named human declarants and roles")
    if any(not isinstance(item, dict) for item in declarants):
        raise AuditError("auditor independence declarants are malformed")
    declarations = declaration.get("declarations")
    if not isinstance(declarations, dict) or set(declarations) != DECLARATIONS:
        raise AuditError("auditor independence declarations are incomplete")
    conflicts = sorted(key for key, value in declarations.items() if value is not False)
    if conflicts:
        raise AuditError("conflict-of-interest declaration blocks ingest: " + ", ".join(conflicts))
    if declaration.get("machine_verification_limit") != (
        "The ingest gate validates this signed declaration and registered identity separation; "
        "it does not establish that automation is an independent human auditor."
    ):
        raise AuditError("auditor independence declaration omits the machine-verification limit")
    if not isinstance(declaration.get("disclosed_relationships"), list):
        raise AuditError("disclosed_relationships must be a list")


def validate_event_chain(finding: dict, auditor_organization_id: str) -> None:
    events = finding.get("lifecycle_events")
    if not isinstance(events, list) or not events:
        raise AuditError(f"finding {finding.get('finding_id')} has no lifecycle events")
    previous_hash = None
    previous_state = None
    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise AuditError(f"finding {finding.get('finding_id')} has a malformed lifecycle event")
        require_exact_keys(event, {
            "sequence", "occurred_at", "actor_organization_id", "state", "prior_event_sha256",
            "evidence_refs", "event_sha256",
        }, f"finding {finding.get('finding_id')} event")
        if event["sequence"] != index or event["prior_event_sha256"] != previous_hash:
            raise AuditError(f"finding {finding.get('finding_id')} lifecycle is not append-only hash chained")
        parse_time(event["occurred_at"], "finding event occurred_at")
        state = event["state"]
        if state not in EVENT_STATES:
            raise AuditError(f"finding {finding.get('finding_id')} has forbidden lifecycle state {state}")
        if index == 1 and state != "open":
            raise AuditError(f"finding {finding.get('finding_id')} must begin open")
        if previous_state is not None and state not in TRANSITIONS[previous_state]:
            raise AuditError(f"finding {finding.get('finding_id')} has invalid transition {previous_state}->{state}")
        projection = {key: value for key, value in event.items() if key != "event_sha256"}
        computed = sha256_bytes(canonical_bytes(projection))
        if event["event_sha256"] != computed:
            raise AuditError(f"finding {finding.get('finding_id')} event hash mismatch")
        previous_hash = computed
        previous_state = state
    if finding.get("severity") == "S1":
        final = events[-1]
        if final["state"] != "resolved_verified":
            raise AuditError(f"unresolved severity-1 finding blocks ingest: {finding.get('finding_id')}")
        if final["actor_organization_id"] != auditor_organization_id:
            raise AuditError(f"severity-1 resolution was not verified by the registered auditor: {finding.get('finding_id')}")


def validate_report(report: dict, manifest: dict, bundle_root: Path, as_of: datetime, key_id: str) -> tuple[dict, set[str]]:
    require_exact_keys(report, REPORT_KEYS, "audit report")
    if report.get("schema_version") != 1 or report.get("report_kind") != "noosphere-independent-audit-report":
        raise AuditError("wrong audit report schema or kind")
    if not isinstance(report.get("report_id"), str) or not report["report_id"]:
        raise AuditError("report_id is missing")
    binding = report.get("binding")
    expected_binding = {
        "bundle_id": manifest["bundle_id"],
        "source_revision": manifest["source_revision"],
        **manifest["binding"],
        "bundle_manifest_sha256": sha256_file(bundle_root / "bundle-manifest.json"),
    }
    if binding != expected_binding:
        raise AuditError("report is unbound or targets the wrong revision/bundle/artifact hashes")
    issued_at = parse_time(report.get("issued_at"), "report issued_at")
    expires_at = parse_time(report.get("expires_at"), "report expires_at")
    max_age_days = read_json(bundle_root / "audit-scope.json", "audit scope")["report_policy"]["max_report_age_days"]
    if issued_at > as_of:
        raise AuditError("report issued_at is in the future")
    if expires_at <= issued_at or as_of > expires_at:
        raise AuditError("stale report: report validity interval has expired or is invalid")
    if (as_of - issued_at).total_seconds() > max_age_days * 86400:
        raise AuditError("stale report: maximum report age exceeded")
    auditor = report.get("auditor")
    if not isinstance(auditor, dict) or set(auditor) != {"organization_id", "signing_key_id"}:
        raise AuditError("auditor identity is missing or malformed")
    if auditor.get("signing_key_id") != key_id:
        raise AuditError("report auditor key id does not match detached signature")
    report_scope = report.get("scope")
    if not isinstance(report_scope, dict) or set(report_scope) != {"workstream_ids", "scope_exceptions"}:
        raise AuditError("report scope is missing or malformed")
    workstream_ids = report_scope.get("workstream_ids")
    if not isinstance(workstream_ids, list) or not workstream_ids or len(workstream_ids) != len(set(workstream_ids)):
        raise AuditError("report scope must name at least one unique workstream")
    known = {item["id"] for item in read_json(bundle_root / "audit-scope.json", "audit scope")["workstreams"]}
    workstreams = set(workstream_ids)
    if not workstreams <= known:
        raise AuditError("report names an unknown workstream")
    if not isinstance(report_scope.get("scope_exceptions"), list):
        raise AuditError("scope_exceptions must be a list")
    findings = report.get("findings")
    if not isinstance(findings, list):
        raise AuditError("findings must be a list")
    finding_ids: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            raise AuditError("finding is malformed")
        require_exact_keys(finding, {"finding_id", "workstream_id", "severity", "title", "description", "lifecycle_events"}, "finding")
        finding_id = finding.get("finding_id")
        if not isinstance(finding_id, str) or not finding_id or finding_id in finding_ids:
            raise AuditError("finding IDs must be non-empty and unique")
        finding_ids.add(finding_id)
        if finding.get("workstream_id") not in workstreams:
            raise AuditError(f"finding {finding_id} is outside the declared report scope")
        if finding.get("severity") not in {"S1", "S2", "S3", "S4"}:
            raise AuditError(f"finding {finding_id} has missing or invalid severity")
        validate_event_chain(finding, auditor["organization_id"])
    if not isinstance(report.get("limitations"), list):
        raise AuditError("limitations must be a list")
    return auditor, workstreams


def validate_submission(bundle: Path, submission: Path, roster_path: Path, as_of: datetime,
                        allow_test_keys: bool = False) -> dict:
    if not submission.is_dir():
        raise AuditError("submission must be a directory")
    with materialize_bundle(bundle) as (bundle_root, manifest):
        report, signature, report_bytes, key_id = validate_signature(submission, allow_test_keys)
        auditor, workstreams = validate_report(report, manifest, bundle_root, as_of, key_id)
        scope = read_json(bundle_root / "audit-scope.json", "audit scope")
        independence = validate_attachments(submission, report)
        validate_independence(independence, manifest, scope, auditor, key_id)
        roster = read_json(roster_path, "external auditor roster")
        validate_roster(roster, manifest, key_id, signature["public_key_base64"], auditor, workstreams, as_of, allow_test_keys)
        return {
            "schema_version": 1,
            "receipt_kind": "noosphere-audit-report-ingest-receipt",
            "result": "ACCEPTED_FOR_EVIDENCE_CUSTODY",
            "report_id": report["report_id"],
            "report_sha256": sha256_bytes(report_bytes),
            "bundle_id": manifest["bundle_id"],
            "source_revision": manifest["source_revision"],
            "auditor_organization_id": auditor["organization_id"],
            "auditor_signing_key_id": key_id,
            "workstream_ids": sorted(workstreams),
            "ingested_as_of": as_of.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "external_audit_complete": False,
            "promotion_effect": "none",
            "notice": "Acceptance verifies package integrity and policy predicates only; it is not an audit verdict or gate pass.",
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--submission", type=Path, required=True)
    parser.add_argument("--auditor-roster", type=Path, required=True)
    parser.add_argument("--as-of", help="real UTC ingest time; defaults to the current system clock")
    parser.add_argument("--ledger-dir", type=Path, help="optional append-only receipt directory")
    args = parser.parse_args()
    try:
        as_of = parse_time(args.as_of, "--as-of") if args.as_of else datetime.now(timezone.utc)
        receipt = validate_submission(
            args.bundle.resolve(), args.submission.resolve(), args.auditor_roster.resolve(), as_of,
            allow_test_keys=False,
        )
        if args.ledger_dir:
            relative = f"{receipt['report_sha256']}.json"
            atomic_append_only_write(args.ledger_dir.resolve() / relative, canonical_bytes(receipt))
    except AuditError as exc:
        print(f"RESULT audit_report_ingest=REFUSED error={exc}")
        print("NOTICE external_audit_complete=false promotion_effect=none")
        return 2
    print("RESULT audit_report_ingest=ACCEPTED report_sha256=" + receipt["report_sha256"])
    print("NOTICE external_audit_complete=false promotion_effect=none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
