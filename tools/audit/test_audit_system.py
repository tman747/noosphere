#!/usr/bin/env python3
from __future__ import annotations

import base64
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from common import (  # noqa: E402
    AuditError,
    canonical_bytes,
    git_entry,
    git_tree,
    sha256_bytes,
    verify_bundle_against_git,
    verify_bundle_dir,
)
from build_handoff import RISC0_TCB_PATHS, templates, validate_scope  # noqa: E402
from ingest_report import TEST_KEY_USE, validate_submission  # noqa: E402

AS_OF = datetime(2026, 7, 11, 18, 0, 0, tzinfo=timezone.utc)


def event(sequence: int, state: str, actor: str, previous: str | None) -> dict:
    value = {
        "sequence": sequence,
        "occurred_at": f"2026-07-{9 + sequence:02d}T12:00:00Z",
        "actor_organization_id": actor,
        "state": state,
        "prior_event_sha256": previous,
        "evidence_refs": [],
    }
    value["event_sha256"] = sha256_bytes(canonical_bytes(value))
    return value


class AuditSystemTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="noos-audit-tests-")
        self.root = Path(self.temporary.name)
        self.bundle = self.root / "bundle"
        self.submission = self.root / "submission"
        self.roster = self.root / "auditor-roster.json"
        self.bundle.mkdir()
        self.submission.mkdir()
        self.private_key = Ed25519PrivateKey.generate()  # Ephemeral TEST_ONLY_NOT_PRODUCTION_SIGNATURE key.
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        self.public_key_base64 = base64.b64encode(public_bytes).decode("ascii")
        self.key_id = sha256_bytes(public_bytes)
        self._write_bundle()
        self.independence = self._independence()
        self._write_submission(self._report(), self.independence)
        self._write_roster()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _write_bundle(self) -> None:
        scope = {
            "schema_version": 1,
            "scope_id": "NOOS-INDEPENDENT-AUDIT-SCOPE-V1",
            "subject": {"organization_ids": ["noosphere", "mindchain-engineering"], "automation_independence_claim": False},
            "report_policy": {"max_report_age_days": 90},
            "workstreams": [{"id": "consensus"}, {"id": "networking"}, {"id": "state-transition"},
                            {"id": "cryptography-cryptanalysis"}, {"id": "economics"}, {"id": "operations"}],
        }
        source_manifest = {"schema_version": 1, "entries": []}
        threat_inventory = {"schema_version": 1, "threats": []}
        payloads = {
            "audit-scope.json": canonical_bytes(scope),
            "source-manifest.json": canonical_bytes(source_manifest),
            "threat-model-inventory.json": canonical_bytes(threat_inventory),
        }
        binding = {
            "scope_sha256": sha256_bytes(payloads["audit-scope.json"]),
            "source_manifest_sha256": sha256_bytes(payloads["source-manifest.json"]),
            "threat_inventory_sha256": sha256_bytes(payloads["threat-model-inventory.json"]),
        }
        self.revision = "1" * 40
        identity = {"source_revision": self.revision, **binding}
        self.bundle_id = "sha256:" + sha256_bytes(canonical_bytes(identity))
        for name, data in payloads.items():
            (self.bundle / name).write_bytes(data)
        manifest = {
            "schema_version": 1,
            "bundle_kind": "noosphere-independent-audit-handoff",
            "bundle_id": self.bundle_id,
            "source_revision": self.revision,
            "source_tree": "2" * 40,
            "binding": binding,
            "files": {name: sha256_bytes(data) for name, data in payloads.items()},
            "external_audit_complete": False,
            "promotion_effect": "none",
        }
        (self.bundle / "bundle-manifest.json").write_bytes(canonical_bytes(manifest))
        self.manifest = manifest

    def _independence(self, organization: str = "external-audit-lab") -> dict:
        return {
            "schema_version": 1,
            "declaration_kind": "noosphere-auditor-independence-declaration",
            "bundle_id": self.bundle_id,
            "source_revision": self.revision,
            "auditor_organization_id": organization,
            "signing_key_id": self.key_id,
            "declarants": [{"legal_name": "Test Auditor", "role": "TEST FIXTURE HUMAN ROLE"}],
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

    def _report(self, organization: str = "external-audit-lab", findings: list[dict] | None = None) -> dict:
        independence_bytes = canonical_bytes(self.independence if hasattr(self, "independence") else self._independence(organization))
        return {
            "schema_version": 1,
            "report_kind": "noosphere-independent-audit-report",
            "report_id": "TEST-REPORT-NOT-AN-AUDIT-VERDICT",
            "binding": {
                "bundle_id": self.bundle_id,
                "source_revision": self.revision,
                **self.manifest["binding"],
                "bundle_manifest_sha256": sha256_bytes((self.bundle / "bundle-manifest.json").read_bytes()),
            },
            "issued_at": "2026-07-10T12:00:00Z",
            "expires_at": "2026-08-10T12:00:00Z",
            "auditor": {"organization_id": organization, "signing_key_id": self.key_id},
            "scope": {"workstream_ids": ["consensus"], "scope_exceptions": []},
            "attachments": {"auditor-independence.json": sha256_bytes(independence_bytes)},
            "findings": findings or [],
            "limitations": ["TEST FIXTURE ONLY; no audit verdict"],
        }

    def _write_submission(self, report: dict, independence: dict, sign: bool = True) -> None:
        for path in self.submission.rglob("*"):
            if path.is_file():
                path.unlink()
        independence_bytes = canonical_bytes(independence)
        (self.submission / "auditor-independence.json").write_bytes(independence_bytes)
        report = copy.deepcopy(report)
        report["attachments"]["auditor-independence.json"] = sha256_bytes(independence_bytes)
        report_bytes = canonical_bytes(report)
        (self.submission / "audit-report.json").write_bytes(report_bytes)
        signature_bytes = self.private_key.sign(report_bytes) if sign else b"\x00" * 64
        signature = {
            "schema_version": 1,
            "signature_kind": "noosphere-detached-audit-report-signature",
            "algorithm": "ed25519",
            "signed_file": "audit-report.json",
            "signed_file_sha256": sha256_bytes(report_bytes),
            "public_key_base64": self.public_key_base64,
            "signature_base64": base64.b64encode(signature_bytes).decode("ascii"),
            "key_use": TEST_KEY_USE,
        }
        (self.submission / "audit-report.signature.json").write_bytes(canonical_bytes(signature))

    def _write_roster(self, organization: str = "external-audit-lab") -> None:
        value = {
            "schema_version": 1,
            "roster_kind": "noosphere-external-auditor-roster",
            "bundle_id": self.bundle_id,
            "source_revision": self.revision,
            "entries": [{
                "organization_id": organization,
                "signing_key_id": self.key_id,
                "public_key_base64": self.public_key_base64,
                "key_use": TEST_KEY_USE,
                "relationship_to_subject": "independent_external",
                "authorized_workstreams": ["consensus"],
                "valid_from": "2026-07-01T00:00:00Z",
                "valid_until": "2026-12-31T00:00:00Z",
            }],
        }
        self.roster.write_bytes(canonical_bytes(value))

    def _validate(self) -> dict:
        return validate_submission(self.bundle, self.submission, self.roster, AS_OF, allow_test_keys=True)

    def test_valid_test_fixture_is_accepted_only_as_evidence_custody(self) -> None:
        receipt = self._validate()
        self.assertEqual(receipt["result"], "ACCEPTED_FOR_EVIDENCE_CUSTODY")
        self.assertFalse(receipt["external_audit_complete"])
        self.assertEqual(receipt["promotion_effect"], "none")

    def test_handoff_templates_are_machine_renderable_and_disclaim_completion(self) -> None:
        rendered = templates(
            self.bundle_id,
            self.revision,
            self.manifest["binding"],
            {"workstreams": [{"id": "consensus"}]},
        )
        independence = json.loads(rendered["templates/auditor-independence.template.json"])
        self.assertFalse(any(independence["declarations"].values()))
        self.assertIn(b"not an audit verdict", rendered["AUDITOR-INSTRUCTIONS.md"])

    def _trusted_git_bundle(self) -> tuple[Path, Path, str]:
        repo = self.root / "trusted-repo"
        bundle = self.root / "trusted-bundle"
        repo.mkdir()
        bundle.mkdir()
        subprocess.run(["git", "init", "--quiet"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=repo, check=True)
        subprocess.run(["git", "config", "user.name", "Test Fixture"], cwd=repo, check=True)
        source_path = repo / "src/security.rs"
        source_path.parent.mkdir()
        source_path.write_bytes(b"trusted source bytes\n")
        subprocess.run(["git", "add", "."], cwd=repo, check=True)
        subprocess.run(["git", "commit", "--quiet", "-m", "trusted source"], cwd=repo, check=True)
        revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
        mode, object_type, blob = git_entry(revision, "src/security.rs", repo)
        data = source_path.read_bytes()
        archive_path = "source/src/security.rs"
        packaged = bundle / archive_path
        packaged.parent.mkdir(parents=True)
        packaged.write_bytes(data)
        source_manifest = {
            "schema_version": 2,
            "manifest_kind": "noosphere-audit-source-manifest",
            "source_revision": revision,
            "source_tree": git_tree(revision, repo),
            "hash_algorithm": "sha256",
            "entries": [{
                "path": "src/security.rs",
                "archive_path": archive_path,
                "git_mode": mode,
                "git_type": object_type,
                "git_blob": blob,
                "sha256": sha256_bytes(data),
                "bytes": len(data),
                "role": "audited_source",
                "workstreams": ["cryptography-cryptanalysis"],
            }],
        }
        payloads = {
            "audit-scope.json": canonical_bytes({"schema_version": 1}),
            "source-manifest.json": canonical_bytes(source_manifest),
            "threat-model-inventory.json": canonical_bytes({"schema_version": 1}),
            archive_path: data,
        }
        for name, payload in payloads.items():
            path = bundle / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
        binding = {
            "scope_sha256": sha256_bytes(payloads["audit-scope.json"]),
            "source_manifest_sha256": sha256_bytes(payloads["source-manifest.json"]),
            "threat_inventory_sha256": sha256_bytes(payloads["threat-model-inventory.json"]),
        }
        identity = {"source_revision": revision, **binding}
        manifest = {
            "schema_version": 1,
            "bundle_kind": "noosphere-independent-audit-handoff",
            "bundle_id": "sha256:" + sha256_bytes(canonical_bytes(identity)),
            "source_revision": revision,
            "source_tree": git_tree(revision, repo),
            "binding": binding,
            "files": {name: sha256_bytes(payload) for name, payload in payloads.items()},
            "external_audit_complete": False,
            "promotion_effect": "none",
        }
        (bundle / "bundle-manifest.json").write_bytes(canonical_bytes(manifest))
        return bundle, repo, revision

    def test_handoff_requires_external_git_trust_root_and_exact_bytes(self) -> None:
        bundle, repo, revision = self._trusted_git_bundle()
        manifest = verify_bundle_dir(bundle)
        self.assertEqual(verify_bundle_against_git(bundle, manifest, repo, revision), revision)

        packaged = bundle / "source/src/security.rs"
        packaged.write_bytes(b"attacker replacement\n")
        manifest["files"]["source/src/security.rs"] = sha256_bytes(packaged.read_bytes())
        (bundle / "bundle-manifest.json").write_bytes(canonical_bytes(manifest))
        self.assertEqual(verify_bundle_dir(bundle)["source_revision"], revision)
        with self.assertRaisesRegex(AuditError, "packaged source bytes differ"):
            verify_bundle_against_git(bundle, verify_bundle_dir(bundle), repo, revision)

    def test_self_consistent_bundle_cannot_relabel_trusted_revision(self) -> None:
        bundle, repo, revision = self._trusted_git_bundle()
        manifest = verify_bundle_dir(bundle)
        manifest["source_revision"] = "1" * 40
        identity = {"source_revision": manifest["source_revision"], **manifest["binding"]}
        manifest["bundle_id"] = "sha256:" + sha256_bytes(canonical_bytes(identity))
        (bundle / "bundle-manifest.json").write_bytes(canonical_bytes(manifest))
        self.assertEqual(verify_bundle_dir(bundle)["source_revision"], "1" * 40)
        with self.assertRaisesRegex(AuditError, "bundle revision mismatch"):
            verify_bundle_against_git(bundle, verify_bundle_dir(bundle), repo, revision)

    def test_external_git_binding_rejects_extra_and_retyped_source_paths(self) -> None:
        bundle, repo, revision = self._trusted_git_bundle()
        manifest = verify_bundle_dir(bundle)
        extra = bundle / "source/extra.rs"
        extra.write_bytes(b"unmanifested source\n")
        manifest["files"]["source/extra.rs"] = sha256_bytes(extra.read_bytes())
        (bundle / "bundle-manifest.json").write_bytes(canonical_bytes(manifest))
        self.assertEqual(verify_bundle_dir(bundle)["source_revision"], revision)
        with self.assertRaisesRegex(AuditError, "packaged source set mismatch"):
            verify_bundle_against_git(bundle, verify_bundle_dir(bundle), repo, revision)

        extra.unlink()
        del manifest["files"]["source/extra.rs"]
        source_path = bundle / "source-manifest.json"
        source_manifest = json.loads(source_path.read_text(encoding="utf-8"))
        source_manifest["entries"][0]["git_mode"] = "100755"
        source_path.write_bytes(canonical_bytes(source_manifest))
        source_hash = sha256_bytes(source_path.read_bytes())
        manifest["files"]["source-manifest.json"] = source_hash
        manifest["binding"]["source_manifest_sha256"] = source_hash
        identity = {"source_revision": revision, **manifest["binding"]}
        manifest["bundle_id"] = "sha256:" + sha256_bytes(canonical_bytes(identity))
        (bundle / "bundle-manifest.json").write_bytes(canonical_bytes(manifest))
        self.assertEqual(verify_bundle_dir(bundle)["source_revision"], revision)
        with self.assertRaisesRegex(AuditError, "source Git identity/type mismatch"):
            verify_bundle_against_git(bundle, verify_bundle_dir(bundle), repo, revision)

    def test_scope_requires_complete_declared_proving_backend(self) -> None:
        scope = json.loads((HERE.parents[1] / "protocol/audit/audit-scope-v1.json").read_text(encoding="utf-8"))
        registry = json.loads((HERE.parents[1] / "protocol/claims/registry.json").read_text(encoding="utf-8"))
        tracked = subprocess.check_output(["git", "ls-files"], cwd=HERE.parents[1], text=True).splitlines()
        paths = sorted(set(tracked) | RISC0_TCB_PATHS)
        validate_scope(scope, registry, paths)
        with self.assertRaisesRegex(AuditError, "omits RISC Zero proving TCB"):
            validate_scope(scope, registry, [path for path in paths if not path.endswith("artifacts/jet_proof.bin")])
        future = [*paths, "crates/noos-jet/future-methods/Cargo.toml", "crates/noos-jet/future-methods/src/lib.rs"]
        with self.assertRaisesRegex(AuditError, "every tracked proving-method backend"):
            validate_scope(scope, registry, future)

    def test_forged_signature_is_refused(self) -> None:
        signature_path = self.submission / "audit-report.signature.json"
        signature = json.loads(signature_path.read_text("utf-8"))
        raw = bytearray(base64.b64decode(signature["signature_base64"]))
        raw[0] ^= 1
        signature["signature_base64"] = base64.b64encode(raw).decode("ascii")
        signature_path.write_bytes(canonical_bytes(signature))
        with self.assertRaisesRegex(AuditError, "signature verification failed"):
            self._validate()

    def test_wrong_revision_is_refused(self) -> None:
        report = self._report()
        report["binding"]["source_revision"] = "2" * 40
        self._write_submission(report, self.independence)
        with self.assertRaisesRegex(AuditError, "wrong revision"):
            self._validate()

    def test_missing_scope_is_refused(self) -> None:
        report = self._report()
        del report["scope"]
        self._write_submission(report, self.independence)
        with self.assertRaisesRegex(AuditError, "missing fields: scope"):
            self._validate()

    def test_conflict_of_interest_declaration_is_refused(self) -> None:
        independence = self._independence()
        independence["declarations"]["material_financial_interest"] = True
        self._write_submission(self._report(), independence)
        with self.assertRaisesRegex(AuditError, "conflict-of-interest"):
            self._validate()

    def test_unresolved_severity_1_is_refused(self) -> None:
        first = event(1, "open", "external-audit-lab", None)
        finding = {"finding_id": "S1-TEST", "workstream_id": "consensus", "severity": "S1",
                   "title": "Test only", "description": "Test only", "lifecycle_events": [first]}
        self._write_submission(self._report(findings=[finding]), self.independence)
        with self.assertRaisesRegex(AuditError, "unresolved severity-1"):
            self._validate()

    def test_report_substitution_is_refused(self) -> None:
        report_path = self.submission / "audit-report.json"
        report = json.loads(report_path.read_text("utf-8"))
        report["report_id"] = "SUBSTITUTED-REPORT"
        report_path.write_bytes(canonical_bytes(report))
        signature_path = self.submission / "audit-report.signature.json"
        signature = json.loads(signature_path.read_text("utf-8"))
        signature["signed_file_sha256"] = sha256_bytes(report_path.read_bytes())
        signature_path.write_bytes(canonical_bytes(signature))
        with self.assertRaisesRegex(AuditError, "signature verification failed"):
            self._validate()

    def test_unsigned_report_is_refused(self) -> None:
        (self.submission / "audit-report.signature.json").unlink()
        with self.assertRaisesRegex(AuditError, "requires audit-report.json"):
            self._validate()

    def test_stale_report_is_refused(self) -> None:
        report = self._report()
        report["issued_at"] = "2025-01-01T00:00:00Z"
        report["expires_at"] = "2025-02-01T00:00:00Z"
        self._write_submission(report, self.independence)
        with self.assertRaisesRegex(AuditError, "stale report"):
            self._validate()

    def test_self_authored_report_is_refused(self) -> None:
        independence = self._independence("noosphere")
        report = self._report("noosphere")
        self._write_submission(report, independence)
        self._write_roster("noosphere")
        with self.assertRaisesRegex(AuditError, "self-authored report refused"):
            self._validate()

    def test_resolved_severity_1_requires_auditor_verification_and_accepts_valid_chain(self) -> None:
        first = event(1, "open", "external-audit-lab", None)
        second = event(2, "remediation_submitted", "noosphere", first["event_sha256"])
        third = event(3, "resolved_verified", "external-audit-lab", second["event_sha256"])
        finding = {"finding_id": "S1-RESOLVED-TEST", "workstream_id": "consensus", "severity": "S1",
                   "title": "Test only", "description": "Test only", "lifecycle_events": [first, second, third]}
        self._write_submission(self._report(findings=[finding]), self.independence)
        self.assertEqual(self._validate()["result"], "ACCEPTED_FOR_EVIDENCE_CUSTODY")


if __name__ == "__main__":
    unittest.main()
