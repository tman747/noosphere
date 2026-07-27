from __future__ import annotations

import copy
import gzip
import json
import tempfile
import unittest
import zipfile
from pathlib import Path

from tools.operations import wwm_plaintext_persistence_audit as audit


class PlaintextPersistenceAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.seed = bytes.fromhex("17" * 32)
        self.source_revision = "a" * 40
        self.deployment = "b" * 64
        self.targets: dict[str, Path] = {}
        for category in sorted(audit.CATEGORIES):
            path = self.root / category
            path.mkdir()
            self.targets[category] = path
        self.targets["database"].joinpath("inference.sqlite3").write_bytes(b"encrypted-pages-only")
        self.targets["logs"].joinpath("gateway.log").write_text("job=abc prompt_commitment=def\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def manifest(self, phase: str) -> dict[str, object]:
        return {
            "schema": audit.MANIFEST_SCHEMA,
            "source_revision": self.source_revision,
            "deployment_sha256": self.deployment,
            "phase": phase,
            "production": False,
            "promotion_effect": "NONE",
            "targets": [
                {"category": category, "path": str(path)}
                for category, path in sorted(self.targets.items())
            ],
        }

    def report(self, phase: str, canary: bytes) -> dict[str, object]:
        body = audit.perform_scan(self.manifest(phase), [canary])
        return audit.sign_body(audit.SCAN_SCHEMA, audit.SCAN_DOMAIN, body, self.seed)

    def test_clean_scan_is_signed_and_never_echoes_canary(self) -> None:
        canary = b"PROMPT_CANARY_7f04c551"
        report = self.report("success", canary)
        body = audit.validate_scan_envelope(report)
        self.assertEqual(body["verdict"], "PASS")
        self.assertEqual({row["category"] for row in body["targets"]}, audit.CATEGORIES)
        self.assertNotIn(canary, audit.canonical_json(report))
        self.assertEqual(body["canary_sha256"], [audit.sha256(canary)])

    def test_raw_zip_and_gzip_payloads_are_detected_without_disclosing_plaintext(self) -> None:
        canary = b"OUTPUT_CANARY_94ba913e"
        self.targets["cache"].joinpath("cache.bin").write_bytes(b"prefix" + canary + b"suffix")
        with zipfile.ZipFile(self.targets["crash_artifacts"] / "crash.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("nested/minidump.txt", b"dump:" + canary)
        with gzip.open(self.targets["telemetry"] / "events.jsonl.gz", "wb") as destination:
            destination.write(b'{"message":"' + canary + b'"}\n')
        report = self.report("crash", canary)
        body = audit.validate_scan_envelope(report)
        self.assertEqual(body["verdict"], "FAIL")
        self.assertEqual({row["category"] for row in body["findings"]}, {"cache", "crash_artifacts", "telemetry"})
        self.assertNotIn(canary, audit.canonical_json(report))
        reports = [
            report if phase == "crash" else self.report(phase, f"CLEAN_{phase}_0123456789".encode("ascii"))
            for phase in sorted(audit.PHASES)
        ]
        with self.assertRaisesRegex(audit.AuditError, "failing persistence scan"):
            audit.seal_matrix(reports, self.seed)

    def test_chunk_boundary_and_case_folded_match_are_detected(self) -> None:
        canary = b"BOUNDARY_CANARY_ABCDEF"
        prefix = b"x" * (audit.CHUNK_BYTES - 5)
        self.targets["database"].joinpath("pages.bin").write_bytes(prefix + canary.lower())
        body = audit.perform_scan(self.manifest("timeout"), [canary])
        self.assertEqual(body["verdict"], "FAIL")
        self.assertEqual(body["findings"][0]["canary_sha256"], audit.sha256(canary))

    def test_matrix_requires_every_phase_on_one_release_and_allows_phase_specific_canaries(self) -> None:
        reports = [self.report(phase, f"CANARY_{phase}_0123456789".encode("ascii")) for phase in sorted(audit.PHASES)]
        matrix = audit.seal_matrix(reports, self.seed)
        body = audit.validate_matrix(matrix)
        self.assertEqual(body["verdict"], "PASS")
        self.assertEqual(body["phases"], sorted(audit.PHASES))

        missing = reports[:-1]
        with self.assertRaisesRegex(audit.AuditError, "every lifecycle phase"):
            audit.seal_matrix(missing, self.seed)

        mismatched = copy.deepcopy(reports)
        changed = dict(mismatched[0]["body"])
        changed["source_revision"] = "c" * 40
        changed["scan_id"] = audit.sha256(audit.SCAN_ID_DOMAIN + audit.canonical_json({**changed, "scan_id": ""}))
        mismatched[0] = audit.sign_body(audit.SCAN_SCHEMA, audit.SCAN_DOMAIN, changed, self.seed)
        with self.assertRaisesRegex(audit.AuditError, "one exact release"):
            audit.seal_matrix(mismatched, self.seed)

    def test_tampering_and_malformed_target_contract_fail_closed(self) -> None:
        report = self.report("reboot", b"REBOOT_CANARY_0123456789")
        report["body"]["total_raw_bytes"] += 1
        with self.assertRaisesRegex(audit.AuditError, "signature is invalid"):
            audit.validate_scan_envelope(report)

        manifest = self.manifest("reboot")
        manifest["targets"] = manifest["targets"][:-1]
        with self.assertRaisesRegex(audit.AuditError, "every exact persistence category"):
            audit.validate_manifest(manifest)


if __name__ == "__main__":
    unittest.main()
