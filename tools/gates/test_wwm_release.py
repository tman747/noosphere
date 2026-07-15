from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import run_wwm_release as release
import wwm_evidence_bundle as evidence


class WwmReleaseApplicabilityTests(unittest.TestCase):
    def test_missing_evidence_blocks_only_mandatory_bonsai_claims(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            code, report, manifest = release.assess_release(
                registry_path=evidence.DEFAULT_REGISTRY,
                experiments_path=evidence.DEFAULT_EXPERIMENTS,
                evidence_root=Path(temp),
                revision="a" * 40,
            )
        self.assertEqual(code, 2)
        self.assertIsNone(manifest)
        self.assertEqual(report["verdict"], "BLOCKED")
        self.assertEqual(report["required_mandatory_claims"], 10)
        self.assertEqual(
            {row["claim"] for row in report["blockers"]},
            evidence.BONSAI_MANDATORY_CLAIMS,
        )
        self.assertEqual(len(report["disabled_not_claimed"]), 13)
        self.assertNotIn("E-WWM-01", {row["claim"] for row in report["blockers"]})
        self.assertFalse(report["controls_enabled"])
        self.assertEqual(report["promotion_effect"], "NONE")

    def test_unknown_applicability_profile_is_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(evidence.EvidenceError, "unknown applicability"):
                release.assess_release(
                    registry_path=evidence.DEFAULT_REGISTRY,
                    experiments_path=evidence.DEFAULT_EXPERIMENTS,
                    evidence_root=Path(temp),
                    revision="a" * 40,
                    profile_id="UNREGISTERED",
                )

    def test_release_schema_declares_dispositions_and_ten_bundle_slots(self) -> None:
        schema = json.loads(
            (release.ROOT / "protocol" / "release" / "wwm-release-manifest.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIn("claim_dispositions", schema["required"])
        self.assertEqual(schema["properties"]["claim_bundle_ids"]["minProperties"], 10)
        self.assertEqual(schema["properties"]["claim_bundle_ids"]["maxProperties"], 10)
        self.assertEqual(
            schema["properties"]["applicability_profile"]["const"],
            "BONSAI_PUBLIC_TEXT_V1",
        )


if __name__ == "__main__":
    unittest.main()
