from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from tools.gates import check_vectors


ROOT = Path(__file__).resolve().parents[2]
WWM_ROOT = ROOT / "protocol" / "vectors" / "wwm-web-capacity-v1"


class CheckVectorsTests(unittest.TestCase):
    def test_registered_wwm_envelopes_validate(self) -> None:
        self.assertEqual(check_vectors.check_file(WWM_ROOT / "manifest.json"), [])
        self.assertEqual(check_vectors.check_file(WWM_ROOT / "vectors.json"), [])

    def test_wwm_case_hash_and_required_category_mutations_fail(self) -> None:
        document = json.loads((WWM_ROOT / "vectors.json").read_text(encoding="utf-8"))
        bad_hash = copy.deepcopy(document)
        bad_hash["positives"][0]["canonical_sha256"] = "0" * 64
        errors = check_vectors.check_wwm_document(bad_hash, WWM_ROOT / "vectors.json")
        self.assertTrue(any("canonical_sha256 mismatch" in error for error in errors))

        missing_category = copy.deepcopy(document)
        missing_category["required_negative_categories"] = missing_category[
            "required_negative_categories"
        ][1:]
        errors = check_vectors.check_wwm_document(
            missing_category, WWM_ROOT / "vectors.json"
        )
        self.assertIn(
            "'required_negative_categories' does not match negative cases", errors
        )

    def test_wwm_manifest_hash_mutation_fails(self) -> None:
        document = json.loads((WWM_ROOT / "manifest.json").read_text(encoding="utf-8"))
        document["files"]["vectors.json"]["sha256"] = "0" * 64
        errors = check_vectors.check_wwm_document(document, WWM_ROOT / "manifest.json")
        self.assertIn("'files.vectors.json.sha256' does not match referenced bytes", errors)

    def test_unregistered_noncanonical_envelope_does_not_silently_skip(self) -> None:
        with tempfile.TemporaryDirectory(prefix="noos-vector-gate-") as directory:
            path = Path(directory) / "vectors.json"
            path.write_text('{"format":"unregistered/v1"}\n', encoding="utf-8")
            errors = check_vectors.check_file(path)
        self.assertIn("missing or empty 'schema' string", errors)
        self.assertIn("'cases' must be a list", errors)


if __name__ == "__main__":
    unittest.main()
