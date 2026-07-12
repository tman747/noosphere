from __future__ import annotations

import importlib.util
import tempfile
import unittest
import sys
from pathlib import Path
from unittest.mock import patch

RUNNER = Path(__file__).with_name("run_nel_lab_claim.py")
sys.path.insert(0, str(RUNNER.parent))
SPEC = importlib.util.spec_from_file_location("run_nel_lab_claim", RUNNER)
assert SPEC is not None and SPEC.loader is not None
nel_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nel_gate)


class NelLabClaimRunnerTests(unittest.TestCase):
    def test_latency_exact_local_boundaries_are_fail_closed(self) -> None:
        passing = {
            "fixture_only": True,
            "lifecycle_sealed": True,
            "all_surfaces_soft": True,
            "control_clusters": 3,
            "p95_ms": 1_999,
            "p99_ms": 4_999,
            "drops": 1,
            "refunds": 1,
            "public_experiment": False,
        }
        nel_gate.validate_local("E-NEL-03", passing)
        for field, boundary in (("p95_ms", 2_000), ("p99_ms", 5_000)):
            with self.subTest(field=field), self.assertRaises(SystemExit):
                nel_gate.validate_local("E-NEL-03", {**passing, field: boundary})

    def test_handshake_artifacts_are_digest_pinned_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            paths = {
                name: Path(directory, f"{name}.json")
                for name in nel_gate.HANDSHAKE_ARTIFACTS
            }
            for path in paths.values():
                path.write_text("{}", encoding="utf-8")
            with patch.object(nel_gate, "HANDSHAKE_ARTIFACTS", paths):
                with self.assertRaisesRegex(SystemExit, "digest mismatch"):
                    nel_gate.validate_handshake()


if __name__ == "__main__":
    unittest.main()
