from __future__ import annotations
import json
import shutil

import tempfile
import unittest
import sys
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import wwm_topology as topology
import wwm_deploy


class WwmTopologyTests(unittest.TestCase):
    def test_static_topology_pins_artifact_runtime_and_isolates_services(self) -> None:
        report = topology.validate_static()
        self.assertEqual(report["verdict"], "VALID_LOCAL_DEVNET_TOPOLOGY")
        self.assertFalse(report["production_capable"])
        self.assertEqual(
            report["services"],
            [
                "artifact-store",
                "custodian",
                "database",
                "edge",
                "executor",
                "gateway",
                "prometheus",
            ],
        )
        self.assertGreaterEqual(len(report["production_external_blockers"]), 10)
    def test_static_topology_rejects_modified_upstream_notice(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            deploy = Path(temp) / "wwm"
            shutil.copytree(topology.DEFAULT_DEPLOY, deploy)
            notice = deploy / "licenses" / "Bonsai-27B" / "NOTICE.txt"
            notice.write_bytes(notice.read_bytes() + b"modified")
            with self.assertRaisesRegex(
                topology.TopologyError, "NOTICE.txt bytes differ"
            ):
                topology.validate_static(deploy)


    def test_environment_requires_digest_images_and_external_secret_files(self) -> None:
        topology_path = topology.DEFAULT_DEPLOY / "topology.json"
        with self.assertRaisesRegex(topology.TopologyError, "immutable image@sha256"):
            topology.validate_environment(topology_path, {})
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            values: dict[str, str] = {}
            contract = topology.load_object(topology_path)
            digest = "a" * 64
            for variable in contract["immutable_image_variables"]:
                values[variable] = f"registry.example/noos/{variable.lower()}:devnet@sha256:{digest}"
            for variable in contract["external_secret_variables"]:
                secret = root / variable.lower()
                secret.write_text("test-only-secret", encoding="utf-8")
                values[variable] = str(secret.resolve())
            report = topology.validate_environment(topology_path, values)
            self.assertEqual(report["verdict"], "ENVIRONMENT_VALID")
            self.assertFalse(report["production_capable"])

    def test_executor_has_no_public_or_database_network(self) -> None:
        contract = topology.load_object(topology.DEFAULT_DEPLOY / "topology.json")
        self.assertEqual(contract["service_networks"]["executor"], ["control", "monitoring"])
        self.assertNotIn("executor", contract["public_services"])
    def test_deploy_entrypoint_plans_only_local_or_devnet_and_reports_blockers(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            code = wwm_deploy.main(["plan", "--environment", "local"])
        self.assertEqual(code, 0)
        report = json.loads(output.getvalue())
        self.assertEqual(report["verdict"], "PLAN_ONLY")
        self.assertFalse(report["production_capable"])
        self.assertIn("WWM_CONTROL_PLANE_URL", report["required_environment"])
        self.assertIn("WWM_BONSAI_SOURCE_PATH", report["required_environment"])
        self.assertGreaterEqual(len(report["production_external_blockers"]), 10)

    def test_local_source_verification_rejects_wrong_length(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "Bonsai-27B-Q1_0.gguf"
            path.write_bytes(b"not-the-model")
            with self.assertRaisesRegex(wwm_deploy.DeployError, "length"):
                wwm_deploy.verify_bonsai_source(str(path.resolve()))

    def test_production_readiness_manifest_is_truthfully_blocked(self) -> None:
        report = topology.load_object(topology.DEFAULT_DEPLOY / "production-readiness.json")
        self.assertEqual(report["verdict"], "BLOCKED")
        self.assertFalse(report["deployment_executed"])
        self.assertFalse(report["public_traffic_authorized"])
        self.assertFalse(report["dns_cutover_authorized"])
        self.assertIsNone(report["observed_at"])



if __name__ == "__main__":
    unittest.main()
