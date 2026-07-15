from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy" / "wwm" / "web-capacity"


class WebCapacityTopologyTests(unittest.TestCase):
    def test_optional_profile_is_nonproduction_and_authority_free(self) -> None:
        contract = json.loads((DEPLOY / "topology.json").read_text(encoding="utf-8"))
        self.assertEqual(contract["schema"], "noos/wwm-web-capacity-topology/v1")
        self.assertEqual(contract["profile"], "web-capacity")
        self.assertTrue(contract["optional"])
        self.assertFalse(contract["production_capable"])
        self.assertFalse(contract["rewards"])
        self.assertEqual(contract["networks"], ["web-capacity-public-egress"])
        self.assertEqual(
            set(contract["activation_scope"]),
            {"local", "devnet", "public-testnet-pilot"},
        )
        self.assertTrue(all(value is False for value in contract["authority"].values()))
        self.assertIn("control", contract["forbidden_networks"])
        self.assertIn("consensus", contract["forbidden_networks"])
        self.assertIn("/var/lib/noos-model", contract["forbidden_mounts"])

    def test_compose_profile_has_no_base_chain_or_model_dependency(self) -> None:
        compose = (DEPLOY / "compose.yaml").read_text(encoding="utf-8")
        self.assertIn("profiles: [web-capacity]", compose)
        self.assertIn("read_only: true", compose)
        self.assertIn("cap_drop: [ALL]", compose)
        self.assertIn("no-new-privileges:true", compose)
        self.assertIn("WWM_PRODUCTION_CAPABLE: \"false\"", compose)
        self.assertIn("networks: [web-capacity-public-egress]", compose)
        self.assertIn("internal: false", compose)
        self.assertNotIn("depends_on:", compose)
        for forbidden in (
            "/var/lib/noos-artifacts",
            "/var/lib/noos-consensus",
            "/var/lib/noos-model",
            "validator_key",
            "custodian_signing_key",
            "networks: [control",
            "networks: [artifact",
        ):
            self.assertNotIn(forbidden, compose)

    def test_operator_inputs_are_explicit_and_canonical_manifest_is_read_only(self) -> None:
        compose = (DEPLOY / "compose.yaml").read_text(encoding="utf-8")
        for variable in (
            "WWM_WEB_CAPACITY_IMAGE",
            "WWM_WEB_CAPACITY_SEED",
            "WWM_WEB_CAPACITY_CONFIG_PATH",
            "WWM_BONSAI_MANIFEST_PATH",
        ):
            self.assertIn(f"${{{variable}:?", compose)
        self.assertIn(
            ":/run/wwm/bonsai-artifact-manifest.bin:ro",
            compose,
        )
        self.assertIn(":/run/wwm/web-capacity.json:ro", compose)
        self.assertIn("immutable noos-web-capacityd image with @sha256 digest required", compose)


if __name__ == "__main__":
    unittest.main()
