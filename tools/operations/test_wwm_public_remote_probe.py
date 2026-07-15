from __future__ import annotations

import unittest

from tools.operations import wwm_public_remote_probe as probe


class PublicRemoteProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.chain_id = "11" * 32
        self.genesis_hash = "22" * 32
        self.signer_key_id = "33" * 32

    def gateway(self) -> dict[str, object]:
        return {
            "status": "ok",
            "production": False,
            "promotion_effect": "NONE",
            "chain_id": self.chain_id,
            "genesis_hash": self.genesis_hash,
            "unsafe_head": {"height": 42},
            "finalized": {"epoch": 3},
        }

    def monitor(self) -> dict[str, object]:
        return {
            "status": "ok",
            "production": False,
            "production_authorized": False,
            "promotion_effect": "NONE",
            "source_revision": "44" * 20,
            "sample_id": "55" * 32,
            "signer_key_id": self.signer_key_id,
            "public_key_base64": "Z" * 42 + "Y=",
            "signature_base64": "Z" * 85 + "Y==",
            "checks": [{"name": "gateway", "ok": True}],
            "observed_at_utc": "2026-07-15T00:00:00Z",
        }

    def test_gateway_requires_exact_fail_closed_chain_identity(self) -> None:
        detail = probe.validate_gateway(200, self.gateway(), self.chain_id, self.genesis_hash)
        self.assertEqual(detail, {"unsafe_height": 42, "finalized_epoch": 3})
        document = self.gateway()
        document["production"] = True
        with self.assertRaisesRegex(probe.ProbeError, "fail-closed"):
            probe.validate_gateway(200, document, self.chain_id, self.genesis_hash)
        with self.assertRaisesRegex(probe.ProbeError, "chain identity"):
            probe.validate_gateway(200, self.gateway(), "99" * 32, self.genesis_hash)

    def test_artifact_host_cannot_claim_production_custody(self) -> None:
        document = {
            "production": False,
            "promotion_effect": "NONE",
            "production_custody": False,
            "share_count": 4086,
            "share_bytes": 4_280_297_472,
        }
        self.assertEqual(probe.validate_artifacts(200, document)["share_count"], 4086)
        document["production_custody"] = True
        with self.assertRaisesRegex(probe.ProbeError, "production-promoting"):
            probe.validate_artifacts(200, document)

    def test_monitor_requires_passing_bound_signature_envelope(self) -> None:
        detail = probe.validate_monitor(200, self.monitor(), self.signer_key_id)
        self.assertEqual(detail["source_revision"], "44" * 20)
        document = self.monitor()
        document["checks"] = [{"name": "gateway", "ok": False}]
        with self.assertRaisesRegex(probe.ProbeError, "degraded"):
            probe.validate_monitor(200, document, self.signer_key_id)
        document = self.monitor()
        document["production_authorized"] = True
        with self.assertRaisesRegex(probe.ProbeError, "authorization"):
            probe.validate_monitor(200, document, self.signer_key_id)


if __name__ == "__main__":
    unittest.main()
