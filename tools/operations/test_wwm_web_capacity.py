from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = ROOT / "protocol" / "schemas" / "wwm-web-capacity-v1.schema.json"
OPENAPI_PATH = ROOT / "protocol" / "api" / "openapi-wwm-web-capacity-v1.yaml"
FROZEN_WWM_V2_PATH = ROOT / "protocol" / "schemas" / "wwm-v2.md"
DOMAIN_PATH = ROOT / "protocol" / "spec" / "crypto-domains-v1.csv"
FROZEN_WWM_V2_SHA256 = "eb6fbd2bb818c60b922d607b7e9a82989d11319e7eb847841b18025af6e01d51"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AssertionError(f"{path} must contain an object")
    return value


def resolve_pointer(document: Any, pointer: str) -> Any:
    if not pointer.startswith("#/"):
        raise AssertionError(f"not an internal JSON pointer: {pointer}")
    current = document
    for component in pointer[2:].split("/"):
        component = component.replace("~1", "/").replace("~0", "~")
        if not isinstance(current, dict) or component not in current:
            raise AssertionError(f"unresolved pointer: {pointer}")
        current = current[component]
    return current


def walk_refs(value: Any) -> list[str]:
    refs: list[str] = []
    if isinstance(value, dict):
        reference = value.get("$ref")
        if isinstance(reference, str):
            refs.append(reference)
        for child in value.values():
            refs.extend(walk_refs(child))
    elif isinstance(value, list):
        for child in value:
            refs.extend(walk_refs(child))
    return refs


class WebCapacityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load_json(SCHEMA_PATH)
        cls.openapi = load_json(OPENAPI_PATH)
        cls.defs = cls.schema["$defs"]

    def test_capacity_contract_is_separately_versioned_and_v2_is_frozen(self) -> None:
        contract = self.schema["x-noos-contract"]
        self.assertEqual(contract["contract_identity"], "noos/wwm-web-capacity/v1")
        self.assertEqual(contract["status"], "EXPERIMENTAL_OFF_CHAIN")
        self.assertFalse(contract["consensus_schema_extended"])
        self.assertFalse(contract["consensus_action_tags_added"])
        self.assertEqual(
            hashlib.sha256(FROZEN_WWM_V2_PATH.read_bytes()).hexdigest(),
            FROZEN_WWM_V2_SHA256,
        )
        self.assertEqual(self.openapi["x-noos-contract"]["api_identity"], "wwm-web-capacity-v1")
        self.assertNotEqual(OPENAPI_PATH.name, "openapi-wwm-v2.yaml")

    def test_participant_classes_and_admission_classes_are_closed(self) -> None:
        self.assertEqual(
            self.defs["ParticipantClass"]["enum"],
            ["STATIC_HOST_SEEDER", "BROWSER_ADVISORY_CACHE"],
        )
        self.assertEqual(
            self.defs["AdmissionClass"]["enum"],
            ["StatelessReissueable", "ChorusAdvisory"],
        )
        static = self.defs["StaticHostManifest"]["properties"]
        browser = self.defs["BrowserSession"]["properties"]
        self.assertEqual(static["participant_class"]["const"], "STATIC_HOST_SEEDER")
        self.assertEqual(static["admission_class"]["const"], "StatelessReissueable")
        self.assertEqual(browser["participant_class"]["const"], "BROWSER_ADVISORY_CACHE")
        self.assertEqual(browser["admission_class"]["const"], "ChorusAdvisory")

        top_level_kinds = []
        for branch in self.schema["oneOf"]:
            definition = resolve_pointer(self.schema, branch["$ref"])
            top_level_kinds.append(definition["properties"]["record_kind"]["const"])
            self.assertFalse(definition["additionalProperties"])
        self.assertEqual(len(top_level_kinds), len(set(top_level_kinds)))
        self.assertNotIn("CUSTODIAN", top_level_kinds)
        self.assertNotIn("EXECUTOR", top_level_kinds)

    def test_web_participants_cannot_claim_custody_schedulability_or_rewards(self) -> None:
        contract = self.schema["x-noos-contract"]
        for field in (
            "production_custody",
            "rewards",
            "custodian_capability_membership",
            "availability_certificate_signer",
            "schedulability_contribution",
            "production_custody_reward_eligible",
            "browser_inference",
            "browser_training",
            "browser_mining",
            "browser_arbitrary_code",
        ):
            self.assertIs(contract[field], False)
        graduation = contract["static_graduation"]
        self.assertFalse(graduation["automatic"])
        self.assertEqual(graduation["required_complete_position_bytes"], 475588608)
        self.assertEqual(graduation["required_existing_path"], "CustodianCapabilitySetV1")
        self.assertEqual(
            graduation["independent_requirements"],
            ["profile", "bond", "diversity", "probe", "availability", "E-WWM-03"],
        )
        for name in (
            "CoordinatorConfig",
            "StaticHostManifest",
            "HostRegistrationResponse",
            "BrowserSession",
            "EvidenceSummary",
        ):
            properties = self.defs[name]["properties"]
            self.assertIs(properties["production_custody"]["const"], False)
            self.assertIs(properties["rewards"]["const"], False)

    def test_static_manifest_is_exact_signed_well_known_contract(self) -> None:
        manifest = self.defs["StaticHostManifest"]
        required = set(manifest["required"])
        self.assertTrue(
            {
                "schema",
                "participant_class",
                "canonical_origin",
                "chain_binding",
                "host_signing_key",
                "valid_from",
                "expires_at",
                "revocation_url",
                "inventory",
                "license",
                "transport_policy",
                "signature",
            }
            <= required
        )
        self.assertEqual(
            self.schema["x-noos-contract"]["well_known_path"],
            "/.well-known/noos/wwm-web-capacity-v1.json",
        )
        signature = manifest["properties"]["signature"]["allOf"][1]
        self.assertEqual(
            signature["properties"]["domain"]["const"],
            "NOOS/SIG/WWM-WEB-HOST-MANIFEST/V1",
        )
        transport = self.defs["TransportPolicy"]["properties"]
        self.assertEqual(transport["cors_allow_origin"]["const"], "*")
        self.assertEqual(transport["credentials"]["const"], "omit")
        self.assertEqual(transport["redirects"]["const"], "reject")
        self.assertIs(transport["range_requests"]["const"], True)
        self.assertIs(transport["immutable_cache"]["const"], True)
        domains = DOMAIN_PATH.read_text(encoding="utf-8")
        self.assertIn("NOOS/SIG/WWM-WEB-HOST-MANIFEST/V1", domains)

    def test_inventory_rows_are_exact_bounded_and_transport_digest_is_non_authoritative(self) -> None:
        inventory = self.defs["StaticInventory"]
        rows = inventory["properties"]["rows"]
        self.assertEqual(rows["minItems"], 1)
        self.assertEqual(rows["maxItems"], 5448)
        row = self.defs["InventoryRow"]
        self.assertEqual(
            set(row["required"]),
            {
                "stripe",
                "position",
                "bytes",
                "transport_sha256",
                "protocol_share_digest",
                "probe_root",
                "url",
            },
        )
        self.assertFalse(row["additionalProperties"])
        self.assertEqual(row["properties"]["stripe"]["maximum"], 453)
        self.assertEqual(row["properties"]["position"]["maximum"], 11)
        self.assertEqual(row["properties"]["bytes"]["const"], 1047552)
        self.assertIn("noos-da verification remains authoritative", row["description"])
        self.assertIn("NOOS/WWM-WEB/INVENTORY/V1", inventory["description"])

    def test_static_host_expiry_stops_future_assignments_without_erasure_claims(self) -> None:
        contract = self.schema["x-noos-contract"]
        self.assertEqual(contract["static_host_refresh_max_seconds"], 60)
        self.assertIs(contract["static_expiry_removes_future_assignments"], True)
        self.assertIs(contract["cached_public_share_erasure_available"], False)
        self.assertIs(contract["cache_disclosure_required"], True)
        coordinator = self.defs["CoordinatorConfig"]
        self.assertIn("static_cache_lifecycle", coordinator["required"])
        lifecycle = self.defs["StaticCacheLifecycleDisclosure"]["properties"]
        self.assertEqual(lifecycle["host_refresh_max_seconds"]["const"], 60)
        self.assertEqual(
            lifecycle["expiry_effect"]["const"],
            "REMOVES_FUTURE_ASSIGNMENTS_ONLY",
        )
        self.assertEqual(lifecycle["public_share_license"]["const"], "Apache-2.0")
        self.assertIs(lifecycle["cached_bytes_may_remain_public"]["const"], True)
        self.assertIs(
            lifecycle["third_party_cache_erasure_available"]["const"],
            False,
        )

    def test_openapi_route_set_and_hard_bounds_match_contract(self) -> None:
        self.assertEqual(
            set(self.openapi["paths"]),
            {
                "/api/wwm-web-capacity/v1/config",
                "/api/wwm-web-capacity/v1/hosts",
                "/api/wwm-web-capacity/v1/offers",
                "/api/wwm-web-capacity/v1/heartbeat",
                "/api/wwm-web-capacity/v1/reports",
                "/api/wwm-web-capacity/v1/restores/{task_id}",
                "/api/wwm-web-capacity/v1/revoke",
            },
        )
        for path, item in self.openapi["paths"].items():
            for method in ("post", "put"):
                if method in item and path != "/api/wwm-web-capacity/v1/restores/{task_id}":
                    self.assertEqual(item[method]["x-max-body-bytes"], 65536)
        restore = self.openapi["paths"]["/api/wwm-web-capacity/v1/restores/{task_id}"]["put"]
        self.assertEqual(restore["x-exact-body-bytes"], 1047552)
        self.assertEqual(restore["x-write-destination"], "ARTIFACT_QUARANTINE_ONLY")
        self.assertEqual(restore["x-canonical-verifier"], "noos-da")

    def test_quota_specific_effective_byte_bounds_match_share_geometry(self) -> None:
        share_bytes = self.schema["x-noos-contract"]["share_bytes"]
        quota_choices = self.defs["CoordinatorConfig"]["properties"][
            "quota_choices_shares"
        ]["const"]
        expected_bounds = {quota: quota * share_bytes for quota in quota_choices}

        for definition_name in ("OfferRequest", "BrowserSession"):
            definition = self.defs[definition_name]
            self.assertEqual(
                definition["properties"]["quota_shares"]["enum"],
                quota_choices,
            )
            conditionals = {}
            for conditional in definition["allOf"]:
                quota = conditional["if"]["properties"]["quota_shares"]["const"]
                self.assertEqual(conditional["if"]["required"], ["quota_shares"])
                conditionals[quota] = conditional["then"]["properties"][
                    "effective_bytes"
                ]["maximum"]
            self.assertEqual(conditionals, expected_bounds)

    def test_restore_request_is_raw_exact_length_binary(self) -> None:
        restore = self.openapi["paths"][
            "/api/wwm-web-capacity/v1/restores/{task_id}"
        ]["put"]
        body_schema = restore["requestBody"]["content"]["application/octet-stream"][
            "schema"
        ]

        self.assertEqual(restore["x-exact-body-bytes"], 1047552)
        self.assertEqual(body_schema["type"], "string")
        self.assertEqual(body_schema["format"], "binary")
        self.assertEqual(body_schema["x-decoded-bytes"], 1047552)
        self.assertNotIn("contentEncoding", body_schema)
        self.assertNotIn("contentMediaType", body_schema)
        content_length = resolve_pointer(
            self.openapi,
            restore["parameters"][3]["$ref"],
        )
        self.assertEqual(content_length["name"], "Content-Length")
        self.assertEqual(content_length["schema"]["const"], 1047552)

    def test_options_are_inline_operations_with_unique_ids_and_valid_responses(self) -> None:
        operation_ids = []
        mutation_paths = [
            path
            for path, item in self.openapi["paths"].items()
            if "post" in item or "put" in item
        ]
        self.assertEqual(len(mutation_paths), 6)

        for path, item in self.openapi["paths"].items():
            for method in ("get", "post", "put", "options"):
                operation = item.get(method)
                if operation is None:
                    continue
                self.assertNotIn("$ref", operation, f"{path} {method}")
                operation_ids.append(operation["operationId"])

            if path not in mutation_paths:
                self.assertNotIn("options", item)
                continue
            options = item["options"]
            self.assertEqual(options["parameters"], [{"$ref": "#/components/parameters/Origin"}])
            self.assertEqual(
                set(options["responses"]),
                {"204", "403"},
            )
            for response in options["responses"].values():
                resolve_pointer(self.openapi, response["$ref"])

        self.assertEqual(len(operation_ids), len(set(operation_ids)))
        self.assertNotIn("pathItems", self.openapi["components"])

        expected_vary = (
            "Origin, Access-Control-Request-Method, "
            "Access-Control-Request-Headers"
        )
        responses = self.openapi["components"]["responses"]
        for name, method in (
            ("MutationPreflightPost", "POST"),
            ("MutationPreflightPut", "PUT"),
        ):
            headers = responses[name]["headers"]
            self.assertEqual(
                headers["Access-Control-Allow-Methods"]["schema"]["const"],
                method,
            )
            self.assertEqual(headers["Vary"]["schema"]["const"], expected_vary)
        self.assertEqual(
            responses["CorsError"]["headers"]["Vary"]["schema"]["const"],
            expected_vary,
        )

    def test_every_json_reference_resolves(self) -> None:
        for reference in walk_refs(self.schema):
            resolve_pointer(self.schema, reference)
        for reference in walk_refs(self.openapi):
            if reference.startswith("#/"):
                resolve_pointer(self.openapi, reference)
                continue
            path_text, pointer = reference.split("#", 1)
            external_path = (OPENAPI_PATH.parent / path_text).resolve()
            external = load_json(external_path)
            resolve_pointer(external, f"#{pointer}")


if __name__ == "__main__":
    unittest.main()
