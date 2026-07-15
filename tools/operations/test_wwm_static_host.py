from __future__ import annotations

import importlib.util
import json
import sys
import re
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "operations" / "wwm_static_host.py"
RECIPE_ROOT = ROOT / "deploy" / "wwm" / "web-capacity" / "static-host"
SPEC = importlib.util.spec_from_file_location("wwm_static_host", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
static_host = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = static_host
SPEC.loader.exec_module(static_host)


def _path_block(text: str, marker: str, next_marker: str | None = None) -> str:
    start = text.index(marker)
    end = text.index(next_marker, start) if next_marker is not None else len(text)
    return text[start:end]


def _cache_control(block: str) -> str:
    terraform = re.search(
        r'header\s*=\s*"Cache-Control".*?value\s*=\s*"([^"]+)"',
        block,
        re.DOTALL,
    )
    if terraform is not None:
        return terraform.group(1)
    match = re.search(r"Cache-Control(?::|\s+)\s*[\"']?([^\"'\r\n;]+)", block)
    if match is None:
        raise AssertionError("Cache-Control header missing")
    return match.group(1).strip()


def _configured_cache_controls(recipe: str) -> dict[str, str]:
    text = (RECIPE_ROOT / recipe).read_text(encoding="utf-8")
    if recipe == "_headers":
        return {
            "manifest": _cache_control(
                _path_block(
                    text,
                    "/.well-known/noos/wwm-web-capacity-v1.json",
                    "/inventory-v1.json",
                )
            ),
            "inventory": _cache_control(
                _path_block(text, "/inventory-v1.json", "/LICENSE.txt")
            ),
            "license_and_notice": _cache_control(
                _path_block(text, "/LICENSE.txt", "/NOTICE.txt")
            ),
            "shares": _cache_control(_path_block(text, "/shares/*")),
        }
    if recipe == "nginx.conf":
        return {
            "manifest": _cache_control(
                _path_block(
                    text,
                    "location = /.well-known/noos/wwm-web-capacity-v1.json",
                    "location = /inventory-v1.json",
                )
            ),
            "inventory": _cache_control(
                _path_block(text, "location = /inventory-v1.json", "location = /LICENSE.txt")
            ),
            "license_and_notice": _cache_control(
                _path_block(text, "location = /LICENSE.txt", "location = /NOTICE.txt")
            ),
            "shares": _cache_control(_path_block(text, "location ~ ^/shares/")),
        }
    if recipe == "Caddyfile":
        return {
            "manifest": _cache_control(
                _path_block(text, "@manifest path", "@inventory path")
            ),
            "inventory": _cache_control(
                _path_block(text, "@inventory path", "@license path")
            ),
            "license_and_notice": _cache_control(
                _path_block(text, "@license path", "@share path_regexp")
            ),
            "shares": _cache_control(_path_block(text, "@share path_regexp")),
        }
    if recipe == "cloudfront.tf":
        inventory_cache = _terraform_resource(
            text, "aws_cloudfront_cache_policy", "noos_wwm_inventory"
        )
        for ttl in ("default_ttl", "max_ttl", "min_ttl"):
            if re.search(rf"^\s*{ttl}\s*=\s*0\s*$", inventory_cache, re.MULTILINE) is None:
                raise AssertionError(f"CloudFront inventory {ttl} must be zero")
        return {
            name: _cache_control(
                _terraform_resource(
                    text,
                    "aws_cloudfront_response_headers_policy",
                    resource,
                )
            )
            for name, resource in {
                "manifest": "noos_wwm_manifest",
                "inventory": "noos_wwm_inventory",
                "license_and_notice": "noos_wwm_legal",
                "shares": "noos_wwm_shares",
            }.items()
        }
    raise AssertionError(f"unknown recipe {recipe}")




def _terraform_resource(text: str, resource_type: str, name: str) -> str:
    marker = f'resource "{resource_type}" "{name}" {{'
    start = text.index(marker)
    cursor = start
    depth = 0
    while cursor < len(text):
        if text[cursor] == "{":
            depth += 1
        elif text[cursor] == "}":
            depth -= 1
            if depth == 0:
                return text[start : cursor + 1]
        cursor += 1
    raise AssertionError(f"unterminated Terraform resource {name}")


class RevalidatingCache:
    def __init__(self, origin: dict[str, tuple[bytes, str]]) -> None:
        self.origin = origin
        self.cached: dict[str, tuple[bytes, str, int]] = {}

    def get(self, path: str, now: int) -> bytes:
        cached = self.cached.get(path)
        if cached is not None:
            body, cache_control, stored_at = cached
            directives = static_host.cache_control_directives(cache_control)
            max_age = directives.get("max-age")
            fresh = max_age is not None and max_age.isdecimal() and now - stored_at <= int(max_age)
            if "no-cache" not in directives and fresh:
                return body
        body, cache_control = self.origin[path]
        self.cached[path] = (body, cache_control, now)
        return body


class CoordinatorHandler(BaseHTTPRequestHandler):
    mode = "success"
    observed: dict[str, Any] = {}

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        type(self).observed = {
            "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "body": json.loads(body),
        }
        if type(self).mode == "redirect":
            self.send_response(302)
            self.send_header("Location", f"http://{self.headers['Host']}{self.path}")
            self.end_headers()
            return
        payload = json.dumps(
            {
                "schema": static_host.SCHEMA,
                "record_kind": "HOST_REGISTRATION_RESPONSE",
                "host_id": "11" * 32,
                "canonical_origin": "https://static.example",
                "participant_class": "STATIC_HOST_SEEDER",
                "admission_class": "StatelessReissueable",
                "inventory_root": "22" * 32,
                "verified_rows": 3,
                "expires_at": int(time.time()) + 3600,
                "production_custody": False,
                "rewards": False,
            },
            separators=(",", ":"),
        ).encode("utf-8")
        self.send_response(201)
        self.send_header("Content-Type", static_host.MEDIA_TYPE)
        self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        del format, args


class StaticHostRecipeTests(unittest.TestCase):
    def setUp(self) -> None:
        CoordinatorHandler.mode = "success"
        CoordinatorHandler.observed = {}
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), CoordinatorHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.coordinator = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    def test_source_record_is_exact_and_rejects_noncanonical_origins(self) -> None:
        record = static_host.source_record(
            "https://static.example",
            "provider-a",
            "region-a",
            "cluster-a",
        )
        self.assertEqual(
            record,
            {
                "origin": "https://static.example",
                "provider": "provider-a",
                "region": "region-a",
                "control_cluster": "cluster-a",
            },
        )
        for origin in (
            "http://static.example",
            "https://STATIC.example",
            "https://static.example/",
            "https://static.example:443",
            "https://user@static.example",
        ):
            with self.subTest(origin=origin):
                with self.assertRaises(static_host.StaticHostError):
                    static_host.source_record(origin, "p", "r", "c")

    def test_registration_uses_no_credentials_and_validates_closed_response(self) -> None:
        report = static_host.register_host(
            self.coordinator,
            "https://operator.example",
            "https://static.example",
            timeout_seconds=5,
            allow_http_loopback=True,
        )
        self.assertFalse(report["redirects_followed"])
        self.assertFalse(report["credentials_sent"])
        response = report["coordinator_verification"]
        self.assertEqual(response["admission_class"], "StatelessReissueable")
        self.assertFalse(response["production_custody"])
        self.assertFalse(response["rewards"])
        observed = CoordinatorHandler.observed
        self.assertEqual(observed["path"], static_host.REGISTER_PATH)
        self.assertEqual(
            observed["body"],
            {
                "schema": static_host.SCHEMA,
                "record_kind": "HOST_REGISTRATION_REQUEST",
                "canonical_origin": "https://static.example",
            },
        )
        self.assertNotIn("authorization", observed["headers"])
        self.assertNotIn("cookie", observed["headers"])
        self.assertEqual(observed["headers"]["origin"], "https://operator.example")

    def test_http_loopback_relaxation_never_applies_to_mutation_origin(self) -> None:
        with self.assertRaisesRegex(static_host.StaticHostError, "origin must use HTTPS"):
            static_host.register_host(
                self.coordinator,
                self.coordinator,
                "https://static.example",
                timeout_seconds=5,
                allow_http_loopback=True,
            )
        self.assertEqual(CoordinatorHandler.observed, {})

    def test_registration_rejects_redirects(self) -> None:
        CoordinatorHandler.mode = "redirect"
        with self.assertRaisesRegex(static_host.StaticHostError, "redirect response is forbidden"):
            static_host.register_host(
                self.coordinator,
                "https://operator.example",
                "https://static.example",
                timeout_seconds=5,
                allow_http_loopback=True,
            )

    def test_registration_rejects_authority_flags_or_expired_result(self) -> None:
        value = {
            "schema": static_host.SCHEMA,
            "record_kind": "HOST_REGISTRATION_RESPONSE",
            "host_id": "11" * 32,
            "canonical_origin": "https://static.example",
            "participant_class": "STATIC_HOST_SEEDER",
            "admission_class": "StatelessReissueable",
            "inventory_root": "22" * 32,
            "verified_rows": 3,
            "expires_at": 99,
            "production_custody": True,
            "rewards": False,
        }
        with self.assertRaises(static_host.StaticHostError):
            static_host.validate_registration_response(
                value,
                host_origin="https://static.example",
                now=100,
            )

    def test_recipe_catalog_closes_transport_and_authorization_contract(self) -> None:
        catalog = json.loads((RECIPE_ROOT / "recipes.json").read_text(encoding="utf-8"))
        self.assertEqual(catalog["schema"], "noos/wwm-web-static-host-recipes/v1")
        self.assertEqual(catalog["status"], "EXPERIMENTAL_UNREWARDED")
        self.assertEqual(catalog["public_infrastructure_catalog"], "public-infrastructure.json")
        self.assertTrue((RECIPE_ROOT / catalog["public_infrastructure_catalog"]).is_file())
        self.assertFalse(catalog["authorization"]["production_custody"])
        self.assertFalse(catalog["authorization"]["rewards"])
        lifecycle = catalog["lifecycle"]
        self.assertEqual(lifecycle["coordinator_refresh_max_seconds"], 60)
        self.assertEqual(
            lifecycle["removed_or_invalid_manifest"],
            "DEACTIVATE_FUTURE_ASSIGNMENTS",
        )
        self.assertEqual(
            lifecycle["expired_manifest"],
            "DEACTIVATE_FUTURE_ASSIGNMENTS",
        )
        self.assertTrue(lifecycle["cached_public_bytes_may_remain"])
        self.assertFalse(lifecycle["third_party_cache_erasure_available"])
        self.assertEqual(
            lifecycle["renewal_publish_order"],
            [
                "REMOVE_OR_WITHHOLD_NEW_HOST_MANIFEST",
                "PUBLISH_AND_INVALIDATE_INVENTORY",
                "VERIFY_LIVE_INVENTORY_BYTES",
                "PUBLISH_60_SECOND_HOST_MANIFEST_LAST",
            ],
        )
        metadata = catalog["response_contract"]["metadata"]
        self.assertEqual(
            metadata["inventory_cache_control"],
            static_host.INVENTORY_CACHE_CONTROL,
        )
        self.assertEqual(
            metadata["license_notice_cache_control"],
            "public, max-age=31536000, immutable",
        )
        for recipe in catalog["recipes"]:
            self.assertEqual(
                recipe["cache_profile"],
                "MANIFEST_60S_INVENTORY_ALWAYS_REVALIDATE_LEGAL_IMMUTABLE",
            )
        self.assertEqual(catalog["response_contract"]["redirects"], "REJECT")
        shares = catalog["response_contract"]["shares"]
        self.assertEqual(shares["cors_allow_origin"], "*")
        self.assertEqual(shares["credentials"], "OMIT")
        self.assertEqual(shares["accept_ranges"], "bytes")
        self.assertEqual(shares["content_length"], 1_047_552)
        self.assertEqual(
            shares["protocol_authority"],
            "NOOS_DA_SHARE_COMMITMENT_AND_PROBE_ROOT",
        )
        recipe_ids = {recipe["id"] for recipe in catalog["recipes"]}
        self.assertEqual(recipe_ids, {"nginx", "caddy", "pages", "cloudfront"})
        for recipe in catalog["recipes"]:
            self.assertTrue((RECIPE_ROOT / recipe["file"]).is_file())
            self.assertFalse(recipe["automatic_compression"])

    def test_public_infrastructure_catalog_never_confuses_access_with_authorization(self) -> None:
        catalog = json.loads(
            (RECIPE_ROOT / "public-infrastructure.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            catalog["schema"],
            "noos/wwm-web-public-infrastructure/v1",
        )
        self.assertEqual(catalog["status"], "EXPERIMENTAL_OWNER_AUTHORIZED_ONLY")
        self.assertEqual(catalog["research_snapshot"], "2026-07-15")
        binding = catalog["model_binding"]
        self.assertEqual(binding["source_bytes"], 3_803_452_480)
        self.assertEqual(
            binding["source_sha256"],
            "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0",
        )
        self.assertEqual(binding["share_count"], 5_448)
        self.assertEqual(binding["share_bytes"], 1_047_552)
        self.assertEqual(binding["encoded_bytes"], 5_707_063_296)
        self.assertTrue(all(value is False for value in catalog["non_claims"].values()))
        authorization = catalog["owner_authorization"]
        self.assertTrue(authorization["required_for_every_upload_or_pin"])
        self.assertIn(
            "INFER_AUTHORIZATION_FROM_PUBLIC_READABILITY",
            authorization["forbidden"],
        )
        admission = catalog["direct_static_host_admission"]
        self.assertEqual(admission["decision"], "LIVE_EXACT_ORIGIN_PROBE_ONLY")
        self.assertTrue(admission["provider_name_never_preapproves"])
        self.assertIn("NO_REDIRECTS", admission["required"])
        self.assertIn(
            "NOOS_DA_SHARE_COMMITMENT_AND_PROBE_ROOT",
            admission["required"],
        )

        entries = {entry["id"]: entry for entry in catalog["infrastructure"]}
        self.assertEqual(
            set(entries),
            {
                "owner-object-storage-cdn",
                "owner-fixed-cid-kubo-gateway",
                "managed-ipfs-custom-domain",
                "owner-ar-io-gateway",
                "filecoin-pin-position-recovery",
                "pinned-managed-hub-mirrors",
                "native-bittorrent-v2-mirror",
                "webtorrent-browser",
                "shared-public-gateways",
            },
        )
        conditional = {
            entry_id
            for entry_id, entry in entries.items()
            if entry["direct_static_host_eligibility"] == "CONDITIONAL_LIVE_PROBE"
        }
        self.assertEqual(
            conditional,
            {
                "owner-object-storage-cdn",
                "owner-fixed-cid-kubo-gateway",
                "managed-ipfs-custom-domain",
                "owner-ar-io-gateway",
            },
        )
        self.assertTrue(
            all(
                entry["direct_static_host_eligibility"]
                in {False, "CONDITIONAL_LIVE_PROBE"}
                for entry in entries.values()
            )
        )
        filecoin = entries["filecoin-pin-position-recovery"]
        self.assertFalse(filecoin["direct_static_host_eligibility"])
        self.assertEqual(filecoin["packaging"]["car_count"], 12)
        self.assertEqual(
            filecoin["packaging"]["raw_position_bytes"] * 12,
            binding["encoded_bytes"],
        )
        self.assertLess(
            filecoin["packaging"]["raw_position_bytes"],
            filecoin["max_single_upload_bytes"],
        )
        self.assertGreater(binding["encoded_bytes"], filecoin["max_single_upload_bytes"])
        self.assertEqual(
            entries["webtorrent-browser"]["v1_browser_capacity_transport"],
            "FORBIDDEN",
        )
        self.assertFalse(entries["shared-public-gateways"]["direct_static_host_eligibility"])
        for entry in entries.values():
            for source in entry["official_sources"]:
                self.assertTrue(source.startswith("https://"), source)
        graduation = catalog["graduation"]
        self.assertFalse(graduation["static_or_mirror_shortcut_to_custody"])
        self.assertEqual(graduation["required_complete_position_bytes"], 475_588_608)

    def test_every_recipe_revalidates_inventory_and_preserves_immutable_bytes(self) -> None:
        for recipe in ("nginx.conf", "Caddyfile", "_headers", "cloudfront.tf"):
            with self.subTest(recipe=recipe):
                controls = _configured_cache_controls(recipe)
                static_host.validate_recipe_cache_controls(**controls)
                self.assertEqual(
                    controls["inventory"],
                    static_host.INVENTORY_CACHE_CONTROL,
                )

    def test_recipe_cache_contract_rejects_stale_inventory_policy(self) -> None:
        with self.assertRaisesRegex(
            static_host.StaticHostError,
            "inventory cache policy",
        ):
            static_host.validate_recipe_cache_controls(
                manifest="public, max-age=60, must-revalidate",
                inventory="public, max-age=300, must-revalidate",
                license_and_notice="public, max-age=31536000, immutable",
                shares="public, max-age=31536000, immutable, no-transform",
            )

    def test_staged_renewal_cannot_pair_new_manifest_with_cached_old_inventory(self) -> None:
        manifest_path = "/.well-known/noos/wwm-web-capacity-v1.json"
        inventory_path = "/inventory-v1.json"
        cache = RevalidatingCache(
            {
                manifest_path: (b"manifest-old:inventory-old", "public, max-age=60, must-revalidate"),
                inventory_path: (b"inventory-old", static_host.INVENTORY_CACHE_CONTROL),
            }
        )
        self.assertEqual(cache.get(manifest_path, 0), b"manifest-old:inventory-old")
        self.assertEqual(cache.get(inventory_path, 0), b"inventory-old")

        cache.origin[inventory_path] = (
            b"inventory-new",
            static_host.INVENTORY_CACHE_CONTROL,
        )
        self.assertEqual(cache.get(inventory_path, 30), b"inventory-new")
        cache.origin[manifest_path] = (
            b"manifest-new:inventory-new",
            "public, max-age=60, must-revalidate",
        )

        self.assertEqual(cache.get(manifest_path, 61), b"manifest-new:inventory-new")
        self.assertEqual(cache.get(inventory_path, 61), b"inventory-new")

        stale_cache = RevalidatingCache(
            {
                inventory_path: (
                    b"inventory-old",
                    "public, max-age=300, must-revalidate",
                )
            }
        )
        self.assertEqual(stale_cache.get(inventory_path, 0), b"inventory-old")
        stale_cache.origin[inventory_path] = (
            b"inventory-new",
            "public, max-age=300, must-revalidate",
        )
        self.assertEqual(stale_cache.get(inventory_path, 61), b"inventory-old")

    def test_output_writer_refuses_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "source.json"
            static_host.write_new_json(path, {"origin": "https://static.example"})
            with self.assertRaises(static_host.StaticHostError):
                static_host.write_new_json(path, {"origin": "https://other.example"})


if __name__ == "__main__":
    unittest.main()
