from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import wwm_hosted_model_demo as demo


GOVERNANCE_SEED = "33" * 32
GOVERNANCE_ACCOUNT = "17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce"
TOKENIZER_FIXTURE_SHA256 = demo.hashlib.sha256(b"test fixture").hexdigest()


class FakeMatrix:
    def base_url(self, position: int) -> str:
        return f"http://127.0.0.1:{12000 + position}"


class HostedModelDemoTests(unittest.TestCase):
    def make_config(self, root: Path) -> dict[str, object]:
        disposable = root / "disposable"
        return {
            "schema": demo.SCHEMA,
            "environment": "devnet",
            "production": False,
            "publisher_or_gateway_fallback": False,
            "external_model_egress": [],
            "tokenizer_executable_sha256": TOKENIZER_FIXTURE_SHA256,
            "identities": {
                "artifact_id": demo.ARTIFACT_ID,
                "manifest_root": demo.MANIFEST_ROOT,
                "model_sha256": demo.MODEL_SHA256,
                "model_bytes": demo.MODEL_BYTES,
                "encoded_bytes": demo.ENCODED_BYTES,
                "positions": demo.POSITIONS,
                "reconstruction_threshold": demo.RECONSTRUCTION_THRESHOLD,
                "schedulable_minimum": demo.SCHEDULABLE_MINIMUM,
            },
            "paths": {
                "cli": str(root / "bin" / "noos-cli"),
                "artifact_service": str(root / "bin" / "noos-artifact-service"),
                "workerd": str(root / "bin" / "noos-workerd"),
                "tokenizer": str(root / "bin" / "llama-tokenize"),
                "manifest": str(root / "manifest.bin"),
                "store_verification": str(root / "store-verification.json"),
                "workerd_template": str(root / "workerd.toml"),
                "disposable_root": str(disposable),
                "cache": str(disposable / "model" / "Bonsai-27B-Q1_0.gguf"),
                "evidence_dir": str(root / "evidence"),
                "panel_state": str(root / "panel.json"),
                "source_store_root": str(root / "canonical-store"),
                "source_staging_root": str(root / "canonical-staging"),
                "source_consensus_root": str(root / "canonical-consensus"),
                "replacement_consensus_root": str(root / "replacement-consensus"),
            },
            "network": {
                "node_rpc": "http://127.0.0.1:9642",
                "node_token": "test-node-token",
                "artifact_url": "http://127.0.0.1:9761",
                "sidecar_url": "http://127.0.0.1:9867",
                "sidecar_token_hex": "22" * 32,
                "proxy_host": "127.0.0.1",
                "proxy_port_start": 12000,
            },
            "governance": {
                "seed_hex": GOVERNANCE_SEED,
                "account_id": GOVERNANCE_ACCOUNT,
            },
            "source_store_quota_bytes": 8 * 1024 * 1024 * 1024,
            "replacement_store_quota_bytes": 1024 * 1024 * 1024,
        }

    def prepare_validate_only_files(self, config: dict[str, object]) -> None:
        paths = config["paths"]
        self.assertIsInstance(paths, dict)
        for key in ("cli", "artifact_service", "workerd", "tokenizer", "manifest"):
            path = Path(paths[key])
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"test fixture")
        Path(paths["workerd_template"]).write_text(
            'build_flags = ["GGML_HIP=ON", "LLAMA_CURL=OFF"]\n',
            encoding="utf-8",
        )
        verification = {
            "schema": "noos.wwm.artifact-store-verification.v1",
            "artifact_id": demo.ARTIFACT_ID,
            "manifest_root": demo.MANIFEST_ROOT,
            "published_sha256": demo.MODEL_SHA256,
            "source_bytes": demo.MODEL_BYTES,
            "encoded_share_bytes": demo.ENCODED_BYTES,
            "verified_share_count": demo.STRIPES * demo.POSITIONS,
            "published": True,
            "position_roots": [f"{position + 1:064x}" for position in range(demo.POSITIONS)],
        }
        Path(paths["store_verification"]).write_text(
            json.dumps(verification), encoding="utf-8"
        )

    def test_validate_contract_accepts_only_exact_test_isolation_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = self.make_config(Path(temp))
            paths, network = demo.validate_contract(config)
            self.assertEqual(paths.cache.name, "Bonsai-27B-Q1_0.gguf")
            self.assertEqual(network.proxy_host, "127.0.0.1")

            invalid_cases = (
                ("production environment", ("environment",), "production"),
                ("production flag", ("production",), True),
                ("publisher fallback", ("publisher_or_gateway_fallback",), True),
                ("external egress", ("external_model_egress",), ["https://example.invalid"]),
                ("unpinned tokenizer", ("tokenizer_executable_sha256",), "00"),
                ("non-loopback node", ("network", "node_rpc"), "http://192.0.2.1:9642"),
                ("wrong governance seed", ("governance", "seed_hex"), "44" * 32),
            )
            for label, keys, value in invalid_cases:
                with self.subTest(label=label):
                    candidate = copy.deepcopy(config)
                    target = candidate
                    for key in keys[:-1]:
                        target = target[key]
                    target[keys[-1]] = value
                    with self.assertRaises(demo.DemoError):
                        demo.validate_contract(candidate)

    def test_validate_contract_rejects_cache_or_source_store_in_unsafe_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.make_config(root)
            config["paths"]["cache"] = str(root / "outside.gguf")
            with self.assertRaisesRegex(demo.DemoError, "outside disposable_root"):
                demo.validate_contract(config)

            config = self.make_config(root)
            config["paths"]["cache"] = str(root / "disposable" / "Bonsai-27B-Q1_0.gguf")
            with self.assertRaisesRegex(demo.DemoError, "dedicated directory"):
                demo.validate_contract(config)

            config = self.make_config(root)
            config["paths"]["source_store_root"] = str(root / "disposable" / "source")
            with self.assertRaisesRegex(demo.DemoError, "canonical source store"):
                demo.validate_contract(config)

    def test_clear_disposable_cache_removes_only_cache_and_partial(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths, _ = demo.validate_contract(self.make_config(root))
            paths.cache.parent.mkdir(parents=True)
            paths.cache.write_bytes(b"cache")
            partial = paths.cache.with_suffix(paths.cache.suffix + ".partial")
            partial.write_bytes(b"partial")
            sibling = paths.cache.parent / "preserve.txt"
            sibling.write_bytes(b"preserve")
            source = paths.source_store_root
            source.mkdir(parents=True)
            (source / "share").write_bytes(b"canonical")

            demo.clear_disposable_cache(paths)

            self.assertFalse(paths.cache.exists())
            self.assertFalse(partial.exists())
            self.assertEqual(sibling.read_bytes(), b"preserve")
            self.assertEqual((source / "share").read_bytes(), b"canonical")

    def test_custodian_map_requires_a_complete_profile_permutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "custodians.json"
            profiles = [
                {
                    "profile_id": f"{position + 1:064x}",
                    "endpoint_root": f"{position + 101:064x}",
                }
                for position in range(demo.POSITIONS)
            ]
            assignment = (3, 1, 2, 0, 4, 5, 6, 7, 8, 9, 10, 11)
            demo.write_custodian_map(output, profiles, FakeMatrix(), assignment)
            rows = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual([row["position"] for row in rows], list(range(12)))
            self.assertEqual(rows[0]["profile_id"], profiles[3]["profile_id"])
            self.assertEqual(rows[3]["profile_id"], profiles[0]["profile_id"])
            self.assertEqual(rows[3]["base_url"], "http://127.0.0.1:12003")

            with self.assertRaisesRegex(demo.DemoError, "permutation"):
                demo.write_custodian_map(output, profiles, FakeMatrix(), [0] * 12)

    def test_patch_executor_config_replaces_every_trusted_runtime_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths, network = demo.validate_contract(self.make_config(root))
            template = root / "template.toml"
            output = root / "workerd.toml"
            proof = root / "proof.json"
            custodians = root / "custodians.json"
            scratch = root / "scratch"
            drain = root / "drain"
            template.write_text(
                "\n".join(
                    [
                        'genesis_hash_hex = "old"',
                        'sidecar_token_hex = "old"',
                        'listen = "tcp://127.0.0.1:1"',
                        'scratch_dir = "old"',
                        'drain_file = "old"',
                        'path = "old"',
                        'manifest_path = "old"',
                        'custodian_map_path = "old"',
                        'finalized_resolution_path = "old"',
                        "trusted_checkpoint_epoch = 0",
                        "trusted_checkpoint_height = 0",
                        'trusted_checkpoint_hash_hex = "old"',
                        "current_finalized_height = 0",
                        'certificate_id_hex = "old"',
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            resolution = {
                "genesis_hash": "aa" * 32,
                "finalized_height": 1025,
                "finalized_hash": "bb" * 32,
                "active": {"availability_certificate_id": "cc" * 32},
            }

            demo.patch_executor_config(
                template,
                output,
                paths,
                network,
                resolution,
                proof,
                custodians,
                scratch,
                drain,
            )
            patched = output.read_text(encoding="utf-8")
            self.assertIn(f'path = "{paths.cache.as_posix()}"', patched)
            self.assertIn("trusted_checkpoint_epoch = 4", patched)
            self.assertIn("trusted_checkpoint_height = 1025", patched)
            self.assertIn(f'certificate_id_hex = "{"cc" * 32}"', patched)
            self.assertNotIn('= "old"', patched)

    def test_signed_evidence_verifies_exact_canonical_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = self.make_config(Path(temp))
            paths, _ = demo.validate_contract(config)
            body = {
                "schema": demo.EVIDENCE_SCHEMA,
                "run_id": "fixture",
                "production_claimed": False,
                "publisher_or_gateway_fallback": False,
            }
            evidence_path = demo.seal_evidence(config, paths, body)
            signed = json.loads(evidence_path.read_text(encoding="utf-8"))
            signature = signed.pop("signature")
            canonical = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode()
            self.assertEqual(signature["domain"], "NOOS/EVIDENCE/WWM-HOSTED-DEMO/V1")
            self.assertEqual(signature["signed_payload_sha256"], demo.hashlib.sha256(canonical).hexdigest())
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(signature["public_key"])).verify(
                bytes.fromhex(signature["signature"]),
                signature["domain"].encode() + canonical,
            )
    def test_offline_tokenizer_uses_stdin_and_commits_exact_token_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = self.make_config(Path(temp))
            self.prepare_validate_only_files(config)
            paths, _ = demo.validate_contract(config)
            paths.cache.parent.mkdir(parents=True, exist_ok=True)
            paths.cache.write_bytes(b"reconstructed model fixture")
            completed = demo.subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=b"[7, 8, 9]",
                stderr=b"",
            )
            with patch.object(demo.subprocess, "run", return_value=completed) as invoked:
                result = demo.tokenize_output(
                    paths,
                    b"resilient",
                    16,
                    TOKENIZER_FIXTURE_SHA256,
                )
            self.assertEqual(result["token_count"], 3)
            self.assertTrue(demo.HEX32.fullmatch(result["token_history_root"]))
            positional, keyword = invoked.call_args
            self.assertNotIn("resilient", positional[0])
            self.assertEqual(keyword["input"], b"resilient")
            self.assertIn("--stdin", positional[0])
            self.assertIn("--no-bos", positional[0])
            self.assertEqual(keyword["env"]["NO_PROXY"], "*")
            over_bound = demo.subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=(" ".join(str(value) for value in range(17))).encode(),
                stderr=b"",
            )
            with (
                patch.object(demo.subprocess, "run", return_value=over_bound),
                self.assertRaisesRegex(demo.DemoError, "max_output_tokens"),
            ):
                demo.tokenize_output(
                    paths,
                    b"too many",
                    16,
                    TOKENIZER_FIXTURE_SHA256,
                )

    def test_prerequisites_reject_changed_tokenizer_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = self.make_config(Path(temp))
            self.prepare_validate_only_files(config)
            paths, _ = demo.validate_contract(config)
            paths.tokenizer.write_bytes(b"changed executable")
            with (
                patch.object(demo, "verify_operator_capabilities", return_value={}),
                patch.object(demo, "repository_revision", return_value="ab" * 20),
                self.assertRaisesRegex(demo.DemoError, "tokenize executable hash"),
            ):
                demo.verify_prerequisites(config, paths)


    def test_validate_only_rejects_cli_without_chain_bound_settlement(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = self.make_config(Path(temp))
            self.prepare_validate_only_files(config)
            paths, _ = demo.validate_contract(config)
            with patch.object(
                demo,
                "run_json",
                return_value={
                    "schema": "noos/wwm-devnet-operator-capabilities/v1",
                    "typed_open_wwm_job": True,
                    "typed_record_wwm_receipt": True,
                    "typed_settle_wwm_job": False,
                    "finalized_record_route": "/wwm-record/{kind}/{id}",
                    "production_capable": False,
                },
            ):
                with self.assertRaisesRegex(demo.DemoError, "settlement operator path"):
                    demo.verify_operator_capabilities(paths)

    def test_validate_only_entrypoint_reports_non_production_no_fallback_verdict(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = self.make_config(root)
            self.prepare_validate_only_files(config)
            config_path = root / "config.json"
            config_path.write_text(json.dumps(config), encoding="utf-8")
            output = StringIO()
            capabilities = {
                "schema": "noos/wwm-devnet-operator-capabilities/v1",
                "typed_open_wwm_job": True,
                "typed_record_wwm_receipt": True,
                "typed_settle_wwm_job": True,
                "finalized_record_route": "/wwm-record/{kind}/{id}",
                "production_capable": False,
            }
            with (
                patch.object(demo, "verify_operator_capabilities", return_value=capabilities),
                patch.object(demo, "repository_revision", return_value="ab" * 20),
                redirect_stdout(output),
            ):
                code = demo.main(["--config", str(config_path), "--validate-only"])
            self.assertEqual(code, 0)
            report = json.loads(output.getvalue())
            self.assertEqual(report["verdict"], "VALID_TEST_ONLY_HOSTED_MODEL_DEMO")
            self.assertFalse(report["production_claimed"])
            self.assertFalse(report["publisher_or_gateway_fallback"])
            self.assertEqual(report["external_model_egress"], [])

    def test_executor_startup_timeout_stops_the_spawned_process(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = Mock(workerd=Path(temp) / "noos-workerd")
            network = Mock(sidecar_url="http://127.0.0.1:9877")
            process = Mock()
            with (
                patch.object(demo.subprocess, "Popen", return_value=process),
                patch.object(demo, "wait_port", side_effect=demo.DemoError("timeout")) as wait,
                patch.object(demo, "stop_executor") as stop,
            ):
                with self.assertRaisesRegex(demo.DemoError, "timeout"):
                    demo.start_executor(
                        paths,
                        network,
                        Path(temp) / "workerd.toml",
                        Path(temp) / "workerd.log",
                    )
            wait.assert_called_once_with(network.sidecar_url, process, timeout=900)
            stop.assert_called_once_with(process)
            getattr(process, "_noos_log").close()

    def test_chain_bound_job_verifies_only_the_finalized_projection(self) -> None:
        network = Mock()
        plan = {
            "job_id": "11" * 32,
            "job": {"client_commitment": "12" * 32},
            "bindings": {
                "capsule_id": "13" * 32,
                "execution_profile_id": "14" * 32,
                "availability_certificate_id": "15" * 32,
                "fund_profile_id": "16" * 32,
            },
        }
        projected = {"record": {"job_id": "11" * 32}}
        with patch.object(demo, "finalized_wwm_record", return_value=projected) as finalized:
            self.assertEqual(demo.verify_chain_bound_job(network, plan), projected)
        expected = finalized.call_args.args[3]
        self.assertEqual(
            set(expected),
            {
                "job_id",
                "capsule_id",
                "execution_profile_id",
                "availability_certificate_id",
                "fund_profile_id",
            },
        )
        self.assertNotIn("client_commitment", expected)

    def test_submit_wwm_actions_builds_one_atomic_finality_batch(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = {
                "governance": {
                    "seed_hex": GOVERNANCE_SEED,
                    "account_id": GOVERNANCE_ACCOUNT,
                }
            }
            paths = Mock(cli=root / "noos-cli", disposable_root=root / "disposable")
            network = Mock(node_rpc="http://127.0.0.1:9642", node_token="token")
            status = {
                "chain_id": "11" * 32,
                "genesis_hash": "22" * 32,
                "unsafe_head": {"height": 100},
            }
            actions = (
                {"type": "record_wwm_receipt", "receipt_id": "44" * 32},
                {"type": "settle_wwm_job", "settlement_id": "55" * 32},
            )
            encoded = (
                {
                    "schema": "noos/wwm-devnet-operator-action/v1",
                    "production_capable": False,
                    "id": "44" * 32,
                    "action": "aa",
                },
                {
                    "schema": "noos/wwm-devnet-operator-action/v1",
                    "production_capable": False,
                    "id": "55" * 32,
                    "action": "bb",
                },
            )
            receipt = {"state": {"settled_height": 101}}
            submitted = Mock()
            with (
                patch.object(demo, "http_json", return_value=status),
                patch.object(demo, "run_json", side_effect=encoded),
                patch.object(
                    demo,
                    "build_and_submit",
                    return_value=("66" * 32, receipt),
                ) as build,
                patch.object(demo, "wait_finalized", return_value=status) as finalized,
            ):
                result = demo.submit_wwm_actions(config, paths, network, actions, submitted)

            spec = build.call_args.args[3]
            self.assertEqual(spec["actions"], ["aa", "bb"])
            self.assertEqual(spec["resource_limits"]["bytes"], 131_072)
            self.assertEqual(spec["resource_limits"]["proof_units"], 128)
            self.assertEqual(result["action_ids"], ["44" * 32, "55" * 32])
            self.assertEqual(result["finalized_height"], 101)
            finalized.assert_called_once_with(network, 101)
            self.assertIs(build.call_args.args[5], submitted)
            with self.assertRaisesRegex(demo.DemoError, "1..8"):
                demo.submit_wwm_actions(config, paths, network, ())


if __name__ == "__main__":
    unittest.main()
