from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import wwm_model_improvement as improvement


def hx(value: int) -> str:
    return f"{value:064x}"


SEEDS = {
    "builder": "11" * 32,
    "sponsor": "22" * 32,
    "trainer": "33" * 32,
    "evaluator_a": "44" * 32,
    "evaluator_b": "55" * 32,
    "activator": "66" * 32,
}


class ModelImprovementTests(unittest.TestCase):
    def dataset_spec(self) -> dict[str, object]:
        return {
            "knowledge_snapshot_id": hx(100),
            "train_ids": [hx(1)],
            "evaluation_ids": [hx(2)],
            "exclusion_ids": [hx(3)],
            "rights_policy_root": hx(101),
            "rights_records": [
                {
                    "item_id": hx(1),
                    "rights_root": hx(201),
                    "training_permission": True,
                    "derivative_model_permission": True,
                    "revoked": False,
                },
                {
                    "item_id": hx(2),
                    "rights_root": hx(202),
                    "training_permission": True,
                    "derivative_model_permission": True,
                    "revoked": False,
                },
                {
                    "item_id": hx(3),
                    "rights_root": hx(203),
                    "training_permission": False,
                    "derivative_model_permission": False,
                    "revoked": True,
                },
            ],
            "deduplication_evidence": {
                "schema": "noos/wwm-deduplication-evidence/v1",
                "input_ids": [hx(1), hx(2), hx(3)],
                "duplicate_groups": [],
                "unresolved_duplicate_ids": [],
            },
            "private_canary_evidence": {
                "schema": "noos/wwm-private-canary-commitment/v1",
                "count": 8,
                "salted_canary_root": hx(301),
                "holdout_ids_root": hx(302),
            },
            "builder_control_cluster": hx(401),
            "created_height": 10,
        }

    def recipe_spec(self, dataset_id: str) -> dict[str, object]:
        return {
            "parent_revision_id": improvement.REAL_PARENT_SHA256,
            "dataset_id": dataset_id,
            "tokenizer_root": hx(501),
            "numeric_profile_root": hx(502),
            "optimizer_root": hx(503),
            "sampling_profile_root": hx(504),
            "randomness_commitment": hx(505),
            "intended_capability_root": hx(506),
            "evaluator_policy_root": hx(507),
            "rollback_parent_id": improvement.REAL_PARENT_SHA256,
            "budget": {
                "maximum_compute_seconds": 120,
                "maximum_gpu_seconds": 120,
                "maximum_cost_microunits": 1_000_000,
            },
            "adapter_rank": 8,
            "trainable_parameter_count": 4096,
            "maximum_steps": 1,
            "batch_size": 1,
            "learning_rate_q32": 100,
            "clipping_norm_q20": 100,
            "sponsor_control_cluster": hx(402),
            "evaluator_control_clusters": [hx(404), hx(405)],
            "created_height": 11,
        }

    def build_core(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        dataset = improvement.build_dataset_snapshot(self.dataset_spec(), SEEDS["builder"])
        recipe = improvement.build_training_recipe(
            self.recipe_spec(dataset["object_id"]), dataset["object_id"], SEEDS["sponsor"]
        )
        job = improvement.build_adapter_job(
            {
                "trainer_control_cluster": hx(403),
                "work_loom_assignment_id": hx(601),
                "accepted_height": 12,
                "deadline_height": 20,
            },
            recipe,
            SEEDS["trainer"],
        )
        return dataset, recipe, job

    def evaluation_spec(
        self,
        cluster: str,
        *,
        score: int = 100,
        critical: list[str] | None = None,
        conflict: bool = False,
        suffix: int = 0,
    ) -> dict[str, object]:
        return {
            "evaluator_control_cluster": cluster,
            "public_suite_root": hx(700 + suffix),
            "hidden_suite_commitment": hx(710 + suffix),
            "hidden_suite_reveal_root": hx(720 + suffix),
            "scores_q20": {
                "capability": score,
                "safety": score,
                "privacy": score,
                "rights": score,
                "conformance": score,
                "performance": score,
            },
            "critical_failures": critical or [],
            "conflict_disclosure_root": hx(730 + suffix),
            "conflict_detected": conflict,
            "artifact_root": hx(740 + suffix),
            "evaluated_height": 100,
        }

    def canary_spec(self, stage: int, *, critical: bool = False) -> dict[str, object]:
        ceiling = improvement.CANARY_CEILINGS[stage]
        return {
            "stage_index": stage,
            "total_requests": 100,
            "candidate_requests": ceiling,
            "scores_q20": {
                "capability": 100,
                "safety": 100,
                "privacy": 100,
                "rights": 100,
                "conformance": 100,
                "performance": 100,
            },
            "critical_failures": ["safety"] if critical else [],
            "rollback_trigger_bitset": 0,
            "artifact_root": hx(800 + stage),
            "observed_height": 120 + stage,
        }

    def test_dataset_is_signed_sorted_rights_bound_and_private_canary_only(self) -> None:
        snapshot = improvement.build_dataset_snapshot(self.dataset_spec(), SEEDS["builder"])
        self.assertEqual(snapshot["schema"], improvement.DATASET_SCHEMA)
        self.assertEqual(snapshot["train_ids"], [hx(1)])
        self.assertNotIn("raw_canaries", json.dumps(snapshot))
        improvement.verify_signed_record("NOOS-WWM-DATASET-SNAPSHOT-V1", snapshot)

        denied = self.dataset_spec()
        denied["rights_records"][0]["training_permission"] = False
        with self.assertRaisesRegex(improvement.ImprovementError, "rights leakage"):
            improvement.build_dataset_snapshot(denied, SEEDS["builder"])

        revoked_leak = self.dataset_spec()
        revoked_leak["exclusion_ids"] = []
        with self.assertRaisesRegex(improvement.ImprovementError, "revoked item"):
            improvement.build_dataset_snapshot(revoked_leak, SEEDS["builder"])

    def test_dataset_rejects_split_dedup_and_canary_failures(self) -> None:
        unsorted = self.dataset_spec()
        unsorted["train_ids"] = [hx(4), hx(1)]
        with self.assertRaisesRegex(improvement.ImprovementError, "strictly sorted"):
            improvement.build_dataset_snapshot(unsorted, SEEDS["builder"])

        unresolved = self.dataset_spec()
        unresolved["deduplication_evidence"]["unresolved_duplicate_ids"] = [hx(1)]
        with self.assertRaisesRegex(improvement.ImprovementError, "unresolved duplicates"):
            improvement.build_dataset_snapshot(unresolved, SEEDS["builder"])

        duplicate = self.dataset_spec()
        duplicate["deduplication_evidence"]["duplicate_groups"] = [[hx(1), hx(2)]]
        with self.assertRaisesRegex(improvement.ImprovementError, "multiple duplicates"):
            improvement.build_dataset_snapshot(duplicate, SEEDS["builder"])

        leaked_canary = self.dataset_spec()
        leaked_canary["private_canary_evidence"]["raw_canaries"] = ["secret"]
        with self.assertRaisesRegex(improvement.ImprovementError, "never raw canaries"):
            improvement.build_dataset_snapshot(leaked_canary, SEEDS["builder"])

    def test_training_recipe_enforces_q1_parent_and_all_bounds(self) -> None:
        dataset = improvement.build_dataset_snapshot(self.dataset_spec(), SEEDS["builder"])
        valid = self.recipe_spec(dataset["object_id"])
        recipe = improvement.build_training_recipe(valid, dataset["object_id"], SEEDS["sponsor"])
        improvement.verify_signed_record("NOOS-WWM-TRAINING-RECIPE-V1", recipe)
        for field, value in (
            ("adapter_rank", improvement.MAX_ADAPTER_RANK + 1),
            ("trainable_parameter_count", improvement.MAX_ADAPTER_PARAMETERS + 1),
            ("maximum_steps", improvement.MAX_TRAINING_STEPS + 1),
        ):
            with self.subTest(field=field):
                candidate = copy.deepcopy(valid)
                candidate[field] = value
                with self.assertRaises(improvement.ImprovementError):
                    improvement.build_training_recipe(candidate, dataset["object_id"], SEEDS["sponsor"])
        q1 = copy.deepcopy(valid)
        q1["parent_revision_id"] = improvement.FROZEN_Q1_SHA256
        q1["rollback_parent_id"] = improvement.FROZEN_Q1_SHA256
        with self.assertRaisesRegex(improvement.ImprovementError, "Q1 inference artifact"):
            improvement.build_training_recipe(q1, dataset["object_id"], SEEDS["sponsor"])

    def test_job_update_checkpoints_and_receipt_are_immutable_signed_evidence(self) -> None:
        dataset, recipe, job = self.build_core()
        improvement.verify_signed_record("NOOS-WWM-ADAPTER-JOB-V1", job)
        with tempfile.TemporaryDirectory() as temp:
            adapter = Path(temp) / "candidate.lora"
            adapter.write_bytes(b"real adapter fixture")
            update_spec = {
                "checkpoints": [
                    {
                        "sequence": 0,
                        "checkpoint_root": hx(901),
                        "parent_checkpoint_root": None,
                        "optimizer_state_root": hx(902),
                        "examples_seen": 1,
                    },
                    {
                        "sequence": 1,
                        "checkpoint_root": improvement.sha256_file(adapter),
                        "parent_checkpoint_root": hx(901),
                        "optimizer_state_root": hx(904),
                        "examples_seen": 2,
                    },
                ],
                "steps_completed": 1,
                "resource_receipt_root": hx(905),
                "deterministic_fidelity_audit_root": hx(906),
                "sampled_fidelity_audit_root": hx(907),
                "execution_implementation_root": hx(908),
                "started_height": 13,
                "completed_height": 14,
            }
            update, receipt = improvement.build_update_and_receipt(
                update_spec, recipe, dataset, job, hx(909), adapter, SEEDS["trainer"]
            )
            self.assertTrue(update["shadow_only"])
            self.assertTrue(receipt["one_step_roundtrip_completed"])
            improvement.verify_signed_record("NOOS-WWM-ADAPTER-UPDATE-PACKET-V1", update)
            improvement.verify_signed_record("NOOS-WWM-TRAINER-RECEIPT-V1", receipt)

            broken = copy.deepcopy(update_spec)
            broken["checkpoints"][1]["parent_checkpoint_root"] = hx(999)
            with self.assertRaisesRegex(improvement.ImprovementError, "parent chain"):
                improvement.build_update_and_receipt(
                    broken, recipe, dataset, job, hx(909), adapter, SEEDS["trainer"]
                )

    def test_missing_and_wrong_real_parent_fail_closed_without_training_claim(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            config = {
                "schema": improvement.SCHEMA,
                "environment": "devnet",
                "production": False,
                "feature_flags": {name: False for name in improvement.FEATURE_FLAGS},
                "real_parent": {
                    "name": improvement.REAL_PARENT_NAME,
                    "path": str(root / improvement.REAL_PARENT_NAME),
                    "bytes": improvement.REAL_PARENT_BYTES,
                    "sha256": improvement.REAL_PARENT_SHA256,
                    "license": {},
                },
            }
            gate = improvement.probe_gate(config)
            self.assertFalse(gate.passed)
            self.assertEqual(gate.code, "MISSING_REAL_PARENT")
            self.assertFalse(gate.evidence["weight_training_enabled"])
            self.assertFalse(gate.evidence["promotion_enabled"])

            parent = root / improvement.REAL_PARENT_NAME
            parent.write_bytes(b"not a 53 GB parent")
            wrong = improvement.probe_gate(config)
            self.assertEqual(wrong.code, "WRONG_REAL_PARENT_LENGTH")
            self.assertIn(str(improvement.REAL_PARENT_BYTES), wrong.detail)

    def test_toolchain_rejects_wrong_revision_executable_hash_and_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            executable = Path(temp) / "tool.exe"
            executable.write_bytes(b"pinned tool")
            actual = improvement.sha256_file(executable)
            toolchain = {
                "prism_source_revision": improvement.PRISM_RUNTIME_REVISION,
                "runtime_root": improvement.PRISM_RUNTIME_ROOT,
                "build_root": improvement.PRISM_BUILD_ROOT,
                "tokenizer_root": improvement.BONSAI_TOKENIZER_ROOT,
                "network_allowed": False,
                **{
                    role: {"path": str(executable), "sha256": actual}
                    for role in ("train", "merge", "quantize", "runtime")
                },
            }
            checked = improvement.validate_toolchain(toolchain)
            self.assertEqual(checked["runtime"], executable.resolve())

            wrong_revision = copy.deepcopy(toolchain)
            wrong_revision["prism_source_revision"] = "0" * 40
            with self.assertRaisesRegex(improvement.ImprovementError, "wrong pinned Prism"):
                improvement.validate_toolchain(wrong_revision)

            wrong_runtime = copy.deepcopy(toolchain)
            wrong_runtime["runtime"]["sha256"] = hx(999)
            with self.assertRaisesRegex(improvement.ImprovementError, "runtime executable hash"):
                improvement.validate_toolchain(wrong_runtime)

    def test_roundtrip_runs_train_merge_quantize_and_two_reproducible_runtime_loads(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            parent = root / "parent.gguf"
            tool = root / "pinned-tool.exe"
            parent.write_bytes(b"licensed parent fixture")
            tool.write_bytes(b"pinned tool fixture")
            expected_output = b"deterministic successor output"
            config = {
                "real_parent": {},
                "toolchain": {},
                "one_step": True,
                "command_timeout_seconds": 10,
                "reproduction": {"expected_output_sha256": improvement.sha256_bytes(expected_output)},
                "train_command": [str(tool), "train", "{parent}", "{adapter}"],
                "merge_command": [str(tool), "merge", "{parent}", "{adapter}", "{merged}"],
                "quantize_command": [str(tool), "quantize", "{merged}", "{successor}"],
                "runtime_command": [str(tool), "runtime", "{successor}", "{output}"],
            }
            executables = {role: tool.resolve() for role in ("train", "merge", "quantize", "runtime")}

            def fake_run(argv: list[str], _cwd: Path, _timeout: int) -> None:
                operation = argv[1]
                output = Path(argv[-1])
                payload = {
                    "train": b"one-step LoRA adapter",
                    "merge": b"merged F16 candidate",
                    "quantize": b"quantized successor GGUF",
                    "runtime": expected_output,
                }[operation]
                output.write_bytes(payload)

            with (
                patch.object(improvement, "validate_real_parent", return_value=parent.resolve()),
                patch.object(improvement, "validate_toolchain", return_value=executables),
                patch.object(improvement, "_run_command", side_effect=fake_run),
            ):
                evidence, paths = improvement.run_real_roundtrip(config, root / "work")
            self.assertTrue(evidence["passed"])
            self.assertTrue(evidence["one_step_completed"])
            self.assertEqual(evidence["runtime_reproduction_count"], 2)
            self.assertEqual(evidence["runtime_output_sha256"], improvement.sha256_bytes(expected_output))
            self.assertEqual(paths["successor"].read_bytes(), b"quantized successor GGUF")

            mismatch = copy.deepcopy(config)
            mismatch["reproduction"]["expected_output_sha256"] = hx(999)
            with (
                patch.object(improvement, "validate_real_parent", return_value=parent.resolve()),
                patch.object(improvement, "validate_toolchain", return_value=executables),
                patch.object(improvement, "_run_command", side_effect=fake_run),
                self.assertRaisesRegex(improvement.ImprovementError, "reproduction mismatch"),
            ):
                improvement.run_real_roundtrip(mismatch, root / "work-mismatch")

    def test_successor_identity_is_new_complete_and_insert_once(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            successor_path = root / "successor.gguf"
            successor_path.write_bytes(b"immutable successor bytes")
            license_path = root / "LICENSE.txt"
            notice_path = root / "NOTICE.txt"
            license_path.write_bytes(b"Apache-2.0 license fixture")
            notice_path.write_bytes(b"successor notice fixture")
            license_sha = improvement.sha256_file(license_path)
            notice_sha = improvement.sha256_file(notice_path)
            exported, manifest = improvement.export_immutable_successor_bundle(
                successor_path, root / "exports", license_path, notice_path, license_sha, notice_sha
            )
            with self.assertRaisesRegex(improvement.ImprovementError, "already exists"):
                improvement.export_immutable_successor_bundle(
                    successor_path, root / "exports", license_path, notice_path, license_sha, notice_sha
                )
            self.assertEqual(improvement.sha256_file(exported), improvement.sha256_file(successor_path))
            bindings = {
                name: hx(index + 1000)
                for index, name in enumerate(
                    (
                        "parent_revision_id",
                        "dataset_id",
                        "recipe_id",
                        "adapter_update_packet_id",
                        "trainer_receipt_id",
                        "evaluation_set_root",
                        "license_root",
                        "rights_root",
                        "provenance_root",
                        "runtime_root",
                        "tokenizer_root",
                        "quantization_toolchain_root",
                    )
                )
            }
            successor = improvement.build_successor_evidence(
                {
                    "created_height": 200,
                    "license_sha256": license_sha,
                    "notice_sha256": notice_sha,
                    "bundle_root": manifest["bundle_root"],
                },
                exported,
                bindings,
                SEEDS["activator"],
            )
            self.assertTrue(successor["immutable"])
            self.assertFalse(successor["overwrites_parent"])
            self.assertTrue(successor["direct_canonical_training_objects_require_reviewed_wwm_v3"])
            improvement.verify_signed_record("NOOS-WWM-IMMUTABLE-SUCCESSOR-V1", successor)
            store = improvement.ImmutableEvidenceStore(root / "evidence")
            store.insert("successors", successor)
            with self.assertRaisesRegex(improvement.ImprovementError, "duplicate immutable"):
                store.insert("successors", successor)

            successor_path.write_bytes(b"different immutable successor bytes")
            changed_export, changed_manifest = improvement.export_immutable_successor_bundle(
                successor_path, root / "exports", license_path, notice_path, license_sha, notice_sha
            )
            changed = improvement.build_successor_evidence(
                {
                    "created_height": 200,
                    "license_sha256": license_sha,
                    "notice_sha256": notice_sha,
                    "bundle_root": changed_manifest["bundle_root"],
                },
                changed_export,
                bindings,
                SEEDS["activator"],
            )
            self.assertNotEqual(successor["successor_artifact_id"], changed["successor_artifact_id"])
            self.assertNotEqual(successor["object_id"], changed["object_id"])

    def test_evaluations_are_independent_insert_once_and_preserve_unfavorable_reports(self) -> None:
        registry = improvement.EvaluationRegistry(hx(1100), improvement.REAL_PARENT_SHA256, hx(403))
        first_spec = self.evaluation_spec(hx(404), suffix=1)
        first = registry.insert(first_spec, SEEDS["evaluator_a"])
        with self.assertRaisesRegex(improvement.ImprovementError, "duplicate evaluation"):
            registry.insert(first_spec, SEEDS["evaluator_a"])
        second = registry.insert(
            self.evaluation_spec(hx(405), score=-10, critical=["safety"], suffix=2),
            SEEDS["evaluator_b"],
        )
        self.assertTrue(first["favorable"])
        self.assertFalse(second["favorable"])
        self.assertEqual(len(registry.reports), 2)
        gate = registry.hard_floor_gate({name: 0 for name in improvement.DIMENSIONS})
        self.assertFalse(gate["passed"])
        self.assertTrue(any("critical-failure" in failure for failure in gate["failures"]))

    def test_evaluator_conflict_and_trainer_cluster_conflict_block_gate(self) -> None:
        registry = improvement.EvaluationRegistry(hx(1200), improvement.REAL_PARENT_SHA256, hx(403))
        registry.insert(self.evaluation_spec(hx(404), conflict=True, suffix=3), SEEDS["evaluator_a"])
        registry.insert(self.evaluation_spec(hx(405), suffix=4), SEEDS["evaluator_b"])
        gate = registry.hard_floor_gate({name: 0 for name in improvement.DIMENSIONS})
        self.assertFalse(gate["passed"])
        self.assertTrue(any("evaluator-conflict" in failure for failure in gate["failures"]))

        clustered = improvement.EvaluationRegistry(hx(1201), improvement.REAL_PARENT_SHA256, hx(403))
        clustered.insert(self.evaluation_spec(hx(403), suffix=5), SEEDS["evaluator_a"])
        clustered.insert(self.evaluation_spec(hx(405), suffix=6), SEEDS["evaluator_b"])
        with self.assertRaisesRegex(improvement.ImprovementError, "not independent"):
            clustered.hard_floor_gate({name: 0 for name in improvement.DIMENSIONS})

    def test_timelock_and_all_canary_ceiling_transitions_complete_in_order(self) -> None:
        floors = {name: 0 for name in improvement.DIMENSIONS}
        controller = improvement.CanaryController(hx(1300), improvement.REAL_PARENT_SHA256, 100, 120, floors)
        gate = {"passed": True, "evaluation_set_root": hx(1301)}
        with self.assertRaisesRegex(improvement.ImprovementError, "timelock"):
            controller.begin(119, gate)
        controller.begin(120, gate)
        for stage, ceiling in enumerate(improvement.CANARY_CEILINGS):
            self.assertEqual(controller.stage, stage)
            state = controller.observe(self.canary_spec(stage))
            self.assertEqual(controller.observations[stage]["traffic_ceiling_percent"], ceiling)
        self.assertEqual(state, "CANARY_COMPLETE")
        evidence = controller.evidence()
        self.assertEqual(evidence["canary_ceilings_percent"], [1, 5, 25, 50, 100])
        self.assertEqual(evidence["shadow_alias_revision_id"], hx(1300))
        self.assertEqual(evidence["production_alias_revision_id"], improvement.REAL_PARENT_SHA256)

    def test_critical_canary_failure_immediately_rolls_back_to_parent(self) -> None:
        floors = {name: 0 for name in improvement.DIMENSIONS}
        controller = improvement.CanaryController(hx(1400), improvement.REAL_PARENT_SHA256, 100, 120, floors)
        controller.begin(120, {"passed": True, "evaluation_set_root": hx(1401)})
        state = controller.observe(self.canary_spec(0, critical=True))
        self.assertEqual(state, "ROLLED_BACK")
        self.assertEqual(controller.shadow_revision, improvement.REAL_PARENT_SHA256)
        self.assertEqual(controller.transitions[-1]["kind"], "AUTOMATIC_ROLLBACK")
        with self.assertRaisesRegex(improvement.ImprovementError, "not running"):
            controller.observe(self.canary_spec(1))

    def test_flags_remain_disabled_and_frozen_v2_hash_is_unchanged(self) -> None:
        config = improvement.load_object(improvement.ROOT / "deploy" / "wwm" / "model-improvement.json")
        self.assertEqual(
            improvement.feature_flags_false(config),
            {name: False for name in improvement.FEATURE_FLAGS},
        )
        self.assertEqual(improvement.verify_frozen_v2(), improvement.FROZEN_V2_SHA256)
        schema_hash = improvement.sha256_file(improvement.ROOT / "protocol" / "schemas" / "wwm-v2.md")
        self.assertEqual(schema_hash, "68c6799ec95194379b8e5325d4307abe65eac8f14e8ebd8e4d6856b569641837")

    def test_deploy_probe_smoke_emits_precise_disabled_evidence(self) -> None:
        config_path = improvement.ROOT / "deploy" / "wwm" / "model-improvement.json"
        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp) / "gate.json"
            stdout = StringIO()
            stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = improvement.main(["probe", "--config", str(config_path), "--evidence", str(evidence)])
            self.assertEqual(result, 2)
            payload = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertFalse(payload["passed"])
            self.assertFalse(payload["weight_training_enabled"])
            self.assertIn("MISSING_REAL_PARENT", payload["failure"])
            self.assertEqual(payload["frozen_wwm_v2_sha256"], improvement.FROZEN_V2_SHA256)
            self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
