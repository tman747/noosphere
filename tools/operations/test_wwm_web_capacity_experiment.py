from __future__ import annotations

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "operations" / "wwm_web_capacity_experiment.py"
SPEC = importlib.util.spec_from_file_location("wwm_web_capacity_experiment", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
experiment = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = experiment
SPEC.loader.exec_module(experiment)


class WebCapacityExperimentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = experiment.load_manifest()
        cls.fixture = experiment.qualifying_fixture(cls.manifest)
        cls.benchmark = experiment.simulate_sessions(
            cls.manifest["minimums"]["synthetic_sessions"],
            cls.manifest["maximums"]["synthetic_state_records"],
            cls.manifest["maximums"]["synthetic_queue_depth"],
        )

    def evaluate(self, fixture=None, benchmark=None):
        return experiment.evaluate_fixture(
            fixture if fixture is not None else copy.deepcopy(self.fixture),
            self.manifest,
            benchmark if benchmark is not None else copy.deepcopy(self.benchmark),
        )

    def mutate(self, path, value):
        fixture = copy.deepcopy(self.fixture)
        target = fixture
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = value
        return fixture

    def assert_gate_fails(self, gate_id, fixture=None, benchmark=None):
        result = self.evaluate(fixture, benchmark)
        checks = {check["id"]: check["passed"] for check in result["gates"]}
        self.assertIn(gate_id, checks)
        self.assertFalse(checks[gate_id])
        self.assertIn(result["status"], {"FAIL", "KILLED"})

    def assert_killed_by(self, kill_id, fixture):
        result = self.evaluate(fixture)
        checks = {check["id"]: check["passed"] for check in result["kill_rules"]}
        self.assertEqual(result["status"], "KILLED")
        self.assertIn(kill_id, checks)
        self.assertFalse(checks[kill_id])

    def test_registered_manifest_is_closed_experimental_and_non_production(self):
        manifest = self.manifest
        self.assertEqual(manifest["experiment_id"], "E-WWM-23")
        self.assertEqual(manifest["contract_identity"], "noos/wwm-web-capacity/v1")
        self.assertEqual(manifest["status"], "EXPERIMENTAL_OFF_CHAIN")
        self.assertEqual(manifest["minimums"]["synthetic_sessions"], 1_000_000)
        self.assertEqual(manifest["minimums"]["share_files"], 5_448 * 3)
        self.assertEqual(manifest["maximums"]["base_chain_p95_degradation_bps"], 500)
        self.assertEqual(manifest["minimums"]["control_clusters"], 5)
        self.assertEqual(
            manifest["maximums"]["control_cluster_concentration_bps"], 2500
        )
        self.assertEqual(
            manifest["promotion_order"],
            [
                "LOCAL_DETERMINISTIC_FIXTURE",
                "HOSTED_MODEL_DEVNET_PROOF",
                "MULTI_ORIGIN_WEB_CAPACITY_DEVNET",
                "OPT_IN_TESTNET_PILOT",
                "STATIC_OPERATOR_NORMAL_CUSTODIAN_ADMISSION",
                "BROWSER_ADVISORY_REMAINS_NON_CUSTODIAL",
            ],
        )
        self.assertTrue(all(value is False for value in manifest["participant_boundaries"].values()))
        registry = json.loads((ROOT / "protocol" / "claims" / "wwm-experiments.json").read_text(encoding="utf-8"))
        policy = next(item for item in registry["claim_policies"] if item["claim_id"] == "E-WWM-23")
        self.assertTrue(policy["second_client_vectors_required"])
        self.assertEqual(policy["minimum_independent_builders"], 2)
        self.assertTrue(policy["red_team_required"])
        self.assertEqual(set(policy["required_drills"]), set(manifest["required_drills"]))

    def test_qualifying_lab_fixture_passes_every_simulation_gate_but_not_real_duration(self):
        result = self.evaluate()
        self.assertEqual(result["status"], "LAB_PASS_REAL_PILOT_PENDING")
        checks = {check["id"]: check["passed"] for check in result["gates"]}
        self.assertFalse(checks["real-duration"])
        self.assertTrue(all(passed for gate_id, passed in checks.items() if gate_id != "real-duration"))
        self.assertTrue(all(check["passed"] for check in result["kill_rules"]))
        self.assertEqual([check["id"] for check in result["gates"]], self.manifest["gate_ids"])
        self.assertEqual([check["id"] for check in result["kill_rules"]], self.manifest["kill_rule_ids"])
        duration = next(check for check in result["gates"] if check["id"] == "real-duration")
        self.assertEqual(duration["evidence_class"], "REAL_PUBLIC_PILOT_REQUIRED")
        self.assertTrue(
            all(check["evidence_class"] == experiment.EVIDENCE_SCOPE for check in result["gates"] if check["id"] != "real-duration")
        )
        self.assertTrue(all(check["evidence_class"] == experiment.EVIDENCE_SCOPE for check in result["kill_rules"]))
        placement = result["metrics"]["simulated_placement"]
        self.assertEqual(placement["coordinate_count"], 5_448)
        self.assertEqual(placement["share_file_count"], 16_344)
        self.assertEqual(placement["reconstructible_stripes"], 454)
        self.assertGreaterEqual(placement["minimum_surviving_positions_per_stripe"], 8)

    def test_each_registered_gate_rejects_a_plausible_violation(self):
        cases = {
            "registered-identity": self.mutate(("promotion_authorized",), True),
            # A deterministic lab fixture can never satisfy "real-duration".
            "static-origin-diversity": {**copy.deepcopy(self.fixture), "static_hosts": copy.deepcopy(self.fixture["static_hosts"][:29])},
            "explicit-cross-browser-opt-ins": self.mutate(("browser_cohorts", 0, "explicit_opt_ins"), 0),
            "zero-pre-opt-in-activity": self.mutate(("activity_before_opt_in", "artifact_downloads"), 1),
            "privacy-telemetry-retention": self.mutate(
                ("privacy_controls", "raw_participant_tokens_in_telemetry"), 1
            ),
            "browser-restore-observed": self.mutate(("browser_controls", "restore_successes"), 119),
            "advisory-reporting": self.mutate(("browser_controls", "reported_disposition"), experiment.SIMULATED_ADVISORY),
            "base-chain-p95-isolation": self.mutate(("base_chain", "stressed_p95_us"), 105_000),
        }
        two_provider_fixture = copy.deepcopy(self.fixture)
        for index, host in enumerate(two_provider_fixture["static_hosts"]):
            host["provider"] = f"provider-{index % 2}"
        cases["triple-coordinate-coverage"] = two_provider_fixture
        cases["largest-provider-loss-reconstruction"] = self.mutate(
            ("reconstruction", "reconstructed_source_sha256"), "0" * 64
        )
        cases["zero-production-effects"] = self.mutate(("production_effects", "custody_rewards"), 1)
        cases["outage-isolation"] = self.mutate(("isolation", "coordinator_outage_base_chain_continues"), False)
        short_benchmark = copy.deepcopy(self.benchmark)
        short_benchmark["session_count"] = 999_999
        short_benchmark["event_counts"]["heartbeat"] -= 1
        for gate_id, fixture in cases.items():
            with self.subTest(gate=gate_id):
                self.assert_gate_fails(gate_id, fixture)
        self.assert_gate_fails("bounded-synthetic-million", benchmark=short_benchmark)

    def test_every_required_drill_is_enforced(self):
        for drill in self.manifest["required_drills"]:
            with self.subTest(drill=drill):
                fixture = self.mutate(("drills", drill), False)
                self.assert_gate_fails("required-failure-drills", fixture)

    def test_cross_browser_gate_requires_each_browser_device_storage_and_total(self):
        dimensions = (
            ("browser", "WebKit"),
            ("device_mode", "mobile"),
            ("storage_mode", "IndexedDB"),
        )
        for field, missing in dimensions:
            fixture = copy.deepcopy(self.fixture)
            for cohort in fixture["browser_cohorts"]:
                if cohort[field] == missing:
                    cohort["explicit_opt_ins"] = 0
            with self.subTest(field=field, missing=missing):
                self.assert_gate_fails("explicit-cross-browser-opt-ins", fixture)
        fixture = copy.deepcopy(self.fixture)
        fixture["browser_cohorts"][0]["explicit_opt_ins"] -= 1
        self.assert_gate_fails("explicit-cross-browser-opt-ins", fixture)

    def test_cross_browser_gate_rejects_missing_and_duplicate_exact_cells(self):
        missing = copy.deepcopy(self.fixture)
        removed = missing["browser_cohorts"].pop(0)
        replacement = missing["browser_cohorts"][0]
        for field in (
            "explicit_opt_ins",
            "deletion_attempts",
            "deletion_successes",
            "offline_deletion_attempts",
            "offline_deletion_successes",
        ):
            replacement[field] += removed[field]
        self.assertEqual(
            sum(row["explicit_opt_ins"] for row in missing["browser_cohorts"]), 300
        )
        self.assert_gate_fails("explicit-cross-browser-opt-ins", missing)

        duplicate = copy.deepcopy(self.fixture)
        duplicate_row = copy.deepcopy(duplicate["browser_cohorts"][0])
        for field in (
            "explicit_opt_ins",
            "deletion_attempts",
            "deletion_successes",
            "offline_deletion_attempts",
            "offline_deletion_successes",
        ):
            duplicate_row[field] = 0
        duplicate["browser_cohorts"].append(duplicate_row)
        self.assertEqual(
            sum(row["explicit_opt_ins"] for row in duplicate["browser_cohorts"]), 300
        )
        self.assert_gate_fails("explicit-cross-browser-opt-ins", duplicate)

    def test_quota_egress_and_offline_deletion_guarantees_are_independent(self):
        cases = (
            self.mutate(("browser_controls", "quota_overruns"), 1),
            self.mutate(("browser_controls", "egress_cap_overruns"), 1),
            self.mutate(("browser_controls", "deletion_successes"), 299),
            self.mutate(("browser_controls", "offline_deletion_successes"), 299),
            self.mutate(("browser_cohorts", 0, "deletion_successes"), 24),
            self.mutate(("browser_cohorts", 0, "offline_deletion_successes"), 24),
        )
        for fixture in cases:
            with self.subTest(fixture=fixture["browser_controls"]):
                self.assert_gate_fails("quota-egress-deletion", fixture)

    def test_every_invalid_share_class_is_rejected(self):
        for field in (
            "corrupt_admitted",
            "wrong_artifact_admitted",
            "replayed_admitted",
            "wrong_length_admitted",
            "wrong_origin_admitted",
        ):
            with self.subTest(field=field):
                fixture = self.mutate(("share_admission", field), 1)
                self.assert_gate_fails("invalid-share-rejection", fixture)
                self.assert_killed_by("kill-corrupt-share-or-reconstruction-failure", fixture)

    def test_every_production_effect_must_remain_zero(self):
        for field in (
            "custodian_memberships",
            "availability_certificate_signatures",
            "schedulability_contributions",
            "custody_rewards",
        ):
            with self.subTest(field=field):
                self.assert_gate_fails("zero-production-effects", self.mutate(("production_effects", field), 1))
        self.assert_gate_fails("zero-production-effects", self.mutate(("production_effects", "production_custody"), True))

    def test_every_outage_continuity_observation_is_required(self):
        fields = (
            "coordinator_outage_base_chain_continues",
            "coordinator_outage_existing_inference_continues",
            "artifact_outage_base_chain_continues",
            "artifact_outage_existing_inference_continues",
        )
        for field in fields:
            with self.subTest(field=field):
                self.assert_gate_fails("outage-isolation", self.mutate(("isolation", field), False))

    def test_license_notice_and_concentration_gate_rejects_each_failure(self):
        for field in ("license_ok", "notice_ok", "hosting_terms_ok"):
            with self.subTest(field=field):
                fixture = self.mutate(("static_hosts", 0, field), False)
                self.assert_gate_fails("license-notice-concentration", fixture)
        concentrated = copy.deepcopy(self.fixture)
        for index, host in enumerate(concentrated["static_hosts"]):
            host["provider"] = "provider-0" if index < 26 else f"provider-{index - 25}"
        self.assert_gate_fails("license-notice-concentration", concentrated)

    def test_control_cluster_diversity_and_concentration_are_enforced(self):
        missing = copy.deepcopy(self.fixture)
        missing["static_hosts"][0].pop("control_cluster")
        self.assert_gate_fails("static-origin-diversity", missing)
        self.assert_gate_fails("license-notice-concentration", missing)

        concentrated = copy.deepcopy(self.fixture)
        for index, host in enumerate(concentrated["static_hosts"]):
            host["control_cluster"] = (
                "control-cluster-0"
                if index < 26
                else f"control-cluster-{index - 25}"
            )
        self.assert_gate_fails("license-notice-concentration", concentrated)

    def test_each_review_failure_kills_experiment(self):
        for review in ("licensing", "hosting_terms", "privacy", "accessibility", "security"):
            with self.subTest(review=review):
                fixture = self.mutate(("reviews", review), False)
                self.assert_gate_fails("review-approvals", fixture)
                self.assert_killed_by("kill-legal-privacy-accessibility-security", fixture)

    def test_privacy_telemetry_and_access_log_bounds_are_enforced(self):
        cases = (
            self.mutate(("privacy_controls", "raw_participant_tokens_in_telemetry"), 1),
            self.mutate(("privacy_controls", "raw_ips_in_telemetry"), 1),
            self.mutate(("privacy_controls", "raw_user_agents_in_telemetry"), 1),
            self.mutate(("privacy_controls", "access_log_retention_days"), 8),
            self.mutate(("privacy_controls", "truncated_ip_only"), False),
            self.mutate(("privacy_controls", "coarse_user_agent_only"), False),
        )
        for fixture in cases:
            with self.subTest(privacy=fixture["privacy_controls"]):
                self.assert_gate_fails("privacy-telemetry-retention", fixture)
                self.assert_killed_by("kill-legal-privacy-accessibility-security", fixture)

    def test_each_consent_kill_condition_is_enforced(self):
        for field in ("covert_enrollments", "misleading_consent_events"):
            with self.subTest(field=field):
                self.assert_killed_by(
                    "kill-covert-or-misleading-consent",
                    self.mutate(("browser_controls", field), 1),
                )

    def test_each_deletion_or_quota_bypass_kill_condition_is_enforced(self):
        cases = (
            self.mutate(("browser_controls", "deletion_successes"), 299),
            self.mutate(("browser_controls", "offline_deletion_successes"), 299),
            self.mutate(("browser_controls", "quota_bypass_events"), 1),
            self.mutate(("browser_controls", "quota_overruns"), 1),
            self.mutate(("browser_controls", "egress_cap_overruns"), 1),
        )
        for fixture in cases:
            with self.subTest(controls=fixture["browser_controls"]):
                self.assert_killed_by("kill-incomplete-deletion-or-quota-bypass", fixture)

    def test_each_hidden_work_or_identifier_kill_condition_is_enforced(self):
        for field in ("hidden_background_events", "cross_site_identifier_events"):
            with self.subTest(field=field):
                self.assert_killed_by(
                    "kill-hidden-work-or-cross-site-identity",
                    self.mutate(("browser_controls", field), 1),
                )

    def test_unauthorized_hosting_kills_experiment(self):
        self.assert_killed_by(
            "kill-unauthorized-hosting",
            self.mutate(("static_hosts", 0, "authorized"), False),
        )
        self.assert_killed_by(
            "kill-unauthorized-hosting",
            self.mutate(("browser_controls", "unauthorized_hosting_events"), 1),
        )

    def test_every_false_public_claim_kills_experiment(self):
        for field in ("production_availability", "mainnet_ready", "millions_of_real_websites"):
            with self.subTest(field=field):
                self.assert_killed_by("kill-false-production-claim", self.mutate(("claims", field), True))
        self.assert_killed_by(
            "kill-false-production-claim",
            self.mutate(("claims", "scope"), "REAL_PUBLIC_PILOT"),
        )

    def test_unavailable_model_must_never_remain_schedulable(self):
        self.assert_killed_by(
            "kill-unavailable-remains-schedulable",
            self.mutate(("claims", "unavailable_model_schedulable"), True),
        )

    def test_reconstruction_failure_kills_experiment(self):
        self.assert_killed_by(
            "kill-corrupt-share-or-reconstruction-failure",
            self.mutate(("reconstruction", "reconstructed_source_sha256"), "f" * 64),
        )

    def test_five_percent_base_chain_degradation_is_a_strict_kill_threshold(self):
        fixture = self.mutate(("base_chain", "stressed_p95_us"), 105_000)
        self.assert_killed_by("kill-base-chain-degradation", fixture)

    def test_unbounded_state_queue_and_correctness_dependencies_each_kill(self):
        for field in ("bounded_queue", "bounded_state"):
            with self.subTest(field=field):
                self.assert_killed_by(
                    "kill-unbounded-or-correctness-dependency",
                    self.mutate(("isolation", field), False),
                )
        for field in ("coordinator_consensus_dependency", "coordinator_inference_correctness_dependency"):
            with self.subTest(field=field):
                self.assert_killed_by(
                    "kill-unbounded-or-correctness-dependency",
                    self.mutate(("isolation", field), True),
                )

    def test_simulated_browser_availability_is_always_demoted_not_overclaimed(self):
        fixture = self.mutate(("browser_controls", "simulated_availability_bps"), 9_999)
        fixture["browser_controls"]["reported_disposition"] = experiment.LOCAL_CACHE_ONLY
        result = self.evaluate(fixture)
        self.assertEqual(result["status"], "LAB_PASS_REAL_PILOT_PENDING")
        self.assertEqual(result["browser_disposition"], experiment.LOCAL_CACHE_ONLY)
        fixture["browser_controls"]["reported_disposition"] = experiment.SIMULATED_ADVISORY
        self.assert_killed_by("kill-advisory-overclaim", fixture)

    def test_million_session_benchmark_is_measured_bounded_and_deterministic(self):
        benchmark = self.benchmark
        self.assertEqual(benchmark["session_count"], 1_000_000)
        self.assertEqual(sum(benchmark["event_counts"].values()), 1_000_000)
        self.assertLessEqual(benchmark["peak_state_records"], 4_096)
        self.assertLessEqual(benchmark["peak_queue_depth"], 256)
        self.assertGreater(benchmark["measured_duration_ns"], 0)
        self.assertGreater(benchmark["measured_sessions_per_second"], 0)
        self.assertEqual(
            benchmark["runtime_measurement_class"], "NONDETERMINISTIC_WALL_CLOCK"
        )
        rerun = experiment.simulate_sessions(10_000, 4_096, 256)
        rerun_again = experiment.simulate_sessions(10_000, 4_096, 256)
        for field in (
            "event_counts",
            "rolling_checksum",
            "simulation_sha256",
            "peak_state_records",
            "peak_queue_depth",
        ):
            self.assertEqual(rerun[field], rerun_again[field])

    def test_report_is_canonical_hashed_and_never_authorizes_promotion(self):
        report = experiment.build_report(copy.deepcopy(self.fixture), self.manifest, copy.deepcopy(self.benchmark))
        evidence_hash = report.pop("evidence_sha256")
        self.assertEqual(evidence_hash, experiment.canonical_sha256(report))
        report["evidence_sha256"] = evidence_hash
        self.assertEqual(report["status"], "LAB_PASS_REAL_PILOT_PENDING")
        self.assertFalse(report["production_claim"])
        self.assertFalse(report["promotion_authorized"])
        self.assertTrue(any("not evidence of a real 30-day" in item for item in report["limitations"]))
        metrics = report["metrics"]
        self.assertEqual(metrics["simulated_observation_days"], 0)
        self.assertEqual(metrics["required_real_pilot_duration_days"], 30)
        self.assertNotIn("origins", metrics)
        self.assertNotIn("placement", metrics)
        self.assertTrue(
            all(
                key.startswith("simulated_")
                or key in {"required_real_pilot_duration_days", "real_observation_days"}
                for key in metrics
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            experiment.write_report(path, report)
            self.assertEqual(path.read_bytes(), experiment.canonical_bytes(report))
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), report)


if __name__ == "__main__":
    unittest.main()
