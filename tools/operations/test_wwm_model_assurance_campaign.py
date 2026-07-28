from __future__ import annotations

import base64
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tools.operations import wwm_model_assurance_campaign as campaign


REVISION = "ab" * 20
NOW = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)


class ModelAssuranceCampaignTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.owner_seed = bytes.fromhex("01" * 32)
        self.result_seed = self.owner_seed

    @staticmethod
    def model() -> dict[str, object]:
        return {
            "parameter_count": campaign.REGISTERED_PARAMETERS,
            "source_checkpoint_root": "11" * 32,
            "weight_manifest_root": "12" * 32,
            "tokenizer_root": "13" * 32,
            "numeric_profile_id": "14" * 32,
            "runtime_root": "15" * 32,
        }

    @staticmethod
    def participant(
        index: int,
        *,
        role: str,
        platform: str,
        region: str,
        organization: str | None = None,
        lineage: str | None = None,
    ) -> tuple[dict[str, object], bytes]:
        seed = index.to_bytes(32, "big")
        private = Ed25519PrivateKey.from_private_bytes(seed)
        public = private.public_key().public_bytes_raw()
        return (
            {
                "participant_id": f"participant-{index}",
                "organization_id": organization or f"organization-{index}",
                "role": role,
                "region": region,
                "platform": platform,
                "implementation_lineage": lineage or f"lineage-{index}",
                "adapter_sha256": hashlib.sha256(f"adapter-{index}".encode()).hexdigest(),
                "funded": True,
                "key_id": hashlib.sha256(public).hexdigest(),
                "public_key_base64": base64.b64encode(public).decode("ascii"),
            },
            seed,
        )

    def freeze(
        self,
        kind: str,
        participants: list[dict[str, object]],
        configuration: dict[str, object],
        *,
        start: datetime = datetime(2026, 1, 1, tzinfo=timezone.utc),
        end: datetime = datetime(2026, 1, 2, tzinfo=timezone.utc),
    ) -> dict[str, object]:
        draft = {
            "kind": kind,
            "source_revision": REVISION,
            "release_version": f"0.1.0+git.{REVISION}",
            "production": False,
            "promotion_effect": "NONE",
            "started_at_utc": campaign.format_utc(start),
            "ends_at_utc": campaign.format_utc(end),
            "model": self.model(),
            "participants": participants,
            "configuration": configuration,
        }
        return campaign.freeze_campaign(draft, self.owner_seed, now=NOW)

    @staticmethod
    def artifacts(index: int) -> dict[str, str]:
        return {
            "raw_log_sha256": hashlib.sha256(f"raw-{index}".encode()).hexdigest(),
            "environment_manifest_sha256": hashlib.sha256(f"environment-{index}".encode()).hexdigest(),
            "result_artifact_sha256": hashlib.sha256(f"result-{index}".encode()).hexdigest(),
        }

    def write_report(
        self,
        directory: Path,
        campaign_document: dict[str, object],
        participant_id: str,
        seed: bytes,
        index: int,
        metrics: dict[str, object],
        *,
        start: datetime,
        end: datetime | None = None,
    ) -> Path:
        draft = {
            "observed_start_utc": campaign.format_utc(start),
            "observed_end_utc": campaign.format_utc(end or start),
            "artifacts": self.artifacts(index),
            "metrics": metrics,
        }
        report = campaign.sign_report(
            campaign_document,
            participant_id,
            draft,
            seed,
            now=NOW,
        )
        path = directory / f"{index:05d}.json"
        campaign.atomic_write(path, report)
        return path

    @staticmethod
    def cross_vendor_configuration() -> dict[str, object]:
        return {
            "vector_manifest_sha256": "21" * 32,
            "required_operators": sorted(campaign.REQUIRED_OPERATORS),
            "minimum_operator_instances_per_implementation": campaign.MINIMUM_OPERATOR_INSTANCES,
            "minimum_cpu_lineages": 2,
            "required_platforms": ["amd", "cpu", "nvidia"],
        }

    @staticmethod
    def custody_configuration() -> dict[str, object]:
        return {
            "minimum_custodians": 5,
            "minimum_regions": 3,
            "minimum_duration_seconds": campaign.MINIMUM_CUSTODY_DURATION_SECONDS,
            "minimum_retrieval_success_ppm": 999_000,
            "required_fault_classes": sorted(campaign.CUSTODY_FAULTS),
            "weight_shard_min_bytes": 4 * 1024 * 1024,
            "weight_shard_max_bytes": 16 * 1024 * 1024,
        }

    @staticmethod
    def dispute_configuration() -> dict[str, object]:
        return {
            "tree_depth": 32,
            "required_fault_classes": sorted(campaign.DISPUTE_FAULTS),
            "minimum_honest_chunks": campaign.MINIMUM_HONEST_CHUNKS,
            "terminal_max_seconds": 6 * 60 * 60,
            "expected_rounds": 19,
            "round_tolerance": 1,
            "expected_transactions": 40,
            "transaction_tolerance": 2,
            "expected_transcript_bytes": 8_100,
            "transcript_byte_tolerance": 1_024,
        }

    @staticmethod
    def latency_configuration() -> dict[str, object]:
        return {
            "concurrency_levels": sorted(campaign.CONCURRENCY_LEVELS),
            "fault_classes": sorted(campaign.LATENCY_FAULTS),
            "minimum_completion_ppm": 999_000,
            "committed_token_p95_max_ms": 2_000,
            "committed_token_p99_max_ms": 5_000,
            "maximum_consensus_degradation_ppm": 50_000,
        }

    def test_cross_vendor_harness_requires_billion_instance_identical_replays(self) -> None:
        participant_specs = [
            self.participant(11, role="implementation", platform="cpu", region="us-east", lineage="cpu-a"),
            self.participant(12, role="implementation", platform="cpu", region="eu-west", lineage="cpu-b"),
            self.participant(13, role="implementation", platform="amd", region="us-west", lineage="amd-kernel"),
            self.participant(14, role="implementation", platform="nvidia", region="ap-south", lineage="nvidia-kernel"),
        ]
        frozen = self.freeze(
            "CROSS_VENDOR",
            [value for value, _ in participant_specs],
            self.cross_vendor_configuration(),
        )
        reports = self.root / "cross-vendor"
        reports.mkdir()
        operators = sorted(campaign.REQUIRED_OPERATORS)
        quotient, remainder = divmod(campaign.MINIMUM_OPERATOR_INSTANCES, len(operators))
        counts = {operator: quotient for operator in operators}
        counts[operators[0]] += remainder
        paths: list[Path] = []
        for index, (participant, seed) in enumerate(participant_specs):
            paths.append(
                self.write_report(
                    reports,
                    frozen,
                    str(participant["participant_id"]),
                    seed,
                    index,
                    {
                        "segment_id": "31" * 32,
                        "operator_instances": campaign.MINIMUM_OPERATOR_INSTANCES,
                        "operator_counts": counts,
                        "execution_root": "32" * 32,
                        "mismatch_count": 0,
                        "fallback_count": 0,
                        "mismatch_reproducer_count": 0,
                        "vector_count": 50_000,
                    },
                    start=datetime(2026, 1, 1, 1, tzinfo=timezone.utc),
                )
            )
        result = campaign.seal_campaign(frozen, reports, self.result_seed, now=NOW)
        verified = campaign.verify_result(frozen, reports, result, now=NOW)
        self.assertEqual(verified["metrics"]["minimum_operator_instances_per_implementation"], 1_000_000_000)
        self.assertEqual(verified["metrics"]["platforms"], ["amd", "cpu", "nvidia"])
        self.assertEqual(verified["metrics"]["mismatches"], 0)
        with self.assertRaisesRegex(campaign.CampaignError, "campaign authority"):
            campaign.seal_campaign(frozen, reports, bytes.fromhex("02" * 32), now=NOW)

        tampered = json.loads(paths[-1].read_text(encoding="utf-8"))
        tampered["body"]["metrics"]["execution_root"] = "ff" * 32
        paths[-1].write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaisesRegex(campaign.CampaignError, "signature is invalid"):
            campaign.verify_result(frozen, reports, result, now=NOW)

    def test_custody_campaign_requires_every_custodian_day_and_strict_retrieval(self) -> None:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = start + timedelta(days=30)
        participant_specs = [
            self.participant(21 + index, role="custodian", platform="storage", region=("us-east", "eu-west", "ap-south")[index % 3])
            for index in range(5)
        ]
        frozen = self.freeze(
            "CUSTODY",
            [value for value, _ in participant_specs],
            self.custody_configuration(),
            start=start,
            end=end,
        )
        reports = self.root / "custody"
        reports.mkdir()
        paths: list[Path] = []
        report_index = 0
        for participant, seed in participant_specs:
            for day_index in range(30):
                observed = start + timedelta(days=day_index, hours=1)
                paths.append(
                    self.write_report(
                        reports,
                        frozen,
                        str(participant["participant_id"]),
                        seed,
                        report_index,
                        {
                            "day_utc": observed.date().isoformat(),
                            "retrieval_attempts": 1_000,
                            "retrieval_successes": 1_000,
                            "corrupt_shards_observed": 1,
                            "corrupt_shards_rejected": 1,
                            "replayed_shards_observed": 1,
                            "replayed_shards_rejected": 1,
                            "reconstruction_attempts": 1,
                            "reconstruction_successes": 1,
                            "permitted_loss_attempts": 1,
                            "permitted_loss_successes": 1,
                            "false_availability_events": 0,
                            "repair_bytes": 4 * 1024 * 1024,
                            "fault_classes": sorted(campaign.CUSTODY_FAULTS),
                            "maximum_reconstruction_ms": 900,
                        },
                        start=observed,
                    )
                )
                report_index += 1
        result = campaign.seal_campaign(frozen, reports, self.result_seed, now=NOW)
        verified = campaign.verify_result(frozen, reports, result, now=NOW)
        self.assertEqual(verified["metrics"]["covered_days"], 30)
        self.assertEqual(verified["metrics"]["custodians"], 5)
        self.assertEqual(verified["metrics"]["retrieval_success_ppm"], 1_000_000)

        paths[-1].unlink()
        with self.assertRaisesRegex(campaign.CampaignError, "every custodian"):
            campaign.seal_campaign(frozen, reports, self.result_seed, now=NOW)

    def test_dispute_campaign_requires_complete_fault_matrix_and_no_false_slash(self) -> None:
        participant_specs = [
            self.participant(31, role="challenger", platform="challenger", region="us-east"),
            self.participant(32, role="challenger", platform="challenger", region="eu-west"),
        ]
        frozen = self.freeze(
            "DISPUTE",
            [value for value, _ in participant_specs],
            self.dispute_configuration(),
        )
        reports = self.root / "disputes"
        reports.mkdir()
        report_bodies: list[dict[str, object]] = []
        index = 0
        for fault in sorted(campaign.DISPUTE_FAULTS):
            for mode in ("honest", "frivolous"):
                participant, seed = participant_specs[index % len(participant_specs)]
                path = self.write_report(
                    reports,
                    frozen,
                    str(participant["participant_id"]),
                    seed,
                    index,
                    {
                        "case_id": hashlib.sha256(f"{fault}:{mode}".encode()).hexdigest(),
                        "fault_class": fault,
                        "challenger_mode": mode,
                        "objective_fault_injected": mode == "honest",
                        "challenge_outcome": "UPHELD" if mode == "honest" else "REJECTED",
                        "honest_chunks": 100_000 if mode == "honest" else 0,
                        "false_slash_count": 0,
                        "rounds": 19,
                        "transactions": 40,
                        "transcript_bytes": 8_100,
                        "terminal_seconds": 3_600,
                        "unrelated_jobs_interrupted": 0,
                        "base_consensus_interrupted": False,
                        "bond_conserved": True,
                        "tail_replay_exact": True,
                    },
                    start=datetime(2026, 1, 1, 2, tzinfo=timezone.utc),
                )
                report_bodies.append(json.loads(path.read_text(encoding="utf-8"))["body"])
                index += 1
        result = campaign.seal_campaign(frozen, reports, self.result_seed, now=NOW)
        verified = campaign.verify_result(frozen, reports, result, now=NOW)
        self.assertEqual(verified["metrics"]["matrix_cases"], 22)
        self.assertEqual(verified["metrics"]["honest_chunks"], 1_100_000)
        self.assertEqual(verified["metrics"]["false_slashes"], 0)

        broken = deepcopy(report_bodies)
        broken[0]["metrics"]["false_slash_count"] = 1
        campaign_body = campaign.validate_campaign(frozen, now=NOW)[0]
        with self.assertRaisesRegex(campaign.CampaignError, "false slash"):
            campaign.aggregate_dispute(campaign_body, broken)

    def test_latency_campaign_recomputes_thresholds_and_consensus_impact(self) -> None:
        participant_specs = [
            self.participant(41, role="committee", platform="committee", region="us-east"),
            self.participant(42, role="committee", platform="committee", region="eu-west"),
            self.participant(43, role="committee", platform="committee", region="ap-south"),
        ]
        frozen = self.freeze(
            "LATENCY",
            [value for value, _ in participant_specs],
            self.latency_configuration(),
        )
        reports = self.root / "latency"
        reports.mkdir()
        report_bodies: list[dict[str, object]] = []
        index = 0
        for participant, seed in participant_specs:
            for concurrency in sorted(campaign.CONCURRENCY_LEVELS):
                for fault in sorted(campaign.LATENCY_FAULTS):
                    path = self.write_report(
                        reports,
                        frozen,
                        str(participant["participant_id"]),
                        seed,
                        index,
                        {
                            "cell_id": hashlib.sha256(f"{participant['participant_id']}:{concurrency}:{fault}".encode()).hexdigest(),
                            "concurrency": concurrency,
                            "fault_class": fault,
                            "jobs_admitted": 1_000,
                            "jobs_completed": 1_000,
                            "false_assured": 0,
                            "committed_token_latency_ms": [100, 250, 900, 1_500],
                            "ttft_ms": [200, 500, 1_000],
                            "elapsed_ms": 10_000,
                            "tokens_committed": 20_000,
                            "maximum_memory_bytes": 8 * 1024 * 1024 * 1024,
                            "evidence_bytes": 64_000,
                            "queue_drops": 0,
                            "refunds": 2 if fault != "baseline" else 0,
                            "base_finality_p95_baseline_ms": 1_000,
                            "base_finality_p95_loaded_ms": 1_049,
                            "transaction_p95_baseline_ms": 800,
                            "transaction_p95_loaded_ms": 839,
                        },
                        start=datetime(2026, 1, 1, 3, tzinfo=timezone.utc),
                    )
                    report_bodies.append(json.loads(path.read_text(encoding="utf-8"))["body"])
                    index += 1
        result = campaign.seal_campaign(frozen, reports, self.result_seed, now=NOW)
        verified = campaign.verify_result(frozen, reports, result, now=NOW)
        metrics = verified["metrics"]
        self.assertEqual(metrics["matrix_cells"], 60)
        self.assertEqual(metrics["completion_ppm"], 1_000_000)
        self.assertEqual(metrics["committed_token_p95_ms"], 1_500)
        self.assertLess(metrics["maximum_consensus_degradation_ppm"], 50_000)

        broken = deepcopy(report_bodies)
        broken[0]["metrics"]["base_finality_p95_loaded_ms"] = 1_050
        campaign_body = campaign.validate_campaign(frozen, now=NOW)[0]
        with self.assertRaisesRegex(campaign.CampaignError, "at least five percent"):
            campaign.aggregate_latency(campaign_body, broken)

    def test_preregistration_rejects_weakened_thresholds_and_future_sealing(self) -> None:
        participant, _ = self.participant(
            51,
            role="implementation",
            platform="cpu",
            region="us-east",
        )
        weak = self.cross_vendor_configuration()
        weak["minimum_operator_instances_per_implementation"] = 999_999_999
        with self.assertRaisesRegex(campaign.CampaignError, "one billion"):
            self.freeze("CROSS_VENDOR", [participant], weak)

        valid_participants = [
            self.participant(61, role="implementation", platform="cpu", region="us-east", lineage="cpu-a"),
            self.participant(62, role="implementation", platform="cpu", region="eu-west", lineage="cpu-b"),
            self.participant(63, role="implementation", platform="amd", region="us-west", lineage="amd"),
            self.participant(64, role="implementation", platform="nvidia", region="ap-south", lineage="nvidia"),
        ]
        future_end = NOW + timedelta(days=1)
        frozen = self.freeze(
            "CROSS_VENDOR",
            [value for value, _ in valid_participants],
            self.cross_vendor_configuration(),
            start=NOW - timedelta(hours=1),
            end=future_end,
        )
        reports = self.root / "future"
        reports.mkdir()
        with self.assertRaisesRegex(campaign.CampaignError, "before its frozen end"):
            campaign.seal_campaign(frozen, reports, self.result_seed, now=NOW)


if __name__ == "__main__":
    unittest.main()
