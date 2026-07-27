from __future__ import annotations

import copy
import unittest

import check_throughput as gate


WORKLOAD = {"transactions": 10_000, "workload_blake3": "11" * 32}
COMMITMENT = {"accounts_root": "22" * 32, "receipts_root": "33" * 32}


def report(tps: float, authorization: str, root_share: float = 0.05) -> dict:
    state_seconds = 1.0
    return {
        "environment": {"release_build": True, "authorization": authorization},
        "workload": copy.deepcopy(WORKLOAD),
        "state_commitment": copy.deepcopy(COMMITMENT),
        "result": {
            "applied": 10_000,
            "failed": 0,
            "state_transition_tps": tps,
            "state_transition_seconds": state_seconds,
            "root_materialization_seconds": root_share * state_seconds,
        },
    }


def internal_report(
    rate: float = 250_000_000,
    duration: float = 1.0,
    commitment: str = "44" * 32,
) -> dict:
    equivalents = 4_294_967_296
    return {
        "schema": "noos/internal-transfer-equivalent-benchmark/v1",
        "metric": "logical_transfer_equivalents_per_second",
        "claim": {"network_tps": False, "protocol_transactions": False},
        "environment": {
            "release_build": True,
            "authorization": "none-accounting-kernel-only",
        },
        "workload": {
            "kind": "deterministic-netted-transfer-accounting",
            "logical_transfer_equivalents": equivalents,
            "accounts": 65_536,
            "workload_blake3": "55" * 32,
        },
        "result": {
            "processed": equivalents,
            "failed": 0,
            "execution_seconds": duration,
            "logical_transfer_equivalents_per_second": rate,
            "conservation_verified": True,
            "all_account_deltas_zero": True,
            "total_account_delta": "0",
        },
        "state_commitment": {"kernel_root": commitment},
    }

class ThroughputGateTests(unittest.TestCase):
    def evaluate(self, validator: list[dict], producer: list[dict]) -> dict:
        return gate.evaluate_reports(
            validator,
            producer,
            10_000,
            minimum_validator_tps=7_500,
            minimum_producer_tps=10_000,
            maximum_root_share=0.15,
            maximum_sample_spread=0.30,
        )

    def test_sustained_medians_pass_with_deterministic_commitments(self) -> None:
        validator = [report(value, "sequential-ed25519-production") for value in (7_800, 8_000, 8_200)]
        producer = [report(value, "parallel-ed25519-production-precheck") for value in (14_000, 15_000, 16_000)]
        observed = self.evaluate(validator, producer)
        self.assertEqual(observed["verdict"], "PASS")
        self.assertEqual(observed["checks"]["validator_median_tps"]["observed"], 8_000)
        self.assertEqual(observed["checks"]["producer_median_tps"]["observed"], 15_000)

    def test_threshold_root_share_and_variance_regressions_fail(self) -> None:
        validator = [report(value, "sequential-ed25519-production", root_share=0.20) for value in (4_000, 7_000, 12_000)]
        producer = [report(value, "parallel-ed25519-production-precheck") for value in (8_000, 9_000, 11_000)]
        observed = self.evaluate(validator, producer)
        self.assertEqual(observed["verdict"], "FAIL")
        self.assertIn("validator_median_tps", observed["failures"])
        self.assertIn("producer_median_tps", observed["failures"])
        self.assertIn("maximum_root_share", observed["failures"])
        self.assertIn("validator_sample_spread", observed["failures"])

    def test_commitment_or_workload_divergence_is_a_hard_error(self) -> None:
        validator = [report(8_000, "sequential-ed25519-production") for _ in range(2)]
        producer = [report(15_000, "parallel-ed25519-production-precheck") for _ in range(2)]
        producer[1]["state_commitment"]["accounts_root"] = "99" * 32
        with self.assertRaisesRegex(gate.ThroughputError, "different commitments"):
            self.evaluate(validator, producer)

    def test_gate_refuses_debug_or_wrong_authorization_paths(self) -> None:
        validator = [report(8_000, "trusted") for _ in range(2)]
        producer = [report(15_000, "parallel-ed25519-production-precheck") for _ in range(2)]
        with self.assertRaisesRegex(gate.ThroughputError, "production authorization"):
            self.evaluate(validator, producer)

    def test_durable_two_node_pipeline_enforces_both_roles(self) -> None:
        samples = []
        for producer, validator in ((9_200, 7_800), (9_600, 8_200)):
            sample = report(0, "mempool-preverified-signatures")
            sample["result"].update({
                "applied": 1_200,
                "pending_after_block": 0,
                "block_pipeline_tps": producer,
                "validator_import_tps": validator,
            })
            samples.append(sample)
        observed = gate.evaluate_durable_reports(samples, 1_200, 9_000, 7_500, 0.30)
        self.assertFalse(observed["failures"])
        self.assertEqual(
            observed["checks"]["durable_producer_median_tps"]["observed"],
            9_400,
        )

    def test_durable_two_node_pipeline_rejects_pending_work(self) -> None:
        sample = report(0, "mempool-preverified-signatures")
        sample["result"].update({
            "applied": 1_199,
            "pending_after_block": 1,
            "block_pipeline_tps": 10_000,
            "validator_import_tps": 9_000,
        })
        with self.assertRaisesRegex(gate.ThroughputError, "complete workload"):
            gate.evaluate_durable_reports([sample], 1_200, 9_000, 7_500, 0.30)


    def test_internal_accounting_gate_passes_only_the_explicit_non_network_metric(self) -> None:
        observed = gate.evaluate_internal_reports(
            [internal_report(250_000_000), internal_report(260_000_000)],
            equivalents=4_294_967_296,
            accounts=65_536,
            minimum_rate=200_000_000,
            minimum_sample_seconds=0.5,
            maximum_sample_spread=0.30,
        )
        self.assertFalse(observed["failures"])
        self.assertEqual(
            observed["checks"]["internal_accounting_median_equivalents_per_second"]["observed"],
            255_000_000,
        )
        self.assertTrue(observed["checks"]["internal_accounting_non_network_claim"]["pass"])

    def test_internal_accounting_gate_rejects_a_network_tps_claim(self) -> None:
        sample = internal_report()
        sample["claim"]["network_tps"] = True
        with self.assertRaisesRegex(gate.ThroughputError, "mislabels"):
            gate.evaluate_internal_reports(
                [sample],
                4_294_967_296,
                65_536,
                200_000_000,
                0.5,
                0.30,
            )

    def test_internal_accounting_gate_rejects_short_samples(self) -> None:
        observed = gate.evaluate_internal_reports(
            [internal_report(duration=0.1), internal_report(duration=0.1)],
            4_294_967_296,
            65_536,
            200_000_000,
            0.5,
            0.30,
        )
        self.assertIn("internal_accounting_minimum_sample_seconds", observed["failures"])

if __name__ == "__main__":
    unittest.main()
