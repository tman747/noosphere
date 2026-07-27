#!/usr/bin/env python3
"""Fail closed when deterministic state or durable two-node throughput regresses."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import math
import statistics
import subprocess
import sys
import tempfile
from typing import Any


class ThroughputError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def run_sample(
    binary: Path,
    transactions: int,
    accounts: int,
    batch_size: int,
    preverified: bool,
    output: Path,
    params: Path | None,
    pipeline: str = "state",
) -> dict[str, Any]:
    command = [
        str(binary),
        "--transactions", str(transactions),
        "--accounts", str(accounts),
        "--batch-size", str(batch_size),
        "--output", str(output),
    ]
    if pipeline != "state":
        command.extend(("--pipeline", pipeline))
    if preverified:
        command.append("--preverified-signatures")
    if params is not None:
        command.extend(("--params", str(params)))
    completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ThroughputError(f"benchmark process failed: {detail}")
    try:
        report = json.loads(output.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ThroughputError(f"benchmark report unavailable: {error}") from error
    if not isinstance(report, dict):
        raise ThroughputError("benchmark report is not a JSON object")
    return report

def run_internal_sample(
    binary: Path,
    equivalents: int,
    accounts: int,
    threads: int | None,
    output: Path,
) -> dict[str, Any]:
    command = [
        str(binary),
        "--pipeline", "internal-accounting",
        "--transactions", str(equivalents),
        "--accounts", str(accounts),
        "--output", str(output),
    ]
    if threads is not None:
        command.extend(("--threads", str(threads)))
    completed = subprocess.run(command, capture_output=True, text=True, timeout=300)
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise ThroughputError(f"internal benchmark process failed: {detail}")
    try:
        report = json.loads(output.read_text("utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ThroughputError(f"internal benchmark report unavailable: {error}") from error
    if not isinstance(report, dict):
        raise ThroughputError("internal benchmark report is not a JSON object")
    return report


def evaluate_reports(
    validator_reports: list[dict[str, Any]],
    producer_reports: list[dict[str, Any]],
    transactions: int,
    minimum_validator_tps: float,
    minimum_producer_tps: float,
    maximum_root_share: float,
    maximum_sample_spread: float,
) -> dict[str, Any]:
    if not validator_reports or len(validator_reports) != len(producer_reports):
        raise ThroughputError("validator and producer sample sets must be non-empty and equal")
    all_reports = validator_reports + producer_reports
    commitments = {canonical_json(report.get("state_commitment")) for report in all_reports}
    workload_hashes = {report.get("workload", {}).get("workload_blake3") for report in all_reports}
    if len(commitments) != 1 or len(workload_hashes) != 1 or None in workload_hashes:
        raise ThroughputError("identical workloads produced different commitments")
    for report in validator_reports:
        environment = report.get("environment", {})
        result = report.get("result", {})
        if (
            environment.get("release_build") is not True
            or environment.get("authorization") != "sequential-ed25519-production"
        ):
            raise ThroughputError(
                "validator sample is not a release build with sequential production authorization"
            )
        if result.get("applied") != transactions or result.get("failed") != 0:
            raise ThroughputError("validator sample did not apply the complete workload")
    for report in producer_reports:
        environment = report.get("environment", {})
        result = report.get("result", {})
        if (
            environment.get("release_build") is not True
            or environment.get("authorization") != "parallel-ed25519-production-precheck"
        ):
            raise ThroughputError(
                "producer sample did not exercise the parallel production precheck path"
            )
        if result.get("applied") != transactions or result.get("failed") != 0:
            raise ThroughputError("producer sample did not apply the complete workload")

    validator_tps = [float(report["result"]["state_transition_tps"]) for report in validator_reports]
    producer_tps = [float(report["result"]["state_transition_tps"]) for report in producer_reports]
    root_shares = [
        float(report["result"]["root_materialization_seconds"])
        / float(report["result"]["state_transition_seconds"])
        for report in all_reports
    ]

    def spread(values: list[float]) -> float:
        median = statistics.median(values)
        return (max(values) - min(values)) / median if median > 0 else float("inf")

    validator_median = statistics.median(validator_tps)
    producer_median = statistics.median(producer_tps)
    checks = {
        "validator_median_tps": {
            "observed": validator_median,
            "minimum": minimum_validator_tps,
            "pass": validator_median >= minimum_validator_tps,
        },
        "producer_median_tps": {
            "observed": producer_median,
            "minimum": minimum_producer_tps,
            "pass": producer_median >= minimum_producer_tps,
        },
        "maximum_root_share": {
            "observed": max(root_shares),
            "maximum": maximum_root_share,
            "pass": max(root_shares) <= maximum_root_share,
        },
        "validator_sample_spread": {
            "observed": spread(validator_tps),
            "maximum": maximum_sample_spread,
            "pass": spread(validator_tps) <= maximum_sample_spread,
        },
        "producer_sample_spread": {
            "observed": spread(producer_tps),
            "maximum": maximum_sample_spread,
            "pass": spread(producer_tps) <= maximum_sample_spread,
        },
        "deterministic_commitment": {"pass": True},
    }
    failures = [name for name, value in checks.items() if not value["pass"]]
    return {
        "schema": "noos/throughput-regression-report/v1",
        "verdict": "PASS" if not failures else "FAIL",
        "failures": failures,
        "checks": checks,
        "samples": {
            "validator_state_tps": validator_tps,
            "producer_state_tps": producer_tps,
            "root_share": root_shares,
        },
        "workload": validator_reports[0]["workload"],
        "state_commitment": validator_reports[0]["state_commitment"],
        "environment": validator_reports[0]["environment"],
    }


def evaluate_durable_reports(
    reports: list[dict[str, Any]],
    transactions: int,
    minimum_producer_tps: float,
    minimum_validator_tps: float,
    maximum_sample_spread: float,
) -> dict[str, Any]:
    if not reports:
        raise ThroughputError("durable block sample set must be non-empty")
    commitments = {canonical_json(report.get("state_commitment")) for report in reports}
    workload_hashes = {
        report.get("workload", {}).get("workload_blake3") for report in reports
    }
    if len(commitments) != 1 or len(workload_hashes) != 1 or None in workload_hashes:
        raise ThroughputError("durable block samples produced different commitments")
    for report in reports:
        result = report.get("result", {})
        environment = report.get("environment", {})
        if environment.get("release_build") is not True:
            raise ThroughputError("durable block sample is not a release build")
        if result.get("applied") != transactions or result.get("failed") != 0:
            raise ThroughputError("durable block sample did not settle the complete workload")
        if result.get("pending_after_block") != 0:
            raise ThroughputError("durable block sample left transactions pending")
    producer = [float(report["result"]["block_pipeline_tps"]) for report in reports]
    validator = [float(report["result"]["validator_import_tps"]) for report in reports]

    def spread(values: list[float]) -> float:
        median = statistics.median(values)
        return (max(values) - min(values)) / median if median > 0 else float("inf")

    checks = {
        "durable_producer_median_tps": {
            "observed": statistics.median(producer),
            "minimum": minimum_producer_tps,
            "pass": statistics.median(producer) >= minimum_producer_tps,
        },
        "durable_validator_median_tps": {
            "observed": statistics.median(validator),
            "minimum": minimum_validator_tps,
            "pass": statistics.median(validator) >= minimum_validator_tps,
        },
        "durable_producer_sample_spread": {
            "observed": spread(producer),
            "maximum": maximum_sample_spread,
            "pass": spread(producer) <= maximum_sample_spread,
        },
        "durable_validator_sample_spread": {
            "observed": spread(validator),
            "maximum": maximum_sample_spread,
            "pass": spread(validator) <= maximum_sample_spread,
        },
        "durable_commitment": {"pass": True},
    }
    return {
        "checks": checks,
        "failures": [name for name, value in checks.items() if not value["pass"]],
        "samples": {
            "durable_producer_tps": producer,
            "durable_validator_tps": validator,
        },
    }

def evaluate_internal_reports(
    reports: list[dict[str, Any]],
    equivalents: int,
    accounts: int,
    minimum_rate: float,
    minimum_sample_seconds: float,
    maximum_sample_spread: float,
) -> dict[str, Any]:
    if not reports:
        raise ThroughputError("internal accounting sample set must be non-empty")
    commitments = {canonical_json(report.get("state_commitment")) for report in reports}
    workload_hashes = {
        report.get("workload", {}).get("workload_blake3") for report in reports
    }
    if len(commitments) != 1 or len(workload_hashes) != 1 or None in workload_hashes:
        raise ThroughputError("internal accounting samples produced different commitments")
    rates: list[float] = []
    durations: list[float] = []
    for report in reports:
        if (
            report.get("schema") != "noos/internal-transfer-equivalent-benchmark/v1"
            or report.get("metric") != "logical_transfer_equivalents_per_second"
        ):
            raise ThroughputError("internal accounting report has an unsupported metric contract")
        claim = report.get("claim", {})
        if claim.get("network_tps") is not False or claim.get("protocol_transactions") is not False:
            raise ThroughputError("internal accounting report mislabels the kernel as transaction TPS")
        environment = report.get("environment", {})
        if (
            environment.get("release_build") is not True
            or environment.get("authorization") != "none-accounting-kernel-only"
        ):
            raise ThroughputError("internal accounting sample is not a release kernel measurement")
        workload = report.get("workload", {})
        if (
            workload.get("kind") != "deterministic-netted-transfer-accounting"
            or workload.get("logical_transfer_equivalents") != equivalents
            or workload.get("accounts") != accounts
        ):
            raise ThroughputError("internal accounting sample used the wrong workload")
        result = report.get("result", {})
        if (
            result.get("processed") != equivalents
            or result.get("failed") != 0
            or result.get("conservation_verified") is not True
            or result.get("all_account_deltas_zero") is not True
            or result.get("total_account_delta") != "0"
        ):
            raise ThroughputError("internal accounting sample failed exact processing invariants")
        try:
            duration = float(result["execution_seconds"])
            rate = float(result["logical_transfer_equivalents_per_second"])
        except (KeyError, TypeError, ValueError) as error:
            raise ThroughputError("internal accounting sample has malformed measurements") from error
        if not math.isfinite(duration) or not math.isfinite(rate) or duration <= 0 or rate <= 0:
            raise ThroughputError("internal accounting sample has non-finite measurements")
        durations.append(duration)
        rates.append(rate)

    def spread(values: list[float]) -> float:
        median = statistics.median(values)
        return (max(values) - min(values)) / median if median > 0 else float("inf")

    median_rate = statistics.median(rates)
    sample_spread = spread(rates)
    checks = {
        "internal_accounting_median_equivalents_per_second": {
            "observed": median_rate,
            "minimum": minimum_rate,
            "pass": median_rate >= minimum_rate,
        },
        "internal_accounting_minimum_sample_seconds": {
            "observed": min(durations),
            "minimum": minimum_sample_seconds,
            "pass": min(durations) >= minimum_sample_seconds,
        },
        "internal_accounting_sample_spread": {
            "observed": sample_spread,
            "maximum": maximum_sample_spread,
            "pass": sample_spread <= maximum_sample_spread,
        },
        "internal_accounting_deterministic_commitment": {"pass": True},
        "internal_accounting_non_network_claim": {"pass": True},
    }
    return {
        "checks": checks,
        "failures": [name for name, value in checks.items() if not value["pass"]],
        "samples": {
            "internal_accounting_equivalents_per_second": rates,
            "internal_accounting_seconds": durations,
        },
        "workload": reports[0]["workload"],
        "state_commitment": reports[0]["state_commitment"],
        "claim": reports[0]["claim"],
        "environment": reports[0]["environment"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--params", type=Path)
    parser.add_argument("--transactions", type=int, default=10_000)
    parser.add_argument("--accounts", type=int, default=1_024)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--samples", type=int, default=3)
    parser.add_argument("--minimum-validator-tps", type=float, default=7_500)
    parser.add_argument("--durable-transactions", type=int, default=1_200)
    parser.add_argument("--minimum-durable-producer-tps", type=float, default=8_000)
    parser.add_argument("--minimum-durable-validator-tps", type=float, default=7_500)
    parser.add_argument("--minimum-producer-tps", type=float, default=10_000)
    parser.add_argument("--maximum-root-share", type=float, default=0.15)
    parser.add_argument("--maximum-sample-spread", type=float, default=0.30)
    parser.add_argument("--internal-equivalents", type=int, default=0)
    parser.add_argument("--internal-accounts", type=int, default=65_536)
    parser.add_argument("--internal-threads", type=int)
    parser.add_argument(
        "--minimum-internal-equivalents-per-second",
        type=float,
        default=200_000_000,
    )
    parser.add_argument("--minimum-internal-sample-seconds", type=float, default=0.5)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    if (
        not args.binary.is_file()
        or args.transactions < 1
        or args.accounts < 1
        or args.batch_size < 1
        or not 2 <= args.samples <= 10
        or args.minimum_validator_tps <= 0
        or args.durable_transactions < 1
        or args.minimum_durable_producer_tps <= 0
        or args.minimum_durable_validator_tps <= 0
        or args.minimum_producer_tps <= 0
        or not 0 < args.maximum_root_share < 1
        or not 0 < args.maximum_sample_spread < 1
        or args.internal_equivalents < 0
        or (
            args.internal_equivalents > 0
            and (
                args.internal_accounts < 2
                or args.internal_accounts > 65_536
                or args.internal_accounts & (args.internal_accounts - 1) != 0
                or args.internal_equivalents % args.internal_accounts != 0
                or args.minimum_internal_equivalents_per_second <= 0
                or args.minimum_internal_sample_seconds <= 0
                or args.internal_threads is not None
                and not 1 <= args.internal_threads <= 256
            )
        )
    ):
        print("RESULT check_throughput=FAIL reason=invalid option", file=sys.stderr)
        return 1
    try:
        with tempfile.TemporaryDirectory(prefix="noos-throughput-gate-") as temporary:
            root = Path(temporary)
            validator = [
                run_sample(
                    args.binary,
                    args.transactions,
                    args.accounts,
                    args.batch_size,
                    False,
                    root / f"validator-{index}.json",
                    args.params,
                )
                for index in range(args.samples)
            ]
            producer = [
                run_sample(
                    args.binary,
                    args.transactions,
                    args.accounts,
                    args.batch_size,
                    True,
                    root / f"producer-{index}.json",
                    args.params,
                )
                for index in range(args.samples)
            ]
            report = evaluate_reports(
                validator,
                producer,
                args.transactions,
                args.minimum_validator_tps,
                args.minimum_producer_tps,
                args.maximum_root_share,
                args.maximum_sample_spread,
            )
            durable_reports = [
                run_sample(
                    args.binary,
                    args.durable_transactions,
                    args.accounts,
                    args.batch_size,
                    False,
                    root / f"durable-{index}.json",
                    args.params,
                    "durable-block",
                )
                for index in range(args.samples)
            ]
            durable = evaluate_durable_reports(
                durable_reports,
                args.durable_transactions,
                args.minimum_durable_producer_tps,
                args.minimum_durable_validator_tps,
                args.maximum_sample_spread,
            )
            report["checks"].update(durable["checks"])
            report["failures"].extend(durable["failures"])
            report["samples"].update(durable["samples"])
            if args.internal_equivalents > 0:
                internal_reports = [
                    run_internal_sample(
                        args.binary,
                        args.internal_equivalents,
                        args.internal_accounts,
                        args.internal_threads,
                        root / f"internal-{index}.json",
                    )
                    for index in range(args.samples)
                ]
                internal = evaluate_internal_reports(
                    internal_reports,
                    args.internal_equivalents,
                    args.internal_accounts,
                    args.minimum_internal_equivalents_per_second,
                    args.minimum_internal_sample_seconds,
                    args.maximum_sample_spread,
                )
                report["checks"].update(internal["checks"])
                report["failures"].extend(internal["failures"])
                report["samples"].update(internal["samples"])
                report["internal_accounting"] = {
                    "workload": internal["workload"],
                    "state_commitment": internal["state_commitment"],
                    "claim": internal["claim"],
                    "environment": internal["environment"],
                }
            if report["failures"]:
                report["verdict"] = "FAIL"
    except (ThroughputError, OSError, subprocess.SubprocessError) as error:
        report = {
            "schema": "noos/throughput-regression-report/v1",
            "verdict": "FAIL",
            "failures": [str(error)],
            "checks": {},
        }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_bytes(canonical_json(report))
    print(f"RESULT check_throughput={report['verdict']} out={args.out}")
    return 0 if report["verdict"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
