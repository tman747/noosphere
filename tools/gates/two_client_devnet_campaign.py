#!/usr/bin/env python3
"""Run the exact-revision local two-client devnet campaign.

This campaign exercises Rust/Go pairings, production Rust restart and snapshot
paths, proof rejection, wire bounds, WAN recovery, and AI-off base liveness. It
produces local precursor evidence only. A local process matrix cannot establish
two independently managed implementations or satisfy public-duration gates.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Sequence

if __package__:
    from . import cross_language_lab as lab
else:
    import cross_language_lab as lab


SCHEMA = "noos/two-client-devnet-campaign-result/v1"
REQUIRED_PAIRS = {"rust->rust", "rust->go", "go->rust", "go->go"}
SIMULATION_SCENARIOS = {
    "simulation-base-transfer": "base-transfer-contract",
    "simulation-wan": "wan-fault-matrix",
    "simulation-ai-off": "ai-blackout",
    "simulation-crash": "crash-matrix",
    "simulation-client-matrix": "client-matrix",
}
REQUIRED_CONTRACT_LANES = {
    "process-transition-matrix",
    "process-admission-matrix",
    "restart-recovery",
    "snapshot-recovery",
    "proof-rejection",
    "unknown-wire-tag",
    "oversize-rejection",
    "wan-production-controls",
    "ai-off-production-controls",
}


class CampaignError(ValueError):
    pass


def simulation_command(
    scenario: str,
    *,
    seed: int,
    validators: int,
    duration: str,
    tx_load: int,
    simulated_days: int | None = None,
    max_faults: int | None = None,
    pairs: bool = False,
    seed_file: bool = False,
) -> tuple[str, ...]:
    command = [
        "python",
        "tools/e2e/run_network.py",
        "--scenario",
        scenario,
        "--clients",
        "rust,go",
        "--validators",
        str(validators),
        "--duration",
        duration,
        "--tx-load",
        str(tx_load),
    ]
    if seed_file:
        command += ["--seed-file", "protocol/vectors/wan-seeds.txt"]
    else:
        command += ["--seed", str(seed)]
    if simulated_days is not None:
        command += ["--simulated-days", str(simulated_days), "--max-ai-load"]
    if max_faults is not None:
        command += ["--kill-every-fsync-boundary", "--max-faults", str(max_faults)]
    elif scenario == "crash-matrix":
        command += ["--kill-every-fsync-boundary"]
    if pairs:
        command += ["--pairs", "AA,AB,BA,BB"]
    command += [
        "--raw-log-dir",
        "{artifact_root}",
        "--out",
        "{artifact}",
    ]
    return tuple(command)


def campaign_specs(profile: str, seed: int) -> tuple[lab.LaneSpec, ...]:
    if profile not in lab.PROFILES:
        raise CampaignError(f"unknown profile: {profile}")
    qualification = profile == "qualification"
    duration = "90m" if qualification else "6m"
    tx_load = 10_000 if qualification else 64
    transition_cases = 100_000 if qualification else 256
    admission_cases = 10_000 if qualification else 256
    ai_days = 30 if qualification else 1
    crash_faults = None if qualification else 2
    return (
        lab.LaneSpec(
            "simulation-base-transfer",
            "pairing_matrix",
            simulation_command(
                "base-transfer-contract",
                seed=seed,
                validators=4,
                duration=duration,
                tx_load=tx_load,
            ),
            artifact=True,
        ),
        lab.LaneSpec(
            "simulation-wan",
            "wan",
            simulation_command(
                "wan-fault-matrix",
                seed=seed,
                validators=10 if qualification else 4,
                duration=duration,
                tx_load=tx_load,
                seed_file=True,
            ),
            artifact=True,
        ),
        lab.LaneSpec(
            "simulation-ai-off",
            "ai_off",
            simulation_command(
                "ai-blackout",
                seed=seed,
                validators=4,
                duration=duration,
                tx_load=tx_load,
                simulated_days=ai_days,
            ),
            artifact=True,
        ),
        lab.LaneSpec(
            "simulation-crash",
            "restart",
            simulation_command(
                "crash-matrix",
                seed=seed,
                validators=4,
                duration=duration,
                tx_load=tx_load,
                max_faults=crash_faults,
            ),
            artifact=True,
        ),
        lab.LaneSpec(
            "simulation-client-matrix",
            "pairing_matrix",
            simulation_command(
                "client-matrix",
                seed=seed,
                validators=4,
                duration=duration,
                tx_load=tx_load,
                pairs=True,
            ),
            artifact=True,
        ),
        lab.LaneSpec(
            "process-transition-matrix",
            "pairing_matrix",
            (
                "python",
                "tools/gates/differential_transitions.py",
                "--generated",
                str(transition_cases),
                "--parameterized-max",
                "10000000",
                "--seed",
                hex(seed),
                "--restart-every",
                str(max(1, transition_cases // 4)),
            ),
        ),
        lab.LaneSpec(
            "process-admission-matrix",
            "pairing_matrix",
            (
                "python",
                "tools/gates/differential_admission.py",
                "--generated",
                str(admission_cases),
                "--seed",
                hex(seed),
                "--out",
                "{artifact}",
            ),
            artifact=True,
        ),
        lab.LaneSpec(
            "restart-recovery",
            "restart",
            (
                "cargo",
                "test",
                "--locked",
                "-p",
                "noos-node",
                "e2e_happy_path_finality_and_restart_recovery",
                "--",
                "--test-threads=1",
            ),
        ),
        lab.LaneSpec(
            "snapshot-recovery",
            "snapshot",
            (
                "cargo",
                "test",
                "--locked",
                "-p",
                "noos-node",
                "snapshot_sync_assembles_from_multiple_sources_and_recovers_state",
                "--",
                "--test-threads=1",
            ),
        ),
        lab.LaneSpec(
            "proof-rejection",
            "proof",
            (
                "cargo",
                "test",
                "--locked",
                "-p",
                "noos-jet",
                "malformed_receipts_are_rejected",
            ),
        ),
        lab.LaneSpec(
            "unknown-wire-tag",
            "unknown_tag",
            (
                "cargo",
                "test",
                "--locked",
                "-p",
                "noos-node",
                "claim_e_base_unknown_fields_fail_closed_on_the_production_wire",
                "--",
                "--test-threads=1",
            ),
        ),
        lab.LaneSpec(
            "oversize-rejection",
            "oversize",
            ("cargo", "test", "--locked", "-p", "noos-node", "oversized"),
        ),
        lab.LaneSpec(
            "wan-production-controls",
            "wan",
            (
                "cargo",
                "test",
                "--locked",
                "-p",
                "noos-node",
                "claim_e_wan_",
                "--",
                "--test-threads=1",
            ),
        ),
        lab.LaneSpec(
            "ai-off-production-controls",
            "ai_off",
            (
                "cargo",
                "test",
                "--locked",
                "-p",
                "noos-node",
                "claim_e_blackout_all_optional_controls_off_keeps_base_live",
                "--",
                "--test-threads=1",
            ),
        ),
    )


def validate_plan(lanes: Sequence[lab.LaneSpec]) -> None:
    identifiers = [lane.lane_id for lane in lanes]
    if len(identifiers) != len(set(identifiers)):
        raise CampaignError("lane identifiers must be unique")
    missing_simulations = sorted(set(SIMULATION_SCENARIOS) - set(identifiers))
    missing_contracts = sorted(REQUIRED_CONTRACT_LANES - set(identifiers))
    if missing_simulations or missing_contracts:
        raise CampaignError(
            f"incomplete campaign plan: simulations={missing_simulations} contracts={missing_contracts}"
        )
    required_areas = {
        "pairing_matrix",
        "restart",
        "snapshot",
        "proof",
        "unknown_tag",
        "oversize",
        "wan",
        "ai_off",
    }
    missing_areas = sorted(required_areas - {lane.area for lane in lanes})
    if missing_areas:
        raise CampaignError(f"campaign areas missing: {missing_areas}")
    if any(not lane.command or lane.timeout_seconds < 1 for lane in lanes):
        raise CampaignError("campaign contains an invalid lane")


def verify_bundle_hash(document: dict[str, object]) -> bool:
    expected = document.get("bundle_sha256")
    if not isinstance(expected, str):
        return False
    unsigned = dict(document)
    del unsigned["bundle_sha256"]
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return lab.sha256_bytes(encoded) == expected


def validate_campaign_evidence(
    lane_results: Sequence[dict[str, object]],
    artifacts_root: Path,
    source_revision: str,
) -> dict[str, object]:
    by_id = {str(result.get("lane_id")): result for result in lane_results}
    required_ids = set(SIMULATION_SCENARIOS) | REQUIRED_CONTRACT_LANES
    missing = sorted(required_ids - set(by_id))
    if missing:
        raise CampaignError(f"campaign results missing lanes: {missing}")
    failed = sorted(lane_id for lane_id in required_ids if by_id[lane_id].get("passed") is not True)
    if failed:
        raise CampaignError(f"required lanes failed: {failed}")

    simulations: dict[str, object] = {}
    root = artifacts_root.resolve()
    for lane_id, scenario in SIMULATION_SCENARIOS.items():
        attached = by_id[lane_id].get("attached_evidence")
        if not isinstance(attached, dict) or not isinstance(attached.get("path"), str):
            raise CampaignError(f"{lane_id}: attached evidence missing")
        evidence_path = Path(attached["path"])
        try:
            document = json.loads(evidence_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise CampaignError(f"{lane_id}: invalid evidence: {exc}") from exc
        if not isinstance(document, dict):
            raise CampaignError(f"{lane_id}: evidence must be an object")
        if document.get("schema_version") != "noos.base-g2-evidence.v1":
            raise CampaignError(f"{lane_id}: wrong evidence schema")
        if document.get("scenario") != scenario or document.get("verdict") != "PASS":
            raise CampaignError(f"{lane_id}: scenario or verdict mismatch")
        revision = document.get("revision")
        if not isinstance(revision, dict) or revision.get("git_head") != source_revision:
            raise CampaignError(f"{lane_id}: source revision mismatch")
        parameters = document.get("parameters")
        if not isinstance(parameters, dict) or parameters.get("clients") != ["rust", "go"]:
            raise CampaignError(f"{lane_id}: Rust/Go client declaration missing")
        observations = document.get("observations")
        if not isinstance(observations, dict):
            raise CampaignError(f"{lane_id}: observations missing")
        pair_values = observations.get("client_pairs")
        if not isinstance(pair_values, list) or any(not isinstance(pair, str) for pair in pair_values):
            raise CampaignError(f"{lane_id}: client pair matrix malformed")
        pairs = set(pair_values)
        if pairs != REQUIRED_PAIRS:
            raise CampaignError(f"{lane_id}: incomplete pair matrix {sorted(pairs)}")
        raw_log = document.get("raw_log")
        if not isinstance(raw_log, dict) or not isinstance(raw_log.get("path"), str):
            raise CampaignError(f"{lane_id}: raw log metadata missing")
        raw_path = Path(raw_log["path"]).resolve()
        if not raw_path.is_relative_to(root) or not raw_path.is_file():
            raise CampaignError(f"{lane_id}: raw log is outside the immutable artifact tree")
        raw_bytes = raw_path.read_bytes()
        if raw_log.get("bytes") != len(raw_bytes) or raw_log.get("sha256") != lab.sha256_bytes(raw_bytes):
            raise CampaignError(f"{lane_id}: raw log bytes or digest mismatch")
        if not verify_bundle_hash(document):
            raise CampaignError(f"{lane_id}: evidence bundle hash mismatch")
        simulations[scenario] = {
            "client_pairs": sorted(pairs),
            "run_count": len(observations.get("runs", [])) if isinstance(observations.get("runs"), list) else 0,
            "bundle_sha256": document["bundle_sha256"],
            "raw_log_sha256": raw_log["sha256"],
        }

    expected_matrix = "matrix=AA=PASS;AB=PASS;BA=PASS;BB=PASS"
    for lane_id in ("process-transition-matrix", "process-admission-matrix"):
        log = by_id[lane_id].get("log")
        if not isinstance(log, dict) or not isinstance(log.get("path"), str):
            raise CampaignError(f"{lane_id}: process log missing")
        text = Path(log["path"]).read_text(encoding="utf-8", errors="replace")
        if expected_matrix not in text:
            raise CampaignError(f"{lane_id}: AA/AB/BA/BB process matrix missing")
    return {
        "required_client_pairs": sorted(REQUIRED_PAIRS),
        "simulation_scenarios": simulations,
        "contract_lanes": sorted(REQUIRED_CONTRACT_LANES),
        "process_matrix": {"AA": "PASS", "AB": "PASS", "BA": "PASS", "BB": "PASS"},
    }


def build_result(
    *,
    source_revision: str,
    profile: str,
    seed: int,
    started_at_utc: str,
    completed_at_utc: str,
    lanes: list[dict[str, object]],
    coverage: dict[str, object] | None,
    validation_errors: list[str],
    artifacts_root: Path,
) -> dict[str, object]:
    failed_lanes = [str(lane["lane_id"]) for lane in lanes if lane.get("passed") is not True]
    passed = not failed_lanes and not validation_errors and coverage is not None
    blockers = [
        "TWO_INDEPENDENTLY_MANAGED_CLIENT_FAMILIES_REQUIRED",
        "PUBLIC_WAN_AND_ADVERSARIAL_DEVNET_REQUIRED",
        "SEVEN_UNINTERRUPTED_PUBLIC_AI_OFF_DAYS_REQUIRED",
    ]
    if profile == "smoke":
        blockers.append("QUALIFICATION_SCALE_NOT_RUN")
    blockers.extend(f"LANE_FAILED:{lane_id}" for lane_id in failed_lanes)
    blockers.extend(f"EVIDENCE_INVALID:{message}" for message in validation_errors)
    artifact_hash, artifact_files, artifact_bytes = lab.tree_digest(artifacts_root)
    result: dict[str, object] = {
        "schema": SCHEMA,
        "source_revision": source_revision,
        "profile": profile.upper(),
        "seed": seed,
        "started_at_utc": started_at_utc,
        "completed_at_utc": completed_at_utc,
        "lane_count": len(lanes),
        "passed_lane_count": len(lanes) - len(failed_lanes),
        "failed_lane_ids": failed_lanes,
        "validation_errors": validation_errors,
        "coverage": coverage,
        "control_contract_passed": passed,
        "qualification_scale_completed": profile == "qualification" and passed,
        "independent_management_established": False,
        "public_devnet_evidence": False,
        "artifacts": {
            "root": artifacts_root.as_posix(),
            "files": artifact_files,
            "bytes": artifact_bytes,
            "sha256": artifact_hash,
        },
        "lanes": lanes,
        "blockers": sorted(blockers),
        "production_authorized": False,
        "promotion_effect": "NONE",
    }
    result["result_id"] = lab.sha256_bytes(lab.canonical_bytes(result))
    return result


def run_campaign(args: argparse.Namespace) -> int:
    if args.output.exists():
        raise CampaignError(f"refusing to overwrite {args.output}")
    artifacts_root = args.output.parent / f"{args.output.stem}-artifacts"
    if artifacts_root.exists():
        raise CampaignError(f"refusing to reuse artifact directory {artifacts_root}")
    try:
        lab.verify_clean_revision(args.source_revision)
    except lab.LabError as exc:
        raise CampaignError(str(exc)) from exc
    lanes = campaign_specs(args.profile, args.seed)
    validate_plan(lanes)
    artifacts_root.mkdir(parents=True)
    environment = os.environ.copy()
    environment["PYTHONUTF8"] = "1"
    if args.cargo_target_dir is not None:
        args.cargo_target_dir.mkdir(parents=True, exist_ok=True)
        environment["CARGO_TARGET_DIR"] = str(args.cargo_target_dir.resolve())
    started = lab.utc_now()
    lane_results = [lab.run_lane(lane, artifacts_root, environment) for lane in lanes]
    validation_errors: list[str] = []
    coverage: dict[str, object] | None = None
    try:
        coverage = validate_campaign_evidence(
            lane_results, artifacts_root, args.source_revision
        )
    except CampaignError as exc:
        validation_errors.append(str(exc))
    completed = lab.utc_now()
    result = build_result(
        source_revision=args.source_revision,
        profile=args.profile,
        seed=args.seed,
        started_at_utc=started,
        completed_at_utc=completed,
        lanes=lane_results,
        coverage=coverage,
        validation_errors=validation_errors,
        artifacts_root=artifacts_root,
    )
    lab.write_exclusive(args.output, lab.canonical_bytes(result) + b"\n")
    print(json.dumps(result, sort_keys=True))
    return 0 if result["control_contract_passed"] else 1


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)
    plan = commands.add_parser("plan")
    plan.add_argument("--profile", choices=sorted(lab.PROFILES), default="smoke")
    plan.add_argument("--seed", type=lambda text: int(text, 0), default=0x4E4F4F53)
    run = commands.add_parser("run")
    run.add_argument("--source-revision", required=True)
    run.add_argument("--profile", choices=sorted(lab.PROFILES), default="smoke")
    run.add_argument("--seed", type=lambda text: int(text, 0), default=0x4E4F4F53)
    run.add_argument("--cargo-target-dir", type=Path)
    run.add_argument("--output", type=Path, required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "plan":
            lanes = campaign_specs(args.profile, args.seed)
            validate_plan(lanes)
            print(
                json.dumps(
                    {
                        "schema": "noos/two-client-devnet-campaign-plan/v1",
                        "profile": args.profile.upper(),
                        "seed": args.seed,
                        "lanes": [
                            {
                                "lane_id": lane.lane_id,
                                "area": lane.area,
                                "command": list(lane.command),
                            }
                            for lane in lanes
                        ],
                        "independent_management_established": False,
                        "production_authorized": False,
                        "promotion_effect": "NONE",
                    },
                    sort_keys=True,
                )
            )
            return 0
        return run_campaign(args)
    except (CampaignError, lab.LabError) as exc:
        print(f"TWO_CLIENT_CAMPAIGN_REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
