#!/usr/bin/env python3
"""Run one assigned Neural Lane lab claim and emit immutable raw evidence.

Every row is intentionally EXTERNAL_BLOCKED: the command proves the local
contract and falsifiers, then records the exact independent/public/hardware
prerequisites that this worktree cannot manufacture.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from experimental_gate import ROOT, base_continuity, cargo_test, emit, evidence_check

CLAIMS = (
    "N-PROFILE",
    "E-NEL-01",
    "E-NEL-01a",
    "E-NEL-02",
    "E-NEL-03",
    "E-NEL-04",
    "E-NEL-05",
    "E-NEL-06",
    "E-NEL-07",
)
PREREQUISITES = "crates/noos-nel/fixtures/claim-prerequisites-v1.json"
SOURCES = (
    "crates/noos-nel/Cargo.toml",
    "crates/noos-nel/src/lib.rs",
    "crates/noos-nel/src/inference.rs",
    "crates/noos-nel/src/lab.rs",
    "crates/noos-nel/src/luts.rs",
    "crates/noos-nel/src/bin/nel-claim-harness.rs",
    PREREQUISITES,
    "protocol/vectors/nel/forward-w8a8-v1.json",
    "tools/gates/run_nel_lab_claim.py",
)
HANDSHAKE_ARTIFACTS = {
    "silu": Path("C:/tmp/nel-real-inference/runs/silu_clip.json"),
    "second": Path("C:/tmp/nel-real-inference/runs/second_impl.json"),
    "divergence": Path("C:/tmp/nel-real-inference/runs/divergence_probe.json"),
}


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def harness(claim: str) -> dict[str, object]:
    command = [
        "cargo",
        "run",
        "--locked",
        "-q",
        "-p",
        "noos-nel",
        "--bin",
        "nel-claim-harness",
        "--",
        claim,
    ]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    if completed.returncode:
        raise SystemExit(completed.stdout)
    lines = [line for line in completed.stdout.splitlines() if line.startswith("{")]
    if len(lines) != 1:
        raise SystemExit(f"expected one harness JSON line, got {len(lines)}")
    metrics = json.loads(lines[0])
    if metrics.get("claim") != claim:
        raise SystemExit("harness claim mismatch")
    return {"command": command, "metrics": metrics}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def validate_local(claim: str, metrics: dict[str, object]) -> None:
    if claim in {"N-PROFILE", "E-NEL-01", "E-NEL-01a"}:
        require(metrics.get("semantic_op_families") == 17, "op-family coverage mismatch")
        require(int(metrics.get("matmul_instances", 0)) > 0, "no matmul instances")
        require(metrics.get("schedule_mismatches") == 0, "schedule mismatch")
        require(metrics.get("cobatch_mismatches") == 0, "co-batch mismatch")
        require(metrics.get("invalid_tokenizer_bytes_rejected") is True, "invalid tokenizer accepted")
        require(metrics.get("contract_mutations_rejected") is True, "profile contract mutation accepted")
    elif claim == "E-NEL-02":
        require(metrics.get("fixture_only") is True, "accuracy fixture provenance lost")
        require(metrics.get("registered_tasks") == metrics.get("reported_tasks") == 3, "task suppression")
        require(metrics.get("schema_passed") is True, "accuracy schema fixture failed")
        require(metrics.get("real_0_5b_hidden_suite") is False, "fabricated hidden-suite evidence")
    elif claim == "E-NEL-03":
        require(metrics.get("lifecycle_sealed") is True, "latency lifecycle did not seal")
        require(metrics.get("all_surfaces_soft") is True, "SOFT label laundering")
        require(metrics.get("control_clusters") == 3, "fixture cluster coverage mismatch")
        require(metrics.get("drops") == metrics.get("refunds") == 1, "drop/refund mismatch")
        require(metrics.get("public_experiment") is False, "fabricated public latency evidence")
    elif claim == "E-NEL-04":
        require(metrics.get("t") == 32, "wrong dispute chunk size")
        require(metrics.get("move_deadline") == 25, "wrong move deadline")
        require(metrics.get("declared_public_rounds") == 19, "wrong declared round count")
        require(metrics.get("declared_public_transactions") == 40, "wrong transaction count")
        for field in (
            "wrong_job_lost",
            "unrelated_job_live",
            "late_move_rejected",
            "malformed_move_rejected",
            "frivolous_challenger_lost",
        ):
            require(metrics.get(field) is True, f"dispute falsifier failed: {field}")
        require(metrics.get("public_testnet") is False, "fabricated public testnet evidence")
    elif claim == "E-NEL-05":
        require(metrics.get("single_loss_reconstructs") is True, "single-loss reconstruction failed")
        require(metrics.get("correlated_loss_blocks_assurance") is True, "unavailable evidence admitted")
        require(metrics.get("replay_probes") == 10_000, "KV replay probe count mismatch")
        require(metrics.get("replay_mismatches") == 0, "KV replay mismatch")
        require(metrics.get("poison_detected") is True, "poisoned checkpoint survived")
        require(metrics.get("cross_domain_hits") == 0, "cross-domain cache hit")
        require(metrics.get("real_0_5b_weights") is False, "fabricated real-model evidence")
    elif claim == "E-NEL-06":
        require(metrics.get("benchmark_interface_complete") is True, "proof interface missing")
        require(metrics.get("extrapolation_rejected") is True, "extrapolation was accepted")
        require(metrics.get("real_specialized_proof_run") is False, "fabricated proof run")
        require(metrics.get("independent_verifiers") is False, "fabricated verifier independence")
    elif claim == "E-NEL-07":
        require(metrics.get("schedules") == 1_000_000, "grind schedule count mismatch")
        require(metrics.get("post_reveal_commitments_accepted") == 0, "post-reveal commitment accepted")
        require(metrics.get("alternate_beacons_accepted") == 0, "alternate beacon accepted")
        require(metrics.get("replay_draws_accepted") == 0, "draw replay accepted")
        require(metrics.get("greedy_cursor_is_zero") is True, "greedy randomness detected")
        require(metrics.get("public_30_day_stall_measurement") is False, "fabricated duration evidence")


def validate_handshake() -> dict[str, object]:
    missing = [str(path) for path in HANDSHAKE_ARTIFACTS.values() if not path.is_file()]
    if missing:
        return {"available": False, "missing": missing}
    documents = {
        name: json.loads(path.read_text(encoding="utf-8"))
        for name, path in HANDSHAKE_ARTIFACTS.items()
    }
    silu = documents["silu"]
    second = documents["second"]
    divergence = documents["divergence"]
    require(second.get("layers") == 24, "handshake layer count mismatch")
    require(second.get("digests_equal") is True, "handshake digest mismatch")
    require(second.get("final_logits_equal") is True, "handshake logits mismatch")
    require(second.get("profile_lineage_ok") is True, "handshake profile lineage mismatch")
    require(silu.get("silu_values_total") == 3_502_080, "SiLU denominator mismatch")
    frozen = silu.get("aggregate", {}).get("frozen_lut", {})
    narrow = silu.get("aggregate", {}).get("nel_l0_lut", {})
    require(frozen.get("clip_events") == 41, "frozen LUT clip count mismatch")
    require(narrow.get("clip_events") == 1_166, "NEL-L0 clip count mismatch")
    require(abs(float(frozen.get("max_abs_err")) - 28.268280029296875) < 1e-12, "frozen LUT max error mismatch")
    require(divergence.get("classification") == "quantized-logit tie within FP rounding distance", "divergence classification mismatch")
    require(float(divergence["gaps"]["pair_drift_logits"]) < float(divergence["fp_noise"]["max"]), "divergence exceeds FP noise")
    require(divergence["vulkan_cross_check"]["integer_matches_vulkan_16_of_16"] is True, "Vulkan sequence mismatch")
    return {
        "available": True,
        "artifact_sha256": {
            name: file_sha256(path) for name, path in sorted(HANDSHAKE_ARTIFACTS.items())
        },
        "layers": second["layers"],
        "digests_equal": second["digests_equal"],
        "final_logits_equal": second["final_logits_equal"],
        "silu_values_total": silu["silu_values_total"],
        "frozen_lut_max_abs_err": frozen["max_abs_err"],
        "frozen_lut_mean_abs_err": frozen["mean_abs_err"],
        "frozen_lut_clip_events": frozen["clip_events"],
        "nel_l0_clip_events": narrow["clip_events"],
        "pair_drift_logits": divergence["gaps"]["pair_drift_logits"],
        "fp_noise_max": divergence["fp_noise"]["max"],
        "classification": divergence["classification"],
        "independent_provenance_verified_here": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claim", required=True, choices=CLAIMS)
    parser.add_argument("--rollback-check", action="store_true")
    args = parser.parse_args()
    if args.rollback_check:
        continuity = base_continuity()
        require(continuity["ordinary_base_live"] is True, "ordinary base continuity failed")
        print("RESULT rollback=PASSED")
        return 0

    prereg = json.loads((ROOT / PREREQUISITES).read_text(encoding="utf-8"))
    require(prereg.get("schema") == "NOOS/NEL/CLAIM-PREREQUISITES/V1", "wrong prerequisite schema")
    requirement = prereg.get("claims", {}).get(args.claim)
    require(isinstance(requirement, dict), "claim prerequisite row missing")
    local = harness(args.claim)
    metrics = local["metrics"]
    assert isinstance(metrics, dict)
    validate_local(args.claim, metrics)
    observations: list[object] = [cargo_test(("noos-nel",)), local, requirement]
    if args.claim == "E-NEL-01a":
        handshake = validate_handshake()
        require(handshake.get("available") is True, "required handshake artifacts unavailable")
        observations.append(handshake)
    limitations = [
        "Local deterministic evidence only; it is not independent, cross-vendor, public-duration, or production evidence.",
        *requirement.get("required_external", []),
    ]
    if args.claim == "E-NEL-01a":
        limitations.append(
            "The three existing C:/tmp measured artifacts match the frozen row, but this runner does not certify independent authorship."
        )
    checks = [
        evidence_check("local-precursor", "falsifier", True, observations),
        evidence_check("external-pass-threshold", "external_requirement", False, requirement.get("required_external", ["independent evidence remains unavailable"])),
    ]
    emit(
        gate="implementation-" + args.claim.lower().replace(".", "-"),
        claims=[args.claim],
        result="EXTERNAL_BLOCKED",
        expected="EXTERNAL_BLOCKED",
        checks=checks,
        sources=SOURCES,
        limitations=limitations,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
