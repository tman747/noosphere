#!/usr/bin/env python3
"""Fail closed unless the exact deterministic G2 base evidence battery is present and intact."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EXPECTED_LIBCLANG = "C:/Users/ntrap/AppData/Local/Programs/Swift/Toolchains/6.3.2+Asserts/usr/bin"
FILES = {
    "battery": ROOT / "evidence/base-battery.json",
    "base-transfer-contract": ROOT / "evidence/base-base-transfer-contract.json",
    "wan-fault-matrix": ROOT / "evidence/base-wan-fault-matrix.json",
    "ai-blackout": ROOT / "evidence/base-ai-blackout.json",
    "crash-matrix": ROOT / "evidence/base-crash-matrix.json",
    "client-matrix": ROOT / "evidence/base-client-matrix.json",
}
REQUIRED_PAIRS = {"rust->rust", "rust->go", "go->rust", "go->go"}


class InvalidEvidence(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise InvalidEvidence(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def load(path: Path) -> tuple[dict[str, Any], bytes]:
    require(path.is_file(), f"missing evidence bundle: {path.relative_to(ROOT)}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidEvidence(f"invalid JSON {path.relative_to(ROOT)}: {exc}") from exc
    require(isinstance(value, dict), f"bundle is not an object: {path.relative_to(ROOT)}")
    return value, raw


def verify_bundle_hash(bundle: dict[str, Any], raw: bytes, scenario: str) -> None:
    if scenario == "battery":
        expected = bundle.get("bundle_sha256")
        require(isinstance(expected, str) and len(expected) == 64, "battery bundle_sha256 missing")
        text = raw.decode("utf-8")
        pattern = re.compile(r',\n  "bundle_sha256": "[0-9a-f]{64}"\n}\n?$')
        match = pattern.search(text)
        require(match is not None, "battery bundle hash envelope is noncanonical")
        payload = text[: match.start()] + "\n}"
        require(sha256(payload.encode("utf-8")) == expected, "battery bundle_sha256 mismatch")
    else:
        expected = bundle.get("bundle_sha256")
        require(isinstance(expected, str) and len(expected) == 64, f"{scenario}: bundle_sha256 missing")
        unhashed = dict(bundle)
        del unhashed["bundle_sha256"]
        require(canonical_hash(unhashed) == expected, f"{scenario}: bundle_sha256 mismatch")


def verify_common(bundle: dict[str, Any], raw: bytes, scenario: str) -> None:
    require(bundle.get("schema_version") == "noos.base-g2-evidence.v1", f"{scenario}: wrong schema")
    require(bundle.get("gate") == "G2_INDEPENDENT_DEVNET_DETERMINISTIC_SIMULATION", f"{scenario}: wrong gate")
    require(bundle.get("scenario") == scenario, f"{scenario}: scenario mismatch")
    require(bundle.get("verdict") == "PASS", f"{scenario}: verdict is not PASS")
    require(bundle.get("cwd") in {str(ROOT), str(ROOT).replace("\\", "/")}, f"{scenario}: wrong cwd")
    require(bundle.get("revision", {}).get("git_head") not in {None, "", "unavailable"}, f"{scenario}: revision missing")
    source_hashes = bundle.get("revision", {}).get("source_sha256", {})
    required_sources = {
        "crates/noos-sim-net/src/lib.rs",
        "crates/noos-sim-net/src/main.rs",
        "crates/noos-sim-net/Cargo.toml",
        "Cargo.lock",
    }
    if scenario != "battery":
        required_sources.add("tools/e2e/run_network.py")
    require(required_sources <= set(source_hashes), f"{scenario}: source revision hashes missing")
    for source in required_sources:
        require(source_hashes[source] == sha256((ROOT / source).read_bytes()), f"{scenario}: stale source hash for {source}")
    require(bundle.get("toolchain", {}).get("rustc") not in {None, "", "unavailable"}, f"{scenario}: rustc missing")
    env_path = str(bundle.get("environment", {}).get("LIBCLANG_PATH") or "").replace("\\", "/")
    require(env_path == EXPECTED_LIBCLANG, f"{scenario}: LIBCLANG_PATH not captured as {EXPECTED_LIBCLANG}")
    simulator_exit = bundle.get("exit", {}).get("simulator")
    require(
        simulator_exit == 0
        or (isinstance(simulator_exit, list) and simulator_exit and all(code == 0 for code in simulator_exit)),
        f"{scenario}: nonzero/malformed exit",
    )
    thresholds = bundle.get("thresholds", {})
    require(thresholds.get("eligible_finalization_ratio_min") == 0.99, f"{scenario}: finalization threshold changed")
    require(thresholds.get("recovery_slots_max") == 512, f"{scenario}: recovery threshold changed")
    for name in (
        "conflicting_finalizations_max", "false_certificates_max", "root_divergences_max",
        "fork_divergences_max", "honest_slashes_max", "trapped_escrow_max",
    ):
        require(thresholds.get(name) == 0, f"{scenario}: threshold {name} changed")
    require(bundle.get("rollback", {}).get("verdict") == "PASS", f"{scenario}: rollback did not pass")
    require(bundle.get("rollback", {}).get("ordinary_base_live") is True, f"{scenario}: base not live after rollback")
    exclusions = bundle.get("exclusions", {}).get("G3_EXTERNAL_NOT_SATISFIED", [])
    require(len(exclusions) == 4, f"{scenario}: G3 exclusions missing")
    raw_log = bundle.get("raw_log", {})
    rel = raw_log.get("path")
    require(isinstance(rel, str) and rel, f"{scenario}: raw log path missing")
    log_path = Path(rel)
    if not log_path.is_absolute():
        log_path = ROOT / log_path
    resolved = log_path.resolve()
    require(resolved.is_relative_to(ROOT.resolve()), f"{scenario}: raw log escapes repository")
    require(resolved.is_file(), f"{scenario}: raw log missing")
    log_bytes = resolved.read_bytes()
    require(raw_log.get("bytes") == len(log_bytes), f"{scenario}: raw log byte count mismatch")
    require(raw_log.get("sha256") == sha256(log_bytes), f"{scenario}: raw log hash mismatch")
    verify_bundle_hash(bundle, raw, scenario)


def observation_runs(bundle: dict[str, Any]) -> list[dict[str, Any]]:
    observations = bundle.get("observations")
    if isinstance(observations, dict) and isinstance(observations.get("runs"), list):
        return observations["runs"]
    if isinstance(observations, dict):
        return [observations]
    raise InvalidEvidence(f"{bundle.get('scenario')}: observations missing")


def verify_metrics(bundle: dict[str, Any]) -> None:
    for index, run in enumerate(observation_runs(bundle)):
        scenario = bundle["scenario"]
        require(run.get("verdict") == "PASS", f"{scenario}[{index}]: simulator verdict not PASS")
        safety = run.get("safety", {})
        roots = run.get("roots", {})
        blackout = run.get("blackout", {})
        liveness = run.get("liveness", {})
        workload = run.get("workload", {})
        for key in ("conflicting_finalizations", "false_certificates", "honest_slashes"):
            require(safety.get(key) == 0, f"{scenario}[{index}]: {key} nonzero")
        for key in ("state_divergences", "fork_divergences"):
            require(roots.get(key) == 0, f"{scenario}[{index}]: {key} nonzero")
        require(blackout.get("trapped_escrow") == 0, f"{scenario}[{index}]: trapped escrow")
        require(liveness.get("finalization_ratio", 0) >= 0.99, f"{scenario}[{index}]: liveness below 99%")
        require(liveness.get("max_recovery_slots", 513) <= 512, f"{scenario}[{index}]: recovery exceeds two epochs")
        require(workload.get("historical_receipts_verified") is True, f"{scenario}[{index}]: receipts not verified")


def verify_exact(bundle: dict[str, Any], scenario: str) -> None:
    params = bundle.get("parameters", {})
    require(params.get("crypto") == "real", f"{scenario}: crypto is not real")
    if scenario == "battery":
        require(params.get("seeds_expression") == "0..10000", "battery: wrong seed expression")
        require(bundle.get("seeds") == {"start_inclusive": 0, "end_exclusive": 10000, "count": 10000}, "battery: wrong seed coverage")
        require(params.get("clients") == ["rust", "go"], "battery: both clients required")
        require(bundle.get("observations", {}).get("seeds_run") == 10000, "battery: not all 10000 seeds ran")
        require(
            bundle.get("command") == [
                "cargo", "run", "-p", "noos-sim-net", "--release", "--locked", "--",
                "battery", "--seeds", "0..10000", "--crypto", "real", "--out",
                "evidence/base-battery.json",
            ],
            "battery: exact release command not recorded",
        )
    elif scenario == "base-transfer-contract":
        require(params.get("clients") == ["rust", "go"], "base transfer: both clients required")
        require(params.get("validators") == 4, "base transfer: validators must be 4")
        require(params.get("duration_argument") == "90m" and params.get("duration_slots") == 900, "base transfer: duration must be 90m")
        require(params.get("tx_load") == 10000, "base transfer: tx load must be 10000")
    elif scenario == "wan-fault-matrix":
        require(params.get("clients") == ["rust", "go"], "WAN: both clients required")
        require(params.get("validators") == 10, "WAN: validators must be 10")
        seed_meta = params.get("seed_file", {})
        require(seed_meta.get("path") == "protocol/vectors/wan-seeds.txt", "WAN: wrong seed file")
        seed_file = ROOT / "protocol/vectors/wan-seeds.txt"
        require(seed_meta.get("sha256") == sha256(seed_file.read_bytes()), "WAN: frozen seed hash mismatch")
        frozen = [int(line) for line in seed_file.read_text(encoding="utf-8").splitlines() if line and not line.startswith("#")]
        require(bundle.get("seeds") == frozen, "WAN: seed coverage differs from frozen file")
    elif scenario == "ai-blackout":
        require(params.get("clients") == ["rust", "go"], "blackout: both clients required")
        require(params.get("simulated_days") == 30, "blackout: must cover 30 simulated days")
        require(params.get("max_ai_load") is True, "blackout: max AI load not requested")
        run = observation_runs(bundle)[0]
        blackout = run.get("blackout", {})
        require(blackout.get("optional_lanes_disabled") is True, "blackout: optional lanes remained enabled")
        require(blackout.get("ground_blocks", 0) > 0 and blackout.get("lumen_transfers", 0) > 0 and blackout.get("finalizations", 0) > 0, "blackout: base made no progress")
    elif scenario == "crash-matrix":
        require(params.get("kill_every_fsync_boundary") is True, "crash: full fsync matrix not requested")
        require(params.get("max_faults") is None, "crash: matrix was narrowed")
        require(observation_runs(bundle)[0].get("faults", {}).get("fsync_faults_injected") == 8, "crash: not every boundary was killed")
    elif scenario == "client-matrix":
        pairs = set(bundle.get("observations", {}).get("client_pairs", []))
        require(pairs == REQUIRED_PAIRS, f"client matrix: expected AA/AB/BA/BB, got {sorted(pairs)}")


def main() -> int:
    try:
        for scenario, path in FILES.items():
            bundle, raw = load(path)
            verify_common(bundle, raw, scenario)
            verify_exact(bundle, scenario)
            verify_metrics(bundle)
    except (InvalidEvidence, OSError, KeyError, TypeError, ValueError) as exc:
        print(f"RESULT noosphere_base_evidence=FAIL: {exc}", file=sys.stderr)
        return 1
    print("RESULT noosphere_base_evidence=PASS")
    print("G2 deterministic evidence validated; G3 90-day/seven-day/audit gates remain external and unsatisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
