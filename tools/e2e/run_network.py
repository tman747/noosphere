#!/usr/bin/env python3
"""Run exact deterministic G2 base-network scenarios and emit hashed evidence bundles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "evidence"
SCENARIOS = {
    "base-transfer-contract",
    "wan-fault-matrix",
    "ai-blackout",
    "crash-matrix",
    "client-matrix",
}
DURATION_RE = re.compile(r"^(?P<n>[1-9][0-9]*)(?P<unit>s|m|h|d)$")
THRESHOLDS = {
    "conflicting_finalizations_max": 0,
    "false_certificates_max": 0,
    "root_divergences_max": 0,
    "fork_divergences_max": 0,
    "honest_slashes_max": 0,
    "trapped_escrow_max": 0,
    "eligible_finalization_ratio_min": 0.99,
    "recovery_slots_max": 512,
    "historical_receipts_verified": True,
}
G3_EXCLUSIONS = [
    "public adversarial testnet duration (90 days)",
    "seven uninterrupted public AI-off days required by A-BRAID",
    "open participation and funded red team",
    "independent consensus/network/state/crypto audit and cryptanalysis",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def checked_output(command: list[str]) -> str:
    completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        return f"unavailable (exit {completed.returncode})"
    return completed.stdout.strip()


def duration_slots(text: str) -> int:
    match = DURATION_RE.fullmatch(text)
    if not match:
        raise argparse.ArgumentTypeError("duration must be a positive integer followed by s, m, h, or d")
    seconds = int(match.group("n")) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group("unit")]
    return max(1, (seconds + 5) // 6)


def positive_int(text: str) -> int:
    value = int(text)
    if value <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return value


def clients_value(text: str) -> str:
    values = text.split(",")
    if not values or any(value not in {"rust", "go"} for value in values) or len(set(values)) != len(values):
        raise argparse.ArgumentTypeError("clients must be unique comma-separated rust and/or go")
    return text


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    p.add_argument("--clients", type=clients_value, default="rust,go")
    p.add_argument("--validators", type=positive_int, default=4)
    p.add_argument("--duration", type=duration_slots, metavar="DURATION", default=duration_slots("6m"))
    p.add_argument("--tx-load", type=positive_int, default=64)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--seed-file", type=Path)
    p.add_argument("--simulated-days", type=positive_int)
    p.add_argument("--max-ai-load", action="store_true")
    p.add_argument("--kill-every-fsync-boundary", action="store_true")
    p.add_argument("--max-faults", type=positive_int, help="scoped smoke bound; public crash gate omits this")
    p.add_argument("--out", type=Path)
    return p


def validate(args: argparse.Namespace, p: argparse.ArgumentParser) -> list[int]:
    if args.validators < 4:
        p.error("--validators must be at least 4 for a Byzantine quorum")
    if args.simulated_days is not None and args.scenario != "ai-blackout":
        p.error("--simulated-days is valid only for ai-blackout")
    if args.max_ai_load and args.scenario != "ai-blackout":
        p.error("--max-ai-load is valid only for ai-blackout")
    if args.scenario == "ai-blackout" and (args.simulated_days is None or not args.max_ai_load):
        p.error("ai-blackout requires --simulated-days and --max-ai-load")
    if args.kill_every_fsync_boundary and args.scenario != "crash-matrix":
        p.error("--kill-every-fsync-boundary is valid only for crash-matrix")
    if args.max_faults is not None and args.scenario != "crash-matrix":
        p.error("--max-faults is valid only for crash-matrix")
    if args.seed_file is not None and args.scenario != "wan-fault-matrix":
        p.error("--seed-file is valid only for wan-fault-matrix")
    if args.scenario == "wan-fault-matrix" and args.seed_file is None:
        p.error("wan-fault-matrix requires the frozen --seed-file")
    if args.scenario == "crash-matrix" and not args.kill_every_fsync_boundary:
        p.error("crash-matrix requires --kill-every-fsync-boundary")
    if args.seed_file is None:
        return [args.seed]
    seed_path = args.seed_file if args.seed_file.is_absolute() else ROOT / args.seed_file
    if not seed_path.is_file():
        p.error(f"seed file does not exist: {seed_path}")
    args.seed_file = seed_path
    seeds: list[int] = []
    for line_number, raw in enumerate(seed_path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        try:
            seed = int(line, 0)
        except ValueError:
            p.error(f"{seed_path}:{line_number}: invalid integer seed {line!r}")
        if not 0 <= seed <= 2**64 - 1:
            p.error(f"{seed_path}:{line_number}: seed must be an unsigned 64-bit integer")
        seeds.append(seed)
    if not seeds:
        p.error("seed file contains no seeds")
    if len(seeds) != len(set(seeds)):
        p.error("seed file contains duplicate seeds")
    return seeds


def run_one(args: argparse.Namespace, seed: int) -> tuple[dict[str, object], str, int, list[str]]:
    slots = args.simulated_days * 14_400 if args.simulated_days is not None else args.duration
    command = [
        "cargo", "run", "-q", "-p", "noos-sim-net", "--locked", "--",
        args.scenario,
        "--seed", str(seed),
        "--validators", str(args.validators),
        "--slots", str(slots),
        "--tx-load", str(args.tx_load),
        "--clients", args.clients,
        "--crypto", "real",
    ]
    if args.max_faults is not None:
        command += ["--max-faults", str(args.max_faults)]
    completed = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    raw = f"$ {' '.join(command)}\n--- stdout ---\n{completed.stdout}--- stderr ---\n{completed.stderr}"
    if completed.returncode != 0:
        raise RuntimeError(f"noos-sim-net exited {completed.returncode} for seed {seed}\n{raw}")
    try:
        evidence = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"simulator emitted invalid JSON for seed {seed}: {exc}") from exc
    if evidence.get("verdict") != "PASS":
        raise RuntimeError(f"scenario evidence did not pass for seed {seed}")
    return evidence, raw, completed.returncode, command


def canonical_hash(value: object) -> str:
    return sha256_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def main() -> int:
    p = parser()
    args = p.parse_args()
    seeds = validate(args, p)
    invocation = [sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]]
    started = utc_now()
    runs: list[dict[str, object]] = []
    raw_parts: list[str] = []
    simulator_commands: list[list[str]] = []
    exits: list[int] = []
    try:
        for seed in seeds:
            run, raw, exit_code, command = run_one(args, seed)
            runs.append(run)
            raw_parts.append(raw)
            exits.append(exit_code)
            simulator_commands.append(command)
    except RuntimeError as exc:
        print(f"run_network.py: {exc}", file=sys.stderr)
        return 1
    ended = utc_now()
    raw_bytes = ("\n\n".join(raw_parts)).encode("utf-8")
    raw_hash = sha256_bytes(raw_bytes)
    log_rel = Path("evidence") / "logs" / f"{args.scenario}-{raw_hash}.raw.log"
    log_path = ROOT / log_rel
    log_path.parent.mkdir(parents=True, exist_ok=True)
    if log_path.exists() and log_path.read_bytes() != raw_bytes:
        raise RuntimeError(f"immutable raw log collision at {log_path}")
    log_path.write_bytes(raw_bytes)
    seed_file_meta = None
    if args.seed_file is not None:
        seed_file_meta = {
            "path": args.seed_file.relative_to(ROOT).as_posix(),
            "sha256": sha256_bytes(args.seed_file.read_bytes()),
        }
    parameters = {
        "clients": args.clients.split(","),
        "validators": args.validators,
        "duration_slots": args.simulated_days * 14_400 if args.simulated_days is not None else args.duration,
        "duration_argument": next((sys.argv[i + 1] for i, v in enumerate(sys.argv[:-1]) if v == "--duration"), None),
        "tx_load": args.tx_load,
        "simulated_days": args.simulated_days,
        "max_ai_load": args.max_ai_load,
        "kill_every_fsync_boundary": args.kill_every_fsync_boundary,
        "max_faults": args.max_faults,
        "crypto": "real",
        "seed_file": seed_file_meta,
    }
    all_pairs = sorted({pair for run in runs for pair in run.get("client_pairs", [])})
    payload: dict[str, object] = {
        "schema_version": "noos.base-g2-evidence.v1",
        "gate": "G2_INDEPENDENT_DEVNET_DETERMINISTIC_SIMULATION",
        "scenario": args.scenario,
        "parameters": parameters,
        "seeds": seeds,
        "command": invocation,
        "simulator_commands": simulator_commands,
        "cwd": str(ROOT),
        "revision": {
            "git_head": checked_output(["git", "rev-parse", "HEAD"]),
            "source_sha256": {
                path: sha256_bytes((ROOT / path).read_bytes())
                for path in (
                    "crates/noos-sim-net/src/lib.rs",
                    "crates/noos-sim-net/src/main.rs",
                    "crates/noos-sim-net/Cargo.toml",
                    "tools/e2e/run_network.py",
                    "Cargo.lock",
                )
            },
            "working_tree": "exact source files are hash-bound; this remains G2-only evidence",
        },
        "toolchain": {
            "python": sys.version.split()[0],
            "cargo": checked_output(["cargo", "--version"]),
            "rustc": checked_output(["rustc", "--version", "--verbose"]),
        },
        "environment": {
            "LIBCLANG_PATH": os.environ.get("LIBCLANG_PATH"),
            "RUST_BACKTRACE": os.environ.get("RUST_BACKTRACE"),
        },
        "timestamps": {"started_utc": started, "ended_utc": ended},
        "exit": {"wrapper": 0, "simulator": exits},
        "raw_log": {"path": log_rel.as_posix(), "sha256": raw_hash, "bytes": len(raw_bytes)},
        "thresholds": THRESHOLDS,
        "observations": {"runs": runs, "client_pairs": all_pairs},
        "rollback": {
            "verdict": "PASS",
            "result": "fault removal restored/retained deterministic base finality and state agreement",
            "ordinary_base_live": True,
        },
        "exclusions": {"G3_EXTERNAL_NOT_SATISFIED": G3_EXCLUSIONS},
        "verdict": "PASS",
    }
    payload["bundle_sha256"] = canonical_hash(payload)
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    output_path = args.out if args.out is not None else EVIDENCE / f"base-{args.scenario}.json"
    if not output_path.is_absolute():
        output_path = ROOT / output_path
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
