#!/usr/bin/env python3
"""Executable Docker Compose entrypoint for the non-production WWM stack."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import wwm_topology


class DeployError(RuntimeError):
    pass


def read_env_file(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise DeployError(f"cannot read environment file: {error}") from error
    values: dict[str, str] = {}
    for number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:]
        if "=" not in line:
            raise DeployError(f"malformed environment line {number}")
        key, value = line.split("=", 1)
        if not key or key in values:
            raise DeployError(f"duplicate or empty environment key at line {number}")
        values[key] = value.strip().strip('"').strip("'")
    return values
def verify_bonsai_source(raw_path: str) -> dict[str, Any]:
    path = Path(raw_path)
    if not path.is_absolute() or not path.is_file():
        raise DeployError("WWM_BONSAI_SOURCE_PATH must be an existing absolute file")
    if path.stat().st_size != 3_803_452_480:
        raise DeployError("Bonsai source length differs from 3,803,452,480 bytes")
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    observed = digest.hexdigest()
    expected = "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0"
    if observed != expected:
        raise DeployError("Bonsai source SHA-256 differs from the exact registered artifact")
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": observed}




def compose_command(deploy_dir: Path, environment: str, env_file: Path) -> list[str]:
    return [
        "docker",
        "compose",
        "--env-file",
        str(env_file),
        "-f",
        str(deploy_dir / "compose.yaml"),
        "-f",
        str(deploy_dir / f"compose.{environment}.yaml"),
    ]


def run(command: list[str], *arguments: str, capture: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(
            [*command, *arguments],
            check=False,
            capture_output=capture,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise DeployError(f"cannot execute Docker Compose: {error}") from error
    if completed.returncode != 0:
        raise DeployError((completed.stdout + completed.stderr).strip() or "Docker Compose failed")
    return completed


def verify_running(command: list[str], required_services: list[str]) -> list[str]:
    completed = run(command, "ps", "--format", "json")
    raw = completed.stdout.strip()
    if not raw:
        raise DeployError("Docker Compose returned no running services")
    documents: list[dict[str, Any]] = []
    try:
        parsed = json.loads(raw)
        documents = parsed if isinstance(parsed, list) else [parsed]
    except json.JSONDecodeError:
        for line in raw.splitlines():
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                documents.append(parsed)
    states = {
        str(row.get("Service")): str(row.get("State", "")).lower()
        for row in documents
    }
    missing = [service for service in required_services if states.get(service) != "running"]
    if missing:
        raise DeployError("services are not running: " + ", ".join(missing))
    return sorted(states)


def tcp_probe(host: str, port: int, name: str) -> None:
    try:
        with socket.create_connection((host, port), timeout=3):
            return
    except OSError as error:
        raise DeployError(f"{name} TCP probe failed at {host}:{port}: {error}") from error


def smoke(command: list[str], values: dict[str, str], services: list[str]) -> dict[str, Any]:
    running = verify_running(command, services)
    probes = [
        (values.get("WWM_GATEWAY_BIND", "127.0.0.1"), int(values.get("WWM_GATEWAY_PORT", "9765")), "gateway"),
        (values.get("WWM_EDGE_BIND", "127.0.0.1"), int(values.get("WWM_EDGE_PORT", "9764")), "edge"),
        (values.get("WWM_PROMETHEUS_BIND", "127.0.0.1"), int(values.get("WWM_PROMETHEUS_PORT", "9091")), "prometheus"),
    ]
    for host, port, name in probes:
        if host in {"0.0.0.0", "::"}:
            host = "127.0.0.1"
        tcp_probe(host, port, name)
    return {
        "verdict": "LOCAL_DEVNET_SMOKE_PASS",
        "services": running,
        "tcp_probes": [name for _, _, name in probes],
        "production_claim": False,
        "evidence_effect": "NONE",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("plan", "config", "up", "smoke", "down"))
    parser.add_argument("--environment", choices=("local", "devnet"), default="local")
    parser.add_argument("--deploy-dir", type=Path, default=wwm_topology.DEFAULT_DEPLOY)
    parser.add_argument("--env-file", type=Path)
    args = parser.parse_args(argv)
    try:
        topology_report = wwm_topology.validate_static(args.deploy_dir)
        topology_contract = wwm_topology.load_object(args.deploy_dir / "topology.json")
        override = args.deploy_dir / f"compose.{args.environment}.yaml"
        if not override.is_file():
            raise DeployError(f"missing {args.environment} override")
        plan = {
            "verdict": "PLAN_ONLY" if args.action == "plan" else "PENDING",
            "environment": args.environment,
            "production_capable": False,
            "compose_files": [
                str(args.deploy_dir / "compose.yaml"),
                str(override),
            ],
            "required_environment": topology_contract["immutable_image_variables"]
            + topology_contract["external_secret_variables"]
            + ["WWM_CONTROL_PLANE_URL"]
            + (["WWM_BONSAI_SOURCE_PATH"] if args.environment == "local" else []),
            "production_external_blockers": topology_report["production_external_blockers"],
        }
        if args.action == "plan":
            print(json.dumps(plan, sort_keys=True, separators=(",", ":")))
            return 0
        if args.env_file is None:
            raise DeployError("config/up/smoke/down requires --env-file")
        values = {**os.environ, **read_env_file(args.env_file)}
        wwm_topology.validate_environment(
            args.deploy_dir / "topology.json", values
        )
        if not values.get("WWM_CONTROL_PLANE_URL"):
            raise DeployError("WWM_CONTROL_PLANE_URL is required")
        if args.environment == "local":
            plan["bonsai_source"] = verify_bonsai_source(
                values.get("WWM_BONSAI_SOURCE_PATH", "")
            )
        command = compose_command(args.deploy_dir, args.environment, args.env_file)
        run(command, "config", "--quiet")
        if args.action == "config":
            report = {**plan, "verdict": "COMPOSE_CONFIG_VALID"}
        elif args.action == "up":
            run(command, "up", "-d")
            report = {**plan, "verdict": "LOCAL_DEVNET_STARTED", "production_claim": False}
        elif args.action == "smoke":
            report = smoke(command, values, topology_report["services"])
        else:
            run(command, "down")
            report = {**plan, "verdict": "LOCAL_DEVNET_STOPPED"}
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except (DeployError, wwm_topology.TopologyError, ValueError) as error:
        print(json.dumps({"verdict": "BLOCKED", "error": str(error), "production_capable": False}, sort_keys=True, separators=(",", ":")))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
