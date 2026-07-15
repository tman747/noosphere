#!/usr/bin/env python3
"""Validate the local/devnet WWM topology without claiming production readiness."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Mapping

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DEPLOY = ROOT / "deploy" / "wwm"
IMAGE_REF = re.compile(r"^[^\s@:]+(?:/[^\s@:]+)*:[^\s@]+@sha256:[0-9a-f]{64}$")
SERVICE_LINE = re.compile(r"^  ([a-z][a-z0-9-]*):\s*$", re.MULTILINE)
FORBIDDEN_SECRET = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|(?i:(?:password|private_key|api_token)[ \t]*:[ \t]*[^$/{\s][^\r\n]*)"
)
EXPECTED_MODEL_SHA256 = "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0"
EXPECTED_MODEL_REVISION = "0cf7e3d21581b169b4df1de8bf01316000e2fbb7"
EXPECTED_MANIFEST_ROOT = "80f211eb4ebfd26df62bdeac69bc663ca97664eaf179188af78d1288aee42de7"
EXPECTED_RUNTIME_REVISION = "62061f91088281e65071cc38c5f69ee95c39f14e"


class TopologyError(RuntimeError):
    pass


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TopologyError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise TopologyError(f"{path} must contain an object")
    return value
def verify_pinned_file(
    deploy_dir: Path,
    relative_path: object,
    expected_bytes: object,
    expected_sha256: object,
    label: str,
) -> None:
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or Path(relative_path).is_absolute()
        or not isinstance(expected_bytes, int)
        or expected_bytes < 0
        or not isinstance(expected_sha256, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected_sha256)
    ):
        raise TopologyError(f"{label} evidence is malformed")
    root = deploy_dir.resolve()
    path = (deploy_dir / relative_path).resolve()
    try:
        path.relative_to(root)
    except ValueError as error:
        raise TopologyError(f"{label} path escapes deploy directory") from error
    try:
        body = path.read_bytes()
    except OSError as error:
        raise TopologyError(f"cannot read {label}: {error}") from error
    if len(body) != expected_bytes or hashlib.sha256(body).hexdigest() != expected_sha256:
        raise TopologyError(f"{label} bytes differ from pinned upstream evidence")



def service_blocks(compose: str) -> dict[str, str]:
    services_start = compose.find("services:\n")
    secrets_start = compose.find("\nsecrets:\n", services_start)
    if services_start < 0 or secrets_start < 0:
        raise TopologyError("compose must have top-level services and secrets")
    body = compose[services_start + len("services:\n") : secrets_start]
    matches = list(SERVICE_LINE.finditer(body))
    blocks: dict[str, str] = {}
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(body)
        blocks[match.group(1)] = body[match.start() : end]
    return blocks


def validate_static(deploy_dir: Path = DEFAULT_DEPLOY) -> dict[str, Any]:
    topology = load_object(deploy_dir / "topology.json")
    artifact = load_object(deploy_dir / "bonsai-artifact.json")
    runtime = load_object(deploy_dir / "bonsai-runtime.json")
    compose_path = deploy_dir / "compose.yaml"
    try:
        compose = compose_path.read_text(encoding="utf-8")
    except OSError as error:
        raise TopologyError(f"cannot read {compose_path}: {error}") from error
    if topology.get("schema") != "noos/wwm-topology/v1":
        raise TopologyError("unsupported topology schema")
    if topology.get("application_profile") != "BONSAI_PUBLIC_TEXT_V1":
        raise TopologyError("wrong application profile")
    if topology.get("production_capable") is not False:
        raise TopologyError("local/devnet topology must not claim production capability")
    if (
        artifact.get("source_bytes") != 3_803_452_480
        or artifact.get("sha256") != EXPECTED_MODEL_SHA256
    ):
        raise TopologyError("artifact identity differs from exact Bonsai Q1")
    source = artifact.get("source", {})
    expected_source = {
        "repository": "prism-ml/Bonsai-27B-gguf",
        "revision": EXPECTED_MODEL_REVISION,
        "path": "Bonsai-27B-Q1_0.gguf",
        "git_oid": "dea9011c70135768834ab25b59f451280d0766a5",
        "lfs_sha256": EXPECTED_MODEL_SHA256,
        "xet_hash": "80737a9af79f72a12f4a0a2839baf71b0d0491d78e0db83dec7245978b427430",
    }
    if not isinstance(source, dict) or any(
        source.get(key) != value for key, value in expected_source.items()
    ):
        raise TopologyError("artifact source revision or upstream object binding differs")
    identity = artifact.get("identity", {})
    expected_identity = {
        "artifact_id": "d3d1bcf9f704c58c695d7c0837be25a5cfbd7ff71b440bfc9be4a4a46bb528b0",
        "payload_root": "d9fd68fd5b262b0b3672f71c633956c93228e6e3f331ed92ef40e2647de475f7",
        "manifest_root": EXPECTED_MANIFEST_ROOT,
        "metadata_table_root": "0cc47f6379c069e745986bd95c696d78f51d5d4c0f3510f7f3cc5aa1d8311a8f",
        "tensor_table_root": "ebfc159935469c3c8d40c7ea52dfac26dd996408f70ef36ef981a7dc07b9ee24",
        "tokenizer_root": "58f310f0412514cea1a31757c9cc9714666b64fb67127914ab08554c4e0b4d56",
        "chat_template_root": "7ccfac375b7121adfb8c35763b183a7707bb071bd1abbd76128986b16c3b4d33",
    }
    if not isinstance(identity, dict) or any(
        identity.get(key) != value for key, value in expected_identity.items()
    ):
        raise TopologyError("artifact, manifest, tokenizer, or template root differs")
    codec = artifact.get("codec", {})
    if [
        codec.get("data_positions"),
        codec.get("parity_positions"),
        codec.get("share_bytes"),
        codec.get("stripes"),
        codec.get("share_count"),
        codec.get("position_bytes"),
        codec.get("encoded_bytes"),
    ] != [8, 4, 1_047_552, 454, 5_448, 475_588_608, 5_707_063_296]:
        raise TopologyError("artifact codec geometry differs from RS-GF8-V1")
    license_evidence = artifact.get("license", {})
    if (
        not isinstance(license_evidence, dict)
        or license_evidence.get("spdx") != "Apache-2.0"
        or license_evidence.get("modified") is not False
        or license_evidence.get("redistribution_requires_license_and_notice") is not True
    ):
        raise TopologyError("artifact license policy differs from frozen upstream evidence")
    verify_pinned_file(
        deploy_dir,
        license_evidence.get("license_path"),
        license_evidence.get("license_bytes"),
        license_evidence.get("license_sha256"),
        "Bonsai LICENSE.txt",
    )
    verify_pinned_file(
        deploy_dir,
        license_evidence.get("notice_path"),
        license_evidence.get("notice_bytes"),
        license_evidence.get("notice_sha256"),
        "Bonsai NOTICE.txt",
    )
    if (
        runtime.get("source_revision") != EXPECTED_RUNTIME_REVISION
        or runtime.get("source_repository")
        != "https://github.com/PrismML-Eng/llama.cpp"
        or runtime.get("model_sha256") != EXPECTED_MODEL_SHA256
        or runtime.get("model_bytes") != 3_803_452_480
        or runtime.get("runtime_root")
        != "690d9bbd8d44631fb971e0b0677e10c8d0bb1e08a743bb720eeaab728e30ba27"
        or runtime.get("build_root")
        != "72b5b1514a6fdf64a275d9ae660cda4db3cb2ce64e37a7ca7e97899729dc3b05"
        or runtime.get("sbom_root")
        != "a61768de8786670eb2aefcc59751657bcdbddc8d750f5fe1073f586debe2d0eb"
    ):
        raise TopologyError("runtime is not pinned to the exact Prism/Bonsai identity")
    expected_build_artifacts = {
        "runtime_executable_sha256": "d09e9f62e2bfc20af43f47dac8adddae47de25ae7678702f109faaa03dfe8a56",
        "runtime_implementation_sha256": "b1708e3878a9b7b92753acb45b4981d340372313dd9310e656b259638c5a6dd1",
        "llama_library_sha256": "9feb0af2a625b6789cdd94b378132e2267d19bcea951f2efbe36f15aa114e4cd",
        "hip_backend_sha256": "b81d95e240a46da13ccbb1f71e2bf6c2f74e347c2aa3c9638073454b1b6eac65",
        "hip_archive_sha256": "9b225a990bcde6022b94741866d67d08d1239080954bd43169a74a75c911ca95",
    }
    build_artifacts = runtime.get("build_artifacts", {})
    if not isinstance(build_artifacts, dict) or any(
        build_artifacts.get(key) != value
        for key, value in expected_build_artifacts.items()
    ):
        raise TopologyError("runtime build artifact hashes differ")
    model_roots = runtime.get("model_roots", {})
    if not isinstance(model_roots, dict) or any(
        model_roots.get(key) != expected_identity[key]
        for key in ("manifest_root", "tokenizer_root", "chat_template_root")
    ):
        raise TopologyError("runtime model roots differ from artifact identity")
    execution = runtime.get("execution", {})
    if (
        execution.get("text_only") is not True
        or execution.get("max_context_tokens") != 4096
        or execution.get("max_output_tokens") != 512
        or execution.get("attachments_allowed") is not False
        or execution.get("network_allowed") is not False
    ):
        raise TopologyError("runtime execution bounds are weakened")
    blocks = service_blocks(compose)
    required = set(topology.get("required_services", []))
    if set(blocks) != required:
        raise TopologyError("compose services differ from topology contract")
    service_networks = topology.get("service_networks")
    if not isinstance(service_networks, dict) or set(service_networks) != required:
        raise TopologyError("service-network map is incomplete")
    for service, networks in service_networks.items():
        match = re.search(r"networks: \[([^\]]+)\]", blocks[service])
        observed_networks = (
            [item.strip() for item in match.group(1).split(",")] if match else []
        )
        if len(observed_networks) != len(networks) or set(observed_networks) != set(networks):
            raise TopologyError(f"{service} networks differ from topology contract")
    public = set(topology.get("public_services", []))
    for service, block in blocks.items():
        has_ports = "\n    ports:\n" in block
        if has_ports != (service in public or service == "prometheus"):
            raise TopologyError(f"unexpected port exposure for {service}")
    if "networks: [control, monitoring]" not in blocks["executor"]:
        raise TopologyError("executor must be isolated from ingress, data, and artifact networks")
    manifest_texts = {"compose.yaml": compose}
    for name in (
        "compose.local.yaml",
        "compose.devnet.yaml",
        "compose.production.yaml",
    ):
        try:
            manifest_texts[name] = (deploy_dir / name).read_text(encoding="utf-8")
        except OSError as error:
            raise TopologyError(f"cannot read {name}: {error}") from error
    for name, text in manifest_texts.items():
        if FORBIDDEN_SECRET.search(text):
            raise TopologyError(f"{name} embeds secret material")
    if "${WWM_PRODUCTION_AUTHORIZATION_FILE:?" not in manifest_texts["compose.production.yaml"]:
        raise TopologyError("production override is not fail-closed on G5 authorization")
    for variable in topology.get("external_secret_variables", []):
        if f"${{{variable}:?" not in compose:
            raise TopologyError(f"compose does not require external secret {variable}")
    for variable in topology.get("immutable_image_variables", []):
        if f"${{{variable}:?" not in compose:
            raise TopologyError(f"compose does not require immutable image {variable}")
    blockers = topology.get("production_external_blockers")
    if not isinstance(blockers, list) or len(blockers) < 10 or not all(isinstance(row, str) and row for row in blockers):
        raise TopologyError("production external blockers are incomplete")
    return {
        "schema": topology["schema"],
        "verdict": "VALID_LOCAL_DEVNET_TOPOLOGY",
        "production_capable": False,
        "services": sorted(required),
        "production_external_blockers": blockers,
    }


def validate_environment(
    topology_path: Path,
    values: Mapping[str, str],
    *,
    repository_root: Path = ROOT,
) -> dict[str, Any]:
    topology = load_object(topology_path)
    missing: list[str] = []
    for variable in topology.get("immutable_image_variables", []):
        value = values.get(variable, "")
        if not IMAGE_REF.fullmatch(value):
            missing.append(f"{variable}: immutable image@sha256 reference required")
    for variable in topology.get("external_secret_variables", []):
        raw = values.get(variable, "")
        path = Path(raw) if raw else None
        if path is None or not path.is_absolute() or not path.is_file():
            missing.append(f"{variable}: existing absolute external file required")
            continue
        try:
            path.resolve().relative_to(repository_root.resolve())
        except ValueError:
            pass
        else:
            missing.append(f"{variable}: secret file must be outside the repository")
    if missing:
        raise TopologyError("; ".join(missing))
    return {"verdict": "ENVIRONMENT_VALID", "production_capable": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deploy-dir", type=Path, default=DEFAULT_DEPLOY)
    parser.add_argument("--check-environment", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = validate_static(args.deploy_dir)
        if args.check_environment:
            report["environment"] = validate_environment(
                args.deploy_dir / "topology.json", os.environ
            )
        print(json.dumps(report, sort_keys=True, separators=(",", ":")))
        return 0
    except TopologyError as error:
        print(
            json.dumps(
                {
                    "verdict": "BLOCKED",
                    "error": str(error),
                    "production_capable": False,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
