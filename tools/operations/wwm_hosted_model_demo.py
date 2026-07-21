#!/usr/bin/env python3
"""Run the fail-closed MindChain-hosted Bonsai devnet demonstration.

The command consumes a test-only JSON configuration, verifies every frozen
identity and local isolation precondition, reconstructs into a disposable
executor cache, drives 12 -> 9 -> 8 -> repaired custody admission, submits
ordinary transactions throughout, finalizes a fresh repair certificate, runs
one inference, streams machine-readable panel state, and seals signed evidence.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import http.server
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from blake3 import blake3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "gates"))
from differential_admission import (  # noqa: E402
    FAUCET_KEY,
    FAUCET_PUB,
    enc_intent,
    enc_witnesses,
    sign_txid,
)

SCHEMA = "noos/wwm-hosted-model-demo-config/v1"
EVIDENCE_SCHEMA = "noos.wwm.hosted-model-demo-evidence.v1"
PANEL_SCHEMA = "noos.wwm.hosted-model-demo-panel.v1"
PROOF_SCHEMA = "noos/wwm-executor-bootstrap-proof/v1"
ARTIFACT_ID = "d3d1bcf9f704c58c695d7c0837be25a5cfbd7ff71b440bfc9be4a4a46bb528b0"
MANIFEST_ROOT = "80f211eb4ebfd26df62bdeac69bc663ca97664eaf179188af78d1288aee42de7"
MODEL_SHA256 = "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0"
MODEL_BYTES = 3_803_452_480
ENCODED_BYTES = 5_707_063_296
SHARE_BYTES = 1_047_552
STRIPES = 454
POSITIONS = 12
RECONSTRUCTION_THRESHOLD = 8
SCHEDULABLE_MINIMUM = 9
POSITION_BYTES = 475_588_608
NOOS_ASSET = "00" * 32
MARKER_SIGNATURE_HEX = b"TESTNET_FIXTURE_ONLY".hex()
INFERENCE_MAX_OUTPUT_TOKENS = 16
HEX32 = re.compile(r"^[0-9a-f]{64}$")


class DemoError(RuntimeError):
    """Fail-closed operator error."""


@dataclass(frozen=True)
class Paths:
    cli: Path
    artifact_service: Path
    workerd: Path
    tokenizer: Path
    manifest: Path
    store_verification: Path
    workerd_template: Path
    disposable_root: Path
    cache: Path
    evidence_dir: Path
    panel_state: Path
    source_store_root: Path
    source_staging_root: Path
    source_consensus_root: Path
    replacement_consensus_root: Path


@dataclass(frozen=True)
class Network:
    node_rpc: str
    node_token: str
    artifact_url: str
    sidecar_url: str
    sidecar_token_hex: str
    proxy_host: str
    proxy_port_start: int


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise DemoError(f"cannot load {path}: {error}") from error
    if not isinstance(value, dict):
        raise DemoError(f"{path} must contain a JSON object")
    return value


def required_object(value: Mapping[str, Any], key: str) -> dict[str, Any]:
    item = value.get(key)
    if not isinstance(item, dict):
        raise DemoError(f"{key} must be an object")
    return item


def required_text(value: Mapping[str, Any], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise DemoError(f"{key} must be a non-empty string")
    return item


def required_int(value: Mapping[str, Any], key: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool):
        raise DemoError(f"{key} must be an integer")
    return item


def is_loopback_url(value: str) -> bool:
    try:
        parsed = urllib.parse.urlsplit(value)
    except ValueError:
        return False
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        return False
    return parsed.hostname in {"127.0.0.1", "::1", "localhost"} and parsed.port is not None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(8 * 1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def atomic_write(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".partial")
    with temporary.open("wb") as output:
        output.write(body)
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def validate_contract(config: Mapping[str, Any]) -> tuple[Paths, Network]:
    if config.get("schema") != SCHEMA:
        raise DemoError("unsupported hosted-model demo configuration schema")
    if config.get("environment") not in {"local", "devnet", "testnet"}:
        raise DemoError("demo refuses every non-test environment")
    if config.get("production") is not False:
        raise DemoError("demo configuration must explicitly set production=false")
    if config.get("publisher_or_gateway_fallback") is not False:
        raise DemoError("publisher_or_gateway_fallback must be false")
    if config.get("external_model_egress") != []:
        raise DemoError("external_model_egress must be an explicit empty list")
    tokenizer_sha256 = required_text(config, "tokenizer_executable_sha256")
    if not HEX32.fullmatch(tokenizer_sha256):
        raise DemoError("tokenizer_executable_sha256 must be canonical SHA-256")

    identities = required_object(config, "identities")
    expected = {
        "artifact_id": ARTIFACT_ID,
        "manifest_root": MANIFEST_ROOT,
        "model_sha256": MODEL_SHA256,
        "model_bytes": MODEL_BYTES,
        "encoded_bytes": ENCODED_BYTES,
        "positions": POSITIONS,
        "reconstruction_threshold": RECONSTRUCTION_THRESHOLD,
        "schedulable_minimum": SCHEDULABLE_MINIMUM,
    }
    for key, expected_value in expected.items():
        if identities.get(key) != expected_value:
            raise DemoError(f"frozen identity mismatch: {key}")

    path_config = required_object(config, "paths")
    paths = Paths(
        cli=Path(required_text(path_config, "cli")),
        artifact_service=Path(required_text(path_config, "artifact_service")),
        workerd=Path(required_text(path_config, "workerd")),
        tokenizer=Path(required_text(path_config, "tokenizer")),
        manifest=Path(required_text(path_config, "manifest")),
        store_verification=Path(required_text(path_config, "store_verification")),
        workerd_template=Path(required_text(path_config, "workerd_template")),
        disposable_root=Path(required_text(path_config, "disposable_root")),
        cache=Path(required_text(path_config, "cache")),
        evidence_dir=Path(required_text(path_config, "evidence_dir")),
        panel_state=Path(required_text(path_config, "panel_state")),
        source_store_root=Path(required_text(path_config, "source_store_root")),
        source_staging_root=Path(required_text(path_config, "source_staging_root")),
        source_consensus_root=Path(required_text(path_config, "source_consensus_root")),
        replacement_consensus_root=Path(required_text(path_config, "replacement_consensus_root")),
    )
    disposable = paths.disposable_root.resolve()
    cache = paths.cache.resolve()
    try:
        cache.relative_to(disposable)
    except ValueError as error:
        raise DemoError("executor cache is outside disposable_root") from error
    if cache == disposable:
        raise DemoError("executor cache cannot equal disposable_root")
    if cache.parent == disposable:
        raise DemoError("executor cache must use a dedicated directory under disposable_root")
    source_root = paths.source_store_root.resolve()
    if source_root == disposable or source_root.is_relative_to(disposable):
        raise DemoError("canonical source store cannot be under disposable_root")

    network_config = required_object(config, "network")
    network = Network(
        node_rpc=required_text(network_config, "node_rpc").rstrip("/"),
        node_token=required_text(network_config, "node_token"),
        artifact_url=required_text(network_config, "artifact_url").rstrip("/"),
        sidecar_url=required_text(network_config, "sidecar_url").rstrip("/"),
        sidecar_token_hex=required_text(network_config, "sidecar_token_hex"),
        proxy_host=required_text(network_config, "proxy_host"),
        proxy_port_start=required_int(network_config, "proxy_port_start"),
    )
    for label, url in {
        "node_rpc": network.node_rpc,
        "artifact_url": network.artifact_url,
        "sidecar_url": network.sidecar_url,
    }.items():
        if not is_loopback_url(url):
            raise DemoError(f"{label} must be an explicit loopback HTTP URL")
    if network.proxy_host not in {"127.0.0.1", "::1", "localhost"}:
        raise DemoError("custodian proxy host must be loopback")
    if not 1024 <= network.proxy_port_start <= 65_523:
        raise DemoError("proxy_port_start cannot provide twelve valid ports")
    if not HEX32.fullmatch(network.sidecar_token_hex):
        raise DemoError("sidecar_token_hex must be canonical hex32")

    governance = required_object(config, "governance")
    seed = required_text(governance, "seed_hex")
    account = required_text(governance, "account_id")
    if not HEX32.fullmatch(seed) or not HEX32.fullmatch(account):
        raise DemoError("test governance seed/account must be canonical hex32")
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed))
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    if public.hex() != account:
        raise DemoError("test governance seed does not derive configured account")
    return paths, network


def verify_operator_capabilities(paths: Paths) -> dict[str, Any]:
    capabilities = run_json(paths.cli, ("wwm", "devnet", "capabilities"))
    if (
        capabilities.get("schema") != "noos/wwm-devnet-operator-capabilities/v1"
        or capabilities.get("typed_open_wwm_job") is not True
        or capabilities.get("typed_record_wwm_receipt") is not True
        or capabilities.get("typed_settle_wwm_job") is not True
        or capabilities.get("finalized_record_route") != "/wwm-record/{kind}/{id}"
        or capabilities.get("production_capable") is not False
    ):
        raise DemoError("noos-cli lacks the bounded devnet WWM settlement operator path")
    return capabilities


def repository_revision() -> str:
    process = subprocess.run(
        ("git", "rev-parse", "HEAD"),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    revision = process.stdout.strip()
    if process.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise DemoError("unable to bind evidence to the repository revision")
    return revision


def verify_prerequisites(config: Mapping[str, Any], paths: Paths) -> dict[str, Any]:
    for label, path in {
        "noos-cli": paths.cli,
        "noos-artifact-service": paths.artifact_service,
        "noos-workerd": paths.workerd,
        "llama-tokenize": paths.tokenizer,
        "artifact manifest": paths.manifest,
        "store verification": paths.store_verification,
        "workerd template": paths.workerd_template,
    }.items():
        if not path.is_file():
            raise DemoError(f"missing {label}: {path}")
    report = dict(load_object(paths.store_verification))
    if (
        report.get("schema") != "noos.wwm.artifact-store-verification.v1"
        or report.get("artifact_id") != ARTIFACT_ID
        or report.get("manifest_root") != MANIFEST_ROOT
        or report.get("published_sha256") != MODEL_SHA256
        or report.get("source_bytes") != MODEL_BYTES
        or report.get("encoded_share_bytes") != ENCODED_BYTES
        or report.get("verified_share_count") != STRIPES * POSITIONS
        or report.get("published") is not True
    ):
        raise DemoError("artifact store verification is not the exact published Bonsai store")
    roots = report.get("position_roots")
    if not isinstance(roots, list) or len(roots) != POSITIONS or not all(
        isinstance(root, str) and HEX32.fullmatch(root) for root in roots
    ):
        raise DemoError("store verification lacks twelve canonical position roots")
    template = paths.workerd_template.read_text(encoding="utf-8")
    if "LLAMA_CURL=OFF" not in template:
        raise DemoError("executor runtime template does not disable curl")
    forbidden = ("huggingface.co", "hf.co", "github.com", "publisher_url", "gateway_fallback")
    lowered = template.lower()
    if any(value in lowered for value in forbidden):
        raise DemoError("executor template contains a publisher, upstream, or gateway route")
    tokenizer_sha256 = sha256_file(paths.tokenizer)
    if tokenizer_sha256 != required_text(config, "tokenizer_executable_sha256"):
        raise DemoError("llama-tokenize executable hash does not match the pinned config")
    report["operator_capabilities"] = verify_operator_capabilities(paths)
    report["repository_revision"] = repository_revision()
    report["executable_sha256"] = {
        "noos_cli": sha256_file(paths.cli),
        "noos_artifact_service": sha256_file(paths.artifact_service),
        "noos_workerd": sha256_file(paths.workerd),
        "llama_tokenize": tokenizer_sha256,
    }
    return report


def clear_disposable_cache(paths: Paths) -> None:
    cache = paths.cache.resolve()
    disposable = paths.disposable_root.resolve()
    cache.relative_to(disposable)
    cache.parent.mkdir(parents=True, exist_ok=True)
    for candidate in (cache, cache.with_suffix(cache.suffix + ".partial")):
        if candidate.exists():
            candidate.chmod(0o600)
            candidate.unlink()


def http_json(
    url: str,
    token: str | None = None,
    *,
    method: str = "GET",
    body: Mapping[str, Any] | None = None,
    timeout: float = 30,
) -> dict[str, Any]:
    payload = None if body is None else json.dumps(body, separators=(",", ":")).encode()
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if payload is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=payload, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            value = json.loads(response.read())
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            detail = json.loads(raw)
        except json.JSONDecodeError:
            detail = {"body": raw.decode("utf-8", "replace")}
        raise DemoError(f"HTTP {error.code} {url}: {json.dumps(detail, sort_keys=True)}") from error
    except (OSError, json.JSONDecodeError) as error:
        raise DemoError(f"HTTP failure {url}: {error}") from error
    if not isinstance(value, dict):
        raise DemoError(f"HTTP response {url} is not an object")
    return value


def capture_http(
    url: str,
    token: str,
    body: Mapping[str, Any],
    timeout: float = 30,
) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        data=json.dumps(body, separators=(",", ":")).encode(),
        method="POST",
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return {"status": response.status, "body": json.loads(response.read())}
    except urllib.error.HTTPError as error:
        raw = error.read()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = {"body": raw.decode("utf-8", "replace")}
        return {"status": error.code, "body": parsed}


def run_json(executable: Path, args: Sequence[str], timeout: float = 60) -> dict[str, Any]:
    process = subprocess.run(
        [str(executable), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if process.returncode != 0:
        raise DemoError(
            f"{executable.name} {' '.join(args[:3])} failed: {process.stderr.strip()}"
        )
    try:
        value = json.loads(process.stdout)
    except json.JSONDecodeError as error:
        raise DemoError(f"{executable.name} returned non-JSON output") from error
    if not isinstance(value, dict):
        raise DemoError(f"{executable.name} returned a non-object")
    return value


def wait_port(url: str, process: subprocess.Popen[bytes], timeout: float = 180) -> None:
    parsed = urllib.parse.urlsplit(url)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise DemoError(f"executor exited during startup with code {process.returncode}")
        try:
            with socket.create_connection((parsed.hostname or "127.0.0.1", parsed.port or 0), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    raise DemoError("executor sidecar did not become ready")


def wait_receipt(network: Network, txid: str, timeout: float = 60) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        receipt = http_json(f"{network.node_rpc}/receipt/{txid}", network.node_token)
        state = receipt.get("state")
        if isinstance(state, dict) and isinstance(state.get("settled_height"), int):
            return receipt
        time.sleep(0.05)
    raise DemoError(f"transaction did not settle: {txid}")


def wait_finalized(network: Network, height: int, timeout: float = 3_600) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = http_json(f"{network.node_rpc}/status", network.node_token)
        finalized = status.get("finalized")
        if isinstance(finalized, dict) and isinstance(finalized.get("epoch"), int):
            if finalized["epoch"] * 256 >= height:
                return status
        time.sleep(0.1)
    raise DemoError(f"finality did not cover height {height}")


def build_and_submit(
    paths: Paths,
    network: Network,
    status: Mapping[str, Any],
    spec: Mapping[str, Any],
    signers: Sequence[tuple[bytes, Ed25519PrivateKey]],
    on_submitted: Callable[[str], None] | None = None,
) -> tuple[str, dict[str, Any]]:
    spec_path = paths.disposable_root / "transactions" / f"{time.time_ns()}.json"
    atomic_write(spec_path, json.dumps(spec, separators=(",", ":")).encode())
    built = run_json(paths.cli, ("tx", "build", "--spec-file", str(spec_path)))
    txid = required_text(built, "txid")
    tx = required_text(built, "tx")
    txid_bytes = bytes.fromhex(txid)
    ordered = sorted(signers, key=lambda entry: entry[0])
    witnesses = enc_witnesses(
        [enc_intent(txid_bytes, sign_txid(key, txid_bytes)) for _, key in ordered]
    ).hex()
    submitted = run_json(
        paths.cli,
        (
            "tx",
            "submit",
            "--node",
            urllib.parse.urlsplit(network.node_rpc).netloc,
            "--token",
            network.node_token,
            "--chain-id",
            required_text(status, "chain_id"),
            "--genesis-hash",
            required_text(status, "genesis_hash"),
            "--tx",
            tx,
            "--witnesses",
            witnesses,
        ),
    )
    if submitted.get("accepted") is not True or submitted.get("txid") != txid:
        raise DemoError("node did not accept the exact built transaction")
    if on_submitted is not None:
        on_submitted(txid)
    return txid, wait_receipt(network, txid)


def finalize_wwm_submission(
    network: Network,
    txid: str,
    *,
    receipt_timeout: float = 600,
) -> dict[str, Any]:
    if not isinstance(txid, str) or HEX32.fullmatch(txid) is None:
        raise DemoError("submitted transaction id must be canonical hex32")
    receipt = wait_receipt(network, txid, timeout=receipt_timeout)
    settled_height = required_int(required_object(receipt, "state"), "settled_height")
    return {
        "txid": txid,
        "receipt": receipt,
        "finalized_height": settled_height,
        "finalized_status": wait_finalized(network, settled_height),
    }


def submit_transfer(paths: Paths, network: Network, label: str) -> dict[str, Any]:
    status = http_json(f"{network.node_rpc}/status", network.node_token)
    head = required_object(status, "unsafe_head")
    expiry = required_int(head, "height") + 5_000
    spec = {
        "chain_id": required_text(status, "chain_id"),
        "expiry_height": expiry,
        "fee_payer": FAUCET_PUB.hex(),
        "resource_limits": {
            "bytes": 4096,
            "grain_steps": 0,
            "proof_units": 0,
            "blob_bytes": 0,
            "state_reads": 64,
            "state_writes": 64,
        },
        "account_inputs": [FAUCET_PUB.hex()],
        "actions": [
            {
                "type": "withdraw_from_account",
                "account_id": FAUCET_PUB.hex(),
                "asset_id": NOOS_ASSET,
                "amount": "1",
            },
            {
                "type": "deposit_to_account",
                "account_id": FAUCET_PUB.hex(),
                "asset_id": NOOS_ASSET,
                "amount": "1",
            },
        ],
    }
    txid, receipt = build_and_submit(paths, network, status, spec, ((FAUCET_PUB, FAUCET_KEY),))
    return {"label": label, "txid": txid, "receipt": receipt}


def deterministic_id(run_id: str, label: str) -> str:
    return hashlib.sha256(f"{run_id}:{label}".encode()).hexdigest()

def submit_wwm_actions(
    config: Mapping[str, Any],
    paths: Paths,
    network: Network,
    actions: Sequence[Mapping[str, Any]],
    on_submitted: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    if not actions or len(actions) > 8:
        raise DemoError("WWM action batch must contain 1..8 actions")
    status = http_json(f"{network.node_rpc}/status", network.node_token)
    head = required_object(status, "unsafe_head")
    governance = required_object(config, "governance")
    governance_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(required_text(governance, "seed_hex"))
    )
    governance_account = bytes.fromhex(required_text(governance, "account_id"))
    encoded_actions: list[str] = []
    action_ids: list[str] = []
    for index, action in enumerate(actions):
        action_path = (
            paths.disposable_root
            / "transactions"
            / f"{time.time_ns()}-{index}-wwm-action.json"
        )
        atomic_write(action_path, json.dumps(action, separators=(",", ":")).encode())
        encoded_action = run_json(
            paths.cli,
            ("wwm", "devnet", "action", "--spec-file", str(action_path)),
        )
        id_field = {
            "open_wwm_job": "job_id",
            "record_wwm_receipt": "receipt_id",
            "settle_wwm_job": "settlement_id",
        }.get(action.get("type"))
        if id_field is None:
            raise DemoError("WWM action batch contains an unsupported action")
        expected_id = action.get(id_field)
        if (
            not isinstance(expected_id, str)
            or not HEX32.fullmatch(expected_id)
            or encoded_action.get("schema") != "noos/wwm-devnet-operator-action/v1"
            or encoded_action.get("production_capable") is not False
            or encoded_action.get("id") != expected_id
            or not isinstance(encoded_action.get("action"), str)
        ):
            raise DemoError("typed WWM devnet action builder is unavailable")
        encoded_actions.append(encoded_action["action"])
        action_ids.append(expected_id)
    action_count = len(encoded_actions)
    spec = {
        "chain_id": required_text(status, "chain_id"),
        "expiry_height": required_int(head, "height") + 5_000,
        "fee_payer": FAUCET_PUB.hex(),
        "resource_limits": {
            "bytes": 65_536 * action_count,
            "grain_steps": 0,
            "proof_units": 64 * action_count,
            "blob_bytes": 0,
            "state_reads": 128 * action_count,
            "state_writes": 128 * action_count,
        },
        "account_inputs": sorted([governance_account.hex(), FAUCET_PUB.hex()]),
        "actions": encoded_actions,
    }
    txid, receipt = build_and_submit(
        paths,
        network,
        status,
        spec,
        ((governance_account, governance_key), (FAUCET_PUB, FAUCET_KEY)),
        on_submitted,
    )
    settled_height = required_int(required_object(receipt, "state"), "settled_height")
    finalized_status = wait_finalized(network, settled_height)
    return {
        "txid": txid,
        "receipt": receipt,
        "action_ids": action_ids,
        "finalized_height": settled_height,
        "finalized_status": finalized_status,
    }


def submit_wwm_action(
    config: Mapping[str, Any],
    paths: Paths,
    network: Network,
    action: Mapping[str, Any],
    on_submitted: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    return submit_wwm_actions(config, paths, network, (action,), on_submitted)


def finalized_wwm_record(
    network: Network,
    kind: str,
    identifier: str,
    expected: Mapping[str, str],
) -> dict[str, Any]:
    value = http_json(
        f"{network.node_rpc}/wwm-record/{kind}/{identifier}",
        network.node_token,
        timeout=180,
    )
    record = required_object(value, "record")
    if (
        value.get("schema") != "noos/finalized-wwm-record/v1"
        or value.get("kind") != kind
        or value.get("id") != identifier
        or not isinstance(value.get("finalized_height"), int)
        or not HEX32.fullmatch(str(value.get("finalized_hash", "")))
        or not HEX32.fullmatch(str(value.get("objects_root", "")))
        or not isinstance(value.get("canonical_record_hex"), str)
        or not isinstance(value.get("proof_hex"), str)
    ):
        raise DemoError(f"node did not return a finalized canonical {kind} record")
    for key, expected_value in expected.items():
        if record.get(key) != expected_value:
            raise DemoError(f"finalized {kind} identity mismatch: {key}")
    return value


def submit_repair_certificate(
    config: Mapping[str, Any],
    paths: Paths,
    network: Network,
    active: Mapping[str, Any],
    position_roots: Sequence[str],
    run_id: str,
) -> dict[str, Any]:
    status = http_json(f"{network.node_rpc}/status", network.node_token)
    head = required_int(required_object(status, "unsafe_head"), "height")
    profiles = active.get("custodian_profiles")
    verifiers = active.get("selected_verifiers")
    signer_ids = active.get("certificate_signer_ids")
    if not isinstance(profiles, list) or len(profiles) != POSITIONS:
        raise DemoError("resolution lacks twelve custodian profiles")
    if not isinstance(verifiers, list) or len(verifiers) != 8:
        raise DemoError("resolution lacks exact verifier selection")
    if not isinstance(signer_ids, list) or len(signer_ids) != 5:
        raise DemoError("resolution lacks exact certificate signer set")
    source_positions = list(range(4, 12))
    actions: list[dict[str, Any]] = []
    source_ids: list[str] = []
    for position in source_positions:
        commitment_id = deterministic_id(run_id, f"source-commitment-{position}")
        source_ids.append(commitment_id)
        profile = profiles[position]
        actions.append(
            {
                "type": "commit_custody_positions",
                "commitment_id": commitment_id,
                "policy_id": active["availability_policy_id"],
                "artifact_id": ARTIFACT_ID,
                "position": position,
                "custodian_profile_id": profile["profile_id"],
                "custodian_set_id": active["custodian_set_id"],
                "custodian_set_epoch": active["custodian_set_epoch"],
                "position_root": position_roots[position],
                "committed_bytes": POSITION_BYTES,
                "valid_from": head,
                "valid_until": 2**64 - 1,
                "nonce": 1_000 + position,
                "signature": MARKER_SIGNATURE_HEX,
            }
        )
    prior_commitment = deterministic_id(run_id, "prior-position-3")
    actions.append(
        {
            "type": "commit_custody_positions",
            "commitment_id": prior_commitment,
            "policy_id": active["availability_policy_id"],
            "artifact_id": ARTIFACT_ID,
            "position": 3,
            "custodian_profile_id": profiles[3]["profile_id"],
            "custodian_set_id": active["custodian_set_id"],
            "custodian_set_epoch": active["custodian_set_epoch"],
            "position_root": position_roots[3],
            "committed_bytes": POSITION_BYTES,
            "valid_from": 0,
            "valid_until": 2**64 - 1,
            "nonce": 3,
            "signature": MARKER_SIGNATURE_HEX,
        }
    )
    replacement_commitment = deterministic_id(run_id, "replacement-position-3-profile-0")
    actions.append(
        {
            "type": "commit_custody_positions",
            "commitment_id": replacement_commitment,
            "policy_id": active["availability_policy_id"],
            "artifact_id": ARTIFACT_ID,
            "position": 3,
            "custodian_profile_id": profiles[0]["profile_id"],
            "custodian_set_id": active["custodian_set_id"],
            "custodian_set_epoch": active["custodian_set_epoch"],
            "position_root": position_roots[3],
            "committed_bytes": POSITION_BYTES,
            "valid_from": head,
            "valid_until": 2**64 - 1,
            "nonce": 2_003,
            "signature": MARKER_SIGNATURE_HEX,
        }
    )
    source_root = deterministic_id(run_id, "sources-4-through-11")
    order_id = deterministic_id(run_id, "repair-order-position-3")
    certificate_id = deterministic_id(run_id, f"availability-certificate-{head}")
    repair_id = deterministic_id(run_id, "repair-receipt-position-3")
    assignment_root = deterministic_id(run_id, "assignment-swap-positions-0-3")
    actions.extend(
        [
            {
                "type": "record_artifact_repair_order",
                "order_id": order_id,
                "policy_id": active["availability_policy_id"],
                "artifact_id": ARTIFACT_ID,
                "position": 3,
                "prior_commitment_id": prior_commitment,
                "replacement_profile_id": profiles[0]["profile_id"],
                "source_commitment_ids": sorted(source_ids),
                "source_positions": source_positions,
                "source_positions_root": source_root,
                "expected_position_root": position_roots[3],
                "issued_height": head,
                "deadline_height": head + 5_000,
                "authority_epoch": 1,
                "nonce": 1,
                "signature": MARKER_SIGNATURE_HEX,
            },
            {
                "type": "issue_availability_certificate",
                "certificate_id": certificate_id,
                "policy_id": active["availability_policy_id"],
                "artifact_id": ARTIFACT_ID,
                "custodian_set_id": active["custodian_set_id"],
                "custodian_set_root": active["custodian_set_root"],
                "custodian_set_epoch": active["custodian_set_epoch"],
                "executor_set_id": active["executor_set_id"],
                "executor_set_root": active["executor_set_root"],
                "executor_set_epoch": active["executor_set_epoch"],
                "assignment_root": assignment_root,
                "diversity_root": deterministic_id(run_id, "repair-diversity"),
                "challenge_root": deterministic_id(run_id, "repair-challenge"),
                "selected_verifiers": verifiers,
                "signer_ids": signer_ids,
                "result_root": deterministic_id(run_id, "repaired-nine-live"),
                "availability_state": 0,
                "issued_height": head,
                "valid_until": head + 100_000,
                "signatures": [
                    {"signer_id": signer_id, "signature": MARKER_SIGNATURE_HEX}
                    for signer_id in signer_ids
                ],
            },
            {
                "type": "record_artifact_repair_receipt",
                "repair_id": repair_id,
                "order_id": order_id,
                "policy_id": active["availability_policy_id"],
                "artifact_id": ARTIFACT_ID,
                "position": 3,
                "prior_commitment_id": prior_commitment,
                "new_commitment_id": replacement_commitment,
                "source_positions_root": source_root,
                "new_position_root": position_roots[3],
                "durable_commit_root": deterministic_id(run_id, "repair-durable"),
                "certificate_id": certificate_id,
                "bytes_read": 8 * POSITION_BYTES,
                "bytes_written": POSITION_BYTES,
                "evidence_root": deterministic_id(run_id, "repair-evidence"),
                "signer_id": profiles[0]["profile_id"],
                "completed_height": head + 1,
                "signature": MARKER_SIGNATURE_HEX,
            },
        ]
    )
    governance = required_object(config, "governance")
    governance_key = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(required_text(governance, "seed_hex"))
    )
    governance_public = bytes.fromhex(required_text(governance, "account_id"))
    spec = {
        "chain_id": status["chain_id"],
        "expiry_height": head + 5_000,
        "fee_payer": FAUCET_PUB.hex(),
        "resource_limits": {
            "bytes": 65_536,
            "grain_steps": 100_000,
            "proof_units": 64,
            "state_reads": 64,
            "state_writes": 64,
            "blob_bytes": 0,
        },
        "account_inputs": sorted([governance_public.hex(), FAUCET_PUB.hex()]),
        "actions": actions,
    }
    txid, receipt = build_and_submit(
        paths,
        network,
        status,
        spec,
        ((governance_public, governance_key), (FAUCET_PUB, FAUCET_KEY)),
    )
    settled_height = required_int(required_object(receipt, "state"), "settled_height")
    wait_finalized(network, settled_height)
    return {
        "txid": txid,
        "receipt": receipt,
        "order_id": order_id,
        "repair_id": repair_id,
        "certificate_id": certificate_id,
        "assignment_root": assignment_root,
        "replacement_profile_id": profiles[0]["profile_id"],
        "old_profile_id": profiles[3]["profile_id"],
        "replacement_commitment_id": replacement_commitment,
    }


class CustodianMatrix:
    def __init__(
        self,
        host: str,
        port_start: int,
        upstream: str,
        replacement_root: Path,
    ) -> None:
        self.host = host
        self.port_start = port_start
        self.upstream = urllib.parse.urlsplit(upstream)
        self.replacement_root = replacement_root
        self.online = {position: True for position in range(POSITIONS)}
        self.replacement = {position: False for position in range(POSITIONS)}
        self.headers: dict[int, dict[str, str]] = {}
        self.servers: list[http.server.ThreadingHTTPServer] = []
        self._prime_headers()

    def _prime_headers(self) -> None:
        for position in range(POSITIONS):
            request = urllib.request.Request(
                f"{self.upstream.geturl()}/artifacts/{MANIFEST_ROOT}/shares/0/{position}",
                method="HEAD",
            )
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status != 200 or int(response.headers.get("Content-Length", "0")) != SHARE_BYTES:
                    raise DemoError(f"upstream position {position} failed immutable HEAD probe")
                self.headers[position] = {
                    key.lower(): value for key, value in response.headers.items()
                }

    def base_url(self, position: int) -> str:
        return f"http://{self.host}:{self.port_start + position}"

    def start(self) -> None:
        matrix = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_args: object) -> None:
                return

            def do_HEAD(self) -> None:  # noqa: N802
                self._serve(True)

            def do_GET(self) -> None:  # noqa: N802
                self._serve(False)

            def _serve(self, head_only: bool) -> None:
                position = int(getattr(self.server, "custodian_position"))
                if not matrix.online[position]:
                    self.send_response(503)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                prefix = f"/artifacts/{MANIFEST_ROOT}/shares/"
                if not self.path.startswith(prefix):
                    self.send_error(404)
                    return
                pieces = self.path[len(prefix) :].split("/")
                if (
                    len(pieces) != 2
                    or not pieces[0].isdigit()
                    or not pieces[1].isdigit()
                    or int(pieces[1]) != position
                ):
                    self.send_error(404)
                    return
                stripe = int(pieces[0])
                if stripe >= STRIPES:
                    self.send_error(404)
                    return
                if matrix.replacement[position]:
                    matrix._serve_replacement(self, stripe, position, head_only)
                else:
                    matrix._forward(self, head_only)

        for position in range(POSITIONS):
            server = http.server.ThreadingHTTPServer(
                (self.host, self.port_start + position), Handler
            )
            setattr(server, "custodian_position", position)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.servers.append(server)

    def stop(self) -> None:
        for server in self.servers:
            server.shutdown()
            server.server_close()
        self.servers.clear()

    def set_offline(self, positions: Sequence[int]) -> None:
        for position in positions:
            self.online[position] = False

    def enable_replacement(self, position: int) -> None:
        self.replacement[position] = True
        self.online[position] = True

    def _serve_replacement(
        self,
        handler: http.server.BaseHTTPRequestHandler,
        stripe: int,
        position: int,
        head_only: bool,
    ) -> None:
        if position != 3:
            handler.send_error(404)
            return
        path = (
            self.replacement_root
            / "segments"
            / ARTIFACT_ID
            / f"{stripe:08d}-{position:02d}.share"
        )
        frame = path.read_bytes()
        if len(frame) < 36:
            handler.send_error(500)
            return
        length = int.from_bytes(frame[:4], "little")
        payload = frame[36:]
        if length != SHARE_BYTES or len(payload) != length or blake3(payload).digest() != frame[4:36]:
            handler.send_error(500)
            return
        handler.send_response(200)
        handler.send_header("Content-Length", str(length))
        handler.send_header("Content-Type", "application/octet-stream")
        handler.send_header("Accept-Ranges", "bytes")
        handler.send_header("ETag", self.headers[position]["etag"])
        handler.send_header("Cache-Control", "public, max-age=31536000, immutable")
        handler.send_header("Access-Control-Allow-Origin", "*")
        handler.end_headers()
        if not head_only:
            handler.wfile.write(payload)

    def _forward(
        self,
        handler: http.server.BaseHTTPRequestHandler,
        head_only: bool,
    ) -> None:
        connection = http.client.HTTPConnection(
            self.upstream.hostname,
            self.upstream.port,
            timeout=60,
        )
        try:
            connection.request("HEAD" if head_only else "GET", handler.path)
            response = connection.getresponse()
            body = b"" if head_only else response.read()
            handler.send_response(response.status)
            for name in (
                "Content-Length",
                "Content-Type",
                "Content-Range",
                "Accept-Ranges",
                "ETag",
                "Cache-Control",
                "Access-Control-Allow-Origin",
                "X-Noos-Probe-Root",
            ):
                value = response.getheader(name)
                if value is not None:
                    handler.send_header(name, value)
            handler.end_headers()
            if not head_only and body:
                handler.wfile.write(body)
        finally:
            connection.close()


def write_resolution_proof(path: Path, resolution: Mapping[str, Any]) -> None:
    body = {
        "schema": PROOF_SCHEMA,
        "canonical_resolution_body_hex": required_text(resolution, "canonical_resolution_body_hex"),
    }
    atomic_write(path, json.dumps(body, separators=(",", ":")).encode())


def write_custodian_map(
    path: Path,
    profiles: Sequence[Mapping[str, Any]],
    matrix: CustodianMatrix,
    assignment: Sequence[int],
) -> None:
    if sorted(assignment) != list(range(POSITIONS)):
        raise DemoError("custodian assignment must be a permutation of twelve profiles")
    rows = []
    for position, profile_index in enumerate(assignment):
        profile = profiles[profile_index]
        rows.append(
            {
                "position": position,
                "base_url": matrix.base_url(position),
                "profile_id": required_text(profile, "profile_id"),
                "endpoint_root": required_text(profile, "endpoint_root"),
            }
        )
    atomic_write(path, json.dumps(rows, indent=2, sort_keys=True).encode())


def patch_executor_config(
    template: Path,
    output: Path,
    paths: Paths,
    network: Network,
    resolution: Mapping[str, Any],
    proof_path: Path,
    map_path: Path,
    scratch: Path,
    drain: Path,
) -> None:
    active = required_object(resolution, "active")
    height = required_int(resolution, "finalized_height")
    replacements: dict[str, str | int] = {
        "genesis_hash_hex": required_text(resolution, "genesis_hash"),
        "sidecar_token_hex": network.sidecar_token_hex,
        "listen": f"tcp://{urllib.parse.urlsplit(network.sidecar_url).netloc}",
        "scratch_dir": scratch.as_posix(),
        "drain_file": drain.as_posix(),
        "path": paths.cache.as_posix(),
        "manifest_path": paths.manifest.as_posix(),
        "custodian_map_path": map_path.as_posix(),
        "finalized_resolution_path": proof_path.as_posix(),
        "trusted_checkpoint_epoch": height // 256,
        "trusted_checkpoint_height": height,
        "trusted_checkpoint_hash_hex": required_text(resolution, "finalized_hash"),
        "current_finalized_height": height,
        "certificate_id_hex": required_text(active, "availability_certificate_id"),
    }
    text = template.read_text(encoding="utf-8")
    for key, value in replacements.items():
        rendered = f'"{value}"' if isinstance(value, str) else str(value)
        pattern = re.compile(rf"(?m)^(\s*{re.escape(key)}\s*=\s*).*$")
        text, count = pattern.subn(rf"\g<1>{rendered}", text, count=1)
        if count != 1:
            raise DemoError(f"workerd template lacks unique {key}")
    atomic_write(output, text.encode())


def start_executor(paths: Paths, network: Network, config_path: Path, log_path: Path) -> subprocess.Popen[bytes]:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log = log_path.open("wb")
    process = subprocess.Popen(
        [str(paths.workerd), "serve", "--config", str(config_path)],
        cwd=ROOT,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    setattr(process, "_noos_log", log)
    try:
        wait_port(network.sidecar_url, process, timeout=900)
    except Exception:
        stop_executor(process)
        raise
    return process


def stop_executor(process: subprocess.Popen[bytes] | None) -> None:
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
    log = getattr(process, "_noos_log", None)
    if log is not None:
        log.close()

def tokenize_output(
    paths: Paths,
    output: bytes,
    max_output_tokens: int,
    expected_executable_sha256: str,
) -> dict[str, Any]:
    if not paths.cache.is_file():
        raise DemoError("tokenization requires the reconstructed read-only model")
    executable_sha256 = sha256_file(paths.tokenizer)
    if executable_sha256 != expected_executable_sha256:
        raise DemoError("llama-tokenize changed after prerequisite verification")
    environment = os.environ.copy()
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        environment[key] = ""
    environment["NO_PROXY"] = "*"
    process = subprocess.run(
        (
            str(paths.tokenizer),
            "--model",
            str(paths.cache),
            "--stdin",
            "--ids",
            "--no-bos",
        ),
        input=output,
        capture_output=True,
        check=False,
        timeout=300,
        env=environment,
    )
    if process.returncode != 0:
        detail = process.stderr.decode("utf-8", "replace")[:512]
        raise DemoError(f"pinned offline llama-tokenize failed: {detail}")
    if len(process.stdout) > 1024 * 1024:
        raise DemoError("llama-tokenize output exceeds the bounded ID response")
    try:
        encoded_ids = process.stdout.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise DemoError("llama-tokenize emitted non-ASCII token IDs") from error
    if not re.fullmatch(r"\[?\s*\d+(?:[\s,]+\d+)*\s*\]?", encoded_ids):
        raise DemoError("llama-tokenize emitted a non-canonical token ID list")
    token_ids = [int(value) for value in re.findall(r"\d+", encoded_ids)]
    if not token_ids or any(value > 0xFFFF_FFFF for value in token_ids):
        raise DemoError("llama-tokenize emitted an invalid token ID")
    history = bytearray(b"NOOS/WWM/LLAMA-TOKEN-HISTORY/V1\0")
    history.extend(len(token_ids).to_bytes(4, "little"))
    if len(token_ids) > max_output_tokens:
        raise DemoError("independent tokenizer exceeded the job max_output_tokens bound")
    for token_id in token_ids:
        history.extend(token_id.to_bytes(4, "little"))
    return {
        "token_count": len(token_ids),
        "token_history_root": blake3(bytes(history)).hexdigest(),
        "tokenizer_executable_sha256": executable_sha256,
        "stdin_bytes": len(output),
        "bos_included": False,
    }



def quote(network: Network) -> dict[str, Any]:
    return http_json(
        f"{network.sidecar_url}/internal/wwm/v1/capacity-quotes",
        network.sidecar_token_hex,
        method="POST",
        body={"prompt_tokens": 1, "max_output_tokens": 8},
    )
def run_inference(
    paths: Paths,
    network: Network,
    job_id: str,
    tokenizer_executable_sha256: str,
) -> dict[str, Any]:

    submitted = http_json(
        f"{network.sidecar_url}/internal/wwm/v1/jobs",
        network.sidecar_token_hex,
        method="POST",
        body={
            "job_id": job_id,
            "prompt": "Answer with one word: resilient",
            "prompt_token_ids": [1, 2, 3, 4],
            "runtime_token_ids": [1, 2, 3, 4],
            "max_output_tokens": INFERENCE_MAX_OUTPUT_TOKENS,
        },
    )
    stream_path = required_text(submitted, "stream")
    request = urllib.request.Request(
        f"{network.sidecar_url}{stream_path}",
        headers={
            "Authorization": f"Bearer {network.sidecar_token_hex}",
            "Accept": "text/event-stream",
        },
    )
    events: list[dict[str, Any]] = []
    started = time.monotonic()
    with urllib.request.urlopen(request, timeout=180) as response:
        while True:
            line = response.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").strip()
            if text.startswith("data:"):
                event = json.loads(text[5:].strip())
                if not isinstance(event, dict):
                    raise DemoError("executor stream emitted a non-object event")
                events.append(event)
                if event.get("type") == "terminal":
                    break
    if not events or events[-1].get("code") != "completed":
        raise DemoError("repaired executor inference did not complete")
    terminal = events[-1]
    output_root = terminal.get("output_root")
    if not isinstance(output_root, str) or not HEX32.fullmatch(output_root):
        raise DemoError("executor terminal event lacks a canonical output commitment")
    output = bytearray()
    expected_sequence = 1
    for event in events:
        if event.get("type") != "token_bytes":
            continue
        sequence = event.get("sequence")
        bytes_hex = event.get("bytes_hex")
        incremental_root = event.get("incremental_root")
        if (
            sequence != expected_sequence
            or not isinstance(bytes_hex, str)
            or len(bytes_hex) % 2 != 0
            or not re.fullmatch(r"[0-9a-f]*", bytes_hex)
            or not isinstance(incremental_root, str)
            or not HEX32.fullmatch(incremental_root)
        ):
            raise DemoError("executor emitted a malformed or out-of-order output chunk")
        chunk = bytes.fromhex(bytes_hex)
        output.extend(chunk)
        if blake3(bytes(output)).hexdigest() != incremental_root:
            raise DemoError("executor incremental output commitment mismatch")
        expected_sequence += 1
    if blake3(bytes(output)).hexdigest() != output_root:
        raise DemoError("executor terminal output commitment mismatch")
    tokenization = tokenize_output(
        paths,
        bytes(output),
        INFERENCE_MAX_OUTPUT_TOKENS,
        tokenizer_executable_sha256,
    )
    canonical_events = json.dumps(events, sort_keys=True, separators=(",", ":")).encode()
    return {
        "job_id": job_id,
        "duration_seconds": round(time.monotonic() - started, 3),
        "output_chunks": expected_sequence - 1,
        "output_bytes": len(output),
        "output_root": output_root,
        "output_tokens": tokenization["token_count"],
        "token_history_root": tokenization["token_history_root"],
        "tokenization": tokenization,
        "event_transcript_sha256": hashlib.sha256(canonical_events).hexdigest(),
        "terminal": terminal,
    }

def prepare_chain_bound_inference(
    network: Network,
    resolution: Mapping[str, Any],
    run_id: str,
    capacity_quote: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(run_id, str) or re.fullmatch(r"[0-9a-f]{24}", run_id) is None:
        raise DemoError("chain-bound inference run id must be lowercase hex24")
    active = required_object(resolution, "active")
    status = http_json(f"{network.node_rpc}/status", network.node_token)
    head_height = required_int(required_object(status, "unsafe_head"), "height")
    all_executor_ids = active.get("executor_profile_ids")
    if (
        not isinstance(all_executor_ids, list)
        or not all_executor_ids
        or not all(
            isinstance(value, str) and HEX32.fullmatch(value)
            for value in all_executor_ids
        )
    ):
        raise DemoError("finalized resolution lacks canonical executor identities")
    executor_ids = all_executor_ids[:3]
    job_id = deterministic_id(run_id, "repaired-inference")
    receipt_id = deterministic_id(run_id, "repaired-inference-receipt")
    settlement_id = deterministic_id(run_id, "repaired-inference-settlement")
    prompt_commitment = hashlib.sha256(b"Answer with one word: resilient").hexdigest()
    bindings = {
        "capsule_id": required_text(active, "capsule_id"),
        "artifact_id": required_text(active, "artifact_id"),
        "tokenizer_root": required_text(active, "tokenizer_root"),
        "template_root": required_text(active, "template_root"),
        "runtime_root": required_text(active, "runtime_root"),
        "sbom_root": required_text(active, "sbom_root"),
        "execution_profile_id": required_text(active, "execution_profile_id"),
        "query_policy_id": required_text(active, "query_policy_id"),
        "availability_certificate_id": required_text(active, "availability_certificate_id"),
        "fund_profile_id": required_text(active, "fund_profile_id"),
        "certificate_valid_until": required_int(active, "certificate_valid_until"),
    }
    job = {
        "job_id": job_id,
        "chain_id": required_text(status, "chain_id"),
        "genesis_hash": required_text(status, "genesis_hash"),
        "quote_id": hashlib.sha256(
            json.dumps(capacity_quote, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "registry_epoch": required_int(active, "executor_set_epoch"),
        "client_commitment": prompt_commitment,
        "capsule_id": bindings["capsule_id"],
        "execution_profile_id": bindings["execution_profile_id"],
        "query_policy_id": bindings["query_policy_id"],
        "max_input_tokens": 4,
        "max_output_tokens": INFERENCE_MAX_OUTPUT_TOKENS,
        "deadline_height": head_height + 5_000,
        "selected_executor_ids": executor_ids,
        "availability_certificate_id": bindings["availability_certificate_id"],
        "fund_profile_id": bindings["fund_profile_id"],
        "reserved_amount": "0",
        "offchain_envelope_root": hashlib.sha256(
            f"{run_id}:{prompt_commitment}:no-attachments".encode()
        ).hexdigest(),
    }
    return {
        "schema": "noos/wwm-chain-bound-inference-plan/v1",
        "run_id": run_id,
        "job_id": job_id,
        "receipt_id": receipt_id,
        "settlement_id": settlement_id,
        "prompt_commitment": prompt_commitment,
        "executor_ids": executor_ids,
        "bindings": bindings,
        "job": job,
    }


def verify_chain_bound_job(
    network: Network,
    plan: Mapping[str, Any],
) -> dict[str, Any]:
    bindings = required_object(plan, "bindings")
    job_id = required_text(plan, "job_id")
    return finalized_wwm_record(
        network,
        "job",
        job_id,
        {
            "job_id": job_id,
            "capsule_id": required_text(bindings, "capsule_id"),
            "execution_profile_id": required_text(bindings, "execution_profile_id"),
            "availability_certificate_id": required_text(
                bindings, "availability_certificate_id"
            ),
            "fund_profile_id": required_text(bindings, "fund_profile_id"),
        },
    )


def submit_chain_bound_job(
    config: Mapping[str, Any],
    paths: Paths,
    network: Network,
    plan: Mapping[str, Any],
    on_submitted: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    if plan.get("schema") != "noos/wwm-chain-bound-inference-plan/v1":
        raise DemoError("unsupported chain-bound inference plan")
    opened = submit_wwm_action(
        config,
        paths,
        network,
        {"type": "open_wwm_job", **required_object(plan, "job")},
        on_submitted,
    )
    return {"submission": opened, "record": verify_chain_bound_job(network, plan)}


def prepare_chain_bound_close(
    plan: Mapping[str, Any],
    job_record: Mapping[str, Any],
    inference: Mapping[str, Any],
) -> dict[str, Any]:
    if plan.get("schema") != "noos/wwm-chain-bound-inference-plan/v1":
        raise DemoError("unsupported chain-bound inference plan")
    bindings = required_object(plan, "bindings")
    executor_ids = plan.get("executor_ids")
    if (
        not isinstance(executor_ids, list)
        or not executor_ids
        or not all(isinstance(value, str) and HEX32.fullmatch(value) for value in executor_ids)
    ):
        raise DemoError("chain-bound inference plan lacks canonical executor identities")
    job_id = required_text(plan, "job_id")
    receipt_id = required_text(plan, "receipt_id")
    settlement_id = required_text(plan, "settlement_id")
    receipt = {
        "receipt_id": receipt_id,
        "job_id": job_id,
        "capsule_id": required_text(bindings, "capsule_id"),
        "artifact_id": required_text(bindings, "artifact_id"),
        "tokenizer_root": required_text(bindings, "tokenizer_root"),
        "template_root": required_text(bindings, "template_root"),
        "runtime_root": required_text(bindings, "runtime_root"),
        "sbom_root": required_text(bindings, "sbom_root"),
        "execution_profile_id": required_text(bindings, "execution_profile_id"),
        "input_tokens": 4,
        "output_tokens": required_int(inference, "output_tokens"),
        "token_history_root": required_text(inference, "token_history_root"),
        "output_root": required_text(inference, "output_root"),
        "signer_ids": executor_ids,
        "control_cluster_ids": executor_ids,
        "evidence_tier": "local_verified",
        "availability_until": required_int(bindings, "certificate_valid_until"),
        "evidence_until": required_int(bindings, "certificate_valid_until"),
        "anchor_height": required_int(job_record, "finalized_height"),
        "anchor_block": required_text(job_record, "finalized_hash"),
        "metered_amount": "0",
        "paid_amount": "0",
        "refunded_amount": "0",
        "terminal_code": "complete",
        "signatures": [],
    }
    settlement = {
        "settlement_id": settlement_id,
        "job_id": job_id,
        "receipt_id": receipt_id,
        "fund_profile_id": required_text(bindings, "fund_profile_id"),
        "bucket": "job",
        "prior_settlement_index": 0,
        "paid_amount": "0",
        "refunded_amount": "0",
        "released_amount": "0",
        "settled_height": required_int(job_record, "finalized_height"),
        "authority_epoch": 1,
        "signature": MARKER_SIGNATURE_HEX,
    }
    return {
        "schema": "noos/wwm-chain-bound-close-plan/v1",
        "receipt": receipt,
        "settlement": settlement,
    }


def validate_chain_bound_flow(
    paths: Paths,
    plan: Mapping[str, Any],
    close_plan: Mapping[str, Any],
) -> None:
    if close_plan.get("schema") != "noos/wwm-chain-bound-close-plan/v1":
        raise DemoError("unsupported chain-bound close plan")
    job = required_object(plan, "job")
    receipt = required_object(close_plan, "receipt")
    settlement = required_object(close_plan, "settlement")
    flow_path = (
        paths.disposable_root
        / "transactions"
        / f"{required_text(plan, 'run_id')}-wwm-flow.json"
    )
    atomic_write(
        flow_path,
        json.dumps(
            {"job": job, "receipt": receipt, "settlement": settlement},
            separators=(",", ":"),
        ).encode(),
    )
    checked_flow = run_json(
        paths.cli,
        ("wwm", "devnet", "flow", "--spec-file", str(flow_path)),
    )
    if (
        checked_flow.get("schema") != "noos/wwm-devnet-operator-flow/v1"
        or checked_flow.get("production_capable") is not False
        or checked_flow.get("job_id") != required_text(plan, "job_id")
        or checked_flow.get("capsule_id")
        != required_text(required_object(plan, "bindings"), "capsule_id")
        or checked_flow.get("receipt_id") != required_text(plan, "receipt_id")
        or checked_flow.get("settlement_id") != required_text(plan, "settlement_id")
    ):
        raise DemoError("typed WWM operator rejected or changed the exact lifecycle identities")


def verify_chain_bound_close(
    network: Network,
    plan: Mapping[str, Any],
    close_plan: Mapping[str, Any],
    job_record: Mapping[str, Any],
    inference: Mapping[str, Any],
) -> dict[str, Any]:
    bindings = required_object(plan, "bindings")
    job_id = required_text(plan, "job_id")
    receipt_id = required_text(plan, "receipt_id")
    settlement_id = required_text(plan, "settlement_id")
    receipt_record = finalized_wwm_record(
        network,
        "receipt",
        receipt_id,
        {
            "receipt_id": receipt_id,
            "job_id": job_id,
            "capsule_id": required_text(bindings, "capsule_id"),
            "artifact_id": required_text(bindings, "artifact_id"),
            "execution_profile_id": required_text(bindings, "execution_profile_id"),
            "output_root": required_text(inference, "output_root"),
            "token_history_root": required_text(inference, "token_history_root"),
        },
    )
    settlement_record = finalized_wwm_record(
        network,
        "settlement",
        settlement_id,
        {
            "settlement_id": settlement_id,
            "job_id": job_id,
            "receipt_id": receipt_id,
            "fund_profile_id": required_text(bindings, "fund_profile_id"),
        },
    )
    if not (
        required_int(job_record, "finalized_height")
        <= required_int(receipt_record, "finalized_height")
        <= required_int(settlement_record, "finalized_height")
    ):
        raise DemoError("WWM lifecycle records did not finalize monotonically")
    if (
        required_object(close_plan, "receipt").get("receipt_id") != receipt_id
        or required_object(close_plan, "settlement").get("settlement_id") != settlement_id
    ):
        raise DemoError("chain-bound close plan identities changed")
    return {"receipt": receipt_record, "settlement": settlement_record}


def submit_chain_bound_close(
    config: Mapping[str, Any],
    paths: Paths,
    network: Network,
    plan: Mapping[str, Any],
    close_plan: Mapping[str, Any],
    job_record: Mapping[str, Any],
    inference: Mapping[str, Any],
    on_submitted: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    validate_chain_bound_flow(paths, plan, close_plan)
    closed = submit_wwm_actions(
        config,
        paths,
        network,
        (
            {"type": "record_wwm_receipt", **required_object(close_plan, "receipt")},
            {"type": "settle_wwm_job", **required_object(close_plan, "settlement")},
        ),
        on_submitted,
    )
    records = verify_chain_bound_close(
        network,
        plan,
        close_plan,
        job_record,
        inference,
    )
    return {"submission": closed, **records}


def run_chain_bound_inference(
    config: Mapping[str, Any],
    paths: Paths,
    network: Network,
    resolution: Mapping[str, Any],
    run_id: str,
    capacity_quote: Mapping[str, Any],
) -> dict[str, Any]:
    plan = prepare_chain_bound_inference(network, resolution, run_id, capacity_quote)
    opened = submit_chain_bound_job(config, paths, network, plan)
    inference = run_inference(
        paths,
        network,
        required_text(plan, "job_id"),
        required_text(config, "tokenizer_executable_sha256"),
    )
    close_plan = prepare_chain_bound_close(plan, opened["record"], inference)
    closed = submit_chain_bound_close(
        config,
        paths,
        network,
        plan,
        close_plan,
        opened["record"],
        inference,
    )
    return {
        "job_id": required_text(plan, "job_id"),
        "receipt_id": required_text(plan, "receipt_id"),
        "settlement_id": required_text(plan, "settlement_id"),
        "capsule_id": required_text(required_object(plan, "bindings"), "capsule_id"),
        "output_root": required_text(inference, "output_root"),
        "token_history_root": required_text(inference, "token_history_root"),
        "open": opened["submission"],
        "close": closed["submission"],
        "finalized_job": opened["record"],
        "finalized_receipt": closed["receipt"],
        "finalized_settlement": closed["settlement"],
        "inference": inference,
        "production_capable": False,
    }


def emit_panel(path: Path, phase: str, detail: Mapping[str, Any]) -> None:
    body = {
        "schema": PANEL_SCHEMA,
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "phase": phase,
        "detail": detail,
        "publisher_or_gateway_fallback": False,
        "production_claimed": False,
    }
    atomic_write(path, (json.dumps(body, indent=2, sort_keys=True) + "\n").encode())
    print(json.dumps(body, separators=(",", ":")), flush=True)


def seal_evidence(
    config: Mapping[str, Any],
    paths: Paths,
    body: Mapping[str, Any],
) -> Path:
    governance = required_object(config, "governance")
    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(required_text(governance, "seed_hex")))
    public = key.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    domain = b"NOOS/EVIDENCE/WWM-HOSTED-DEMO/V1"
    signed = dict(body)
    signed["signature"] = {
        "suite": "Ed25519",
        "domain": domain.decode(),
        "public_key": public.hex(),
        "signature": key.sign(domain + canonical).hex(),
        "signed_payload_sha256": hashlib.sha256(canonical).hexdigest(),
    }
    encoded = (json.dumps(signed, indent=2, sort_keys=True) + "\n").encode()
    digest = hashlib.sha256(encoded).hexdigest()
    path = paths.evidence_dir / f"{digest}.json"
    atomic_write(path, encoded)
    return path


def run_demo(config: Mapping[str, Any], paths: Paths, network: Network, report: Mapping[str, Any]) -> Path:
    run_id = hashlib.sha256(
        f"{datetime.now(timezone.utc).isoformat()}:{os.getpid()}".encode()
    ).hexdigest()[:24]
    run_root = paths.disposable_root / "runs" / f"run-{run_id}"
    run_root.mkdir(parents=True, exist_ok=False)
    replacement_root = run_root / "replacement-position-3"
    matrix = CustodianMatrix(
        network.proxy_host,
        network.proxy_port_start,
        network.artifact_url,
        replacement_root,
    )
    executor: subprocess.Popen[bytes] | None = None
    phases: list[dict[str, Any]] = []
    try:
        clear_disposable_cache(paths)
        resolution = http_json(
            f"{network.node_rpc}/model-resolution/bonsai-q1",
            network.node_token,
            timeout=180,
        )
        active = required_object(resolution, "active")
        if (
            resolution.get("registration_state") != "ACTIVE_TESTNET"
            or resolution.get("production_effect") != "NONE"
            or resolution.get("proofs_verified") is not True
            or active.get("artifact_id") != ARTIFACT_ID
            or active.get("manifest_root") != MANIFEST_ROOT
            or active.get("artifact_sha256") != MODEL_SHA256
            or active.get("artifact_bytes") != MODEL_BYTES
        ):
            raise DemoError("node resolution is not the verified Bonsai test graph")
        profiles = active.get("custodian_profiles")
        if not isinstance(profiles, list) or len(profiles) != POSITIONS:
            raise DemoError("node resolution does not carry twelve custodian identities")
        initial_finalized_height = required_int(resolution, "finalized_height")
        matrix.start()
        proof_path = run_root / "finalized-resolution.json"
        map_path = run_root / "custodians.json"
        config_path = run_root / "workerd.toml"
        scratch = run_root / "scratch"
        drain = run_root / "drain"
        write_resolution_proof(proof_path, resolution)
        write_custodian_map(map_path, profiles, matrix, list(range(POSITIONS)))
        patch_executor_config(
            paths.workerd_template,
            config_path,
            paths,
            network,
            resolution,
            proof_path,
            map_path,
            scratch,
            drain,
        )
        executor = start_executor(paths, network, config_path, run_root / "workerd.log")

        quote_12 = quote(network)
        transfer_12 = submit_transfer(paths, network, "12-live")
        phase_12 = {
            "phase": "12_live",
            "offline_positions": [],
            "quote": quote_12,
            "ordinary_transaction": transfer_12,
        }
        phases.append(phase_12)
        emit_panel(paths.panel_state, "12_live", phase_12)

        matrix.set_offline((0, 1, 2))
        time.sleep(1.1)
        quote_9 = quote(network)
        if quote_9.get("live_custodian_positions") != list(range(3, 12)):
            raise DemoError("three-offline state did not retain exact nine-position admission")
        transfer_9 = submit_transfer(paths, network, "9-live")
        phase_9 = {
            "phase": "9_live",
            "offline_positions": [0, 1, 2],
            "quote": quote_9,
            "ordinary_transaction": transfer_9,
        }
        phases.append(phase_9)
        emit_panel(paths.panel_state, "9_live", phase_9)

        matrix.set_offline((3,))
        time.sleep(1.1)
        quote_8 = capture_http(
            f"{network.sidecar_url}/internal/wwm/v1/capacity-quotes",
            network.sidecar_token_hex,
            {"prompt_tokens": 1, "max_output_tokens": 8},
        )
        job_8 = capture_http(
            f"{network.sidecar_url}/internal/wwm/v1/jobs",
            network.sidecar_token_hex,
            {
                "job_id": deterministic_id(run_id, "eight-live-rejected-job"),
                "prompt": "must not run",
                "prompt_token_ids": [1],
                "runtime_token_ids": [1],
                "max_output_tokens": 8,
            },
        )
        if (
            quote_8.get("status") != 503
            or job_8.get("status") != 503
            or required_object(quote_8, "body").get("error")
            != "availability_not_schedulable"
            or required_object(job_8, "body").get("error")
            != "availability_not_schedulable"
        ):
            raise DemoError("eight-live state did not fail new-job admission closed")
        transfer_8 = submit_transfer(paths, network, "8-live-admission-closed")
        repair_report_path = run_root / "repair-report.json"
        repair_report = run_json(
            paths.artifact_service,
            (
                "repair-position",
                "--position",
                "3",
                "--source-positions",
                "4,5,6,7,8,9,10,11",
                "--store-root",
                str(paths.source_store_root),
                "--staging-root",
                str(paths.source_staging_root),
                "--consensus-root",
                str(paths.source_consensus_root),
                "--quota-bytes",
                str(required_int(config, "source_store_quota_bytes")),
                "--replacement-root",
                str(replacement_root),
                "--replacement-consensus-root",
                str(paths.replacement_consensus_root),
                "--replacement-quota-bytes",
                str(required_int(config, "replacement_store_quota_bytes")),
                "--report",
                str(repair_report_path),
            ),
            timeout=3_600,
        )
        if (
            repair_report.get("source_positions") != list(range(4, 12))
            or repair_report.get("repaired_position") != 3
            or repair_report.get("published") is not True
            or repair_report.get("bytes_written") != POSITION_BYTES
        ):
            raise DemoError("canonical eight-position repair report is incomplete")
        phase_8 = {
            "phase": "8_live",
            "offline_positions": [0, 1, 2, 3],
            "capacity_quote": quote_8,
            "job_admission": job_8,
            "ordinary_transaction": transfer_8,
            "canonical_repair": repair_report,
        }
        phases.append(phase_8)
        emit_panel(paths.panel_state, "8_live", phase_8)

        repair_chain = submit_repair_certificate(
            config,
            paths,
            network,
            active,
            report["position_roots"],
            run_id,
        )
        repaired_resolution = http_json(
            f"{network.node_rpc}/model-resolution/bonsai-q1",
            network.node_token,
            timeout=180,
        )
        repaired_active = required_object(repaired_resolution, "active")
        if repaired_active.get("availability_certificate_id") != repair_chain["certificate_id"]:
            raise DemoError("fresh repair certificate is not the finalized current certificate")

        write_resolution_proof(proof_path, repaired_resolution)
        write_custodian_map(
            map_path,
            repaired_active["custodian_profiles"],
            matrix,
            (3, 1, 2, 0, 4, 5, 6, 7, 8, 9, 10, 11),
        )
        patch_executor_config(
            paths.workerd_template,
            config_path,
            paths,
            network,
            repaired_resolution,
            proof_path,
            map_path,
            scratch,
            drain,
        )
        matrix.enable_replacement(3)
        stop_executor(executor)
        executor = start_executor(paths, network, config_path, run_root / "workerd-repaired.log")
        time.sleep(1.1)
        repaired_quote = quote(network)
        if repaired_quote.get("live_custodian_positions") != list(range(3, 12)):
            raise DemoError("repaired assignment did not restore exact nine-position admission")
        repaired_transfer = submit_transfer(paths, network, "repaired-9-live")
        chain_bound_inference = run_chain_bound_inference(
            config,
            paths,
            network,
            repaired_resolution,
            run_id,
            repaired_quote,
        )
        phase_repaired = {
            "phase": "repaired_9_live",
            "offline_positions": [0, 1, 2],
            "quote": repaired_quote,
            "ordinary_transaction": repaired_transfer,
            "repair_chain": repair_chain,
            "chain_bound_inference": chain_bound_inference,
        }
        phases.append(phase_repaired)
        emit_panel(paths.panel_state, "repaired_9_live", phase_repaired)

        settled_heights = [
            required_int(required_object(required_object(phase, "ordinary_transaction")["receipt"], "state"), "settled_height")
            for phase in phases
        ]
        settled_heights.append(
            required_int(chain_bound_inference["finalized_settlement"], "finalized_height")
        )
        final_status = wait_finalized(network, max(settled_heights))
        final_resolution = http_json(
            f"{network.node_rpc}/model-resolution/bonsai-q1",
            network.node_token,
            timeout=180,
        )
        evidence = {
            "schema": EVIDENCE_SCHEMA,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "run_id": run_id,
            "environment": config["environment"],
            "production_claimed": False,
            "publisher_or_gateway_fallback": False,
            "external_model_egress": [],
            "chain_id": final_status["chain_id"],
            "genesis_hash": final_status["genesis_hash"],
            "repository_revision": report["repository_revision"],
            "executable_sha256": report["executable_sha256"],
            "operator_capabilities": report["operator_capabilities"],
            "artifact": {
                "artifact_id": ARTIFACT_ID,
                "manifest_root": MANIFEST_ROOT,
                "model_sha256": MODEL_SHA256,
                "model_bytes": MODEL_BYTES,
                "encoded_bytes": ENCODED_BYTES,
                "positions": POSITIONS,
                "reconstruction_threshold": RECONSTRUCTION_THRESHOLD,
                "schedulable_minimum": SCHEDULABLE_MINIMUM,
            },
            "initial_finalized_height": initial_finalized_height,
            "finalized_resolution": {
                "height": final_resolution["finalized_height"],
                "hash": final_resolution["finalized_hash"],
                "objects_root": final_resolution["objects_root"],
                "certificate_id": final_resolution["active"]["availability_certificate_id"],
                "canonical_resolution_body_sha256": hashlib.sha256(
                    bytes.fromhex(final_resolution["canonical_resolution_body_hex"])
                ).hexdigest(),
            },
            "phases": phases,
            "chain_bound_inference": chain_bound_inference,
            "final_chain_status": final_status,
            "claims": {
                "cold_cache_was_disposable": True,
                "new_job_admission_failed_closed_at_eight": True,
                "canonical_any_eight_repair_completed": True,
                "fresh_certificate_finalized": True,
                "admission_and_inference_resumed": True,
                "ordinary_chain_finality_continued": True,
                "inference_job_receipt_settlement_finalized": True,
                "production_availability_claimed": False,
            },
        }
        evidence_path = seal_evidence(config, paths, evidence)
        emit_panel(paths.panel_state, "complete", {"evidence_path": str(evidence_path)})
        return evidence_path
    finally:
        stop_executor(executor)
        matrix.stop()


def parse_args(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="validate the exact test-only prerequisites without changing runtime state",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        config = load_object(args.config)
        paths, network = validate_contract(config)
        report = verify_prerequisites(config, paths)
        if args.validate_only:
            print(
                json.dumps(
                    {
                        "schema": SCHEMA,
                        "verdict": "VALID_TEST_ONLY_HOSTED_MODEL_DEMO",
                        "artifact_id": ARTIFACT_ID,
                        "manifest_root": MANIFEST_ROOT,
                        "publisher_or_gateway_fallback": False,
                        "external_model_egress": [],
                        "production_claimed": False,
                        "chain_bound_settlement_operator": report["operator_capabilities"],
                        "repository_revision": report["repository_revision"],
                        "executable_sha256": report["executable_sha256"],
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        evidence = run_demo(config, paths, network, report)
        print(json.dumps({"verdict": "PASS", "evidence": str(evidence)}, indent=2))
        return 0
    except (DemoError, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"hosted-model demo failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
