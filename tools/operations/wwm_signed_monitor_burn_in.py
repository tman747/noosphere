from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import time
from typing import Callable
import urllib.error
import urllib.request
from urllib.parse import urlsplit

try:
    from tools.operations import wwm_public_testnet_monitor as monitor
except ModuleNotFoundError:
    import wwm_public_testnet_monitor as monitor


CHECKPOINT_SCHEMA = "noos/wwm-signed-monitor-burn-in-checkpoint/v1"
RESULT_SCHEMA = "noos/wwm-signed-monitor-burn-in-result/v1"
MAX_SAMPLE_BYTES = 2 * 1024 * 1024
MAX_LEDGER_BYTES = 32 * 1024 * 1024
HEX40 = re.compile(r"^[0-9a-f]{40}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


class BurnInError(RuntimeError):
    pass

class BurnInSampleError(BurnInError):
    """A returned monitor sample proves the continuous burn-in failed."""



@dataclass(frozen=True)
class BurnInConfig:
    url: str
    source_revision: str
    release_version: str
    deployment_sha256: str
    signer_key_id: str
    duration_seconds: int
    poll_seconds: int
    maximum_sample_gap_seconds: int
    maximum_observation_gap_seconds: int
    expected_check_count: int
    output: Path
    monitor_source_sha256: str | None = None

    @property
    def ledger_path(self) -> Path:
        return self.output.with_suffix(self.output.suffix + ".samples.jsonl")

    @property
    def checkpoint_path(self) -> Path:
        return self.output.with_suffix(self.output.suffix + ".checkpoint.json")

    @property
    def failure_sample_path(self) -> Path:
        return self.output.with_suffix(self.output.suffix + ".failed-sample.json")

    def validate(self) -> None:
        parsed = urlsplit(self.url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise BurnInError("burn-in URL must be an exact HTTPS endpoint")
        if not HEX40.fullmatch(self.source_revision):
            raise BurnInError("source revision must be canonical lowercase hex40")
        if self.release_version != f"0.1.0+git.{self.source_revision}":
            raise BurnInError("burn-in release identity is not exact")
        if not HEX64.fullmatch(self.deployment_sha256):
            raise BurnInError("deployment SHA-256 must be canonical lowercase hex64")
        if not HEX64.fullmatch(self.signer_key_id):
            raise BurnInError("signer key ID must be canonical lowercase hex64")
        if self.monitor_source_sha256 is not None and not HEX64.fullmatch(
            self.monitor_source_sha256
        ):
            raise BurnInError("monitor source SHA-256 must be canonical lowercase hex64")
        if self.duration_seconds < 60:
            raise BurnInError("burn-in duration must be at least 60 seconds")
        if not 1 <= self.poll_seconds <= 60:
            raise BurnInError("burn-in poll interval must be between 1 and 60 seconds")
        if self.maximum_sample_gap_seconds < 60:
            raise BurnInError("maximum sample gap must be at least 60 seconds")
        if self.maximum_observation_gap_seconds < self.poll_seconds:
            raise BurnInError("maximum observation gap cannot be shorter than the poll interval")
        if not 1 <= self.expected_check_count <= 64:
            raise BurnInError("expected check count must be between 1 and 64")


@dataclass
class BurnInState:
    started_at_utc: datetime
    first_observed_at_utc: datetime | None = None
    last_observed_at_utc: datetime | None = None
    first_sample_id: str | None = None
    last_sample_id: str | None = None
    check_names: tuple[str, ...] | None = None
    sample_count: int = 0
    maximum_sample_gap_seconds: float = 0.0

    def observed_span_seconds(self) -> int:
        if self.first_observed_at_utc is None or self.last_observed_at_utc is None:
            return 0
        return int((self.last_observed_at_utc - self.first_observed_at_utc).total_seconds())


RequestSample = Callable[[str], dict[str, object]]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(value: object, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise BurnInError(f"{label} must be a canonical UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise BurnInError(f"{label} is malformed") from error
    if parsed.tzinfo is None:
        raise BurnInError(f"{label} must include a timezone")
    return parsed.astimezone(timezone.utc)


def load_json_object(path: Path, maximum_bytes: int) -> dict[str, object]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise BurnInError(f"cannot inspect {path}") from error
    if size <= 0 or size > maximum_bytes:
        raise BurnInError(f"{path} size is outside the accepted bound")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BurnInError(f"{path} is not canonical JSON") from error
    if not isinstance(value, dict):
        raise BurnInError(f"{path} must contain a JSON object")
    return value


def request_sample(url: str) -> dict[str, object]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "noos-wwm-burn-in/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            body = response.read(MAX_SAMPLE_BYTES + 1)
            status = int(response.status)
    except urllib.error.HTTPError as error:
        body = error.read(MAX_SAMPLE_BYTES + 1)
        status = int(error.code)
    if status != 200:
        raise BurnInError(f"monitor endpoint returned HTTP {status}")
    if not body or len(body) > MAX_SAMPLE_BYTES:
        raise BurnInError("monitor sample size is outside the accepted bound")
    try:
        value = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BurnInError("monitor endpoint returned malformed JSON") from error
    if not isinstance(value, dict):
        raise BurnInError("monitor endpoint did not return a JSON object")
    return value


def validate_sample(config: BurnInConfig, sample: dict[str, object]) -> tuple[datetime, tuple[str, ...]]:
    expected: dict[str, object] = {
        "schema": monitor.SAMPLE_SCHEMA,
        "environment": "public-testnet",
        "production": False,
        "production_authorized": False,
        "promotion_effect": "NONE",
        "source_revision": config.source_revision,
        "release_version": config.release_version,
        "deployment_sha256": config.deployment_sha256,
        "signer_key_id": config.signer_key_id,
    }
    if config.monitor_source_sha256 is not None:
        expected["monitor_source_sha256"] = config.monitor_source_sha256
    for field, value in expected.items():
        if sample.get(field) != value:
            raise BurnInError(f"monitor sample {field} mismatch")
    try:
        monitor.verify_envelope(sample, monitor.SAMPLE_DOMAIN, "sample_id")
    except monitor.MonitorError as error:
        raise BurnInError(str(error)) from error
    checks = sample.get("checks")
    if not isinstance(checks, list) or len(checks) != config.expected_check_count:
        raise BurnInError("monitor sample check count mismatch")
    names: list[str] = []
    for check in checks:
        if not isinstance(check, dict):
            raise BurnInError("monitor sample check is malformed")
        name = check.get("name")
        if not isinstance(name, str) or not name:
            raise BurnInError("monitor sample check name is malformed")
        if check.get("ok") is not True:
            raise BurnInError(f"monitor sample contains failed check {name}")
        names.append(name)
    if len(set(names)) != len(names):
        raise BurnInError("monitor sample contains duplicate check names")
    if sample.get("status") != "ok":
        raise BurnInError("monitor sample status mismatch")
    return parse_utc(sample.get("observed_at_utc"), "sample observed_at_utc"), tuple(sorted(names))


def atomic_write(path: Path, document: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except OSError as error:
        temporary.unlink(missing_ok=True)
        raise BurnInError(f"cannot atomically write {path}") from error


def append_ledger(path: Path, sample: dict[str, object]) -> None:
    encoded = monitor.canonical_json(sample) + b"\n"
    try:
        current_size = path.stat().st_size if path.exists() else 0
        if current_size + len(encoded) > MAX_LEDGER_BYTES:
            raise BurnInError("burn-in sample ledger exceeds its byte bound")
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("ab") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as error:
        raise BurnInError(f"cannot append burn-in ledger {path}") from error


class BurnInEvidence:
    def __init__(self, config: BurnInConfig, *, started_at_utc: datetime | None = None):
        config.validate()
        self.config = config
        if config.output.exists():
            raise BurnInError("completed burn-in result already exists")
        ledger_exists = config.ledger_path.exists()
        checkpoint_exists = config.checkpoint_path.exists()
        if ledger_exists != checkpoint_exists:
            raise BurnInError("burn-in ledger and checkpoint must exist together")
        if ledger_exists:
            self.state = self._recover()
        else:
            self.state = BurnInState(started_at_utc or utc_now())

    def _recover(self) -> BurnInState:
        checkpoint = load_json_object(self.config.checkpoint_path, MAX_SAMPLE_BYTES)
        expected: dict[str, object] = {
            "schema": CHECKPOINT_SCHEMA,
            "status": "RUNNING",
            "source_revision": self.config.source_revision,
            "release_version": self.config.release_version,
            "deployment_sha256": self.config.deployment_sha256,
            "monitor_source_sha256": self.config.monitor_source_sha256,
        }
        for field, value in expected.items():
            if checkpoint.get(field) != value:
                raise BurnInError(f"burn-in checkpoint {field} mismatch")
        state = BurnInState(parse_utc(checkpoint.get("started_at_utc"), "checkpoint started_at_utc"))
        try:
            ledger_size = self.config.ledger_path.stat().st_size
        except OSError as error:
            raise BurnInError("cannot inspect burn-in sample ledger") from error
        if ledger_size <= 0 or ledger_size > MAX_LEDGER_BYTES:
            raise BurnInError("burn-in sample ledger size is outside the accepted bound")
        try:
            with self.config.ledger_path.open("r", encoding="utf-8") as handle:
                for line_number, line in enumerate(handle, start=1):
                    if not line.endswith("\n"):
                        raise BurnInError("burn-in sample ledger has a truncated final record")
                    try:
                        sample = json.loads(line)
                    except json.JSONDecodeError as error:
                        raise BurnInError(f"burn-in sample ledger line {line_number} is malformed") from error
                    if not isinstance(sample, dict):
                        raise BurnInError(f"burn-in sample ledger line {line_number} is not an object")
                    self._apply_sample(state, sample, persist=False)
        except (OSError, UnicodeDecodeError) as error:
            raise BurnInError("cannot read burn-in sample ledger") from error
        if state.sample_count == 0:
            raise BurnInError("burn-in sample ledger is empty")
        self.state = state
        self._write_checkpoint()
        return state

    def _apply_sample(self, state: BurnInState, sample: dict[str, object], *, persist: bool) -> bool:
        try:
            observed, current_names = validate_sample(self.config, sample)
        except BurnInError as error:
            raise BurnInSampleError(str(error)) from error
        sample_id = sample.get("sample_id")
        if not isinstance(sample_id, str) or not HEX64.fullmatch(sample_id):
            raise BurnInSampleError("monitor sample ID is malformed")
        if sample_id == state.last_sample_id:
            return state.observed_span_seconds() >= self.config.duration_seconds
        if state.last_sample_id is not None:
            if sample.get("previous_sample_id") != state.last_sample_id:
                raise BurnInSampleError("monitor sample hash chain is discontinuous")
            if state.last_observed_at_utc is None:
                raise BurnInSampleError("burn-in state lost its last observation")
            gap = (observed - state.last_observed_at_utc).total_seconds()
            if gap <= 0:
                raise BurnInSampleError("monitor sample timestamps are not increasing")
            if gap > self.config.maximum_sample_gap_seconds:
                raise BurnInSampleError("monitor sample gap exceeded the burn-in bound")
            state.maximum_sample_gap_seconds = max(state.maximum_sample_gap_seconds, gap)
        if state.check_names is not None and current_names != state.check_names:
            raise BurnInSampleError("monitor check set changed during burn-in")
        if persist:
            append_ledger(self.config.ledger_path, sample)
        if state.first_observed_at_utc is None:
            state.first_observed_at_utc = observed
            state.first_sample_id = sample_id
            state.check_names = current_names
        state.last_observed_at_utc = observed
        state.last_sample_id = sample_id
        state.sample_count += 1
        if persist:
            self._write_checkpoint()
        return state.observed_span_seconds() >= self.config.duration_seconds

    def accept(self, sample: dict[str, object], *, now: datetime | None = None) -> bool:
        try:
            observed = parse_utc(sample.get("observed_at_utc"), "sample observed_at_utc")
        except BurnInError as error:
            raise BurnInSampleError(str(error)) from error
        age = abs(((now or utc_now()) - observed).total_seconds())
        if age > self.config.maximum_observation_gap_seconds:
            raise BurnInSampleError("monitor observation freshness exceeded the burn-in bound")
        return self._apply_sample(self.state, sample, persist=True)

    def _checkpoint_document(self) -> dict[str, object]:
        state = self.state
        if (
            state.first_observed_at_utc is None
            or state.last_observed_at_utc is None
            or state.first_sample_id is None
            or state.last_sample_id is None
            or state.check_names is None
        ):
            raise BurnInError("cannot checkpoint burn-in before its first sample")
        return {
            "schema": CHECKPOINT_SCHEMA,
            "status": "RUNNING",
            "source_revision": self.config.source_revision,
            "release_version": self.config.release_version,
            "deployment_sha256": self.config.deployment_sha256,
            "monitor_source_sha256": self.config.monitor_source_sha256,
            "started_at_utc": format_utc(state.started_at_utc),
            "first_observed_at_utc": format_utc(state.first_observed_at_utc),
            "last_observed_at_utc": format_utc(state.last_observed_at_utc),
            "first_sample_id": state.first_sample_id,
            "last_sample_id": state.last_sample_id,
            "sample_count": state.sample_count,
            "observed_span_seconds": state.observed_span_seconds(),
            "maximum_sample_gap_seconds": state.maximum_sample_gap_seconds,
            "check_names": list(state.check_names),
            "ledger_path": str(self.config.ledger_path),
        }

    def _write_checkpoint(self) -> None:
        atomic_write(self.config.checkpoint_path, self._checkpoint_document())

    def fail(
        self,
        reason: str,
        *,
        sample: dict[str, object] | None,
        observed_at_utc: datetime | None = None,
        wall_elapsed_seconds: int = 0,
    ) -> dict[str, object]:
        if self.config.output.exists():
            raise BurnInError("burn-in result already exists")
        failed_at = observed_at_utc or utc_now()
        sample_descriptor: dict[str, object] | None = None
        if sample is not None:
            atomic_write(self.config.failure_sample_path, sample)
            try:
                sample_payload = self.config.failure_sample_path.read_bytes()
            except OSError as error:
                raise BurnInError("cannot read preserved failing monitor sample") from error
            sample_descriptor = {
                "path": str(self.config.failure_sample_path),
                "bytes": len(sample_payload),
                "sha256": hashlib.sha256(sample_payload).hexdigest(),
                "sample_id": sample.get("sample_id"),
                "previous_sample_id": sample.get("previous_sample_id"),
                "observed_at_utc": sample.get("observed_at_utc"),
            }
        ledger_descriptor: dict[str, object] | None = None
        if self.config.ledger_path.exists():
            try:
                ledger_payload = self.config.ledger_path.read_bytes()
            except OSError as error:
                raise BurnInError("cannot read failed burn-in ledger") from error
            ledger_descriptor = {
                "path": str(self.config.ledger_path),
                "bytes": len(ledger_payload),
                "sha256": hashlib.sha256(ledger_payload).hexdigest(),
            }
        if self.state.sample_count > 0:
            checkpoint = self._checkpoint_document()
            checkpoint.update(
                {
                    "status": "FAILED",
                    "failed_at_utc": format_utc(failed_at),
                    "failure_reason": reason,
                }
            )
            atomic_write(self.config.checkpoint_path, checkpoint)
        result: dict[str, object] = {
            "schema": RESULT_SCHEMA,
            "observed_at_utc": format_utc(failed_at),
            "result": "FAIL",
            "release": {
                "source_revision": self.config.source_revision,
                "release_version": self.config.release_version,
                "deployment_sha256": self.config.deployment_sha256,
                "monitor_source_sha256": self.config.monitor_source_sha256,
            },
            "signer_key_id": self.config.signer_key_id,
            "started_at_utc": format_utc(self.state.started_at_utc),
            "observed_span_seconds": self.state.observed_span_seconds(),
            "wall_elapsed_seconds": wall_elapsed_seconds,
            "sample_count": self.state.sample_count,
            "first_sample_id": self.state.first_sample_id,
            "last_sample_id": self.state.last_sample_id,
            "maximum_sample_gap_seconds": self.state.maximum_sample_gap_seconds,
            "failure": {
                "reason": reason,
                "sample": sample_descriptor,
            },
            "ledger": ledger_descriptor,
        }
        atomic_write(self.config.output, result)
        return result

    def finalize(self, *, observed_at_utc: datetime | None = None, wall_elapsed_seconds: int = 0) -> dict[str, object]:
        state = self.state
        if state.observed_span_seconds() < self.config.duration_seconds:
            raise BurnInError("burn-in cannot finalize before the full observed duration")
        if (
            state.first_observed_at_utc is None
            or state.last_observed_at_utc is None
            or state.first_sample_id is None
            or state.last_sample_id is None
            or state.check_names is None
        ):
            raise BurnInError("burn-in state is incomplete")
        try:
            ledger_payload = self.config.ledger_path.read_bytes()
        except OSError as error:
            raise BurnInError("cannot read completed burn-in ledger") from error
        result: dict[str, object] = {
            "schema": RESULT_SCHEMA,
            "observed_at_utc": format_utc(observed_at_utc or utc_now()),
            "result": "PASS",
            "release": {
                "source_revision": self.config.source_revision,
                "release_version": self.config.release_version,
                "deployment_sha256": self.config.deployment_sha256,
                "monitor_source_sha256": self.config.monitor_source_sha256,
            },
            "signer_key_id": self.config.signer_key_id,
            "first_observed_at_utc": format_utc(state.first_observed_at_utc),
            "last_observed_at_utc": format_utc(state.last_observed_at_utc),
            "observed_span_seconds": state.observed_span_seconds(),
            "wall_elapsed_seconds": wall_elapsed_seconds,
            "sample_count": state.sample_count,
            "first_sample_id": state.first_sample_id,
            "last_sample_id": state.last_sample_id,
            "maximum_sample_gap_seconds": state.maximum_sample_gap_seconds,
            "expected_check_count": self.config.expected_check_count,
            "check_names": list(state.check_names),
            "ledger": {
                "path": str(self.config.ledger_path),
                "bytes": len(ledger_payload),
                "sha256": hashlib.sha256(ledger_payload).hexdigest(),
            },
            "acceptance": {
                "elapsed_full_duration": True,
                "every_observed_sample_exact_release": True,
                "every_observed_sample_signature_valid": True,
                "sample_hash_chain_continuous": True,
                "all_monitor_checks_passed": True,
                "sample_gap_within_bound": True,
                "production_boundary_fail_closed": True,
                "restart_recovery_supported": True,
            },
        }
        atomic_write(self.config.output, result)
        self.config.checkpoint_path.unlink(missing_ok=True)
        return result


def run(config: BurnInConfig, *, requester: RequestSample = request_sample) -> dict[str, object]:
    started_monotonic = time.monotonic()
    evidence = BurnInEvidence(config)
    if evidence.state.observed_span_seconds() >= config.duration_seconds:
        return evidence.finalize(wall_elapsed_seconds=0)
    last_success_monotonic = started_monotonic
    last_error = "monitor sample unavailable"
    while True:
        sample: dict[str, object] | None = None
        try:
            sample = requester(config.url)
            completed = evidence.accept(sample)
            last_success_monotonic = time.monotonic()
            if completed:
                break
        except BurnInSampleError as error:
            last_error = str(error)
            evidence.fail(
                last_error,
                sample=sample,
                wall_elapsed_seconds=int(time.monotonic() - started_monotonic),
            )
            raise BurnInError(f"signed monitor burn-in failed: {last_error}") from error
        except (BurnInError, OSError, ValueError, urllib.error.URLError) as error:
            last_error = str(error)
            if time.monotonic() - last_success_monotonic > config.maximum_observation_gap_seconds:
                evidence.fail(
                    last_error,
                    sample=sample,
                    wall_elapsed_seconds=int(time.monotonic() - started_monotonic),
                )
                raise BurnInError(f"signed monitor burn-in failed: {last_error}") from error
        time.sleep(config.poll_seconds)
    return evidence.finalize(wall_elapsed_seconds=int(time.monotonic() - started_monotonic))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify a continuous signed WWM public-testnet burn-in")
    parser.add_argument("--url", default="https://wwm-status.mindchain.network/status.json")
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--release-version", required=True)
    parser.add_argument("--deployment-sha256", required=True)
    parser.add_argument("--signer-key-id", required=True)
    parser.add_argument("--monitor-source-sha256")
    parser.add_argument("--duration-seconds", type=int, default=86_400)
    parser.add_argument("--poll-seconds", type=int, default=15)
    parser.add_argument("--maximum-sample-gap-seconds", type=int, default=90)
    parser.add_argument("--maximum-observation-gap-seconds", type=int, default=90)
    parser.add_argument("--expected-check-count", type=int, default=22)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args(argv)


def config_from_args(args: argparse.Namespace) -> BurnInConfig:
    return BurnInConfig(
        url=args.url,
        source_revision=args.source_revision,
        release_version=args.release_version,
        deployment_sha256=args.deployment_sha256,
        signer_key_id=args.signer_key_id,
        monitor_source_sha256=args.monitor_source_sha256,
        duration_seconds=args.duration_seconds,
        poll_seconds=args.poll_seconds,
        maximum_sample_gap_seconds=args.maximum_sample_gap_seconds,
        maximum_observation_gap_seconds=args.maximum_observation_gap_seconds,
        expected_check_count=args.expected_check_count,
        output=args.output,
    )


def main(argv: list[str] | None = None) -> int:
    try:
        result = run(config_from_args(parse_args(argv)))
    except BurnInError as error:
        print(str(error), flush=True)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
