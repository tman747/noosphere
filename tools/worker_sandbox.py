#!/usr/bin/env python3
"""Fail-closed local policy and process isolation for registered compute work."""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable

POLICY_SCHEMA = "noos/worker-sandbox-policy/v1"
POLICY_ID_DOMAIN = b"NOOS/WORKER/SANDBOX-POLICY/V1\0"
CHILD_REQUEST_SCHEMA = "noos/worker-sandbox-child-request/v1"
CHILD_RESULT_SCHEMA = "noos/worker-sandbox-child-result/v1"
MAX_POLICY_BYTES = 1024 * 1024
MAX_CHILD_REQUEST_BYTES = 16 * 1024
MAX_CHILD_DIAGNOSTIC_BYTES = 8 * 1024
HEX64 = re.compile(r"^[0-9a-f]{64}$")
POLICY_FIELDS = {
    "schema",
    "policy_id",
    "allowed_workload_kinds",
    "cpu_threads",
    "memory_mb",
    "runtime_seconds",
    "max_operations",
    "max_scratch_bytes",
    "filesystem_access",
    "network_access",
    "gpu_access",
    "maximum_temperature_c",
    "temperature_sensor_required",
    "minimum_battery_percent",
    "battery_sensor_required",
    "allow_on_battery",
    "utc_windows",
    "max_payload_bytes",
    "max_result_bytes",
    "max_network_bytes_per_job",
}
WINDOW_FIELDS = {"start_minute", "end_minute"}
CHILD_REQUEST_FIELDS = {
    "schema",
    "policy_id",
    "workload_id",
    "result_domain_hex",
    "seed",
    "start",
    "units",
    "rounds",
}
CHILD_RESULT_FIELDS = {"schema", "policy_id", "workload_id", "result_root"}
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1


class SandboxError(RuntimeError):
    """A stable fail-closed sandbox policy or execution rejection."""


def canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def canonical_file(value: object) -> bytes:
    return canonical_json(value) + b"\n"


def policy_identity(document: dict[str, Any]) -> str:
    payload = dict(document)
    payload.pop("policy_id", None)
    return hashlib.sha256(POLICY_ID_DOMAIN + canonical_json(payload)).hexdigest()


def exact_uint(value: Any, name: str, minimum: int, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise SandboxError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def exact_bool(value: Any, name: str) -> bool:
    if not isinstance(value, bool):
        raise SandboxError(f"{name} must be a boolean")
    return value


def validate_windows(value: Any) -> tuple[tuple[int, int], ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= 16:
        raise SandboxError("utc_windows must contain one to sixteen windows")
    windows: list[tuple[int, int]] = []
    previous_end = -1
    for index, item in enumerate(value):
        if not isinstance(item, dict) or set(item) != WINDOW_FIELDS:
            raise SandboxError(f"utc_windows[{index}] fields are malformed")
        start = exact_uint(item["start_minute"], f"utc_windows[{index}].start_minute", 0, 1439)
        end = exact_uint(item["end_minute"], f"utc_windows[{index}].end_minute", 1, 1440)
        if start >= end:
            raise SandboxError("UTC windows must be non-wrapping; split an overnight window at midnight")
        if start < previous_end:
            raise SandboxError("UTC windows must be sorted and non-overlapping")
        windows.append((start, end))
        previous_end = end
    return tuple(windows)


@dataclass(frozen=True)
class HostObservation:
    observed_at_utc: datetime
    temperature_c: float | None
    temperature_sensor_available: bool
    battery_present: bool | None
    battery_percent: int | None
    on_battery: bool | None

    def public_descriptor(self) -> dict[str, object]:
        return {
            "observed_at_utc": self.observed_at_utc.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "temperature_sensor_available": self.temperature_sensor_available,
            "temperature_c": self.temperature_c,
            "battery_present": self.battery_present,
            "battery_percent": self.battery_percent,
            "on_battery": self.on_battery,
        }


@dataclass(frozen=True)
class SandboxPolicy:
    document: dict[str, Any]
    windows: tuple[tuple[int, int], ...]

    @property
    def policy_id(self) -> str:
        return self.document["policy_id"]

    def __getattr__(self, name: str) -> Any:
        if name in POLICY_FIELDS:
            return self.document[name]
        raise AttributeError(name)

    def summary(self) -> dict[str, object]:
        return {
            "schema": POLICY_SCHEMA,
            "policy_id": self.policy_id,
            "allowed_workload_kinds": self.allowed_workload_kinds,
            "cpu_threads": self.cpu_threads,
            "memory_mb": self.memory_mb,
            "runtime_seconds": self.runtime_seconds,
            "max_operations": self.max_operations,
            "max_scratch_bytes": self.max_scratch_bytes,
            "isolation": {
                "filesystem": self.filesystem_access,
                "network": self.network_access,
                "gpu": self.gpu_access,
            },
            "host_conditions": {
                "maximum_temperature_c": self.maximum_temperature_c,
                "temperature_sensor_required": self.temperature_sensor_required,
                "minimum_battery_percent": self.minimum_battery_percent,
                "battery_sensor_required": self.battery_sensor_required,
                "allow_on_battery": self.allow_on_battery,
                "utc_windows": self.document["utc_windows"],
            },
            "network_budget": {
                "max_payload_bytes": self.max_payload_bytes,
                "max_result_bytes": self.max_result_bytes,
                "max_network_bytes_per_job": self.max_network_bytes_per_job,
            },
        }

    def enforce_job(self, workload_kind: int, operations: int, payload_bytes: int) -> None:
        if workload_kind not in self.allowed_workload_kinds:
            raise SandboxError("workload kind is not allowed by the local sandbox policy")
        exact_uint(operations, "job operations", 1, UINT64_MAX)
        if operations > self.max_operations:
            raise SandboxError("job operations exceed the local sandbox policy")
        exact_uint(payload_bytes, "job payload bytes", 1, MAX_POLICY_BYTES)
        if payload_bytes > self.max_payload_bytes:
            raise SandboxError("job payload exceeds the local network budget")

    def enforce_host(self, observation: HostObservation) -> dict[str, object]:
        observed = observation.observed_at_utc
        if observed.tzinfo is None:
            raise SandboxError("host observation timestamp must include a timezone")
        observed = observed.astimezone(timezone.utc)
        minute = observed.hour * 60 + observed.minute
        if not any(start <= minute < end for start, end in self.windows):
            raise SandboxError("current UTC time is outside the worker schedule")
        if not observation.temperature_sensor_available or observation.temperature_c is None:
            if self.temperature_sensor_required:
                raise SandboxError("required host temperature sensor is unavailable")
        elif not math.isfinite(observation.temperature_c) or observation.temperature_c > self.maximum_temperature_c:
            raise SandboxError("host temperature exceeds the worker policy")
        if observation.battery_present is None:
            if self.battery_sensor_required:
                raise SandboxError("required battery state is unavailable")
        elif observation.battery_present:
            if observation.battery_percent is None or observation.on_battery is None:
                if self.battery_sensor_required:
                    raise SandboxError("required battery state is incomplete")
            else:
                if observation.battery_percent < self.minimum_battery_percent:
                    raise SandboxError("battery charge is below the worker policy")
                if observation.on_battery and not self.allow_on_battery:
                    raise SandboxError("worker policy forbids execution on battery power")
        return observation.public_descriptor()


@dataclass
class JobNetworkBudget:
    policy: SandboxPolicy
    consumed_bytes: int = 0

    def consume(self, count: int, label: str) -> None:
        exact_uint(count, f"{label} bytes", 0, MAX_POLICY_BYTES * 2)
        if self.consumed_bytes + count > self.policy.max_network_bytes_per_job:
            raise SandboxError("job network traffic exceeds the local per-job budget")
        self.consumed_bytes += count


@dataclass(frozen=True)
class SandboxExecution:
    result_root: str
    evidence: dict[str, object]


def validate_policy(value: Any) -> SandboxPolicy:
    if not isinstance(value, dict) or set(value) != POLICY_FIELDS or value.get("schema") != POLICY_SCHEMA:
        raise SandboxError("sandbox policy fields are malformed")
    policy_id = value.get("policy_id")
    if not isinstance(policy_id, str) or HEX64.fullmatch(policy_id) is None:
        raise SandboxError("sandbox policy ID is malformed")
    if policy_id != policy_identity(value):
        raise SandboxError("sandbox policy ID does not match its canonical contents")
    if value.get("allowed_workload_kinds") != [0]:
        raise SandboxError("sandbox policy v1 only admits the registered MIX32 workload")
    if exact_uint(value.get("cpu_threads"), "cpu_threads", 1, 1) != 1:
        raise SandboxError("sandbox policy v1 requires one isolated CPU thread")
    exact_uint(value.get("memory_mb"), "memory_mb", 64, 1_048_576)
    exact_uint(value.get("runtime_seconds"), "runtime_seconds", 1, 86_400)
    exact_uint(value.get("max_operations"), "max_operations", 1, UINT64_MAX)
    if exact_uint(value.get("max_scratch_bytes"), "max_scratch_bytes", 0, 0) != 0:
        raise SandboxError("sandbox policy v1 denies workload scratch storage")
    if (
        value.get("filesystem_access") != "DENY"
        or value.get("network_access") != "DENY"
        or value.get("gpu_access") != "DENY"
    ):
        raise SandboxError("sandbox policy v1 requires filesystem, network, and GPU denial")
    exact_uint(value.get("maximum_temperature_c"), "maximum_temperature_c", 30, 120)
    exact_bool(value.get("temperature_sensor_required"), "temperature_sensor_required")
    exact_uint(value.get("minimum_battery_percent"), "minimum_battery_percent", 0, 100)
    exact_bool(value.get("battery_sensor_required"), "battery_sensor_required")
    exact_bool(value.get("allow_on_battery"), "allow_on_battery")
    windows = validate_windows(value.get("utc_windows"))
    payload_limit = exact_uint(value.get("max_payload_bytes"), "max_payload_bytes", 128, MAX_POLICY_BYTES)
    result_limit = exact_uint(value.get("max_result_bytes"), "max_result_bytes", 128, MAX_POLICY_BYTES)
    total_limit = exact_uint(
        value.get("max_network_bytes_per_job"),
        "max_network_bytes_per_job",
        256,
        MAX_POLICY_BYTES * 2,
    )
    if total_limit < payload_limit + result_limit:
        raise SandboxError("per-job network budget must cover one maximum payload and result")
    return SandboxPolicy(dict(value), windows)


def load_policy(path: Path) -> SandboxPolicy:
    try:
        size = path.stat().st_size
        mode = stat.S_IMODE(path.stat().st_mode)
        raw = path.read_bytes()
    except OSError as error:
        raise SandboxError(f"cannot read sandbox policy: {error}") from error
    if size <= 0 or size > MAX_POLICY_BYTES:
        raise SandboxError("sandbox policy size is outside the accepted bound")
    if os.name != "nt" and mode & 0o077:
        raise SandboxError("sandbox policy must not be accessible by group or other users")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SandboxError("sandbox policy is not canonical JSON") from error
    if canonical_file(value) != raw:
        raise SandboxError("sandbox policy is not canonical JSON")
    return validate_policy(value)


def freeze_policy(path: Path, document: dict[str, Any]) -> SandboxPolicy:
    value = dict(document)
    value["schema"] = POLICY_SCHEMA
    value["policy_id"] = ""
    value["policy_id"] = policy_identity(value)
    policy = validate_policy(value)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(path.parent, 0o700)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_file(value))
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            os.chmod(path, 0o600)
    except OSError as error:
        raise SandboxError(f"cannot create sandbox policy: {error}") from error
    return policy


def _linux_temperature() -> tuple[float | None, bool]:
    root = Path("/sys/class/thermal")
    if not root.is_dir():
        return None, False
    values: list[float] = []
    try:
        paths = list(root.glob("thermal_zone*/temp"))
    except OSError:
        return None, False
    for path in paths:
        try:
            raw = float(path.read_text(encoding="ascii").strip())
        except (OSError, UnicodeDecodeError, ValueError):
            continue
        value = raw / 1000.0 if raw > 1000 else raw
        if math.isfinite(value) and 0 <= value <= 150:
            values.append(value)
    return (max(values), True) if values else (None, False)


def _linux_battery() -> tuple[bool | None, int | None, bool | None]:
    root = Path("/sys/class/power_supply")
    if not root.is_dir():
        return None, None, None
    batteries: list[Path] = []
    try:
        candidates = list(root.iterdir())
    except OSError:
        return None, None, None
    for candidate in candidates:
        try:
            if (candidate / "type").read_text(encoding="ascii").strip().lower() == "battery":
                batteries.append(candidate)
        except (OSError, UnicodeDecodeError):
            continue
    if not batteries:
        return False, None, False
    percentages: list[int] = []
    statuses: list[str] = []
    for battery in batteries:
        try:
            percentage = int((battery / "capacity").read_text(encoding="ascii").strip())
            if 0 <= percentage <= 100:
                percentages.append(percentage)
        except (OSError, UnicodeDecodeError, ValueError):
            pass
        try:
            statuses.append((battery / "status").read_text(encoding="ascii").strip().lower())
        except (OSError, UnicodeDecodeError):
            pass
    percent = min(percentages) if percentages else None
    on_battery = any(status == "discharging" for status in statuses) if statuses else None
    return True, percent, on_battery


def _windows_battery() -> tuple[bool | None, int | None, bool | None]:
    try:
        import ctypes

        class SystemPowerStatus(ctypes.Structure):
            _fields_ = [
                ("ACLineStatus", ctypes.c_ubyte),
                ("BatteryFlag", ctypes.c_ubyte),
                ("BatteryLifePercent", ctypes.c_ubyte),
                ("SystemStatusFlag", ctypes.c_ubyte),
                ("BatteryLifeTime", ctypes.c_uint32),
                ("BatteryFullLifeTime", ctypes.c_uint32),
            ]

        status = SystemPowerStatus()
        if not ctypes.windll.kernel32.GetSystemPowerStatus(ctypes.byref(status)):
            return None, None, None
        if status.BatteryFlag == 128:
            return False, None, False
        percent = None if status.BatteryLifePercent == 255 else int(status.BatteryLifePercent)
        on_battery = None if status.ACLineStatus == 255 else status.ACLineStatus == 0
        return True, percent, on_battery
    except (AttributeError, OSError, ValueError):
        return None, None, None


def _macos_battery() -> tuple[bool | None, int | None, bool | None]:
    try:
        completed = subprocess.run(
            ["/usr/bin/pmset", "-g", "batt"],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None, None
    if completed.returncode != 0:
        return None, None, None
    text = completed.stdout
    if "No batteries" in text:
        return False, None, False
    match = re.search(r"\b(\d{1,3})%;", text)
    if match is None:
        return None, None, None
    percent = int(match.group(1))
    if not 0 <= percent <= 100:
        return None, None, None
    return True, percent, "Battery Power" in text


def probe_host() -> HostObservation:
    temperature: float | None = None
    temperature_available = False
    battery_present: bool | None = None
    battery_percent: int | None = None
    on_battery: bool | None = None
    if sys.platform.startswith("linux"):
        temperature, temperature_available = _linux_temperature()
        battery_present, battery_percent, on_battery = _linux_battery()
    elif os.name == "nt":
        battery_present, battery_percent, on_battery = _windows_battery()
    elif sys.platform == "darwin":
        battery_present, battery_percent, on_battery = _macos_battery()
    return HostObservation(
        observed_at_utc=datetime.now(timezone.utc),
        temperature_c=temperature,
        temperature_sensor_available=temperature_available,
        battery_present=battery_present,
        battery_percent=battery_percent,
        on_battery=on_battery,
    )


def mix32_value(seed: int, global_index: int, rounds: int) -> int:
    value = (seed ^ global_index ^ 0x9E3779B9) & UINT32_MAX
    for _ in range(rounds):
        value ^= (value << 13) & UINT32_MAX
        value ^= value >> 17
        value ^= (value << 5) & UINT32_MAX
        value = (value * 0x85EBCA6B + 0xC2B2AE35) & UINT32_MAX
    return value


def mix32_root(result_domain: bytes, seed: int, start: int, units: int, rounds: int) -> str:
    if not isinstance(result_domain, bytes) or not 1 <= len(result_domain) <= 128:
        raise SandboxError("MIX32 result domain is malformed")
    exact_uint(seed, "MIX32 seed", 0, UINT32_MAX)
    exact_uint(start, "MIX32 start", 0, UINT64_MAX)
    exact_uint(units, "MIX32 units", 1, UINT32_MAX)
    exact_uint(rounds, "MIX32 rounds", 1, UINT32_MAX)
    if start + units - 1 > UINT64_MAX:
        raise SandboxError("MIX32 index interval overflows u64")
    digest = hashlib.sha256(result_domain)
    for item in range(start, start + units):
        digest.update(mix32_value(seed, item, rounds).to_bytes(4, "little"))
    return digest.hexdigest()


def install_workload_guard() -> None:
    denied_exact = {
        "open",
        "os.chdir",
        "os.chmod",
        "os.chown",
        "os.listdir",
        "os.mkdir",
        "os.remove",
        "os.rename",
        "os.rmdir",
        "os.scandir",
        "os.system",
        "os.truncate",
        "os.unlink",
        "pathlib.Path.glob",
        "shutil.copyfile",
    }
    denied_prefixes = ("socket.", "subprocess.", "ctypes.dlopen", "os.spawn", "winreg.")

    def deny(event: str, _arguments: tuple[object, ...]) -> None:
        if event in denied_exact or event.startswith(denied_prefixes):
            raise PermissionError(f"sandbox denied audit event: {event}")

    sys.addaudithook(deny)


def _child_main() -> int:
    if os.environ.get("NOOS_SANDBOX_CHILD") != "1":
        print("sandbox child marker is missing", file=sys.stderr)
        return 2
    raw = sys.stdin.buffer.read(MAX_CHILD_REQUEST_BYTES + 1)
    if not raw or len(raw) > MAX_CHILD_REQUEST_BYTES:
        print("sandbox child request size is outside the accepted bound", file=sys.stderr)
        return 2
    try:
        request = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        print("sandbox child request is malformed", file=sys.stderr)
        return 2
    if not isinstance(request, dict) or set(request) != CHILD_REQUEST_FIELDS:
        print("sandbox child request fields are malformed", file=sys.stderr)
        return 2
    if request.get("schema") != CHILD_REQUEST_SCHEMA:
        print("sandbox child request schema is malformed", file=sys.stderr)
        return 2
    policy_id = request.get("policy_id")
    workload_id = request.get("workload_id")
    domain_hex = request.get("result_domain_hex")
    if (
        not isinstance(policy_id, str)
        or HEX64.fullmatch(policy_id) is None
        or not isinstance(workload_id, str)
        or HEX64.fullmatch(workload_id) is None
        or not isinstance(domain_hex, str)
        or len(domain_hex) % 2 != 0
    ):
        print("sandbox child identity fields are malformed", file=sys.stderr)
        return 2
    try:
        result_domain = bytes.fromhex(domain_hex)
        seed = exact_uint(request.get("seed"), "MIX32 seed", 0, UINT32_MAX)
        start = exact_uint(request.get("start"), "MIX32 start", 0, UINT64_MAX)
        units = exact_uint(request.get("units"), "MIX32 units", 1, UINT32_MAX)
        rounds = exact_uint(request.get("rounds"), "MIX32 rounds", 1, UINT32_MAX)
    except (ValueError, SandboxError) as error:
        print(str(error), file=sys.stderr)
        return 2
    install_workload_guard()
    try:
        root = mix32_root(result_domain, seed, start, units, rounds)
        response = {
            "schema": CHILD_RESULT_SCHEMA,
            "policy_id": policy_id,
            "workload_id": workload_id,
            "result_root": root,
        }
        sys.stdout.buffer.write(canonical_file(response))
        sys.stdout.buffer.flush()
    except (OSError, SandboxError, PermissionError) as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


def _posix_limit_setup(policy: SandboxPolicy) -> Callable[[], None] | None:
    if os.name != "posix":
        return None

    def apply() -> None:
        import resource

        memory = policy.memory_mb * 1024 * 1024
        cpu_seconds = max(1, policy.runtime_seconds)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (policy.max_scratch_bytes, policy.max_scratch_bytes))
        resource.setrlimit(resource.RLIMIT_AS, (memory, memory))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        current_soft, current_hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        descriptor_limit = min(32, current_soft, current_hard)
        resource.setrlimit(resource.RLIMIT_NOFILE, (descriptor_limit, descriptor_limit))

    return apply


def _assign_windows_job(process: subprocess.Popen[bytes], policy: SandboxPolicy) -> object | None:
    if os.name != "nt":
        return None
    import ctypes
    from ctypes import wintypes

    class LargeInteger(ctypes.Structure):
        _fields_ = [("QuadPart", ctypes.c_longlong)]

    class IoCounters(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class BasicLimitInformation(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", LargeInteger),
            ("PerJobUserTimeLimit", LargeInteger),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class ExtendedLimitInformation(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", BasicLimitInformation),
            ("IoInfo", IoCounters),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.SetInformationJobObject.restype = wintypes.BOOL
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise SandboxError(f"cannot create Windows sandbox job: {ctypes.get_last_error()}")
    information = ExtendedLimitInformation()
    information.BasicLimitInformation.PerProcessUserTimeLimit.QuadPart = policy.runtime_seconds * 10_000_000
    information.BasicLimitInformation.ActiveProcessLimit = 1
    information.BasicLimitInformation.LimitFlags = 0x00000002 | 0x00000008 | 0x00000100 | 0x00002000
    information.ProcessMemoryLimit = policy.memory_mb * 1024 * 1024
    if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(information), ctypes.sizeof(information)):
        error = ctypes.get_last_error()
        kernel32.CloseHandle(job)
        raise SandboxError(f"cannot configure Windows sandbox job: {error}")
    process_handle = wintypes.HANDLE(int(getattr(process, "_handle")))
    if not kernel32.AssignProcessToJobObject(job, process_handle):
        error = ctypes.get_last_error()
        kernel32.CloseHandle(job)
        raise SandboxError(f"cannot assign process to Windows sandbox job: {error}")
    return (kernel32, job)


def _close_windows_job(job: object | None) -> None:
    if job is None:
        return
    kernel32, handle = job
    kernel32.CloseHandle(handle)


def _scratch_usage(root: Path) -> int:
    total = 0
    try:
        for path in root.rglob("*"):
            if path.is_symlink():
                raise SandboxError("sandbox scratch contains a forbidden symlink")
            if path.is_file():
                total += path.stat().st_size
    except OSError as error:
        raise SandboxError(f"cannot inspect sandbox scratch: {error}") from error
    return total


def execute_mix32(
    policy: SandboxPolicy,
    *,
    workload_id: str,
    result_domain: bytes,
    seed: int,
    start: int,
    units: int,
    rounds: int,
    payload_bytes: int,
    observation_provider: Callable[[], HostObservation] = probe_host,
) -> SandboxExecution:
    if not isinstance(workload_id, str) or HEX64.fullmatch(workload_id) is None:
        raise SandboxError("workload ID is malformed")
    operations = exact_uint(units, "MIX32 units", 1, UINT32_MAX) * exact_uint(
        rounds, "MIX32 rounds", 1, UINT32_MAX
    )
    policy.enforce_job(0, operations, payload_bytes)
    host_checks: list[dict[str, object]] = [policy.enforce_host(observation_provider())]
    request = {
        "schema": CHILD_REQUEST_SCHEMA,
        "policy_id": policy.policy_id,
        "workload_id": workload_id,
        "result_domain_hex": result_domain.hex(),
        "seed": seed,
        "start": start,
        "units": units,
        "rounds": rounds,
    }
    encoded = canonical_file(request)
    if len(encoded) > MAX_CHILD_REQUEST_BYTES:
        raise SandboxError("sandbox child request exceeds its fixed bound")
    child_script = Path(__file__).resolve()
    environment = {
        "NOOS_SANDBOX_CHILD": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONIOENCODING": "utf-8",
    }
    for name in ("SYSTEMROOT", "WINDIR", "COMSPEC"):
        if name in os.environ:
            environment[name] = os.environ[name]
    creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    started = time.monotonic()
    process: subprocess.Popen[bytes] | None = None
    windows_job: object | None = None
    failure: SandboxError | None = None
    stdout = b""
    stderr = b""
    scratch_bytes = 0
    with tempfile.TemporaryDirectory(prefix="mindchain-worker-sandbox-") as temporary:
        scratch = Path(temporary)
        if os.name != "nt":
            os.chmod(scratch, 0o700)
        try:
            process = subprocess.Popen(
                [sys.executable, "-I", "-B", str(child_script), "__sandbox-child"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=scratch,
                env=environment,
                close_fds=True,
                creationflags=creationflags,
                preexec_fn=_posix_limit_setup(policy),
            )
            try:
                windows_job = _assign_windows_job(process, policy)
            except SandboxError:
                process.kill()
                process.wait(timeout=5)
                raise
            if process.stdin is None or process.stdout is None or process.stderr is None:
                raise SandboxError("sandbox child pipes are unavailable")
            try:
                process.stdin.write(encoded)
                process.stdin.close()
            except (BrokenPipeError, OSError) as error:
                failure = SandboxError(f"sandbox child rejected its input: {error}")
            deadline = started + policy.runtime_seconds
            next_host_check = started + min(1.0, policy.runtime_seconds / 2)
            while failure is None and process.poll() is None:
                now = time.monotonic()
                if now >= deadline:
                    failure = SandboxError("sandbox runtime limit exceeded")
                    break
                if now >= next_host_check:
                    try:
                        host_checks.append(policy.enforce_host(observation_provider()))
                    except SandboxError as error:
                        failure = error
                        break
                    next_host_check = now + 1.0
                time.sleep(min(0.05, max(0.0, deadline - now)))
            if failure is not None and process.poll() is None:
                process.kill()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            stdout = process.stdout.read(policy.max_result_bytes + 1)
            stderr = process.stderr.read(MAX_CHILD_DIAGNOSTIC_BYTES + 1)
            scratch_bytes = _scratch_usage(scratch)
        finally:
            _close_windows_job(windows_job)
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()
    elapsed_ms = max(0, int((time.monotonic() - started) * 1000))
    if failure is not None:
        raise failure
    if process is None:
        raise SandboxError("sandbox child did not start")
    if scratch_bytes > policy.max_scratch_bytes:
        raise SandboxError("sandbox scratch storage exceeds the local policy")
    if len(stdout) > policy.max_result_bytes:
        raise SandboxError("sandbox result exceeds the local network budget")
    if len(stderr) > MAX_CHILD_DIAGNOSTIC_BYTES:
        raise SandboxError("sandbox diagnostics exceed the fixed bound")
    if process.returncode != 0:
        detail = stderr.decode("utf-8", errors="replace").strip() or f"exit {process.returncode}"
        raise SandboxError(f"sandbox execution failed: {detail}")
    try:
        response = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SandboxError("sandbox result is malformed") from error
    if canonical_file(response) != stdout:
        raise SandboxError("sandbox result is not canonical JSON")
    if not isinstance(response, dict) or set(response) != CHILD_RESULT_FIELDS:
        raise SandboxError("sandbox result fields are malformed")
    if (
        response.get("schema") != CHILD_RESULT_SCHEMA
        or response.get("policy_id") != policy.policy_id
        or response.get("workload_id") != workload_id
        or not isinstance(response.get("result_root"), str)
        or HEX64.fullmatch(response["result_root"]) is None
    ):
        raise SandboxError("sandbox result identity is malformed or mismatched")
    evidence: dict[str, object] = {
        "schema": "noos/worker-sandbox-execution/v1",
        "policy_id": policy.policy_id,
        "workload_id": workload_id,
        "isolation": {
            "filesystem_access": "DENY",
            "network_access": "DENY",
            "gpu_access": "DENY",
            "isolated_working_directory": True,
            "secret_environment_inherited": False,
        },
        "resources": {
            "cpu_threads": policy.cpu_threads,
            "memory_mb": policy.memory_mb,
            "runtime_limit_seconds": policy.runtime_seconds,
            "elapsed_ms": elapsed_ms,
            "max_operations": policy.max_operations,
            "operations": operations,
            "max_scratch_bytes": policy.max_scratch_bytes,
            "scratch_bytes": scratch_bytes,
        },
        "host_condition_checks": len(host_checks),
        "last_host_observation": host_checks[-1],
        "result_bytes": len(stdout),
    }
    return SandboxExecution(str(response["result_root"]), evidence)


def parse_utc_window(value: str) -> dict[str, int]:
    match = re.fullmatch(r"(\d{2}):(\d{2})-(\d{2}):(\d{2})", value)
    if match is None:
        raise argparse.ArgumentTypeError("UTC window must use HH:MM-HH:MM")
    start_hour, start_minute, end_hour, end_minute = (int(item) for item in match.groups())
    if not 0 <= start_hour <= 23 or not 0 <= start_minute <= 59:
        raise argparse.ArgumentTypeError("UTC window start is invalid")
    if not 0 <= end_hour <= 24 or not 0 <= end_minute <= 59 or (end_hour == 24 and end_minute != 0):
        raise argparse.ArgumentTypeError("UTC window end is invalid")
    return {
        "start_minute": start_hour * 60 + start_minute,
        "end_minute": end_hour * 60 + end_minute,
    }


def default_document(args: argparse.Namespace) -> dict[str, Any]:
    windows = args.utc_window or [{"start_minute": 0, "end_minute": 1440}]
    windows = sorted(windows, key=lambda item: (item["start_minute"], item["end_minute"]))
    return {
        "allowed_workload_kinds": [0],
        "cpu_threads": 1,
        "memory_mb": args.memory_mb,
        "runtime_seconds": args.runtime_seconds,
        "max_operations": args.max_operations,
        "max_scratch_bytes": 0,
        "filesystem_access": "DENY",
        "network_access": "DENY",
        "gpu_access": "DENY",
        "maximum_temperature_c": args.maximum_temperature_c,
        "temperature_sensor_required": args.require_temperature_sensor,
        "minimum_battery_percent": args.minimum_battery_percent,
        "battery_sensor_required": args.require_battery_sensor,
        "allow_on_battery": args.allow_on_battery,
        "utc_windows": windows,
        "max_payload_bytes": args.max_payload_bytes,
        "max_result_bytes": args.max_result_bytes,
        "max_network_bytes_per_job": args.max_network_bytes_per_job,
    }


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["__sandbox-child"]:
        return _child_main()
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("freeze", help="create a local content-addressed sandbox policy")
    freeze.add_argument("--out", type=Path, required=True)
    freeze.add_argument("--memory-mb", type=int, default=256)
    freeze.add_argument("--runtime-seconds", type=int, default=300)
    freeze.add_argument("--max-operations", type=int, default=100_000_000)
    freeze.add_argument("--maximum-temperature-c", type=int, default=85)
    freeze.add_argument("--require-temperature-sensor", action="store_true")
    freeze.add_argument("--minimum-battery-percent", type=int, default=25)
    freeze.add_argument("--require-battery-sensor", action="store_true")
    freeze.add_argument("--allow-on-battery", action="store_true")
    freeze.add_argument("--utc-window", action="append", type=parse_utc_window)
    freeze.add_argument("--max-payload-bytes", type=int, default=64 * 1024)
    freeze.add_argument("--max-result-bytes", type=int, default=64 * 1024)
    freeze.add_argument("--max-network-bytes-per-job", type=int, default=256 * 1024)
    inspect = commands.add_parser("inspect", help="validate and print a sandbox policy")
    inspect.add_argument("--policy", type=Path, required=True)
    probe = commands.add_parser("probe", help="evaluate current host conditions against a policy")
    probe.add_argument("--policy", type=Path, required=True)
    args = parser.parse_args(arguments)
    try:
        if args.command == "freeze":
            result = freeze_policy(args.out, default_document(args)).summary()
        elif args.command == "inspect":
            result = load_policy(args.policy).summary()
        else:
            policy = load_policy(args.policy)
            result = {
                "schema": "noos/worker-sandbox-host-probe/v1",
                "policy_id": policy.policy_id,
                "host": policy.enforce_host(probe_host()),
                "allowed": True,
            }
    except SandboxError as error:
        print(f"worker_sandbox.py: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
