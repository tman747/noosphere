import copy
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import compute_worker
import worker_sandbox as sandbox


WORKLOAD_ID = "ab" * 32
RESULT_DOMAIN = b"NOOS/COMPUTE/MIX32/RESULT/V1"


def policy_document(**overrides):
    value = {
        "schema": sandbox.POLICY_SCHEMA,
        "policy_id": "",
        "allowed_workload_kinds": [0],
        "cpu_threads": 1,
        "memory_mb": 256,
        "runtime_seconds": 10,
        "max_operations": 10_000,
        "max_scratch_bytes": 0,
        "filesystem_access": "DENY",
        "network_access": "DENY",
        "gpu_access": "DENY",
        "maximum_temperature_c": 85,
        "temperature_sensor_required": False,
        "minimum_battery_percent": 25,
        "battery_sensor_required": False,
        "allow_on_battery": False,
        "utc_windows": [{"start_minute": 0, "end_minute": 1440}],
        "max_payload_bytes": 4096,
        "max_result_bytes": 4096,
        "max_network_bytes_per_job": 8192,
    }
    value.update(overrides)
    value["policy_id"] = sandbox.policy_identity(value)
    return value


def make_policy(**overrides):
    return sandbox.validate_policy(policy_document(**overrides))


def observation(
    *,
    hour=12,
    temperature=45.0,
    temperature_available=True,
    battery_present=False,
    battery_percent=None,
    on_battery=False,
):
    return sandbox.HostObservation(
        observed_at_utc=datetime(2026, 7, 27, hour, 0, tzinfo=timezone.utc),
        temperature_c=temperature,
        temperature_sensor_available=temperature_available,
        battery_present=battery_present,
        battery_percent=battery_percent,
        on_battery=on_battery,
    )


class WorkerSandboxTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_policy_is_canonical_content_addressed_and_private(self):
        path = self.root / "private" / "sandbox-policy.json"
        policy = sandbox.freeze_policy(
            path,
            {key: value for key, value in policy_document().items() if key not in {"schema", "policy_id"}},
        )
        loaded = sandbox.load_policy(path)
        self.assertEqual(loaded.policy_id, policy.policy_id)
        self.assertEqual(path.read_bytes(), sandbox.canonical_file(loaded.document))
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

        tampered = copy.deepcopy(loaded.document)
        tampered["memory_mb"] += 1
        tampered_path = self.root / "tampered.json"
        tampered_path.write_bytes(sandbox.canonical_file(tampered))
        if os.name != "nt":
            os.chmod(tampered_path, 0o600)
        with self.assertRaisesRegex(sandbox.SandboxError, "policy ID"):
            sandbox.load_policy(tampered_path)

        permissive = policy_document(filesystem_access="ALLOW")
        with self.assertRaisesRegex(sandbox.SandboxError, "filesystem, network, and GPU denial"):
            sandbox.validate_policy(permissive)
        with self.assertRaisesRegex(sandbox.SandboxError, "cannot create"):
            sandbox.freeze_policy(path, loaded.document)

    def test_host_temperature_battery_and_schedule_fail_closed(self):
        required_temperature = make_policy(temperature_sensor_required=True)
        with self.assertRaisesRegex(sandbox.SandboxError, "temperature sensor"):
            required_temperature.enforce_host(
                observation(temperature=None, temperature_available=False)
            )
        with self.assertRaisesRegex(sandbox.SandboxError, "temperature exceeds"):
            required_temperature.enforce_host(observation(temperature=86.0))

        battery_policy = make_policy(battery_sensor_required=True)
        with self.assertRaisesRegex(sandbox.SandboxError, "battery state is unavailable"):
            battery_policy.enforce_host(
                observation(battery_present=None, on_battery=None)
            )
        with self.assertRaisesRegex(sandbox.SandboxError, "charge is below"):
            battery_policy.enforce_host(
                observation(battery_present=True, battery_percent=24, on_battery=False)
            )
        with self.assertRaisesRegex(sandbox.SandboxError, "forbids execution on battery"):
            battery_policy.enforce_host(
                observation(battery_present=True, battery_percent=90, on_battery=True)
            )

        scheduled = make_policy(utc_windows=[{"start_minute": 0, "end_minute": 60}])
        with self.assertRaisesRegex(sandbox.SandboxError, "outside the worker schedule"):
            scheduled.enforce_host(observation(hour=12))

    def test_job_and_coordinator_bandwidth_limits_are_enforced(self):
        policy = make_policy(max_operations=100, max_payload_bytes=128, max_result_bytes=128, max_network_bytes_per_job=256)
        policy.enforce_job(0, 100, 128)
        with self.assertRaisesRegex(sandbox.SandboxError, "workload kind"):
            policy.enforce_job(9, 1, 1)
        with self.assertRaisesRegex(sandbox.SandboxError, "operations"):
            policy.enforce_job(0, 101, 1)
        with self.assertRaisesRegex(sandbox.SandboxError, "payload"):
            policy.enforce_job(0, 1, 129)
        budget = sandbox.JobNetworkBudget(policy)
        budget.consume(128, "payload")
        budget.consume(128, "result")
        with self.assertRaisesRegex(sandbox.SandboxError, "network traffic"):
            budget.consume(1, "overflow")

    def test_registration_binds_advertised_resources_to_local_policy(self):
        identity = compute_worker.WorkerIdentity(
            chain_id="01" * 32,
            genesis_hash="02" * 32,
            account=0,
            index=0,
            payout_account="03" * 32,
            seed=bytearray(range(32)),
        )
        args = SimpleNamespace(market="https://market.invalid/", price_per_unit=7)
        first = make_policy(memory_mb=256)
        second = make_policy(memory_mb=512)
        with patch.object(compute_worker, "submit_action", return_value={"state": "INCLUDED"}) as submit:
            compute_worker.register(args, {}, identity, first)
            compute_worker.register(args, {}, identity, second)
        first_action = submit.call_args_list[0].args[2]
        second_action = submit.call_args_list[1].args[2]
        self.assertEqual(first_action["cpu_threads"], 1)
        self.assertEqual(first_action["memory_mb"], 256)
        self.assertEqual(first_action["gpu_memory_mb"], 0)
        self.assertNotEqual(
            first_action["endpoint_commitment"],
            second_action["endpoint_commitment"],
            "registration commitment did not bind the local policy ID",
        )

    def test_actual_child_matches_reference_and_emits_zero_capability_evidence(self):
        policy = make_policy()
        expected = sandbox.mix32_root(RESULT_DOMAIN, 7, 11, 32, 4)
        execution = sandbox.execute_mix32(
            policy,
            workload_id=WORKLOAD_ID,
            result_domain=RESULT_DOMAIN,
            seed=7,
            start=11,
            units=32,
            rounds=4,
            payload_bytes=256,
            observation_provider=observation,
        )
        self.assertEqual(execution.result_root, expected)
        self.assertEqual(
            execution.evidence["isolation"],
            {
                "filesystem_access": "DENY",
                "network_access": "DENY",
                "gpu_access": "DENY",
                "isolated_working_directory": True,
                "secret_environment_inherited": False,
            },
        )
        self.assertEqual(execution.evidence["resources"]["scratch_bytes"], 0)
        self.assertEqual(execution.evidence["resources"]["cpu_threads"], 1)
        self.assertGreaterEqual(execution.evidence["host_condition_checks"], 1)

    def test_wall_runtime_and_midflight_thermal_policy_kill_work(self):
        timeout_policy = make_policy(runtime_seconds=1, max_operations=200_000_000)
        with self.assertRaisesRegex(sandbox.SandboxError, "runtime limit|execution failed"):
            sandbox.execute_mix32(
                timeout_policy,
                workload_id=WORKLOAD_ID,
                result_domain=RESULT_DOMAIN,
                seed=1,
                start=0,
                units=1,
                rounds=200_000_000,
                payload_bytes=128,
                observation_provider=observation,
            )

        thermal_policy = make_policy(runtime_seconds=5, max_operations=200_000_000)
        observations = iter([observation(), observation(temperature=100.0)])
        with self.assertRaisesRegex(sandbox.SandboxError, "temperature exceeds"):
            sandbox.execute_mix32(
                thermal_policy,
                workload_id=WORKLOAD_ID,
                result_domain=RESULT_DOMAIN,
                seed=1,
                start=0,
                units=1,
                rounds=200_000_000,
                payload_bytes=128,
                observation_provider=lambda: next(observations),
            )

    def test_audit_guard_denies_filesystem_network_gpu_device_and_subprocess(self):
        code = """
import socket, subprocess, sys
sys.path.insert(0, sys.argv[1])
import worker_sandbox as sandbox
sandbox.install_workload_guard()
denied = 0
for operation in (
    lambda: open('forbidden', 'wb'),
    lambda: socket.socket(),
    lambda: subprocess.run([sys.executable, '-V']),
    lambda: open('gpu-device', 'rb'),
):
    try:
        operation()
    except PermissionError:
        denied += 1
print(denied)
"""
        completed = subprocess.run(
            [sys.executable, "-I", "-c", code, str(Path(sandbox.__file__).resolve().parent)],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.stdout.strip(), "4")

    def test_worker_payload_and_result_responses_are_bounded(self):
        policy = make_policy(max_payload_bytes=128, max_result_bytes=128, max_network_bytes_per_job=256)
        job_id = "cd" * 32
        payload = json.dumps(
            {"job_id": job_id, "seed": 1, "start": 0, "units": 2, "rounds": 3},
            separators=(",", ":"),
        ).encode()
        budget = sandbox.JobNetworkBudget(policy)
        with patch("urllib.request.urlopen", return_value=io.BytesIO(payload)):
            value, size = compute_worker.get_payload("https://market.invalid", job_id, policy, budget)
        self.assertEqual(value, {"seed": 1, "start": 0, "units": 2, "rounds": 3})
        self.assertEqual(size, len(payload))

        with patch("urllib.request.urlopen", return_value=io.BytesIO(b"{" + b"x" * 128)):
            with self.assertRaisesRegex(RuntimeError, "payload response exceeds"):
                compute_worker.get_payload(
                    "https://market.invalid",
                    job_id,
                    policy,
                    sandbox.JobNetworkBudget(policy),
                )

        response = b'{"state":"ACCEPTED"}'
        result_budget = sandbox.JobNetworkBudget(policy)
        with patch("urllib.request.urlopen", return_value=io.BytesIO(response)):
            accepted = compute_worker.notify_result(
                "https://market.invalid",
                job_id,
                "ef" * 32,
                policy,
                result_budget,
            )
        self.assertEqual(accepted, {"state": "ACCEPTED"})
        self.assertGreater(result_budget.consumed_bytes, len(response))


if __name__ == "__main__":
    unittest.main()
