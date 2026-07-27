import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import plistlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

import host_lifecycle as host


class HostLifecycleContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.install_root = self.root / "installed-host"
        self.state_root = self.root / "durable-state"
        self.private_root = self.root / "private-config"
        self.private_source = self.root / "private-source"
        self.private_source.mkdir()
        for name in host.SERVICE_ORDER:
            (self.private_source / f"{name}.env").write_text(
                f"MINDCHAIN_{name.upper()}_MODE=production\n", encoding="utf-8"
            )

        self.release_seed = self.root / "release.seed"
        self.rollback_seed = self.root / "rollback.seed"
        self.release_identity = host.keygen(self.release_seed)
        self.rollback_identity = host.keygen(self.rollback_seed)
        self.now = datetime(2026, 7, 15, 12, 0, tzinfo=timezone.utc)

    def tearDown(self):
        self.temporary.cleanup()

    def build_release(
        self, sequence, *, content_label=None, platform="linux", arch=None
    ):
        label = content_label or f"{platform}-release-{sequence}"
        source_root = self.root / f"source-{label}"
        source_root.mkdir()
        artifacts = []
        services = []
        for name in host.SERVICE_ORDER:
            artifact_path = f"bin/{name}{'.exe' if platform == 'windows' else ''}"
            artifact = source_root / artifact_path
            artifact.parent.mkdir(parents=True, exist_ok=True)
            artifact.write_bytes(f"{label}:{name}\n".encode("utf-8"))
            artifacts.append(
                {
                    "path": artifact_path,
                    "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
                    "executable": True,
                }
            )
            services.append(
                {
                    "name": name,
                    "artifact": artifact_path,
                    "argv": ["--host-role", name],
                    "dependencies": list(host.SERVICE_DEPENDENCIES[name]),
                    "private_config": f"{name}.env",
                }
            )
        artifacts.sort(key=lambda item: item["path"])
        body = {
            "release_id": "",
            "release_sequence": sequence,
            "version": f"1.0.{sequence}",
            "source_revision": f"{sequence:040x}",
            "chain_id": "a" * 64,
            "genesis_hash": "b" * 64,
            "platform": platform,
            "arch": arch or ("universal2" if platform == "macos" else "x86_64"),
            "release_signer_key_id": self.release_identity["key_id"],
            "rollback_signer_key_id": self.rollback_identity["key_id"],
            "rollback_public_key_base64": self.rollback_identity[
                "public_key_base64"
            ],
            "artifacts": artifacts,
            "services": services,
        }
        body["release_id"] = host.release_id(body)
        unsigned_path = self.root / f"unsigned-{label}.json"
        manifest_path = self.root / f"manifest-{label}.json"
        unsigned_path.write_text(
            json.dumps({"schema": host.MANIFEST_SCHEMA, "body": body}),
            encoding="utf-8",
        )
        envelope = host.freeze_manifest(
            unsigned_path, self.release_seed, manifest_path
        )
        return envelope, source_root

    def install(self, release, source_root, *, now=None):
        return host.install_release(
            release,
            self.release_identity["key_id"],
            source_root,
            self.private_source,
            self.install_root,
            self.state_root,
            self.private_root,
            now=now or self.now,
            enforce_runtime_target=False,
        )

    def test_manifest_signature_service_dag_and_secret_argv_fail_closed(self):
        release, _ = self.build_release(1)
        self.assertEqual(
            host.verify_manifest(release, self.release_identity["key_id"]),
            release["body"],
        )

        tampered = copy.deepcopy(release)
        tampered["body"]["version"] = "1.0.99"
        tampered["body"]["release_id"] = host.release_id(tampered["body"])
        with self.assertRaisesRegex(host.HostLifecycleError, "signature"):
            host.verify_manifest(tampered, self.release_identity["key_id"])

        wrong_dag = copy.deepcopy(release["body"])
        wrong_dag["services"][2]["dependencies"] = []
        wrong_dag["release_id"] = host.release_id(wrong_dag)
        with self.assertRaisesRegex(host.HostLifecycleError, "dependencies"):
            host.validate_manifest_body(wrong_dag)

        secret_argv = copy.deepcopy(release["body"])
        secret_argv["services"][0]["argv"].append("--api-token=value")
        secret_argv["release_id"] = host.release_id(secret_argv)
        with self.assertRaisesRegex(host.HostLifecycleError, "contains a secret"):
            host.validate_manifest_body(secret_argv)

        unrelated_seed = self.root / "unrelated.seed"
        unrelated = host.keygen(unrelated_seed)
        with self.assertRaisesRegex(host.HostLifecycleError, "trust anchor"):
            host.verify_manifest(release, unrelated["key_id"])

    def test_install_builds_hardened_ordered_autostart_package(self):
        release, source_root = self.build_release(1)
        result = self.install(release, source_root)
        self.assertEqual(result["action"], "INSTALL")
        self.assertEqual(result["platform"], "linux")
        self.assertEqual(
            result["service_package_files"],
            sorted(
                [
                    "activate-systemd.sh",
                    "deactivate-systemd.sh",
                    *(f"mindchain-{name}.service" for name in host.SERVICE_ORDER),
                ]
            ),
        )

        release_root = self.install_root / "releases" / release["body"]["release_id"]
        units_root = self.install_root / "systemd"
        for service in release["body"]["services"]:
            name = service["name"]
            unit = (units_root / f"mindchain-{name}.service").read_text(
                encoding="utf-8"
            )
            self.assertIn(f"User=mindchain-{name}", unit)
            self.assertIn("Restart=on-failure", unit)
            self.assertIn("NoNewPrivileges=true", unit)
            self.assertIn("ProtectSystem=strict", unit)
            self.assertIn("CapabilityBoundingSet=\n", unit)
            self.assertIn("RestrictNamespaces=true", unit)
            self.assertIn(str(release_root).replace("\\", "\\\\"), unit)
            for dependency in service["dependencies"]:
                self.assertIn(f"mindchain-{dependency}.service", unit)
            self.assertTrue((self.state_root / name).is_dir())
            self.assertEqual(
                (self.private_root / f"{name}.env").read_bytes(),
                host.validate_private_config(self.private_source / f"{name}.env"),
            )
            self.assertFalse((self.install_root / f"{name}.env").exists())

        activate = (units_root / "activate-systemd.sh").read_text(encoding="utf-8")
        expected_order = " ".join(
            f"mindchain-{name}.service" for name in host.SERVICE_ORDER
        )
        self.assertIn(f"systemctl enable --now {expected_order}", activate)
        self.assertIn("useradd --system", activate)
        pointer = host.load_object(self.install_root / "current.json")
        security = host.load_security(self.state_root)
        self.assertEqual(pointer["release_id"], release["body"]["release_id"])
        self.assertEqual(security["current_release_id"], release["body"]["release_id"])
        self.assertEqual(security["events"][-1]["action"], "INSTALL")
        if os.name == "posix":
            for script in (
                units_root / "activate-systemd.sh",
                units_root / "deactivate-systemd.sh",
            ):
                subprocess.run(["/bin/sh", "-n", str(script)], check=True)

    def test_windows_package_uses_limited_restartable_user_tasks(self):
        release, source_root = self.build_release(1, platform="windows")
        result = self.install(release, source_root)
        self.assertEqual(result["platform"], "windows")
        package = self.install_root / "task-scheduler"
        self.assertEqual(Path(result["service_package_directory"]), package)

        activate = (package / "activate-tasks.ps1").read_text(encoding="utf-8")
        self.assertIn("-RunLevel Limited", activate)
        self.assertIn("-RestartCount 5", activate)
        self.assertIn("/inheritance:r", activate)
        start_positions = [
            activate.index(f"Start-ScheduledTask -TaskName 'MindChain-{name}'")
            for name in host.SERVICE_ORDER
        ]
        self.assertEqual(start_positions, sorted(start_positions))
        self.assertNotIn("=production", activate)

        for service in release["body"]["services"]:
            name = service["name"]
            runner = (package / f"run-{name}.ps1").read_text(encoding="utf-8")
            descriptor = host.load_object(package / f"mindchain-{name}.task.json")
            self.assertIn("[Environment]::SetEnvironmentVariable", runner)
            self.assertIn(f"bin\\{name}.exe", runner)
            self.assertNotIn("=production", runner)
            self.assertEqual(descriptor["service"], name)
            self.assertEqual(descriptor["run_level"], "LIMITED")
            self.assertEqual(
                descriptor["dependencies"], service["dependencies"]
            )
            self.assertEqual(descriptor["restart_count"], 5)

        security = host.load_security(self.state_root)
        self.assertEqual((security["platform"], security["arch"]), ("windows", "x86_64"))
        if os.name == "nt":
            for script in sorted(package.glob("*.ps1")):
                escaped = str(script).replace("'", "''")
                parse_command = (
                    "$Tokens=$null; $Errors=$null; "
                    "[System.Management.Automation.Language.Parser]::ParseFile("
                    f"'{escaped}', [ref]$Tokens, [ref]$Errors) | Out-Null; "
                    "if ($Errors.Count -ne 0) { "
                    "$Errors | ForEach-Object { Write-Error $_.Message }; exit 1 }"
                )
                completed = subprocess.run(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        parse_command,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(
                    completed.returncode,
                    0,
                    f"{script}: {completed.stdout}{completed.stderr}",
                )

    def test_macos_package_uses_user_launch_agents_and_safe_env_wrappers(self):
        release, source_root = self.build_release(1, platform="macos")
        result = self.install(release, source_root)
        self.assertEqual(result["platform"], "macos")
        package = self.install_root / "launchd"
        self.assertEqual(Path(result["service_package_directory"]), package)

        activate = (package / "activate-launchd.sh").read_text(encoding="utf-8")
        self.assertIn('DOMAIN="gui/$(id -u)"', activate)
        self.assertIn('AGENT_ROOT="$HOME/Library/LaunchAgents"', activate)
        start_positions = [
            activate.index(f'launchctl kickstart -k "$DOMAIN/org.mindchain.{name}"')
            for name in host.SERVICE_ORDER
        ]
        self.assertEqual(start_positions, sorted(start_positions))
        self.assertNotIn("=production", activate)

        for service in release["body"]["services"]:
            name = service["name"]
            wrapper = (package / f"run-{name}.sh").read_text(encoding="utf-8")
            plist = plistlib.loads(
                (package / f"org.mindchain.{name}.plist").read_bytes()
            )
            self.assertIn('export "$key=$value"', wrapper)
            self.assertIn(f"bin/{name}", wrapper.replace("\\", "/"))
            self.assertNotIn("=production", wrapper)
            self.assertEqual(plist["Label"], f"org.mindchain.{name}")
            self.assertTrue(plist["RunAtLoad"])
            self.assertEqual(plist["KeepAlive"], {"SuccessfulExit": False})
            self.assertEqual(
                plist["ProgramArguments"], [str(package / f"run-{name}.sh")]
            )
            self.assertEqual(plist["WorkingDirectory"], str(self.state_root / name))

        security = host.load_security(self.state_root)
        self.assertEqual((security["platform"], security["arch"]), ("macos", "universal2"))
        if sys.platform == "darwin":
            for script in sorted(package.glob("*.sh")):
                subprocess.run(["/bin/sh", "-n", str(script)], check=True)

    def test_update_cannot_change_signed_platform_or_architecture(self):
        linux, linux_source = self.build_release(1)
        windows, windows_source = self.build_release(2, platform="windows")
        self.install(linux, linux_source)
        with self.assertRaisesRegex(
            host.HostLifecycleError, "platform/architecture changed"
        ):
            self.install(
                windows, windows_source, now=self.now + timedelta(minutes=1)
            )
        security = host.load_security(self.state_root)
        self.assertEqual((security["platform"], security["arch"]), ("linux", "x86_64"))

    def test_install_rejects_a_release_for_another_runtime_target(self):
        local_platform, _ = host.runtime_target()
        wrong_platform = "windows" if local_platform != "windows" else "linux"
        release, source_root = self.build_release(1, platform=wrong_platform)
        with self.assertRaisesRegex(host.HostLifecycleError, "different runtime"):
            host.install_release(
                release,
                self.release_identity["key_id"],
                source_root,
                self.private_source,
                self.install_root,
                self.state_root,
                self.private_root,
                now=self.now,
            )
        self.assertFalse(self.install_root.exists())
        self.assertIsNone(host.load_security(self.state_root))

    def test_update_rejects_private_mutation_replay_and_downgrade(self):
        first, first_source = self.build_release(1)
        second, second_source = self.build_release(2)
        self.install(first, first_source)
        marker = self.state_root / "node" / "ledger.marker"
        marker.write_bytes(b"durable-ledger")

        node_private = self.private_source / "node.env"
        original_private = node_private.read_bytes()
        node_private.write_bytes(b"MINDCHAIN_NODE_MODE=changed\n")
        with self.assertRaisesRegex(host.HostLifecycleError, "credential rotation"):
            self.install(second, second_source, now=self.now + timedelta(minutes=1))
        self.assertEqual(
            host.load_security(self.state_root)["current_release_id"],
            first["body"]["release_id"],
        )
        node_private.write_bytes(original_private)

        result = self.install(second, second_source, now=self.now + timedelta(minutes=2))
        self.assertEqual(result["previous_release_id"], first["body"]["release_id"])
        self.assertEqual(marker.read_bytes(), b"durable-ledger")
        with self.assertRaisesRegex(host.HostLifecycleError, "replay or downgrade"):
            self.install(second, second_source, now=self.now + timedelta(minutes=3))
        with self.assertRaisesRegex(host.HostLifecycleError, "replay or downgrade"):
            self.install(first, first_source, now=self.now + timedelta(minutes=4))

    def test_signed_direct_rollback_consumes_authorization_once(self):
        first, first_source = self.build_release(1)
        second, second_source = self.build_release(2)
        self.install(first, first_source)
        self.install(second, second_source, now=self.now + timedelta(minutes=1))

        rollback_to_first = host.authorize_rollback(
            second,
            first["body"]["release_id"],
            self.rollback_seed,
            self.root / "rollback-to-first.json",
            self.now,
            self.now + timedelta(hours=1),
            "Second release failed health checks",
        )
        forged = copy.deepcopy(rollback_to_first)
        forged["signature"]["signature_base64"] = base64.b64encode(b"x" * 64).decode(
            "ascii"
        )
        with self.assertRaisesRegex(host.HostLifecycleError, "signature"):
            host.rollback_release(
                forged,
                self.install_root,
                self.state_root,
                self.private_root,
                now=self.now + timedelta(minutes=2),
            )

        result = host.rollback_release(
            rollback_to_first,
            self.install_root,
            self.state_root,
            self.private_root,
            now=self.now + timedelta(minutes=2),
        )
        self.assertEqual(result["release_id"], first["body"]["release_id"])
        self.assertEqual(result["rolled_back_from"], second["body"]["release_id"])

        rollback_to_second = host.authorize_rollback(
            first,
            second["body"]["release_id"],
            self.rollback_seed,
            self.root / "rollback-to-second.json",
            self.now,
            self.now + timedelta(hours=1),
            "Restore repaired second release",
        )
        host.rollback_release(
            rollback_to_second,
            self.install_root,
            self.state_root,
            self.private_root,
            now=self.now + timedelta(minutes=3),
        )
        with self.assertRaisesRegex(host.HostLifecycleError, "already been consumed"):
            host.rollback_release(
                rollback_to_first,
                self.install_root,
                self.state_root,
                self.private_root,
                now=self.now + timedelta(minutes=4),
            )
        self.assertEqual(host.load_security(self.state_root)["highest_release_sequence"], 2)

    def test_rollback_rejects_expired_and_non_predecessor_authorizations(self):
        first, first_source = self.build_release(1)
        second, second_source = self.build_release(2)
        third, third_source = self.build_release(3)
        self.install(first, first_source)
        self.install(second, second_source, now=self.now + timedelta(minutes=1))
        self.install(third, third_source, now=self.now + timedelta(minutes=2))

        expired = host.authorize_rollback(
            third,
            second["body"]["release_id"],
            self.rollback_seed,
            self.root / "expired.json",
            self.now,
            self.now + timedelta(minutes=3),
            "Short emergency approval",
        )
        with self.assertRaisesRegex(host.HostLifecycleError, "not currently valid"):
            host.rollback_release(
                expired,
                self.install_root,
                self.state_root,
                self.private_root,
                now=self.now + timedelta(minutes=4),
            )

        skips_predecessor = host.authorize_rollback(
            third,
            first["body"]["release_id"],
            self.rollback_seed,
            self.root / "skip-predecessor.json",
            self.now,
            self.now + timedelta(hours=1),
            "Attempt to skip a release",
        )
        with self.assertRaisesRegex(host.HostLifecycleError, "direct transition"):
            host.rollback_release(
                skips_predecessor,
                self.install_root,
                self.state_root,
                self.private_root,
                now=self.now + timedelta(minutes=4),
            )

    def test_repair_restores_release_without_mutating_state_or_private_config(self):
        release, source_root = self.build_release(1)
        self.install(release, source_root)
        state_marker = self.state_root / "indexer" / "database.marker"
        state_marker.write_bytes(b"indexed-height=991")
        private_before = {
            name: (self.private_root / f"{name}.env").read_bytes()
            for name in host.SERVICE_ORDER
        }
        artifact_record = release["body"]["artifacts"][0]
        installed_artifact = (
            self.install_root
            / "releases"
            / release["body"]["release_id"]
            / artifact_record["path"]
        )
        os.chmod(installed_artifact, 0o644)
        installed_artifact.write_bytes(b"corrupt")
        with self.assertRaisesRegex(host.HostLifecycleError, "missing or corrupt"):
            host.verify_release_tree(
                release["body"],
                self.install_root / "releases" / release["body"]["release_id"],
            )

        result = host.repair_release(
            release,
            self.release_identity["key_id"],
            source_root,
            self.private_source,
            self.install_root,
            self.state_root,
            self.private_root,
            now=self.now + timedelta(minutes=1),
            enforce_runtime_target=False,
        )
        self.assertEqual(result["action"], "REPAIR")
        host.verify_release_tree(
            release["body"],
            self.install_root / "releases" / release["body"]["release_id"],
        )
        self.assertEqual(state_marker.read_bytes(), b"indexed-height=991")
        self.assertEqual(
            private_before,
            {
                name: (self.private_root / f"{name}.env").read_bytes()
                for name in host.SERVICE_ORDER
            },
        )

    def test_uninstall_preserves_durable_data_and_allows_exact_reinstall(self):
        release, source_root = self.build_release(1)
        self.install(release, source_root)
        marker = self.state_root / "gateway" / "queue.marker"
        marker.write_bytes(b"pending=7")
        private_before = (self.private_root / "gateway.env").read_bytes()

        record = host.uninstall_host(
            self.install_root,
            self.state_root,
            self.private_root,
            now=self.now + timedelta(minutes=1),
        )
        self.assertFalse(self.install_root.exists())
        self.assertTrue(record["state_preserved"])
        self.assertTrue(record["private_config_preserved"])
        self.assertEqual(marker.read_bytes(), b"pending=7")
        self.assertEqual((self.private_root / "gateway.env").read_bytes(), private_before)
        self.assertTrue((self.state_root / "host-control" / "last-uninstall.json").is_file())

        result = self.install(release, source_root, now=self.now + timedelta(minutes=2))
        self.assertEqual(result["action"], "REINSTALL")
        security = host.load_security(self.state_root)
        self.assertEqual(security["highest_release_sequence"], 1)
        self.assertEqual(security["events"][-1]["action"], "REINSTALL")
        self.assertEqual(marker.read_bytes(), b"pending=7")

    def test_nested_install_state_and_private_roots_are_rejected(self):
        release, source_root = self.build_release(1)
        with self.assertRaisesRegex(host.HostLifecycleError, "must be separate"):
            host.install_release(
                release,
                self.release_identity["key_id"],
                source_root,
                self.private_source,
                self.install_root,
                self.install_root / "state",
                self.private_root,
                now=self.now,
            )


if __name__ == "__main__":
    unittest.main()
