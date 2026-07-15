#!/usr/bin/env python3
"""Focused release-candidate portability and boundary tests."""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import generate_release
import repro_build


class ReleaseCiTests(unittest.TestCase):
    def test_go_module_graph_uses_real_module_offline_and_surfaces_stderr(self):
        env = {"GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": "-mod=readonly"}
        output = '{"Path":"example.test/main","Main":true}\n{"Path":"example.test/dep","Version":"v1.2.3"}\n'
        completed = subprocess.CompletedProcess([], 0, stdout=output, stderr="")
        with mock.patch.object(repro_build.subprocess, "run", return_value=completed) as run:
            self.assertEqual(repro_build.go_modules(env), [
                {"path": "example.test/dep", "version": "v1.2.3"},
                {"path": "example.test/main", "version": "workspace"},
            ])
        _, kwargs = run.call_args
        self.assertEqual(kwargs["cwd"], repro_build.GO_MODULE)
        self.assertIs(kwargs["env"], env)
        self.assertTrue(kwargs["capture_output"])

        failure = subprocess.CalledProcessError(
            1, ["go", "list"], output="", stderr="go: module lookup disabled by GOPROXY=off",
        )
        with mock.patch.object(repro_build.subprocess, "run", side_effect=failure):
            with self.assertRaisesRegex(repro_build.AssuranceError, "module lookup disabled.*GOPROXY=off") as raised:
                repro_build.go_modules(env)
        self.assertIn(f"cwd={repro_build.GO_MODULE}", str(raised.exception))

    def _windows_fixture(self, root: Path) -> tuple[dict[str, str], dict]:
        lock = repro_build.load_toolchains()
        target = lock["targets"]["windows-x86_64"]
        msvc = root / "vs" / "VC" / "Tools" / "MSVC" / target["msvc_tools_version"]
        sdk = root / "kits" / "10"
        sdk_version = target["windows_sdk_version"]
        directories = [
            msvc / "lib" / "x64", msvc / "bin" / "Hostx64" / "x64", msvc / "include",
            sdk / "Lib" / sdk_version / "ucrt" / "x64",
            sdk / "Lib" / sdk_version / "um" / "x64",
            sdk / "bin" / sdk_version / "x64",
            sdk / "Include" / sdk_version / "ucrt", sdk / "Include" / sdk_version / "shared",
            sdk / "Include" / sdk_version / "um", sdk / "Include" / sdk_version / "winrt",
        ]
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
        files = {
            msvc / "bin" / "Hostx64" / "x64" / "cl.exe": b"pinned-cl",
            msvc / "bin" / "Hostx64" / "x64" / "link.exe": b"pinned-link",
            sdk / "bin" / sdk_version / "x64" / "rc.exe": b"pinned-rc",
            sdk / "Lib" / sdk_version / "ucrt" / "x64" / "ucrt.lib": b"ucrt",
            sdk / "Lib" / sdk_version / "um" / "x64" / "kernel32.lib": b"kernel32",
        }
        for path, contents in files.items():
            path.write_bytes(contents)
        return {
            "NOOS_MSVC_ROOT": str(msvc),
            "NOOS_MSVC_TOOLS_VERSION": target["msvc_tools_version"],
            "NOOS_WINDOWS_SDK_ROOT": str(sdk),
            "NOOS_WINDOWS_SDK_VERSION": sdk_version,
        }, lock

    def test_windows_toolchain_explicit_resolution_and_version_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            environ, lock = self._windows_fixture(Path(directory))
            versions = {
                "cl.exe": lock["targets"]["windows-x86_64"]["msvc_cl_file_version"],
                "link.exe": lock["targets"]["windows-x86_64"]["msvc_link_file_version"],
                "rc.exe": lock["targets"]["windows-x86_64"]["windows_sdk_rc_file_version"],
            }
            resolved = repro_build.resolve_windows_toolchain(
                lock, environ, file_version_reader=lambda path: versions[path.name],
            )
            provenance = repro_build.windows_toolchain_provenance(resolved)
            self.assertEqual(provenance["msvc_tools_version"], "14.44.35207")
            self.assertEqual(provenance["windows_sdk_version"], "10.0.26100.0")
            self.assertEqual(set(provenance["binary_sha256"]), {"cl.exe", "link.exe", "rc.exe"})
            self.assertEqual(provenance["binary_file_versions"], versions)
            self.assertFalse(any(key.startswith("_") for key in provenance))

            mismatched = dict(environ, NOOS_MSVC_TOOLS_VERSION="14.99.0")
            with self.assertRaisesRegex(repro_build.AssuranceError, "NOOS_MSVC_TOOLS_VERSION mismatch"):
                repro_build.resolve_windows_toolchain(
                    lock, mismatched, file_version_reader=lambda path: versions[path.name],
                )
            with self.assertRaisesRegex(repro_build.AssuranceError, "binary version mismatch"):
                repro_build.resolve_windows_toolchain(
                    lock, environ, file_version_reader=lambda path: "0.0.0.0",
                )
            with self.assertRaisesRegex(repro_build.AssuranceError, "environment missing"):
                repro_build.resolve_windows_toolchain(lock, {})

    def test_every_matrix_target_requires_truthful_native_host_architecture(self):
        cases = {
            "windows-x86_64": ("windows", "aarch64"),
            "linux-x86_64": ("linux", "aarch64"),
            "linux-aarch64": ("linux", "x86_64"),
        }
        for target, observed in cases.items():
            with self.subTest(target=target), mock.patch.object(repro_build, "_host", return_value=observed):
                with self.assertRaisesRegex(repro_build.AssuranceError, "requires a native"):
                    repro_build.build_target(target, repro_build.ROOT / "release" / "candidates" / "never-created", smoke=True)

    def test_smoke_bundle_is_repeatable_and_preserves_candidate_boundary(self):
        identity = repro_build.source_identity()
        installed = {
            "rustc": {"path": "/pinned/rustc", "version_output": "rustc-pinned"},
            "cargo": {"path": "/pinned/cargo", "version_output": "cargo-pinned"},
            "go": {"path": "/pinned/go", "version_output": "go-pinned"},
        }

        def fake_build(_target: str, out: Path, **_kwargs: object) -> dict:
            artifacts = out / "artifacts"
            artifacts.mkdir(parents=True, exist_ok=True)
            binary_hashes = {}
            for name in ("noos-transition-rust", "noos-transition-go", "noos-verify"):
                path = artifacts / name
                path.write_bytes(name.encode("ascii"))
                binary_hashes[f"artifacts/{name}"] = repro_build.sha256_file(path)
            details = {
                "source": identity,
                "binary_hashes": binary_hashes,
                "installed_toolchain_provenance": installed,
                "windows_toolchain_provenance": None,
                "go_module_provenance": {
                    "modules": [{"path": "example.test/dep", "version": "v1.0.0"}],
                },
            }
            (out / "build-details.json").write_bytes(repro_build.canonical_json(details))
            return details

        with tempfile.TemporaryDirectory(dir=repro_build.ROOT) as directory:
            root = Path(directory)
            patches = (
                mock.patch.object(repro_build, "build_target", side_effect=fake_build),
                mock.patch.object(generate_release, "cargo_packages", return_value=[]),
            )
            with patches[0], patches[1]:
                for name in ("first", "second"):
                    generate_release.create_bundle(
                        "linux-x86_64", root / name, "test-version", smoke=True,
                        revision=identity["revision"], builder_profile="github-hosted-owner-smoke",
                    )
            first = {path.relative_to(root / "first"): path.read_bytes() for path in (root / "first").rglob("*") if path.is_file()}
            second = {path.relative_to(root / "second"): path.read_bytes() for path in (root / "second").rglob("*") if path.is_file()}
            self.assertEqual(first, second)
            manifest = json.loads(first[Path("bundle-manifest.json")])
            self.assertEqual(manifest["candidate_status"], "SMOKE_ONLY")
            self.assertEqual(manifest["promotion_effect"], "NONE")
            self.assertEqual(manifest["external_builder_gate"], "EXTERNAL_BLOCKED")
            self.assertFalse(manifest["independent_builder_evidence"])
            self.assertEqual(manifest["control_plane"], "github-actions-owner-controlled-smoke-control-plane")
            sbom = json.loads(first[Path("sbom.cdx.json")])
            self.assertIn(
                "pkg:golang/example.test/dep@v1.0.0",
                {component.get("purl") for component in sbom["components"]},
            )

        with self.assertRaisesRegex(repro_build.AssuranceError, "must remain --smoke"):
            generate_release.candidate_boundary(False, "github-hosted-owner-smoke")

    def test_workflows_pin_actions_and_encode_go_and_candidate_contracts(self):
        workflows = sorted((repro_build.ROOT / ".github" / "workflows").glob("*.yml"))
        for workflow in workflows:
            text = workflow.read_text("utf-8")
            for use in re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", text, flags=re.MULTILINE):
                if use.startswith("./"):
                    continue
                self.assertRegex(use, r"^[^@]+@[0-9a-f]{40}$", f"unpinned action in {workflow}: {use}")

        candidate = (repro_build.ROOT / ".github/workflows/reproducible-release-candidates.yml").read_text("utf-8")
        self.assertIn("working-directory: go", candidate)
        self.assertIn("go mod download all", candidate)
        self.assertIn("git diff --exit-code -- go.mod go.sum", candidate)
        self.assertIn("GOPROXY=off GOSUMDB=off go list -mod=readonly -m all", candidate)
        self.assertIn("--builder-profile github-hosted-owner-smoke", candidate)
        self.assertIn("promotion effect NONE", candidate)
        self.assertIn("Provision isolated offline dependency homes", candidate)
        self.assertIn('controlled="../.noosphere-controlled-build/${{ matrix.target }}"', candidate)
        self.assertNotIn('controlled="release/candidates/', candidate)
        self.assertFalse(repro_build.CONTROLLED_BUILD_ROOT.is_relative_to(repro_build.ROOT))
        with tempfile.TemporaryDirectory() as directory:
            target_dir = Path(directory)
            env = repro_build.deterministic_environment(
                repro_build.ROOT, target_dir, "linux-x86_64", 1,
            )
            self.assertEqual(Path(env["CARGO_HOME"]), target_dir / "cargo-home")
            self.assertEqual(Path(env["GOMODCACHE"]), target_dir / "go-home/pkg/mod")
            self.assertEqual(env["GOENV"], "off")
        for target, locked in repro_build.load_toolchains()["targets"].items():
            self.assertIn(f"target: {target}", candidate)
            self.assertIn(f"runner: {locked['runner']}", candidate)
            self.assertIn(f"rust_target: {locked['rust_target']}", candidate)


if __name__ == "__main__":
    unittest.main()
