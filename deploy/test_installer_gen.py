"""Deterministic-generation and tamper falsifiers for the platform installers."""
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import pytest

import installer_gen

HERE = Path(__file__).resolve().parent


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fixture_manifest(artifacts: dict[str, bytes]) -> dict:
    return {
        "release": {"version": "0.1.0-test", "channel": "devnet"},
        "source": {"repo_revision": "f" * 40},
        "artifact_hashes": {
            f"release/artifacts/{name}": sha256(content) for name, content in artifacts.items()
        },
    }


def make_source(tmp_path: Path, artifacts: dict[str, bytes]) -> Path:
    source = tmp_path / "source"
    source.mkdir()
    for name, content in artifacts.items():
        (source / name).write_bytes(content)
    return source


ARTIFACTS = {"noos-transition-rust.exe": b"rust binary bytes", "noos-verify.exe": b"go verify bytes"}
TEMPLATE_TEXT = installer_gen.TEMPLATE.read_text("utf-8")


class TestDeterministicGeneration:
    def test_same_manifest_renders_identical_bytes(self):
        manifest = fixture_manifest(ARTIFACTS)
        first = installer_gen.render(manifest, TEMPLATE_TEXT)
        second = installer_gen.render(manifest, TEMPLATE_TEXT)
        assert first == second
        assert set(first) == {"install-noos.ps1", "install-noos.sh"}

    def test_generate_writes_byte_identical_files(self, tmp_path):
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(json.dumps(fixture_manifest(ARTIFACTS)), "utf-8")
        a = installer_gen.generate(manifest_path, tmp_path / "a")
        b = installer_gen.generate(manifest_path, tmp_path / "b")
        assert [(p.name, p.read_bytes()) for p in a] == [(p.name, p.read_bytes()) for p in b]

    def test_all_placeholders_resolved_and_hashes_embedded(self):
        manifest = fixture_manifest(ARTIFACTS)
        for content in installer_gen.render(manifest, TEMPLATE_TEXT).values():
            assert "{{" not in content
            for name, blob in ARTIFACTS.items():
                assert f"{name} {sha256(blob)}" in content

    def test_empty_artifact_set_is_refused(self):
        with pytest.raises(installer_gen.GenerationError, match="no artifacts"):
            installer_gen.render(fixture_manifest({}), TEMPLATE_TEXT)

    def test_bad_digest_is_refused(self):
        manifest = fixture_manifest(ARTIFACTS)
        manifest["artifact_hashes"]["release/artifacts/evil.bin"] = "not-a-digest"
        with pytest.raises(installer_gen.GenerationError, match="invalid sha256"):
            installer_gen.render(manifest, TEMPLATE_TEXT)


def write_installers(tmp_path: Path) -> dict[str, Path]:
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(fixture_manifest(ARTIFACTS)), "utf-8")
    return {p.name: p for p in installer_gen.generate(manifest_path, tmp_path / "gen")}


def run_ps1(script: Path, source: Path, dest: Path):
    return subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script),
         "-Source", str(source), "-Dest", str(dest)],
        capture_output=True, text=True, timeout=120,
    )


def run_sh(script: Path, source: Path, dest: Path):
    return subprocess.run(
        ["sh", str(script), source.as_posix(), dest.as_posix()],
        capture_output=True, text=True, timeout=120,
    )


RUNNERS = {
    "install-noos.ps1": (run_ps1, "powershell"),
    "install-noos.sh": (run_sh, "sh"),
}


@pytest.mark.parametrize("script_name", sorted(RUNNERS))
class TestInstallerExecution:
    def test_clean_artifacts_install(self, tmp_path, script_name):
        runner, interpreter = RUNNERS[script_name]
        if shutil.which(interpreter) is None:
            pytest.skip(f"{interpreter} not on PATH")
        scripts = write_installers(tmp_path)
        source = make_source(tmp_path, ARTIFACTS)
        dest = tmp_path / "dest"
        proc = runner(scripts[script_name], source, dest)
        assert proc.returncode == 0, proc.stdout + proc.stderr
        for name, blob in ARTIFACTS.items():
            assert (dest / name).read_bytes() == blob

    def test_tampered_artifact_is_refused_and_nothing_installs(self, tmp_path, script_name):
        runner, interpreter = RUNNERS[script_name]
        if shutil.which(interpreter) is None:
            pytest.skip(f"{interpreter} not on PATH")
        scripts = write_installers(tmp_path)
        tampered = dict(ARTIFACTS)
        tampered["noos-transition-rust.exe"] = b"rust binary bytes TAMPERED"
        source = make_source(tmp_path, tampered)
        dest = tmp_path / "dest"
        proc = runner(scripts[script_name], source, dest)
        assert proc.returncode != 0, proc.stdout + proc.stderr
        assert "checksum mismatch" in proc.stdout + proc.stderr
        assert not dest.exists() or not any(dest.iterdir())
