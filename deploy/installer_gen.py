"""Deterministic platform-installer generation from one template.

Reads a NOOSPHERE release manifest (release/manifest.json) and renders
`deploy/installers/installer.template` — a single template file whose
sections share one placeholder vocabulary — into the Windows PowerShell and
Linux sh installers. Output depends only on the manifest content: no
timestamps, no host state, LF newlines, byte-identical across runs.
"""
from __future__ import annotations
import json, posixpath, re
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEMPLATE = HERE / "installers" / "installer.template"
SECTION = re.compile(r"^=== \[(?P<name>[a-z0-9-]+)\] ===$")
OUTPUTS = {"windows-powershell": "install-noos.ps1", "linux-sh": "install-noos.sh"}
PLACEHOLDER = re.compile(r"\{\{[A-Z_]+\}\}")


class GenerationError(RuntimeError):
    pass


def load_sections(template_text: str) -> dict[str, str]:
    """Split the single template into named platform sections."""
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in template_text.split("\n"):
        match = SECTION.match(line)
        if match:
            name = match.group("name")
            if name in sections:
                raise GenerationError(f"duplicate template section {name}")
            current = sections.setdefault(name, [])
            continue
        if current is not None:
            current.append(line)
    if set(sections) != set(OUTPUTS):
        raise GenerationError(f"template sections {sorted(sections)} != expected {sorted(OUTPUTS)}")
    return {name: "\n".join(body).strip("\n") + "\n" for name, body in sections.items()}


def artifact_table(manifest: dict) -> str:
    """`name<SP>sha256` rows, basename per artifact, sorted, one per line."""
    hashes = manifest.get("artifact_hashes", {})
    if not hashes:
        raise GenerationError("manifest has no artifacts; refusing to generate an installer that installs nothing")
    rows = {}
    for rel_path, digest in hashes.items():
        name = posixpath.basename(rel_path)
        if not re.fullmatch(r"[0-9a-f]{64}", str(digest)):
            raise GenerationError(f"invalid sha256 for {rel_path}")
        if name in rows:
            raise GenerationError(f"duplicate artifact basename {name}")
        rows[name] = digest
    return "\n".join(f"{name} {digest}" for name, digest in sorted(rows.items()))


def render(manifest: dict, template_text: str) -> dict[str, str]:
    """Render every platform script; returns {output_filename: content}."""
    values = {
        "{{RELEASE_VERSION}}": str(manifest["release"]["version"]),
        "{{CHANNEL}}": str(manifest["release"]["channel"]),
        "{{SOURCE_REVISION}}": str(manifest["source"]["repo_revision"]),
        "{{ARTIFACT_TABLE}}": artifact_table(manifest),
    }
    out = {}
    for section, body in load_sections(template_text).items():
        for key, val in values.items():
            body = body.replace(key, val)
        leftover = PLACEHOLDER.findall(body)
        if leftover:
            raise GenerationError(f"unresolved placeholders in {section}: {sorted(set(leftover))}")
        out[OUTPUTS[section]] = body
    return out


def generate(manifest_path: Path, out_dir: Path) -> list[Path]:
    manifest = json.loads(manifest_path.read_text("utf-8"))
    rendered = render(manifest, TEMPLATE.read_text("utf-8"))
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for filename, content in sorted(rendered.items()):
        path = out_dir / filename
        path.write_bytes(content.encode("utf-8"))
        written.append(path)
    return written


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", default=str(HERE.parent / "release" / "manifest.json"))
    parser.add_argument("--out", default=str(HERE / "installers"))
    args = parser.parse_args()
    for path in generate(Path(args.manifest), Path(args.out)):
        print(f"wrote {path}")
