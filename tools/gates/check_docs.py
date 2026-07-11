#!/usr/bin/env python3
"""Validate the versioned documentation bundle without optional dependencies."""
from __future__ import annotations
import json
import re
import sys
from pathlib import Path

REQUIRED_PAGES = {
    "index.md": ("documentation bundle", "OWNER_BLOCKED", "promotion-blockers.json"),
    "protocol-and-registries.md": ("Normative protocol", "Glossary", "Registries", "floor(2*W/3)+1"),
    "security-and-economics.md": ("Threat model", "security assumptions", "Genesis disclosure", "Economics, fees, and issuance", "NOOS_TEST"),
    "governance-and-lifecycle.md": ("Governance", "upgrades", "Emergency disable", "Exit", "Rollback"),
    "node-and-key-operations.md": ("validator", "full node", "light node", "Recovery", "DKG", "key operations"),
    "developer-guides.md": ("Wallet guide", "Agent guide", "Contract guide", "Weft guide"),
    "assurance-disclosures.md": ("Work Loom", "Neural Execution Lane", "Umbra", "BESI", "disabled"),
    "interfaces-and-explorer.md": ("REST API", "P2P", "Indexer", "Explorer interpretation", "feature_disabled"),
    "build-and-operations.md": ("SBOM", "provenance", "Monitoring", "Incident response", "Disaster recovery", "Retention and privacy"),
    "migration-and-evidence.md": ("Domain migration", "historical-chain archive", "Evidence records", "Negative results", "DNS cutover is prohibited"),
}
BINDING_KEYS = ("doc_bundle", "protocol_version", "api_version", "release_version", "chain_id", "genesis_hash", "status")
LINK = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


def front_matter(text: str) -> dict[str, str]:
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        return {}
    out: dict[str, str] = {}
    for line in lines[1:]:
        if line == "---":
            return out
        if ":" not in line:
            return {}
        key, value = line.split(":", 1)
        out[key.strip()] = value.strip()
    return {}


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    bundle_dir = root / "docs" / "v1"
    manifest_path = bundle_dir / "bundle.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [f"{manifest_path}: cannot parse: {exc}"]
    expected = set(REQUIRED_PAGES)
    actual = manifest.get("pages")
    if not isinstance(actual, list) or set(actual) != expected or len(actual) != len(expected):
        errors.append("bundle page set must exactly match required unique pages")
    expected_binding = {
        "doc_bundle": manifest.get("bundle_version"),
        "protocol_version": manifest.get("protocol_version"),
        "api_version": manifest.get("api_version"),
        "release_version": manifest.get("release_version"),
        "chain_id": manifest.get("chain_id"),
        "genesis_hash": manifest.get("genesis_hash"),
        "status": manifest.get("status"),
    }
    if manifest.get("schema_version") != 1 or manifest.get("bundle_version") != "v1":
        errors.append("bundle schema/version must be 1/v1")
    for key in ("chain_id", "genesis_hash", "parameter_manifest_hash"):
        value = manifest.get(key)
        if value != "OWNER_BLOCKED" and not (isinstance(value, str) and HEX64.fullmatch(value)):
            errors.append(f"manifest {key} must be OWNER_BLOCKED or lowercase hash32")
    if "OWNER_BLOCKED" in (manifest.get("chain_id"), manifest.get("genesis_hash")):
        if manifest.get("status") != "PREPRODUCTION_OWNER_BLOCKED":
            errors.append("unbound chain identity must be PREPRODUCTION_OWNER_BLOCKED")
        if not str(manifest.get("release_version", "")).endswith("-preproduction"):
            errors.append("unbound chain identity must use a preproduction release version")
    for name, snippets in REQUIRED_PAGES.items():
        page = bundle_dir / name
        try:
            text = page.read_text(encoding="utf-8")
        except OSError as exc:
            errors.append(f"{name}: missing/unreadable: {exc}")
            continue
        fm = front_matter(text)
        for key in BINDING_KEYS:
            if fm.get(key) != str(expected_binding[key]):
                errors.append(f"{name}: {key} does not match bundle manifest")
        for snippet in snippets:
            if snippet.casefold() not in text.casefold():
                errors.append(f"{name}: required topic/snippet absent: {snippet}")
        if "OWNER_BLOCKED / NOT A PRODUCTION RELEASE" not in text:
            errors.append(f"{name}: honest blocker banner absent")
        for target in LINK.findall(text):
            clean = target.split("#", 1)[0].split("?", 1)[0]
            if not clean or re.match(r"^[a-z][a-z0-9+.-]*:", clean, re.I):
                continue
            resolved = (page.parent / clean).resolve()
            try:
                resolved.relative_to(root.resolve())
            except ValueError:
                errors.append(f"{name}: link escapes repository: {target}")
                continue
            if not resolved.exists():
                errors.append(f"{name}: broken link: {target}")
    return errors


def main(argv: list[str]) -> int:
    root = Path(argv[1]).resolve() if len(argv) > 1 else Path(__file__).resolve().parents[2]
    errors = validate(root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        print(f"Documentation gate: FAIL ({len(errors)} error(s))")
        return 1
    print(f"Documentation gate: PASS ({len(REQUIRED_PAGES)} version-bound pages; links and blocker disclosures verified)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
