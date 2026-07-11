#!/usr/bin/env python3
"""check_identity.py — protocol-identity boundary gate.

Usage:
    python tools/gates/check_identity.py --reject-root C:/ascent [--root PATH]

Proves that no runtime dependency, accepted schema/domain, state path,
default endpoint, old chain identity, ASCENT-* DST, ascent.* domain, or
`mind` address HRP crosses the NOOSPHERE protocol boundary.

Two phases, both mandatory:

  1. LIVE SCAN — walk the repository tree (default: the repo containing this
     script) and report every forbidden-identity finding in non-doc files.
     Historical/provenance text is allowlisted via
     tools/gates/identity-allowlist.txt (path prefixes relative to the repo
     root, '#' comments; a trailing '/' allowlists a directory).
     Markdown files are documentation and are exempt from content rules
     (runtime identity cannot cross via *.md); they are still counted.

  2. SELF-TEST — every sample in tools/gates/adversarial-corpus/ is copied
     into a temporary tree and MUST be detected by the same scanning engine.
     A scanner that cannot re-detect its own adversarial corpus is broken
     and the gate fails regardless of the live-scan result.

Exit 0 only when the live tree has zero findings AND all (>= 4) adversarial
samples are detected.

Forbidden-identity surface (grounded in the historical Ascent tree):
  * Cargo.toml / go.mod dependencies on ascent-* crates or path/replace
    entries resolving into the reject root
  * ASCENT-* / ASCENT_* domain-separation tags and env prefixes
    (e.g. ASCENT-BLS-STAGE-ATTEST-V0, ASCENT_RPC_AUTH_TOKEN)
  * ascent.* hash/schema domains (e.g. ascent.tx, ascent.keystore.v1)
  * ascent-* crate/network names (e.g. ascent-crypto, ascent-devnet-1)
  * `mind` address HRP literals and mind1... bech32(m) addresses
  * hardcoded paths into the reject root (old state dirs, endpoints)

Ascent chain IDs are BLAKE-derived Hash32 values with no textual constant;
any artifact carrying one necessarily also carries an ascent.* domain,
ASCENT-* tag, or reject-root path, all of which are covered above.
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

# Directories never scanned (build output, VCS, evidence archives).
EXCLUDED_DIRS = {
    ".git",
    "target",
    "evidence",
    "node_modules",
    "__pycache__",
    ".idea",
    ".vscode",
}

# Files that intentionally contain forbidden patterns (this scanner, its
# corpus, its allowlist).  Relative to repo root, forward slashes.
SELF_EXCLUDED = (
    "tools/gates/check_identity.py",
    "tools/gates/identity-allowlist.txt",
    "tools/gates/adversarial-corpus/",
)

ALLOWLIST_FILE = "tools/gates/identity-allowlist.txt"
CORPUS_DIR = "tools/gates/adversarial-corpus"
MIN_CORPUS_SAMPLES = 4


def build_rules(reject_root: str):
    """Compile (category, regex) content rules."""
    # Path rule tolerant of /, \, and doubled separators, case-insensitive
    # drive letter: C:/ascent, C:\ascent, c://ascent ...
    root = reject_root.rstrip("/\\")
    drive, _, tail = root.partition(":")
    if tail:
        tail_pattern = re.escape(tail.lstrip("/\\").replace("\\", "/")).replace(
            "/", r"[/\\]+"
        )
        path_pattern = rf"(?i)\b{re.escape(drive)}:[/\\]+{tail_pattern}\b"
    else:
        path_pattern = rf"(?i){re.escape(root)}\b"
    return [
        ("ascent-dst", re.compile(r"\bASCENT[-_][A-Z0-9]")),
        ("ascent-domain", re.compile(r"\bascent\.[a-z]")),
        ("ascent-name", re.compile(r"\bascent-[a-z0-9]")),
        ("mind-hrp-literal", re.compile(r"""["']mind["']""")),
        (
            "mind-address",
            re.compile(rf"\bmind1[{BECH32_CHARSET}]{{6,}}"),
        ),
        ("reject-root-path", re.compile(path_pattern)),
    ]


def manifest_findings(relpath: str, name: str, text: str, reject_tail: str):
    """Extra dependency checks for Cargo.toml / go.mod manifests."""
    findings = []
    lines = text.splitlines()
    if name.endswith("Cargo.toml"):
        for lineno, line in enumerate(lines, 1):
            stripped = line.split("#", 1)[0]
            if re.search(r"\bascent-[a-z0-9-]+\s*(=|\.|\])", stripped) or re.search(
                r'"ascent-[a-z0-9-]+"', stripped
            ):
                findings.append(
                    (relpath, lineno, "cargo-ascent-dep", stripped.strip())
                )
            m = re.search(r'path\s*=\s*"([^"]+)"', stripped)
            if m and reject_tail in m.group(1).replace("\\", "/").lower():
                findings.append(
                    (relpath, lineno, "cargo-reject-root-path-dep", stripped.strip())
                )
    elif name.endswith("go.mod"):
        for lineno, line in enumerate(lines, 1):
            stripped = line.split("//", 1)[0]
            if re.search(r"\bascent\b|\bascent-[a-z0-9-]+", stripped):
                findings.append((relpath, lineno, "go-ascent-dep", stripped.strip()))
    return findings


def load_allowlist(root: Path):
    entries = []
    path = root / ALLOWLIST_FILE
    if path.is_file():
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                entries.append(line.replace("\\", "/"))
    return entries


def is_allowlisted(relpath: str, entries) -> bool:
    for entry in entries:
        if entry.endswith("/"):
            if relpath.startswith(entry):
                return True
        elif relpath == entry:
            return True
    return False


def looks_binary(chunk: bytes) -> bool:
    return b"\x00" in chunk


def scan_tree(root: Path, rules, allowlist, *, self_exclude: bool):
    """Scan every non-doc text file under root; return findings list."""
    findings = []
    reject_tail = "/ascent"
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in EXCLUDED_DIRS for part in rel_parts):
            continue
        relpath = "/".join(rel_parts)
        if self_exclude and (
            relpath in SELF_EXCLUDED
            or any(relpath.startswith(p) for p in SELF_EXCLUDED if p.endswith("/"))
        ):
            continue
        if is_allowlisted(relpath, allowlist):
            continue
        if path.suffix.lower() == ".md":
            continue  # documentation: provenance text, not runtime identity
        try:
            raw = path.read_bytes()
        except OSError as exc:
            findings.append((relpath, 0, "unreadable", str(exc)))
            continue
        if looks_binary(raw[:4096]):
            continue
        text = raw.decode("utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), 1):
            for category, rx in rules:
                if rx.search(line):
                    findings.append((relpath, lineno, category, line.strip()[:160]))
        findings.extend(manifest_findings(relpath, path.name, text, reject_tail))
    return findings


def self_test(root: Path, rules) -> tuple[bool, list[str]]:
    """Plant every adversarial sample in a temp tree; each must be flagged."""
    corpus = root / CORPUS_DIR
    report: list[str] = []
    if not corpus.is_dir():
        return False, [f"MISSING corpus dir: {corpus}"]
    samples = sorted(p for p in corpus.iterdir() if p.is_file())
    if len(samples) < MIN_CORPUS_SAMPLES:
        return False, [
            f"corpus has {len(samples)} sample(s), need >= {MIN_CORPUS_SAMPLES}"
        ]
    all_detected = True
    tmp = Path(tempfile.mkdtemp(prefix="noos-identity-selftest-"))
    try:
        for idx, sample in enumerate(samples):
            # Manifest-style samples are planted under their canonical
            # basenames so the dedicated dependency checks also fire.
            name = sample.name
            if "cargo-manifest" in name:
                name = "Cargo.toml"
            elif name.endswith("go.mod") or "go-mod" in name:
                name = "go.mod"
            plant_dir = tmp / f"sample-{idx}"
            plant_dir.mkdir()
            shutil.copyfile(sample, plant_dir / name)
            found = scan_tree(plant_dir, rules, [], self_exclude=False)
            if found:
                cats = sorted({f[2] for f in found})
                report.append(f"DETECTED  {sample.name}  -> {', '.join(cats)}")
            else:
                report.append(f"MISSED    {sample.name}  -> no findings")
                all_detected = False
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return all_detected, report


def main(argv) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--reject-root",
        default="C:/ascent",
        help="historical chain root whose identity must not cross (default C:/ascent)",
    )
    parser.add_argument(
        "--root",
        default=None,
        help="tree to scan (default: repository containing this script)",
    )
    args = parser.parse_args(argv[1:])

    root = (
        Path(args.root).resolve()
        if args.root
        else Path(__file__).resolve().parents[2]
    )
    if not root.is_dir():
        print(f"ERROR: scan root not found: {root}", file=sys.stderr)
        return 2

    rules = build_rules(args.reject_root)
    allowlist = load_allowlist(root)

    findings = scan_tree(root, rules, allowlist, self_exclude=True)
    detected, report = self_test(root, rules)

    print(f"identity gate: root={root} reject-root={args.reject_root}")
    print(f"live scan: {len(findings)} forbidden finding(s)")
    for relpath, lineno, category, snippet in findings:
        print(f"  FORBIDDEN [{category}] {relpath}:{lineno}: {snippet}")
    print("adversarial self-test:")
    for line in report:
        print(f"  {line}")

    ok = not findings and detected
    print(f"RESULT identity_gate={'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
