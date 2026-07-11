#!/usr/bin/env python3
"""crawl_sources.py — NOOSPHERE Phase 1.2 corpus provenance and hash inventory.

Freezes the source of truth per the approved build plan:
  * Walks the research corpus (C:/tmp/noosphere) and the research site
    (C:/tmp/noosphere-site), hashing every file (SHA-256).
  * Parses VERIFICATION-2026-07-11.md to extract every lab root named in the
    run ledger, and scans chapters 01-11 (plus the addendum and README) for
    external filesystem/repository root references.
  * Explicitly requires C:/tmp/kt-verification-ladder/ and
    C:/tmp/nel-private-inference-lab/.
  * Emits protocol/spec/source-index.json (per-file inventory: corpus trees,
    every required lab root, and every resolvable external root up to the
    bulk threshold) and protocol/spec/external-root-index.json (per-root
    summary: existence, file count, aggregate hash, classification). Every
    file of every resolved root — bulk or not — is hashed into its root's
    aggregate SHA-256.

Exit policy:
  * exit 1 if any root named in the VERIFICATION ledger or either explicit
    root is absent, contains an unhashable file, or if any inventoried file
    falls through classification.
  * Roots referenced only by chapters that were never delivered to this host
    are recorded in `missing_roots` (with referencing chapters) and do NOT
    fail the crawl.
  * Unreadable files (Windows-unresolvable WSL reparse points, symlinks)
    inside NON-required roots are recorded per-root in `skipped_unreadable`
    and do not fail the crawl.

Read-only over all corpus/lab trees; writes only under C:/noosphere.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from pathlib import Path

# --------------------------------------------------------------------------
# Layout constants
# --------------------------------------------------------------------------
TMP = Path("C:/tmp")
CORPUS = TMP / "noosphere"
SITE = TMP / "noosphere-site"
CORPUS_TREES = [CORPUS, SITE]
VERIFICATION = CORPUS / "VERIFICATION-2026-07-11.md"
REPO = Path("C:/noosphere")
OUT_SOURCE_INDEX = REPO / "protocol/spec/source-index.json"
OUT_EXTERNAL_INDEX = REPO / "protocol/spec/external-root-index.json"

# venv/.venv are Python virtualenvs vendored inside raw third-party corpora
# (never evidence); symlinks/reparse points are skipped and recorded.
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".wrangler", "venv", ".venv"}

# Roots with more file entries than this get aggregate-hash-only treatment in
# source-index.json (their per-file hashes still feed the root aggregate).
BULK_THRESHOLD = 2000

# Chapters 01-11 + binding addendum + corpus README (scanned for external
# root references).
CHAPTER_FILES = [
    "01-architecture.md",
    "02-mathematics.md",
    "03-living-model.md",
    "04-experiments-and-falsifiers.md",
    "04-addendum-A.md",
    "05-neural-lane.md",
    "06-weft-language.md",
    "07-hearth-and-swarm.md",
    "08-memetics-and-launch.md",
    "09-the-identity.md",
    "10-competitive-audit.md",
    "11-private-inference-fiber.md",
    "README.md",
]

# Roots that MUST resolve on this host (plan §1.2): every VERIFICATION lab
# root (parsed below) plus these two explicit roots.
EXPLICIT_REQUIRED = ["kt-verification-ladder", "nel-private-inference-lab"]

# Repository shorthand used by chapter 10 (competitive audit). These are the
# frozen NCK/OCT competitor-audit corpora, delivered to this host under the
# research-handoff tree rather than at C:/tmp/<root>. Alias resolution keeps
# them EVIDENCE-classified instead of falsely "missing".
ROOT_ALIASES = {
    "NCK": TMP / "nockchain-octra-ai-research-handoff/L1-plans/NOCKCHAIN",
    "OCT": TMP / "nockchain-octra-ai-research-handoff/L1-plans/OCTRA",
}

# --------------------------------------------------------------------------
# Classification maps (plan §1.2 dispositions)
# --------------------------------------------------------------------------
DISPOSITIONS = {
    "NORMATIVE", "EVIDENCE", "HISTORICAL", "SUPERSEDED", "KILLED",
    "NO_IMPLEMENTATION_ACTION",
}

# filename -> (source_role, disposition, implementation_phase,
#              owning_mechanism, test_artifact)
CHAPTER_CLASS = {
    "01-architecture.md": (
        "frozen-base-protocol", "NORMATIVE", "P2-P8-base-protocol", None, None),
    "02-mathematics.md": (
        "formal-boundary", "NORMATIVE", "P12-analytics-boundary",
        "M-HDF-ENERGY", "C:/tmp/frontier-lab/math/checker.py"),
    "03-living-model.md": (
        "application-spec-living-model", "NORMATIVE", "P12-living-system",
        None, None),
    "04-experiments-and-falsifiers.md": (
        "gate-kill-authority", "NORMATIVE", "P1-P14-gates", None, None),
    "04-addendum-A.md": (
        "binding-addendum", "NORMATIVE", "P1-P14-gates", None, None),
    "05-neural-lane.md": (
        "application-spec-nel", "NORMATIVE", "P10-nel", "E-NEL-01",
        "C:/tmp/nel-dispute-ladder/autoresearch.sh"),
    "06-weft-language.md": (
        "application-spec-weft", "NORMATIVE", "P5-grain-weft", "E-WEFT-01",
        "C:/tmp/weft-v0/run_tests.py"),
    "07-hearth-and-swarm.md": (
        "application-spec-hearth-swarm", "NORMATIVE", "P12-hearth-swarm",
        None, "C:/tmp/swarm-agent-sim/run.py"),
    "08-memetics-and-launch.md": (
        "launch-memetics-spec", "NORMATIVE", "P13-P14-launch", None, None),
    "09-the-identity.md": (
        "application-spec-identity", "NORMATIVE", "P12-identity-pentagon",
        None, None),
    "10-competitive-audit.md": (
        "competitive-audit", "EVIDENCE", "none", None, None),
    "11-private-inference-fiber.md": (
        "application-spec-private-inference", "NORMATIVE", "P11-umbra-besi",
        "E-NEL-PRIVATE-01", "C:/tmp/nel-private-inference-lab/results.json"),
    "README.md": ("corpus-readme", "EVIDENCE", "none", None, None),
    "VERIFICATION-2026-07-11.md": (
        "verification-ledger", "EVIDENCE", "P1-freeze", None, None),
}

# External/lab root name (as referenced) ->
#   (source_role, owning_mechanism, mechanism_disposition, test_artifact)
# mechanism_disposition is the *mechanism-level* standing recorded in the
# ledger/addendum; the files themselves remain EVIDENCE.
LAB_ROOTS = {
    "weft-v0": ("lab-artifact", "E-WEFT-01a", "PASS", "run_tests.py"),
    "chorus-quorum-lab": (
        "lab-artifact", "M-LINEAGE-QUORUM", "PASS", "chorus_adapter.py"),
    "nel-quarantine-lab": (
        "lab-artifact", "M-QUARANTINE-SETTLE", "PASS", "nel_adapter.py"),
    "dream-lane": ("lab-artifact", "E-DREAM-02", "KILLED", "dream_lane_sim.py"),
    "nel-real-inference": ("lab-artifact", "E-NEL-01a", "PASS", "silu_probe.py"),
    "nel-dispute-ladder": ("lab-artifact", "E-NEL-01", "PASS", "autoresearch.sh"),
    "noosphere/research/nel-quant": (
        "lab-artifact", "E-NEL-01", "PASS", "numbers.py"),
    "frontier-lab/math": ("lab-artifact", "M-HDF-ENERGY", "PASS", "checker.py"),
    "frontier-lab": ("lab-artifact", "M-HDF-ENERGY", "PASS", "math/checker.py"),
    "swarm-agent-sim": ("lab-artifact", "S-SWARM", "PASS", "run.py"),
    "reflex-lane-lab": ("lab-artifact", "E-REFLEX-02", "PASS", "reflex_sim_v2.py"),
    "gate1-gpu-lab": ("lab-artifact", "E-NEL-01b", "PASS", "gate1_gpu_probe.py"),
    "class-gate-lab": (
        "lab-artifact", "A-CLASS-GATE.v2", "PASS", "class_gate_v2.py"),
    "reflex-fraud-lab": ("lab-artifact", "A-REFLEX-F9", "PASS", "reflex_fraud.py"),
    "oracle-court-lab": ("lab-artifact", "E-ORACLE-01", "PASS", "oracle_court.py"),
    "gradient-market-lab": (
        "lab-artifact", "E-GRAD-01", "PASS", "gradient_market.py"),
    "demand-wash-lab": (
        "lab-artifact", "E-DEMAND-WASH-01", "KILLED", "demand_wash.py"),
    "kt-verification-ladder": (
        "lab-artifact", "E-NEL-01", "PASS", "autoresearch.sh"),
    "nel-private-inference-lab": (
        "lab-artifact", "E-NEL-PRIVATE-01", "PARTIAL", "results.json"),
    "zkvm-port": ("lab-artifact", "E-NEL-01", "PARTIAL", "README.md"),
    "research": ("research-survey", None, None, None),
    "NCK": ("competitor-audit-corpus", None, None, None),
    "OCT": ("competitor-audit-corpus", None, None, None),
    "l1-blockchain": ("memetics-research-corpus", None, None, None),
    "nockchain-octra-ai-research-handoff": (
        "competitor-audit-corpus", None, None, None),
    "decentralized-ai-l1-experiment": (
        "historical-design-experiment", None, None, None),
}

ROOT_NOTES = {
    "dream-lane": "E-DREAM-02 preregistered KILL 2026-07-10; lane stays dead; files retained as evidence.",
    "demand-wash-lab": "E-DEMAND-WASH-01 preregistered KILL for consensus activation 2026-07-10; shadow accounting only.",
    "reflex-lane-lab": "Contains WITHDRAWN v1 instrument reflex_sim.py (zero evidentiary weight) alongside passing rebuilt reflex_sim_v2.py.",
    "NCK": "Nockchain competitor audit corpus (chapter 10 shorthand NCK/), delivered under nockchain-octra-ai-research-handoff/L1-plans/NOCKCHAIN.",
    "OCT": "Octra competitor audit corpus (chapter 10 shorthand OCT/), delivered under nockchain-octra-ai-research-handoff/L1-plans/OCTRA.",
    "frontier-lab": "Superset of the VERIFICATION-named frontier-lab/math root (adds gpu-conformance and red-team).",
    "l1-blockchain": "Raw memetics/due-diligence corpus cited by chapter 08; bulk root, aggregate hash only.",
    "zkvm-port": "RISC Zero span-verify port cited by chapter 10 (288 B Groth16 settlement receipt); bulk root (build target/ retained), aggregate hash only.",
    "decentralized-ai-l1-experiment": "Predecessor design experiment cited by chapter 08; historical input, no implementation action.",
}

# Heuristic for backtick repo-relative references that are external root
# candidates even when unresolvable (so they land in missing_roots).
EXTERNAL_NAME_RE = re.compile(
    r"(?:-lab|-sim|-ladder|-lane|-v0|-port|-inference|-demo)$|^[A-Z]{2,4}$")

ABS_REF_RE = re.compile(
    r"C:[/\\]tmp[/\\]([A-Za-z0-9_\-]+(?:[/\\][A-Za-z0-9_\-\.]+)*)")
TICK_REF_RE = re.compile(r"`([A-Za-z0-9][A-Za-z0-9_\-]*)/([A-Za-z0-9_\-\./]*)`")
VERIF_CWD_RE = re.compile(r"\(`([^`]+)`\)")


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def walk_files(root: Path) -> tuple[list[Path], list[dict]]:
    """All regular files under root, honoring SKIP_DIRS; symlinks/reparse
    points and unstatable files are returned separately as skipped records."""
    files: list[Path] = []
    skipped: list[dict] = []

    def onerror(err: OSError) -> None:
        skipped.append({"path": getattr(err, "filename", "?"),
                        "reason": f"walk: {err.strerror}"})

    for dirpath, dirnames, filenames in os.walk(str(root), onerror=onerror):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            p = os.path.join(dirpath, name)
            try:
                if os.path.islink(p):
                    skipped.append({"path": p.replace("\\", "/"),
                                    "reason": "symlink"})
                    continue
                os.stat(p)
            except OSError as exc:
                skipped.append({"path": p.replace("\\", "/"),
                                "reason": f"unreadable: {exc.strerror or exc}"})
                continue
            files.append(Path(p))
    return sorted(files), skipped


def posix(p: Path) -> str:
    return p.as_posix()


# --------------------------------------------------------------------------
# Reference extraction
# --------------------------------------------------------------------------

def parse_verification_roots() -> list[str]:
    """Every cwd named in the run ledger, e.g. `python run_tests.py` (`weft-v0`)."""
    text = VERIFICATION.read_text(encoding="utf-8", errors="replace")
    roots: list[str] = []
    for m in VERIF_CWD_RE.finditer(text):
        cwd = m.group(1).strip().replace("\\", "/")
        if re.fullmatch(r"[A-Za-z0-9_\-]+(/[A-Za-z0-9_\-]+)*", cwd):
            if cwd not in roots:
                roots.append(cwd)
    return roots


def corpus_internal(ref: str) -> bool:
    """True when a repo-relative reference resolves inside the corpus tree."""
    first = ref.split("/", 1)[0]
    if first in ("noosphere", "noosphere-site"):
        return True
    return (CORPUS / ref).exists()


def scan_chapter_roots(known_root_paths: list[Path]) -> dict[str, set[str]]:
    """root-name-as-referenced -> set of referencing chapter filenames.

    known_root_paths: resolved lab roots; a backtick reference that resolves
    INSIDE one of them (e.g. chapter 06's `harness/kt2_zk.py`, relative to
    kt-verification-ladder/) is internal to that root, not a new root.
    """
    refs: dict[str, set[str]] = {}

    def add(root: str, chapter: str) -> None:
        refs.setdefault(root, set()).add(chapter)

    for name in CHAPTER_FILES:
        path = CORPUS / name
        if not path.exists():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for m in ABS_REF_RE.finditer(text):
            rel = m.group(1).replace("\\", "/")
            first = rel.split("/", 1)[0]
            if first in ("noosphere", "noosphere-site"):
                continue  # corpus tree itself
            add(first, name)
        for m in TICK_REF_RE.finditer(text):
            seg, rest = m.group(1), m.group(2)
            ref = f"{seg}/{rest}".rstrip("/.")
            if corpus_internal(ref):
                continue
            if any((rp / ref).exists() for rp in known_root_paths):
                continue  # relative to an already-known lab root
            if seg in ROOT_ALIASES:
                add(seg, name)
            elif (TMP / seg).is_dir() or Path(f"C:/{seg}").is_dir():
                # e.g. research/08-pearl-matmul-pow.md lives at C:/tmp/research,
                # not in the corpus research/ dir.
                add(seg, name)
            elif EXTERNAL_NAME_RE.search(seg):
                add(seg, name)  # candidate; resolution decides missing or not
    return refs


def resolve_root(name: str):
    """Return (resolved_path or None, resolved_via or None)."""
    if name in ROOT_ALIASES:
        p = ROOT_ALIASES[name]
        return (p, "alias") if p.is_dir() else (None, None)
    cand = TMP / name
    if cand.is_dir():
        via = ("corpus-internal"
               if name.replace("\\", "/").startswith(("noosphere/",
                                                      "noosphere-site/"))
               else "C:/tmp")
        return cand, via
    cand = Path("C:/") / name
    if cand.is_dir():
        return cand, "C:/"
    return None, None


# --------------------------------------------------------------------------
# Per-file classification
# --------------------------------------------------------------------------

def classify_corpus_file(path: Path) -> dict | None:
    rel = path.relative_to(CORPUS).as_posix()
    top = rel.split("/", 1)[0]
    if rel in CHAPTER_CLASS:
        role, disp, phase, mech, test = CHAPTER_CLASS[rel]
        return dict(source_role=role, disposition=disp,
                    implementation_phase=phase, owning_mechanism=mech,
                    test_artifact=test)
    if top == "research":
        mech = None
        test = None
        if rel.startswith("research/nel-quant"):
            mech = "E-NEL-01"
            test = "C:/tmp/noosphere/research/nel-quant/numbers.py"
        return dict(source_role="research-memo", disposition="EVIDENCE",
                    implementation_phase="none", owning_mechanism=mech,
                    test_artifact=test)
    if top == "papers":
        return dict(source_role="paper", disposition="EVIDENCE",
                    implementation_phase="none", owning_mechanism=None,
                    test_artifact=None)
    if top == "brand":
        return dict(source_role="brand-asset",
                    disposition="NO_IMPLEMENTATION_ACTION",
                    implementation_phase="none", owning_mechanism=None,
                    test_artifact=None)
    return None  # unclassified -> crawl failure


def classify_site_file(path: Path) -> dict:
    # Old research-site copy: rebranded to MindChain in Phase 13; the copy on
    # this host is historical input, never served as-is.
    return dict(source_role="research-site", disposition="HISTORICAL",
                implementation_phase="P13-product", owning_mechanism=None,
                test_artifact=None)


def classify_lab_file(root_name: str, root_path: Path) -> dict:
    role, mech, _mdisp, test = LAB_ROOTS.get(
        root_name, ("lab-artifact", None, None, None))
    disposition = "EVIDENCE"
    if root_name == "decentralized-ai-l1-experiment":
        disposition = "HISTORICAL"
    return dict(source_role=role, disposition=disposition,
                implementation_phase="none", owning_mechanism=mech,
                test_artifact=posix(root_path / test) if test else None)


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    errors: list[str] = []

    verification_roots = parse_verification_roots()
    required = list(dict.fromkeys(verification_roots + EXPLICIT_REQUIRED))
    known_root_paths = [p for p, _via in map(resolve_root, required) if p]
    chapter_refs = scan_chapter_roots(known_root_paths)

    all_root_names = list(dict.fromkeys(required + sorted(chapter_refs)))

    # ---- per-file inventory -------------------------------------------
    entries: dict[str, dict] = {}

    def hash_one(path: Path):
        try:
            return sha256_file(str(path)), path.stat().st_size
        except OSError as exc:
            return None, str(exc)

    def add_entry(path: Path, cls: dict | None, origin: str,
                  required_tree: bool) -> str | None:
        """Hash + classify one file; returns its sha256 (or None on error)."""
        key = posix(path)
        if key in entries:
            return entries[key]["sha256"]
        if cls is None:
            errors.append(f"UNCLASSIFIED: {key} (origin {origin})")
            return None
        digest, size_or_err = hash_one(path)
        if digest is None:
            msg = f"UNHASHED: {key}: {size_or_err}"
            if required_tree:
                errors.append(msg)
            return None
        entries[key] = {
            "path": key,
            "sha256": digest,
            "size": size_or_err,
            "source_role": cls["source_role"],
            "owning_mechanism": cls["owning_mechanism"],
            "implementation_phase": cls["implementation_phase"],
            "test_artifact": cls["test_artifact"],
            "disposition": cls["disposition"],
        }
        return digest

    corpus_skipped: list[dict] = []
    for tree, classify in ((CORPUS, classify_corpus_file),
                           (SITE, classify_site_file)):
        if not tree.is_dir():
            errors.append(f"ABSENT CORPUS TREE: {posix(tree)}")
            continue
        files, skipped = walk_files(tree)
        for rec in skipped:
            errors.append(f"UNHASHED (corpus): {rec['path']}: {rec['reason']}")
        corpus_skipped.extend(skipped)
        for f in files:
            add_entry(f, classify(f), posix(tree), required_tree=True)

    # ---- external roots -------------------------------------------------
    roots_out: list[dict] = []
    missing_roots: list[dict] = []

    for name in all_root_names:
        resolved, via = resolve_root(name)
        referenced_by = sorted(chapter_refs.get(name, set()))
        if name in verification_roots:
            referenced_by = ["VERIFICATION-2026-07-11.md"] + referenced_by
        is_required = name in required
        role, mech, mdisp, _test = LAB_ROOTS.get(
            name, ("lab-artifact", None, None, None))

        if resolved is None:
            record = {
                "root": name,
                "resolved_path": None,
                "exists": False,
                "resolved_via": None,
                "file_count": 0,
                "aggregate_sha256": None,
                "classification": "EVIDENCE",
                "owning_mechanism": mech,
                "mechanism_disposition": mdisp,
                "referenced_by": referenced_by,
                "required": is_required,
                "tried": [posix(TMP / name), f"C:/{name}"],
            }
            if is_required:
                errors.append(
                    f"REQUIRED ROOT ABSENT: {name} (tried {record['tried']})")
                roots_out.append(record)
            else:
                missing_roots.append(record)
            continue

        files, skipped = walk_files(resolved)
        bulk = not is_required and len(files) > BULK_THRESHOLD
        cls = classify_lab_file(name, resolved)
        agg = hashlib.sha256()
        hashed = 0
        for f in files:
            key = posix(f)
            if key in entries:
                digest = entries[key]["sha256"]
            elif bulk:
                digest, size_or_err = hash_one(f)
                if digest is None:
                    skipped.append({"path": key,
                                    "reason": f"unreadable: {size_or_err}"})
                    continue
            else:
                digest = add_entry(f, cls, name, required_tree=is_required)
                if digest is None:
                    continue
            agg.update(
                f"{f.relative_to(resolved).as_posix()}:{digest}\n".encode())
            hashed += 1
        if is_required:
            for rec in skipped:
                errors.append(f"UNHASHED (required root {name}): "
                              f"{rec['path']}: {rec['reason']}")
        classification = cls["disposition"]
        record = {
            "root": name,
            "resolved_path": posix(resolved),
            "exists": True,
            "resolved_via": via,
            "file_count": hashed,
            "aggregate_sha256": agg.hexdigest(),
            "classification": classification,
            "source_role": cls["source_role"],
            "owning_mechanism": mech,
            "mechanism_disposition": mdisp,
            "referenced_by": referenced_by,
            "required": is_required,
            "per_file_entries": not bulk,
        }
        if skipped:
            record["skipped_unreadable"] = skipped
        if name in ROOT_NOTES:
            record["notes"] = ROOT_NOTES[name]
        roots_out.append(record)

    # ---- outputs ----------------------------------------------------------
    source_index = {
        "schema_version": 1,
        "generated_by": "tools/inventory/crawl_sources.py",
        "hash_algorithm": "sha256",
        "corpus_trees": [posix(t) for t in CORPUS_TREES],
        "skip_dirs": sorted(SKIP_DIRS),
        "bulk_threshold": BULK_THRESHOLD,
        "dispositions": sorted(DISPOSITIONS),
        "file_count": len(entries),
        "files": [entries[k] for k in sorted(entries)],
    }
    external_index = {
        "schema_version": 1,
        "generated_by": "tools/inventory/crawl_sources.py",
        "verification_ledger": posix(VERIFICATION),
        "verification_roots": verification_roots,
        "explicit_required_roots": EXPLICIT_REQUIRED,
        "root_count": len(roots_out),
        "roots": roots_out,
        "missing_roots": missing_roots,
    }

    OUT_SOURCE_INDEX.parent.mkdir(parents=True, exist_ok=True)
    OUT_SOURCE_INDEX.write_text(
        json.dumps(source_index, indent=1) + "\n", encoding="utf-8")
    OUT_EXTERNAL_INDEX.write_text(
        json.dumps(external_index, indent=1) + "\n", encoding="utf-8")

    print(f"files_indexed={len(entries)}")
    print(f"external_roots_resolved="
          f"{sum(1 for r in roots_out if r['exists'])}")
    print(f"required_roots={len(required)}")
    print(f"missing_roots={[r['root'] for r in missing_roots]}")
    for e in errors:
        print(f"ERROR {e}", file=sys.stderr)
    if errors:
        print("RESULT source_freeze=FAIL", file=sys.stderr)
        return 1
    print("RESULT source_freeze=PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
