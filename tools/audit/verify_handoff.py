#!/usr/bin/env python3
"""Verify a NOOSPHERE independent-audit handoff directory or deterministic zip."""
from __future__ import annotations

import argparse
from pathlib import Path

from common import AuditError, materialize_bundle, sha256_file, verify_bundle_against_git


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument(
        "--repo",
        type=Path,
        required=True,
        help="independently obtained repository/worktree containing the trusted Git object database",
    )
    parser.add_argument(
        "--revision",
        required=True,
        help="trusted revision to resolve in --repo; it must resolve exactly to the bundle commit",
    )
    args = parser.parse_args()
    try:
        target = args.bundle.resolve()
        repo = args.repo.resolve()
        with materialize_bundle(target) as (root, manifest):
            resolved = verify_bundle_against_git(root, manifest, repo, args.revision)
            outer = sha256_file(target) if target.is_file() else "directory-not-applicable"
    except AuditError as exc:
        print(f"RESULT audit_handoff_verify=FAIL error={exc}")
        return 1
    print(
        "RESULT audit_handoff_verify=READY_FOR_EXTERNAL_HANDOFF "
        f"source_revision={resolved} source_tree={manifest['source_tree']} "
        f"bundle_id={manifest['bundle_id']} outer_sha256={outer}"
    )
    print("NOTICE external_audit_complete=false promotion_effect=none")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
