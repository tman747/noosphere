#!/usr/bin/env python3
"""differential_grain.py — Rust/Go Grain differential conformance gate (plan §5.4).

Runs the frozen vectors in protocol/vectors/grain/ through BOTH the Rust
reference (crates/noos-grain, bin grain-vec) and the independent Go
implementation (go/grainref, bin go/cmd/grainref-vec), then a deterministic
sharded campaign of generated pseudo-random programs. The compared outcome
is the canonical conformance triple: value-or-trap (+ trap code) and charge.

Usage:
    python tools/gates/differential_grain.py \
        --vectors protocol/vectors/grain --generated 100000000 --shards 256

Sharding law (frozen): shard k of S is seeded with (seed_base + k) and
generates ceil/floor(N/S) programs (the first N mod S shards take one
extra), so any mismatch is reproducible from (seed_base, k, index) alone.

Shim line protocol (self-describing; both binaries implement it):
    E <version> <meter_limit> <arena_limit> <subject_hex> <formula_hex>
        -> V <noun_hex> <charge> | T <trap_code> <charge>
    D <role: formula|subject> <hex>
        -> N <reencoded_hex> | T <trap_code>
Empty byte strings are spelled "-".

Any divergence (impl vs impl, or impl vs frozen expectation) prints a
reproducer and exits 1. Exit 0 means zero divergence.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys

MASK64 = (1 << 64) - 1
DEFAULT_SEED_BASE = 0x4E4F4F532D763100  # "NOOS-v1\0"


class Rng:
    """splitmix64 — deterministic, dependency-free, integer-only."""

    def __init__(self, seed: int) -> None:
        self.state = seed & MASK64

    def next(self) -> int:
        self.state = (self.state + 0x9E3779B97F4A7C15) & MASK64
        z = self.state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
        return z ^ (z >> 31)

    def below(self, n: int) -> int:
        return self.next() % n


# ---------------------------------------------------------------- nouns ----
# A noun is an int (atom) or a 2-tuple (head, tail).


def encode_noun(n) -> bytes:
    """Canonical Grain bytes (spec §4), iterative."""
    out = bytearray()
    stack = [n]
    while stack:
        cur = stack.pop()
        if isinstance(cur, tuple):
            out.append(0x01)
            stack.append(cur[1])
            stack.append(cur[0])
        else:
            payload = cur.to_bytes((cur.bit_length() + 7) // 8, "little")
            out.append(0x00)
            out += len(payload).to_bytes(4, "little")
            out += payload
    return bytes(out)


def gen_atom(rng: Rng) -> int:
    r = rng.below(100)
    if r < 45:
        return rng.below(13)  # opcode/axis/loobean range, incl. 12
    if r < 70:
        return rng.below(256)
    if r < 90:
        return rng.next()
    # multi-word atom (2..5 words)
    v = 0
    for _ in range(2 + rng.below(4)):
        v = (v << 64) | rng.next()
    return v or 1


def gen_noun(rng: Rng, depth: int) -> object:
    if depth <= 0 or rng.below(100) < 45:
        return gen_atom(rng)
    return (gen_noun(rng, depth - 1), gen_noun(rng, depth - 1))


def gen_axis(rng: Rng) -> int:
    r = rng.below(100)
    if r < 5:
        return 0  # INVALID_AXIS probe
    if r < 80:
        return 1 + rng.below(7)
    if r < 95:
        return 1 + rng.below(1 << 12)
    return 1 + rng.below(1 << 40)


def gen_formula(rng: Rng, depth: int) -> object:
    if depth <= 0:
        # leaf: quote or slot
        if rng.below(2) == 0:
            return (1, gen_noun(rng, 1))
        return (0, gen_axis(rng))
    r = rng.below(100)
    if r < 7:
        return gen_noun(rng, 2)  # arbitrary noun: shape/opcode trap paths
    if r < 15:  # cons composition
        return (gen_formula(rng, depth - 1), gen_formula(rng, depth - 1))
    op = rng.below(13)  # 12 exercises UNKNOWN_OPCODE
    sub = lambda: gen_formula(rng, depth - 1)  # noqa: E731
    if rng.below(100) < 5:
        return (op, gen_noun(rng, 1))  # deliberately unshaped argument
    if op == 0:
        return (0, gen_axis(rng))
    if op == 1:
        return (1, gen_noun(rng, depth))
    if op in (2, 5, 7, 8):
        return (op, (sub(), sub()))
    if op in (3, 4):
        return (op, sub())
    if op == 6:
        return (6, (sub(), (sub(), sub())))
    if op == 9:
        return (9, (gen_axis(rng), sub()))
    if op == 10:
        return (10, ((gen_axis(rng), sub()), sub()))
    if op == 11:
        return (11, (gen_noun(rng, 1), sub()))
    return (op, (sub(), sub()))  # op 12: shaped but unknown


METER_CHOICES = (0, 1, 25, 200, 5_000, 1_000_000)
ARENA_CHOICES = (0, 2, 50, 1_000, 1_000_000)


def gen_case(rng: Rng) -> str:
    """One generated program as a shim request line."""
    subject = gen_noun(rng, 1 + rng.below(4))
    formula = gen_formula(rng, 1 + rng.below(5))
    meter = METER_CHOICES[rng.below(len(METER_CHOICES))]
    if meter and rng.below(4) == 0:
        meter = rng.below(meter) or 1
    arena = ARENA_CHOICES[rng.below(len(ARENA_CHOICES))]
    version = 1 if rng.below(100) else 2 + rng.below(3)
    subj_hex = encode_noun(subject).hex() or "-"
    form = bytearray(encode_noun(formula))
    # ~10% of cases mutate the formula bytes to diff the decode law too.
    mut = rng.below(10) == 0
    if mut:
        kind = rng.below(4)
        if kind == 0 and len(form) > 1:
            form = form[: 1 + rng.below(len(form) - 1)]  # truncate
        elif kind == 1:
            form.append(rng.below(256))  # trailing byte
        elif kind == 2:
            form[rng.below(len(form))] ^= 1 << rng.below(8)  # bit flip
        else:
            form[rng.below(len(form))] = rng.below(256)  # byte stomp
    form_hex = form.hex() or "-"
    return f"E {version} {meter} {arena} {subj_hex} {form_hex}"


# -------------------------------------------------------------- vectors ----


def vector_requests(vectors_dir: str):
    """Yield (label, request_line, expected_reply_or_None) from the frozen
    vector files. Expected replies mirror the shim protocol exactly."""

    def load(name):
        with open(os.path.join(vectors_dir, name), encoding="utf-8") as fh:
            return json.load(fh)["cases"]

    def expect_eval(c):
        e = c["expect"]
        if e["kind"] == "value":
            return f"V {e['noun']} {e['charge']}"
        return f"T {e['trap_code']} {e['charge']}"

    def hx(s):
        return s if s else "-"

    for c in load("grain-eval-v1.json"):
        line = (
            f"E {c.get('version', 1)} {c['meter_limit']} {c['arena_limit']} "
            f"{hx(c['subject'])} {hx(c['formula'])}"
        )
        yield f"eval:{c['name']}", line, expect_eval(c)

    for c in load("grain-hint-erasure-v1.json"):
        base = f"E {c.get('version', 1)} {c['meter_limit']} {c['arena_limit']} {hx(c['subject'])}"
        yield f"hint:{c['name']}:hinted", f"{base} {hx(c['bytes'])}", expect_eval(c)
        yield f"hint:{c['name']}:erased", f"{base} {hx(c['erased_formula'])}", expect_eval(c)

    for c in load("grain-noun-bytes-v1.json"):
        e = c["expect"]
        # Positive obligation: decode succeeds AND re-encodes byte-identically.
        want = f"N {hx(c['bytes'])}" if e["kind"] == "noun" else f"T {e['trap_code']}"
        yield f"bytes:{c['name']}", f"D {c['role']} {hx(c['bytes'])}", want


# ----------------------------------------------------------------- shims ----


def run_batch(binary: str, lines: list[str]) -> list[str]:
    proc = subprocess.run(
        [binary],
        input="\n".join(lines) + "\n",
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        sys.exit(f"FATAL: {binary} exited {proc.returncode}: {proc.stderr.strip()}")
    out = proc.stdout.split("\n")
    replies = [ln.strip() for ln in out if ln.strip()]
    if len(replies) != len(lines):
        sys.exit(
            f"FATAL: {binary} answered {len(replies)} of {len(lines)} requests"
        )
    return replies


def build_binaries(root: str, rust_bin: str | None, go_bin: str | None):
    exe = ".exe" if os.name == "nt" else ""
    if rust_bin is None:
        subprocess.run(
            ["cargo", "build", "--release", "-p", "noos-grain", "--bin", "grain-vec"],
            cwd=root,
            check=True,
        )
        meta = subprocess.run(
            ["cargo", "metadata", "--format-version", "1", "--no-deps"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        )
        target_dir = json.loads(meta.stdout)["target_directory"]
        rust_bin = os.path.join(target_dir, "release", f"grain-vec{exe}")
    if go_bin is None:
        go_bin = os.path.join(root, "target", "gates", f"grainref-vec{exe}")
        subprocess.run(
            ["go", "build", "-o", go_bin, "./cmd/grainref-vec"],
            cwd=os.path.join(root, "go"),
            check=True,
        )
    for b in (rust_bin, go_bin):
        if not os.path.isfile(b):
            sys.exit(f"FATAL: shim binary missing: {b}")
    return rust_bin, go_bin


# ------------------------------------------------------------------ main ----


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--vectors", required=True, help="frozen vector directory")
    ap.add_argument("--generated", type=int, default=0, help="generated program count N")
    ap.add_argument("--shards", type=int, default=1, help="deterministic shard count S")
    ap.add_argument("--seed-base", type=lambda s: int(s, 0), default=DEFAULT_SEED_BASE)
    ap.add_argument("--rust-bin", help="prebuilt grain-vec path (skips cargo build)")
    ap.add_argument("--go-bin", help="prebuilt grainref-vec path (skips go build)")
    args = ap.parse_args()
    if args.shards < 1:
        ap.error("--shards must be >= 1")

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    rust_bin, go_bin = build_binaries(root, args.rust_bin, args.go_bin)
    print(f"rust shim: {rust_bin}")
    print(f"go   shim: {go_bin}")

    # Phase 1 — frozen vectors through both implementations.
    labels, lines, wants = [], [], []
    for label, line, want in vector_requests(args.vectors):
        labels.append(label)
        lines.append(line)
        wants.append(want)
    rust_replies = run_batch(rust_bin, lines)
    go_replies = run_batch(go_bin, lines)
    bad = 0
    for label, line, want, r, g in zip(labels, lines, wants, rust_replies, go_replies):
        if r != g or r != want:
            bad += 1
            print(f"VECTOR DIVERGENCE {label}\n  input: {line}\n  want:  {want}\n  rust:  {r}\n  go:    {g}")
    if bad:
        print(f"FAIL: {bad} vector divergence(s)")
        return 1
    print(f"vectors: {len(lines)} requests ({len(labels)} runner obligations), zero divergence")

    # Phase 2 — deterministic sharded generated campaign.
    n, s = args.generated, args.shards
    total = 0
    for k in range(s):
        count = n // s + (1 if k < n % s else 0)
        if count == 0:
            continue
        seed = (args.seed_base + k) & MASK64
        rng = Rng(seed)
        batch = [gen_case(rng) for _ in range(count)]
        rust_replies = run_batch(rust_bin, batch)
        go_replies = run_batch(go_bin, batch)
        for i, (line, r, g) in enumerate(zip(batch, rust_replies, go_replies)):
            if r != g:
                print(
                    "GENERATED DIVERGENCE\n"
                    f"  shard: {k}/{s}  seed: 0x{seed:016x}  index: {i}\n"
                    f"  reproduce: --seed-base 0x{args.seed_base:016x} --shards {s} (shard {k}, case {i})\n"
                    f"  input: {line}\n  rust:  {r}\n  go:    {g}"
                )
                return 1
        total += count
        print(f"shard {k}: seed 0x{seed:016x}, {count} programs, zero divergence")

    print(f"PASS: {len(lines)} vector requests + {total} generated programs, zero divergence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
