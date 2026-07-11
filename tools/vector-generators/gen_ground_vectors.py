#!/usr/bin/env python3
"""gen_ground_vectors.py — Ground/Pulse conformance vectors.

Independently generates `protocol/vectors/ground/*.json` with a pure-Python
big-integer oracle (Python `blake3` for the ticket law, arbitrary-precision
ints for Pulse). The Rust crate `noos-ground` and the future Go client must
reproduce every case bit-for-bit; the exact Pulse evaluation and rounding
law is frozen in `protocol/spec/pulse-exp2-v1.md`.

Files:
  * ground-ticket-v1.json  — ticket recomputation/validation cases; `bytes`
    is the canonical 76-byte GroundTicketV1 encoding
    (profile_id u32 LE || nonce u64 LE || extra_nonce[32] || digest[32]).
  * pulse-retarget-v1.json — {anchor_target_hex, t, t_a, h, h_a,
    expected_target_hex} cases (hex fields big-endian, 64 digits); `bytes`
    is the expected target as 32 bytes little-endian.

Usage:
    python tools/vector-generators/gen_ground_vectors.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import blake3

sys.path.insert(0, str(Path(__file__).resolve().parent))
from gen_exp2_table import exp2_table_entries  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = REPO_ROOT / "protocol" / "vectors" / "ground"

CHALLENGE_CTX = b"NOOS/GROUND/CHALLENGE/V1"
TICKET_CTX = b"NOOS/GROUND/TICKET/V1"
MAX = (1 << 256) - 1
TABLE = exp2_table_entries()


# ---------------------------------------------------------------- oracles

def ground_challenge(chain_id: bytes, parent_hash: bytes, parent_target: int,
                     slot: int, proposal_commitment: bytes, proposer_pubkey: bytes) -> bytes:
    assert len(chain_id) == len(parent_hash) == len(proposal_commitment) == 32
    assert len(proposer_pubkey) == 48
    payload = (CHALLENGE_CTX + chain_id + parent_hash
               + parent_target.to_bytes(32, "little") + slot.to_bytes(8, "little")
               + proposal_commitment + proposer_pubkey)
    return blake3.blake3(payload).digest()


def ground_digest(challenge: bytes, nonce: int, extra_nonce: bytes) -> bytes:
    assert len(extra_nonce) == 32
    payload = TICKET_CTX + nonce.to_bytes(8, "little") + extra_nonce
    return blake3.blake3(payload, key=challenge).digest()


def pulse_target_v1(anchor_target: int, t_a: int, h_a: int, t: int, h: int) -> int:
    """Frozen Pulse v1 law (protocol/spec/pulse-exp2-v1.md)."""
    assert 1 <= anchor_target <= MAX and h > h_a
    n = t - t_a - 6 * (h - h_a)
    q, r = divmod(n, 3600)           # Python divmod == Euclidean for +ve divisor
    f = (r << 64) // 3600            # exact floor; 0 <= f < 2^64
    if q >= 256:
        return MAX
    if q <= -257:
        return 1
    acc = anchor_target
    for k in range(64):              # MSB fractional bit first
        if (f >> (63 - k)) & 1:
            acc = (acc * TABLE[k]) >> 64
    if q >= 0:
        acc <<= q
    else:
        acc >>= -q
    return min(max(acc, 1), MAX)


def ground_work(target: int) -> int:
    return MAX // (target + 1)


# ------------------------------------------------------------- ticket file

def h32(fill: int) -> bytes:
    return bytes([fill]) * 32


def encode_ticket(profile_id: int, nonce: int, extra_nonce: bytes, digest: bytes) -> str:
    return (profile_id.to_bytes(4, "little") + nonce.to_bytes(8, "little")
            + extra_nonce + digest).hex()


def ticket_cases() -> list[dict]:
    genesis = 1_700_000_000_000
    base = {
        "chain_id": h32(0x11).hex(),
        "parent_hash": h32(0x22).hex(),
        "parent_ground_target_le": (1 << 200).to_bytes(32, "little").hex(),
        "proposal_commitment": h32(0x33).hex(),
        "proposer_pubkey": (bytes([0x44]) * 48).hex(),
        "genesis_time_ms": genesis,
        "timestamp_ms": genesis + 150_000,   # slot 25
        "parent_slot": 22,
        "parent_timestamps_ms": [genesis + 6_000 * (i + 1) for i in range(11)],
        "adjusted_now_ms": genesis + 150_000,
        "max_future_drift_ms": 12_000,
        "duplicate": False,
    }
    slot = (base["timestamp_ms"] - genesis) // 6000
    target = 1 << 255

    def challenge_for(case: dict, slot_val: int | None = None) -> bytes:
        c_slot = (slot_val if slot_val is not None
                  else (case["timestamp_ms"] - case["genesis_time_ms"]) // 6000)
        return ground_challenge(
            bytes.fromhex(case["chain_id"]), bytes.fromhex(case["parent_hash"]),
            int.from_bytes(bytes.fromhex(case["parent_ground_target_le"]), "little"),
            c_slot, bytes.fromhex(case["proposal_commitment"]),
            bytes.fromhex(case["proposer_pubkey"]))

    def mine(case: dict, tgt: int, extra: bytes) -> tuple[int, bytes]:
        chal = challenge_for(case)
        for nonce in range(100_000):
            digest = ground_digest(chal, nonce, extra)
            if int.from_bytes(digest, "little") < tgt:
                return nonce, digest
        raise AssertionError("unminable fixture target")

    extra = bytes([0x55]) * 32
    cases: list[dict] = []

    def emit(name: str, kind: str, case: dict, *, profile_id=1, nonce=None,
             extra_nonce=extra, digest=None, tgt=target, expected_tgt=None,
             slot_override=None, expect_error=None, why=None):
        if nonce is None or digest is None:
            nonce, digest = mine(case, tgt, extra_nonce)
        row_slot = (slot_override if slot_override is not None
                    else (case["timestamp_ms"] - case["genesis_time_ms"]) // 6000)
        row = {
            "name": name, "kind": kind,
            "bytes": encode_ticket(profile_id, nonce, extra_nonce, digest),
            **case,
            "slot": row_slot,
            "ground_target_le": tgt.to_bytes(32, "little").hex(),
            "expected_target_le": (tgt if expected_tgt is None
                                   else expected_tgt).to_bytes(32, "little").hex(),
            "challenge": challenge_for(case, row_slot).hex(),
        }
        if expect_error:
            row["expect_error"] = expect_error
        if why:
            row["why"] = why
        cases.append(row)

    # -- positives --------------------------------------------------------
    emit("valid-ticket-baseline", "positive", dict(base))

    c = dict(base)
    c["parent_slot"] = slot  # same slot as parent is legal
    emit("valid-same-slot-as-parent", "positive", c,
         why="slot >= parent_slot allows equality")

    c = dict(base)
    c["parent_slot"] = slot - 20  # exactly max_slot_skip
    emit("valid-max-slot-skip", "positive", c,
         why="exactly max_slot_skip=20 ahead is legal")

    c = dict(base)
    c["adjusted_now_ms"] = c["timestamp_ms"] - 12_000  # timestamp == now+drift
    emit("valid-at-future-drift-limit", "positive", c,
         why="timestamp exactly at adjusted_now + max_future_drift is legal")

    # digest == target - 1 accepts (strict-< boundary).
    nonce, digest = mine(dict(base), target, extra)
    dv = int.from_bytes(digest, "little")
    emit("valid-digest-equals-target-minus-one", "positive", dict(base),
         nonce=nonce, digest=digest, tgt=dv + 1,
         why="uint256_le(digest) == ground_target - 1 satisfies strict <")

    # -- negatives --------------------------------------------------------
    # digest == target rejects.
    emit("reject-digest-equals-target", "negative", dict(base),
         nonce=nonce, digest=digest, tgt=dv,
         expect_error="DigestNotBelowTarget",
         why="uint256_le(digest) == ground_target fails strict <")

    emit("reject-wrong-profile-id", "negative", dict(base), profile_id=2,
         expect_error="WrongProfileId", why="profile_id must be exactly 1")

    # Field mutations: mine against base, then validate under mutated context.
    nonce_b, digest_b = mine(dict(base), target, extra)
    for field, value, label in [
        ("chain_id", h32(0xAA).hex(), "chain-id"),
        ("parent_hash", h32(0xAB).hex(), "parent-hash"),
        ("parent_ground_target_le", (1 << 201).to_bytes(32, "little").hex(),
         "parent-target"),
        ("proposal_commitment", h32(0xAC).hex(), "proposal-commitment"),
        ("proposer_pubkey", (bytes([0xAD]) * 48).hex(), "proposer-pubkey"),
    ]:
        c = dict(base)
        c[field] = value
        row_challenge = ground_challenge(
            bytes.fromhex(c["chain_id"]), bytes.fromhex(c["parent_hash"]),
            int.from_bytes(bytes.fromhex(c["parent_ground_target_le"]), "little"),
            slot, bytes.fromhex(c["proposal_commitment"]),
            bytes.fromhex(c["proposer_pubkey"]))
        cases.append({
            "name": f"reject-mutated-{label}", "kind": "negative",
            "bytes": encode_ticket(1, nonce_b, extra, digest_b),
            **c, "slot": slot,
            "ground_target_le": target.to_bytes(32, "little").hex(),
            "expected_target_le": target.to_bytes(32, "little").hex(),
            "challenge": row_challenge.hex(),
            "expect_error": "DigestMismatch",
            "why": f"{field} mutated after search; challenge recomputation must not match",
        })

    # Ticket-side mutations.
    cases.append({
        "name": "reject-mutated-nonce", "kind": "negative",
        "bytes": encode_ticket(1, nonce_b ^ 1, extra, digest_b),
        **base, "slot": slot,
        "ground_target_le": target.to_bytes(32, "little").hex(),
        "expected_target_le": target.to_bytes(32, "little").hex(),
        "challenge": challenge_for(dict(base)).hex(),
        "expect_error": "DigestMismatch",
        "why": "nonce flipped; keyed recomputation must not match the digest",
    })
    extra_mut = bytes([0x55]) * 31 + bytes([0x54])
    cases.append({
        "name": "reject-mutated-extra-nonce", "kind": "negative",
        "bytes": encode_ticket(1, nonce_b, extra_mut, digest_b),
        **base, "slot": slot,
        "ground_target_le": target.to_bytes(32, "little").hex(),
        "expected_target_le": target.to_bytes(32, "little").hex(),
        "challenge": challenge_for(dict(base)).hex(),
        "expect_error": "DigestMismatch",
        "why": "extra_nonce byte flipped; keyed recomputation must not match",
    })
    digest_mut = bytes([digest_b[0] ^ 1]) + digest_b[1:]
    cases.append({
        "name": "reject-mutated-digest", "kind": "negative",
        "bytes": encode_ticket(1, nonce_b, extra, digest_mut),
        **base, "slot": slot,
        "ground_target_le": target.to_bytes(32, "little").hex(),
        "expected_target_le": target.to_bytes(32, "little").hex(),
        "challenge": challenge_for(dict(base)).hex(),
        "expect_error": "DigestMismatch",
        "why": "digest claim flipped; recomputation must not match",
    })

    # Pulse disagreement.
    emit("reject-target-differs-from-pulse", "negative", dict(base),
         expected_tgt=1 << 250, expect_error="TargetMismatch",
         why="header ground_target differs from deterministic Pulse output")

    # Slot law.
    c = dict(base)
    c["parent_slot"] = slot + 1
    emit("reject-slot-behind-parent", "negative", c,
         expect_error="SlotBehindParent", why="slot < parent_slot")
    c = dict(base)
    c["parent_slot"] = slot - 21
    emit("reject-slot-skip-too-large", "negative", c,
         expect_error="SlotSkipTooLarge", why="slot 21 > max_slot_skip=20 ahead")
    emit("reject-slot-mismatch", "negative", dict(base), slot_override=slot + 1,
         expect_error="DigestMismatch",
         why="header slot != floor((timestamp-genesis)/6000); the mismatched "
             "slot also changes the challenge, so recomputation fails first")

    # Median-time-past and drift.
    mtp = sorted(base["parent_timestamps_ms"])[5]
    c = dict(base)
    c["timestamp_ms"] = mtp
    c["parent_slot"] = (mtp - genesis) // 6000
    emit("reject-timestamp-at-mtp", "negative", c,
         expect_error="TimestampNotAfterMedianTimePast",
         why="timestamp must be strictly greater than parent MTP-11")
    c = dict(base)
    c["adjusted_now_ms"] = c["timestamp_ms"] - 12_001
    emit("reject-timestamp-beyond-drift", "negative", c,
         expect_error="TimestampTooFarInFuture",
         why="timestamp exceeds adjusted_now + max_future_drift_ms=12000 by 1ms")

    # Duplicate tuple.
    c = dict(base)
    c["duplicate"] = True
    emit("reject-duplicate-tuple", "negative", c,
         expect_error="DuplicateTicket",
         why="(proposer, nonce, extra_nonce) reused since last finalized checkpoint")

    return cases


# -------------------------------------------------------------- pulse file

def pulse_cases() -> list[dict]:
    cases: list[dict] = []

    def emit(name: str, anchor_target: int, t_a: int, h_a: int, t: int, h: int,
             why: str | None = None):
        expected = pulse_target_v1(anchor_target, t_a, h_a, t, h)
        row = {
            "name": name, "kind": "positive",
            "bytes": expected.to_bytes(32, "little").hex(),
            "anchor_target_hex": f"{anchor_target:064x}",
            "t": t, "t_a": t_a, "h": h, "h_a": h_a,
            "expected_target_hex": f"{expected:064x}",
        }
        if why:
            row["why"] = why
        cases.append(row)

    ta, ha = 10_000_000, 1024
    mid = 0xDEADBEEFCAFEF00D_123456789ABCDEF0_0000000000000001_5555AAAA5555AAAA

    # Exact exponent 0 / +1 / -1.
    emit("exp-zero-identity", mid, ta, ha, ta + 6 * 100, ha + 100,
         why="on-schedule parent: exponent 0 leaves the target unchanged")
    emit("exp-plus-one-doubles", mid, ta, ha, ta + 6 + 3600, ha + 1,
         why="exponent exactly +1 doubles the target")
    emit("exp-minus-one-halves-floor", mid | 1, ta, ha, ta + 6 - 3600, ha + 1,
         why="exponent exactly -1 halves with floor on an odd target")
    emit("exp-plus-two", 12345, ta, ha, ta + 6 + 7200, ha + 1)
    emit("exp-minus-two", 12345, ta, ha, ta + 6 - 7200, ha + 1)

    # Clamps.
    emit("clamp-t-max-from-max", MAX, ta, ha, ta + 6 + 3600, ha + 1,
         why="doubling T_max clamps at 2^256-1")
    emit("clamp-t-max-short-circuit", 1, ta, ha, ta + 6 + 3600 * 300, ha + 1,
         why="integer exponent >= 256 short-circuits to T_max")
    emit("clamp-t-min-from-one", 1, ta, ha, ta + 6 - 3600, ha + 1,
         why="halving T_min clamps at 1")
    emit("clamp-t-min-short-circuit", MAX, ta, ha, ta + 6 - 3600 * 600, ha + 1,
         why="integer exponent <= -257 short-circuits to T_min")
    emit("boundary-q-255-exact-power", 1, ta, ha, ta + 6 + 3600 * 255, ha + 1,
         why="q=255 on T_a=1 is exactly 2^255 (long path, no clamp)")
    emit("boundary-q-minus-256", 1 << 255, ta, ha, ta + 6 - 3600 * 256, ha + 1,
         why="q=-256 on 2^255 floors to 0 and clamps to T_min")

    # Fractional exponents: rounding toward negative infinity.
    emit("frac-half-sqrt2", 1 << 64, ta, ha, ta + 6 + 1800, ha + 1,
         why="exponent +1/2 multiplies by floor(sqrt(2)*2^64)")
    emit("frac-neg-half", 1 << 64, ta, ha, ta + 6 - 1800, ha + 1,
         why="exponent -1/2: q=-1, f=2^63; halve after sqrt(2) step, floored")
    emit("frac-minus-one-second", (1 << 100) + 12345, ta, ha, ta + 6 - 1, ha + 1,
         why="exponent -1/3600: q=-1, r=3599; probes floor at every step")
    emit("frac-plus-one-second", (1 << 100) + 12345, ta, ha, ta + 6 + 1, ha + 1,
         why="exponent +1/3600 probes the fractional table walk upward")
    emit("frac-seven-seconds-late", mid, ta, ha, ta + 6 + 7, ha + 1,
         why="non-dyadic fractional exponent 7/3600")
    emit("frac-behind-schedule-drift", mid, ta, ha, ta + 6 * 1000 + 4321, ha + 1000,
         why="1000 blocks with cumulative +4321s drift")
    emit("frac-ahead-of-schedule", mid, ta, ha, ta + 6 * 1000 - 4321, ha + 1000,
         why="1000 blocks with cumulative -4321s drift")
    emit("frac-small-target-rounds-down", 3, ta, ha, ta + 6 - 1, ha + 1,
         why="tiny target: fractional decay floors from 3")
    emit("frac-max-target-fraction", MAX, ta, ha, ta + 6 + 1799, ha + 1,
         why="near-half positive fraction on T_max clamps only via table floors")

    # Determinism / anchor-roll independence: same physical history encoded
    # against two different (equivalent) anchor checkpoints.
    emit("anchor-roll-old-checkpoint", 1 << 128, ta, ha, ta + 6 * 512 + 900, ha + 512,
         why="anchor at checkpoint e; see anchor-roll-new-checkpoint")
    rolled_target = pulse_target_v1(1 << 128, ta, ha, ta + 6 * 256 + 450, ha + 256)
    emit("anchor-roll-new-checkpoint", rolled_target, ta + 6 * 256 + 450, ha + 256,
         ta + 6 * 512 + 900, ha + 512,
         why="anchor rolled to checkpoint e+1 using its validated (h,t,T); "
             "output depends only on validated fields, never arrival time")

    return cases


def write(name: str, schema: str, description: str, cases: list[dict]) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    path = OUT_DIR / name
    doc = {"schema": schema, "description": description, "cases": cases}
    path.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8", newline="\n")
    print(f"wrote {path} ({len(cases)} cases)")


def main() -> int:
    write(
        "ground-ticket-v1.json", "noos-ground/ticket-v1",
        "Ground v1 ticket validation vectors (ch01 section 4.2 rules 1-8). "
        "bytes = canonical GroundTicketV1 encoding: profile_id u32 LE || nonce "
        "u64 LE || extra_nonce[32] || digest[32]. All hex lowercase; targets "
        "little-endian 32 bytes. Independently generated with Python blake3.",
        ticket_cases(),
    )
    write(
        "pulse-retarget-v1.json", "noos-ground/pulse-v1",
        "Pulse v1 ASERT retarget vectors: T_h = clamp(1, 2^256-1, floor(T_a * "
        "2^((t - t_a - 6*(h - h_a))/3600))) under the frozen Q64.64 law of "
        "protocol/spec/pulse-exp2-v1.md. anchor_target_hex/expected_target_hex "
        "are big-endian; bytes is the expected target 32-byte little-endian. "
        "Independently generated with pure-Python big integers.",
        pulse_cases(),
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
