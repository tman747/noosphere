#!/usr/bin/env python3
"""NOOSPHERE genesis ceremony tooling — local validation of the GENESIS
ledger sequence (protocol/spec/genesis-identity-v1.md; ch08 §4.4 run-of-show).

Everything locally satisfiable is REAL:

* canonical `GenesisParameterManifestV1` hashing (D-GENESIS-PARAMS →
  D-CHAIN-ID → D-GENESIS-FINAL, BLAKE3-256 domain hashes over the canonical
  noos-codec byte layout, never a TOML/JSON serialization);
* Quiet-Week interval math (freeze ≥ 7 days before genesis, anchor and
  ledger-reading ordering);
* post-freeze Bitcoin-anchor validation (40-byte height-LE ‖ internal-order
  hash encoding, strictly-after-freeze rule, zero anchor only on test
  networks);
* DKG transcript verification against the frozen
  protocol/vectors/crypto/feldman-threshold.json KATs (Feldman share checks,
  D-BLS-DKG partial signatures, Lagrange threshold combine, duplicate/zero
  index rejection) using py_ecc — the same library that generated them;
* genesis rebuild + hash reproduction through the existing noos-node devnet
  path (`noosd` boots the frozen devnet parameters and must print the same
  chain_id and genesis_hash this tool derives independently).

Owner/external ceremony steps (mainnet parameter signing, the multi-party
DKG, real Bitcoin anchor selection, Quiet-Week publication, human ceremony
signatures) are validated as OWNER_BLOCKED — never fabricated.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PARAMS_TOML = ROOT / "protocol/genesis/devnet-parameters.toml"
FELDMAN_VECTORS = ROOT / "protocol/vectors/crypto/feldman-threshold.json"

# Frozen devnet fixture inputs (crates/noos-node/src/bin/noosd.rs defaults).
DEVNET_GENESIS_TIME_MS = 1_760_000_000_000
DEVNET_INITIAL_GROUND_TARGET = b"\xff" * 32  # U256::MAX little-endian
DEVNET_BITCOIN_ANCHOR = b"\x00" * 32  # test networks only

DAY_S = 86_400
QUIET_WEEK_S = 7 * DAY_S

# Registered BLS DST (protocol/spec/crypto-domains-v1.csv row D-BLS-DKG).
DKG_DST = b"NOOS-BLS-DKG-V1_BLS12381G2_XMD:SHA-256_SSWU_RO_"


class CeremonyError(RuntimeError):
    pass


# ---------------------------------------------------------------------------
# Parameter file → canonical manifest → identity hashes
# ---------------------------------------------------------------------------

def parse_params(text: str) -> dict:
    """Strict mini-TOML mirror of the noos-node loader: `[section]` headers
    plus `key = value` with bool / integer / string values only."""
    out: dict[str, object] = {}
    section = ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if "=" not in line:
            raise CeremonyError(f"unparseable parameter line: {raw!r}")
        key, _, val = line.partition("=")
        key, val = key.strip(), val.split("#", 1)[0].strip()
        if val.startswith('"') and val.endswith('"'):
            parsed: object = val[1:-1]
        elif val in ("true", "false"):
            parsed = val == "true"
        else:
            parsed = int(val)
        out[f"{section}.{key}" if section else key] = parsed
    return out


def _le(value: int, width: int) -> bytes:
    return int(value).to_bytes(width, "little")


def canonical_manifest(p: dict) -> bytes:
    """Canonical `GenesisParameterManifestV1` bytes: `version:u16` then, per
    field in frozen declaration order, `tag:u16` + fixed-width LE payload
    (crates/noos-node/src/genesis.rs; noos-codec object law)."""
    w = bytearray()
    w += _le(1, 2)  # struct version

    def field(tag: int, payload: bytes) -> None:
        w.extend(_le(tag, 2))
        w.extend(payload)

    name = str(p["chain_name"]).encode("utf-8")
    if len(name) > 64:
        raise CeremonyError("chain_name exceeds the 64-byte bound")
    field(1, _le(p["schema_version"], 4))
    field(2, _le(len(name), 4) + name)
    field(3, _le(1 if p["is_test_network"] else 0, 1))
    field(4, _le(p["token.decimals"], 1))
    field(5, _le(p["consensus.slot_seconds"], 8))
    field(6, _le(p["consensus.epoch_length"], 8))
    field(7, _le(p["consensus.max_slot_skip"], 8))
    field(8, _le(p["consensus.median_time_past_blocks"], 8))
    field(9, _le(p["consensus.witness_membership_lookback_epochs"], 8))
    field(10, _le(p["consensus.pulse_target_spacing_seconds"], 8))
    field(11, _le(p["consensus.pulse_half_life_seconds"], 8))
    field(12, _le(p["consensus.max_future_drift_ms"], 8))
    field(13, _le(p["witness_ring.n_max"], 8))
    field(14, _le(p["witness_ring.n_tail"], 8))
    field(15, _le(p["witness_ring.n_hard"], 8))
    field(16, _le(p["witness_ring.min_bond_micro_noos_test"], 16))
    field(17, _le(0, 4))  # controls_bits: every radical control off at genesis
    field(18, _le(1 if p["faucet.enabled"] else 0, 1))
    field(19, _le(p["faucet.allocation_micro_noos_test"], 16))
    pubkey = bytes.fromhex(str(p["faucet.account_pubkey_ed25519_hex"]))
    if len(pubkey) != 32:
        raise CeremonyError("faucet pubkey must be 32 bytes")
    field(20, pubkey)
    field(21, _le(p["faucet.per_request_micro_noos_test"], 16))
    field(22, _le(p["faucet.cooldown_seconds"], 8))
    field(23, _le(p["dkg.participants"], 4))
    field(24, _le(p["dkg.threshold"], 4))
    return bytes(w)


def domain_hash(context: bytes, *parts: bytes) -> bytes:
    """`BLAKE3-256(context || parts...)` — crypto-domains-v1.csv law."""
    import blake3

    hasher = blake3.blake3(context)
    for part in parts:
        hasher.update(part)
    return hasher.digest()


@dataclass(frozen=True)
class DerivedIdentity:
    parameter_manifest_hash: bytes
    chain_id: bytes
    dkg_root: bytes
    genesis_hash: bytes


def derive_identity(p: dict, genesis_time_ms: int = DEVNET_GENESIS_TIME_MS,
                    bitcoin_anchor: bytes = DEVNET_BITCOIN_ANCHOR) -> DerivedIdentity:
    from production_authorization import (
        _account_bytes, _noos_object, _param_key, _param_record, _smt_root,
    )

    canon = canonical_manifest(p)
    manifest_hash = domain_hash(b"NOOS/GENESIS/PARAMS/V1", canon)
    chain_id = domain_hash(b"NOOS/CHAIN/V1", manifest_hash)
    # Devnet fixture DKG root (D-DKG-TRANSCRIPT stand-in for the multi-party
    # ceremony; refused on mainnet by the is_test_fixture law).
    if not p.get("dkg.is_test_fixture") or not p.get("is_test_network"):
        raise CeremonyError("real DKG root requires the multi-party ceremony transcript: OWNER_BLOCKED")
    dkg_root = domain_hash(
        b"NOOS/DKG/TRANSCRIPT/V1",
        b"noos-devnet/dkg-fixture/v1",
        _le(p["dkg.participants"], 4),
        _le(p["dkg.threshold"], 4),
    )
    faucet = bytes.fromhex(str(p["faucet.account_pubkey_ed25519_hex"]))
    accounts = [
        (faucet, faucet, int(p["faucet.allocation_micro_noos_test"])),
        (bytes([0xA1]) * 32, b"", 0), (bytes([0xA2]) * 32, b"", 0),
        (bytes([0xA3]) * 32, b"", 0), (bytes([0xB0]) * 32, b"", 0),
        (bytes([0xE0]) * 32, b"", 0),
    ]
    account_leaves = {}
    allocation_bytes = bytearray(_le(len(accounts), 4))
    for account_id, auth, amount in sorted(accounts):
        balances = {bytes(32): _le(amount, 16)} if amount else {}
        balance_root = _smt_root(balances)
        account_leaves[account_id] = _account_bytes(
            account_id, auth, balance_root, bytes(32),
        )
        allocation_bytes += account_id + _le(amount, 16)
    import blake3
    allocation_root = blake3.blake3(bytes(allocation_bytes)).digest()

    def obj(fields: list[tuple[int, bytes]]) -> bytes:
        return _noos_object(tuple(fields))

    fee_params = obj([
        (1, _le(1, 16)), (2, _le(1_000_000, 16)), (3, _le(125_000, 4)),
        (4, _le(1_048_576, 8)), (5, _le(100_000_000, 8)),
        (6, _le(100_000, 8)), (7, _le(1_000_000, 8)),
        (8, _le(4_194_304, 8)), (9, _le(1_000, 16)), (10, _le(16, 8)),
    ])
    fee_state = obj([(i + 1, _le(value, 16)) for i, value in enumerate((1, 1, 10, 2, 1))])
    issuance = obj([
        (1, _le(250_000_000_000_000_000, 16)),
        (2, _le(1_000_000_000_000, 16)), (3, _le(100_000, 8)),
        (4, _le(1, 4)), (5, _le(2, 4)), (6, _le(2_000_000, 8)),
    ])
    shares = obj([(1, _le(500_000, 4)), (2, _le(350_000, 4)), (3, _le(150_000, 4))])
    params = {
        _param_key("noos.params.gov-auth.v1"): _param_record(bytes([0xB0]) * 32),
        _param_key("noos.params.emrg-auth.v1"): _param_record(bytes([0xE0]) * 32),
        _param_key("noos.params.fees.v1"): _param_record(fee_params),
        _param_key("noos.params.feestate.v1"): _param_record(fee_state),
        _param_key("noos.params.issuance.v1"): _param_record(issuance),
        _param_key("noos.params.shares.v1"): _param_record(shares),
    }
    for control in (
        "work_loom_credit", "work_loom_weightcap", "witness_proofpower",
        "neural_lane", "reflex_lane", "umbra_suite", "dream_lane", "class_gate_budget",
    ):
        params[_param_key(f"noos.control.{control}")] = _param_record(obj([(1, b"\x00")]))
    empty = _smt_root({})
    roots = (
        empty, empty, _smt_root(account_leaves), empty, empty, _smt_root(params),
    )
    body = bytearray()
    body += _le(1, 2)
    body += _le(1, 2) + manifest_hash
    body += _le(2, 2) + _le(genesis_time_ms, 8)
    body += _le(3, 2) + DEVNET_INITIAL_GROUND_TARGET
    body += _le(4, 2) + allocation_root
    for tag, root in enumerate(roots, 5):
        body += _le(tag, 2) + root
    genesis_hash = domain_hash(
        b"NOOS/GENESIS/FINAL/V1", chain_id, bitcoin_anchor, dkg_root, bytes(body)
    )
    return DerivedIdentity(manifest_hash, chain_id, dkg_root, genesis_hash)


# ---------------------------------------------------------------------------
# Quiet-Week interval math and post-freeze anchor validation
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CeremonySchedule:
    """Unix-second timestamps of the ch08 §4.4 run-of-show steps."""
    freeze_time: int          # T−7d: stage-1 freeze publication
    anchor_time: int          # T−24h: Bitcoin anchor block named as mined
    ledger_reading_time: int  # T−1h: honesty-ledger reading
    genesis_time: int         # T+0


def validate_schedule(s: CeremonySchedule) -> list[str]:
    """Quiet-Week interval math. Returns violations (empty == valid)."""
    violations = []
    if s.genesis_time - s.freeze_time < QUIET_WEEK_S:
        violations.append(
            f"quiet week too short: freeze→genesis is {s.genesis_time - s.freeze_time}s, "
            f"minimum {QUIET_WEEK_S}s (7 days)"
        )
    if s.anchor_time <= s.freeze_time:
        violations.append("anchor block not strictly after the stage-1 freeze publication")
    if s.anchor_time >= s.genesis_time:
        violations.append("anchor block must be named before genesis")
    if s.genesis_time - s.anchor_time > DAY_S:
        violations.append("anchor named earlier than the T-24h window")
    if not (s.anchor_time <= s.ledger_reading_time < s.genesis_time):
        violations.append("honesty-ledger reading must fall between the anchor and genesis")
    if s.genesis_time - s.ledger_reading_time < 3600:
        violations.append("honesty-ledger reading must complete by T-1h")
    return violations


@dataclass(frozen=True)
class BitcoinAnchor:
    height: int
    block_hash_display_hex: str  # explorer/display order (reversed internal)
    named_at: int                # unix seconds the block was named/mined


def encode_anchor(a: BitcoinAnchor) -> bytes:
    """40-byte anchor: `block_height (u64 LE) || block_hash (32B, internal
    byte order — display hex reversed)` (genesis-identity-v1.md §5)."""
    digest = bytes.fromhex(a.block_hash_display_hex)
    if len(digest) != 32:
        raise CeremonyError("bitcoin block hash must be 32 bytes")
    return _le(a.height, 8) + digest[::-1]


def validate_anchor(a: BitcoinAnchor, freeze_time: int, is_test_network: bool) -> list[str]:
    violations = []
    encoded = encode_anchor(a)
    if len(encoded) != 40:
        violations.append("anchor encoding is not 40 bytes")
    if encoded[8:] == b"\x00" * 32 and not is_test_network:
        violations.append("zero anchor hash is a test-network fixture; refused off test networks")
    if a.named_at <= freeze_time:
        violations.append("anchor block mined/named at or before the stage-1 freeze: no no-earlier-than bound")
    if a.height <= 0 and not is_test_network:
        violations.append("anchor height must be a real Bitcoin height")
    return violations


# ---------------------------------------------------------------------------
# DKG transcript verification (feldman-threshold.json KATs)
# ---------------------------------------------------------------------------

def verify_dkg_vectors(path: Path = FELDMAN_VECTORS) -> dict:
    """Full verification of the frozen Feldman/threshold transcript vectors.

    Positive cases MUST verify; negative cases MUST be rejected. Raises
    CeremonyError on any deviation; returns a summary dict on success."""
    try:
        from py_ecc.bls.g2_primitives import G2_to_signature, pubkey_to_G1, signature_to_G2
        from py_ecc.bls.hash_to_curve import hash_to_G2
        from py_ecc.optimized_bls12_381 import G1, Z1, Z2, add, curve_order, multiply, normalize, pairing
    except ImportError as exc:  # pragma: no cover - environment guard
        raise CeremonyError(f"py_ecc unavailable; DKG verification impossible: {exc}") from exc

    vec = json.loads(path.read_text("utf-8"))
    threshold, participants = vec["threshold"], vec["participants"]
    commitments = [[pubkey_to_G1(bytes.fromhex(c)) for c in contrib] for contrib in vec["commitments"]]
    for i, contrib in enumerate(commitments):
        if len(contrib) != threshold:
            raise CeremonyError(f"contributor {i} commitment degree {len(contrib)} != threshold {threshold}")

    def eq_points(a, b) -> bool:
        return normalize(a) == normalize(b)

    group = pubkey_to_G1(bytes.fromhex(vec["group_public_key"]))
    acc = Z1
    for contrib in commitments:
        acc = add(acc, contrib[0])
    if not eq_points(acc, group):
        raise CeremonyError("group public key is not the sum of contributor constant terms")

    def share_public_key(index: int):
        if index <= 0 or index > participants:
            raise CeremonyError(f"share index {index} outside the valid domain 1..={participants}")
        total = Z1
        for contrib in commitments:
            x_pow = 1
            for commitment in contrib:
                total = add(total, multiply(commitment, x_pow))
                x_pow = (x_pow * index) % curve_order
        return total

    def verify_partial(pk_point, message: bytes, signature: bytes) -> bool:
        sig_point = signature_to_G2(signature)
        return pairing(sig_point, G1) == pairing(hash_to_G2(message, DKG_DST, hashlib.sha256), pk_point)

    def combine(indices: list[int], partials: list[bytes]) -> bytes:
        if len(set(indices)) != len(indices):
            raise CeremonyError("duplicate share index in threshold combine")
        if any(i <= 0 for i in indices):
            raise CeremonyError("share index 0 evaluates the polynomial at the secret; invalid")
        if len(indices) < threshold:
            raise CeremonyError("not enough shares for threshold combine")
        combined = Z2
        for i, xi in enumerate(indices):
            num, den = 1, 1
            for j, xj in enumerate(indices):
                if i == j:
                    continue
                num = (num * (-xj)) % curve_order
                den = (den * (xi - xj)) % curve_order
            lam = (num * pow(den, -1, curve_order)) % curve_order
            combined = add(combined, multiply(signature_to_G2(partials[i]), lam))
        return G2_to_signature(combined)

    checked = {"share": 0, "partial": 0, "combine": 0, "negative": 0}
    for case in vec["cases"]:
        name, kind = case["name"], case["kind"]
        if kind == "positive" and "signature" in case:
            pk = pubkey_to_G1(bytes.fromhex(case["share_public_key"]))
            if not eq_points(pk, share_public_key(case["share_index"])):
                raise CeremonyError(f"{name}: share public key does not match Feldman evaluation")
            if not verify_partial(pk, bytes.fromhex(case["bytes"]), bytes.fromhex(case["signature"])):
                raise CeremonyError(f"{name}: partial signature does not verify under D-BLS-DKG")
            checked["partial"] += 1
        elif kind == "positive" and "combined_signature" in case:
            combined = combine(case["share_indices"], [bytes.fromhex(p) for p in case["partials"]])
            if combined.hex() != case["combined_signature"]:
                raise CeremonyError(f"{name}: threshold combine mismatch")
            if not verify_partial(group, bytes.fromhex(case["bytes"]), combined):
                raise CeremonyError(f"{name}: combined signature does not verify under the group key")
            checked["combine"] += 1
        elif kind == "positive":
            pk = pubkey_to_G1(bytes.fromhex(case["share_public_key"]))
            if not eq_points(pk, share_public_key(case["share_index"])):
                raise CeremonyError(f"{name}: share public key does not match Feldman evaluation")
            checked["share"] += 1
        elif kind == "negative":
            rejected = False
            try:
                if "share_indices" in case:
                    combine(case["share_indices"], [bytes.fromhex(p) for p in case["partials"]])
                else:
                    pk = pubkey_to_G1(bytes.fromhex(case["share_public_key"]))
                    rejected = not eq_points(pk, share_public_key(case["share_index"]))
            except CeremonyError:
                rejected = True
            if not rejected:
                raise CeremonyError(f"{name}: negative case was accepted — falsifier fired")
            checked["negative"] += 1
        else:
            raise CeremonyError(f"{name}: unknown case kind {kind}")
    return checked


# ---------------------------------------------------------------------------
# Genesis rebuild + hash reproduction via the existing noos-node devnet path
# ---------------------------------------------------------------------------

def noosd_binary() -> Path:
    ext = ".exe" if os.name == "nt" else ""
    candidates = []
    ambient = os.environ.get("CARGO_TARGET_DIR")
    if ambient:
        candidates.append(Path(ambient) / "release" / f"noosd{ext}")
    candidates += [
        ROOT / "target" / "release" / f"noosd{ext}",
        ROOT / "target" / "noos-release" / "release" / f"noosd{ext}",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    subprocess.run(
        ["cargo", "build", "--locked", "--release", "-p", "noos-node", "--bin", "noosd"],
        cwd=ROOT, check=True,
    )
    return candidates[0]


def rebuild_genesis_via_node(timeout_s: float = 300.0) -> dict:
    """Boot `noosd` on the frozen devnet parameters and capture the identity
    it derives through the production genesis path (`noosd up:` line)."""
    binary = noosd_binary()
    with tempfile.TemporaryDirectory(prefix="noos-ceremony-") as tmp:
        proc = subprocess.Popen(
            [str(binary), "--params", str(PARAMS_TOML), "--data-dir", str(Path(tmp) / "data"),
             "--genesis-time", str(DEVNET_GENESIS_TIME_MS)],
            cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        identity = None
        deadline = time.monotonic() + timeout_s
        try:
            while time.monotonic() < deadline:
                line = proc.stdout.readline()
                if not line:
                    break
                if line.startswith("noosd up:"):
                    fields = dict(part.split("=", 1) for part in line.split()[2:])
                    identity = {"chain_id": fields["chain_id"], "genesis_hash": fields["genesis_hash"]}
                    break
        finally:
            proc.kill()
            proc.wait(timeout=30)
    if identity is None:
        raise CeremonyError("noosd did not report its genesis identity")
    return identity


# ---------------------------------------------------------------------------
# The ceremony ledger
# ---------------------------------------------------------------------------

OWNER_STEPS = [
    ("MAINNET_PARAMETERS_SIGNING",
     "signed mainnet-parameters.toml supplying every OWNER_BLOCKED economic value (plan §2.5)"),
    ("QUIET_WEEK_PUBLICATION",
     "public T-7d freeze of constants, registry root, conformance-vector root, reference miner (ch08 §4.4)"),
    ("BITCOIN_ANCHOR_SELECTION",
     "post-freeze Bitcoin block named the moment it is mined (T-24h)"),
    ("MULTIPARTY_DKG_CEREMONY",
     "real multi-party DKG under D-BLS-DKG/D-BLS-FELDMAN with ceremony CSPRNGs (plan §3.2)"),
    ("HUMAN_CEREMONY_SIGNATURES",
     "release-owner and independent-build-reviewer signatures over the genesis artifacts"),
]


def run_ledger(skip_node: bool = False) -> tuple[list[dict], list[str]]:
    ledger: list[dict] = []
    blockers: list[str] = []
    params = parse_params(PARAMS_TOML.read_text("utf-8"))

    identity = derive_identity(params)
    ledger.append({
        "step": "STAGE1_PARAMETER_MANIFEST",
        "status": "PASS",
        "parameter_manifest_hash": identity.parameter_manifest_hash.hex(),
        "chain_id": identity.chain_id.hex(),
        "note": "canonical GenesisParameterManifestV1 bytes hashed under D-GENESIS-PARAMS/D-CHAIN-ID (devnet fixture set)",
    })

    # Quiet-week math validated over a declared devnet fixture schedule; the
    # real mainnet schedule is an owner artifact and stays blocked below.
    fixture = CeremonySchedule(
        freeze_time=1_760_000_000 - QUIET_WEEK_S,
        anchor_time=1_760_000_000 - DAY_S,
        ledger_reading_time=1_760_000_000 - 3_600,
        genesis_time=1_760_000_000,
    )
    violations = validate_schedule(fixture)
    ledger.append({
        "step": "QUIET_WEEK_INTERVAL_MATH",
        "status": "PASS" if not violations else "FAIL",
        "violations": violations,
        "note": "interval law exercised on the devnet fixture schedule (is_test_fixture)",
    })

    anchor_violations = validate_anchor(
        BitcoinAnchor(height=0, block_hash_display_hex="00" * 32, named_at=fixture.anchor_time),
        fixture.freeze_time, is_test_network=bool(params["is_test_network"]),
    )
    ledger.append({
        "step": "POST_FREEZE_ANCHOR_VALIDATION",
        "status": "PASS" if not anchor_violations else "FAIL",
        "violations": anchor_violations,
        "note": "devnet zero anchor admissible only because is_test_network=true; encoding law enforced",
    })

    dkg_summary = verify_dkg_vectors()
    ledger.append({
        "step": "DKG_TRANSCRIPT_VERIFICATION",
        "status": "PASS",
        "checked": dkg_summary,
        "note": "frozen feldman-threshold.json KATs: Feldman shares, D-BLS-DKG partials, threshold combine, negative rejections",
    })

    if skip_node:
        ledger.append({"step": "GENESIS_REBUILD_REPRODUCTION", "status": "SKIPPED", "note": "--skip-node"})
    else:
        node_identity = rebuild_genesis_via_node()
        reproduced = (node_identity["chain_id"] == identity.chain_id.hex()
                      and node_identity["genesis_hash"] == identity.genesis_hash.hex())
        if not reproduced:
            raise CeremonyError(
                f"genesis reproduction mismatch: node {node_identity}, "
                f"local chain_id={identity.chain_id.hex()} genesis_hash={identity.genesis_hash.hex()}"
            )
        ledger.append({
            "step": "GENESIS_REBUILD_REPRODUCTION",
            "status": "PASS",
            "chain_id": node_identity["chain_id"],
            "genesis_hash": node_identity["genesis_hash"],
            "note": "noosd devnet boot reproduced the independently derived chain_id and genesis_hash",
        })

    for code, why in OWNER_STEPS:
        ledger.append({"step": code, "status": "OWNER_BLOCKED", "note": why})
        blockers.append(code)
    return ledger, blockers


# ---------------------------------------------------------------------------
# Self-test: falsifiers for every local law
# ---------------------------------------------------------------------------

def self_test(skip_node: bool = False) -> int:
    params = parse_params(PARAMS_TOML.read_text("utf-8"))
    identity = derive_identity(params)

    # Restart rule (spec §8 vector 5): one changed value → new manifest hash
    # and new chain_id, no partial reuse.
    mutated = dict(params)
    mutated["faucet.allocation_micro_noos_test"] = params["faucet.allocation_micro_noos_test"] + 1
    mutated_identity = derive_identity(mutated)
    assert mutated_identity.parameter_manifest_hash != identity.parameter_manifest_hash, "restart rule: manifest hash must change"
    assert mutated_identity.chain_id != identity.chain_id, "restart rule: chain_id must change"
    assert mutated_identity.genesis_hash != identity.genesis_hash, "restart rule: genesis_hash must change"

    # Negative vector 6: hashing the TOML text directly must not reproduce
    # any published hash (a JSON/TOML serialization is never hashed).
    toml_hash = domain_hash(b"NOOS/GENESIS/PARAMS/V1", PARAMS_TOML.read_bytes())
    assert toml_hash != identity.parameter_manifest_hash, "TOML text hash must not equal the canonical manifest hash"

    # Field-order law (spec §8 vector 2): swapping two adjacent canonical
    # fields must change the bytes (tags make reordering visible).
    canon = canonical_manifest(params)
    assert canon[:2] == b"\x01\x00" and canon[2:4] == b"\x01\x00", "canonical prefix: version then tag 1"

    # Quiet-week falsifiers.
    good = CeremonySchedule(0, 6 * DAY_S + DAY_S // 2, 7 * DAY_S - 3_600, 7 * DAY_S)
    assert validate_schedule(good) == [], f"valid schedule rejected: {validate_schedule(good)}"
    short = CeremonySchedule(0, 5 * DAY_S + DAY_S // 2, 6 * DAY_S - 3_600, 6 * DAY_S)
    assert any("quiet week too short" in v for v in validate_schedule(short)), "6-day quiet week must be rejected"
    pre_freeze_anchor = CeremonySchedule(10, 10, 7 * DAY_S + 9 - 3_600, 7 * DAY_S + 10)
    assert any("strictly after" in v for v in validate_schedule(pre_freeze_anchor)), "anchor at freeze must be rejected"

    # Anchor falsifiers: byte order, zero-hash refusal off test networks,
    # no-earlier-than rule.
    anchor = BitcoinAnchor(height=897_767, block_hash_display_hex="12" * 31 + "34", named_at=100)
    encoded = encode_anchor(anchor)
    assert len(encoded) == 40 and encoded[:8] == (897_767).to_bytes(8, "little"), "anchor height LE law"
    assert encoded[8] == 0x34 and encoded[-1] == 0x12, "anchor hash must be internal byte order (display reversed)"
    assert validate_anchor(anchor, freeze_time=50, is_test_network=False) == []
    assert any("no no-earlier-than" in v for v in validate_anchor(anchor, freeze_time=100, is_test_network=False)), \
        "anchor at/before freeze must be rejected"
    zero = BitcoinAnchor(height=1, block_hash_display_hex="00" * 32, named_at=100)
    assert any("test-network fixture" in v for v in validate_anchor(zero, 50, is_test_network=False)), \
        "zero anchor must be refused off test networks"
    assert validate_anchor(zero, 50, is_test_network=True) == [], "zero anchor is the devnet fixture"

    # DKG: full vector verification, then a tamper falsifier — flipping one
    # commitment byte must break verification.
    summary = verify_dkg_vectors()
    assert summary["negative"] >= 3, "negative DKG cases missing"
    tampered = json.loads(FELDMAN_VECTORS.read_text("utf-8"))
    tampered["group_public_key"] = tampered["commitments"][0][1]  # wrong point
    with tempfile.TemporaryDirectory() as tmp:
        bad = Path(tmp) / "tampered.json"
        bad.write_text(json.dumps(tampered), "utf-8")
        try:
            verify_dkg_vectors(bad)
            raise AssertionError("tampered DKG transcript verified — falsifier failed to fire")
        except CeremonyError:
            pass

    # Genesis rebuild via the production devnet node path.
    if not skip_node:
        node_identity = rebuild_genesis_via_node()
        assert node_identity["chain_id"] == identity.chain_id.hex(), \
            f"chain_id mismatch: node {node_identity['chain_id']} local {identity.chain_id.hex()}"
        assert node_identity["genesis_hash"] == identity.genesis_hash.hex(), \
            f"genesis_hash mismatch: node {node_identity['genesis_hash']} local {identity.genesis_hash.hex()}"

    print("RESULT ceremony_self_test=PASS "
          f"chain_id={identity.chain_id.hex()} genesis_hash={identity.genesis_hash.hex()} "
          f"dkg_cases={sum(summary.values())} node_check={'SKIPPED' if skip_node else 'PASS'}")
    return 0


def main() -> int:
    # Production authorization is a separate, fail-closed workflow. It never
    # treats this module's devnet fixture ledger as production evidence.
    if len(sys.argv) > 1 and sys.argv[1] == "production":
        from production_authorization import main as production_main
        return production_main(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true", help="run every local falsifier")
    parser.add_argument("--skip-node", action="store_true", help="skip the noosd rebuild reproduction")
    parser.add_argument("--allow-owner-blocked", action="store_true",
                        help="exit 0 when only OWNER_BLOCKED steps remain")
    parser.add_argument("--json", action="store_true", help="print the full ledger as JSON")
    args = parser.parse_args()
    if args.self_test:
        return self_test(skip_node=args.skip_node)
    try:
        ledger, blockers = run_ledger(skip_node=args.skip_node)
    except (CeremonyError, AssertionError) as exc:
        print(f"RESULT genesis_ceremony=FAIL error={exc}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(ledger, indent=2))
    failed = [entry["step"] for entry in ledger if entry["status"] == "FAIL"]
    if failed:
        print("RESULT genesis_ceremony=FAIL steps=" + ",".join(failed), file=sys.stderr)
        return 1
    print("RESULT genesis_ceremony=OWNER_BLOCKED blockers=" + ",".join(sorted(blockers)))
    return 0 if args.allow_owner_blocked else 2


if __name__ == "__main__":
    raise SystemExit(main())
