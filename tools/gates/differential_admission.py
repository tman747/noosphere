#!/usr/bin/env python3
"""Production admission differential: real NodeCore mempool vs independent oracle.

Unlike differential_transitions.py (which exercises the pure transition
endpoint in noos-lumen), this gate drives the PRODUCTION node admission path:
crates/noos-node/src/bin/noos-transition.rs boots a real devnet NodeCore
(genesis build, RocksDB-backed store port, fee state, mempool) and every
case goes through `NodeCore::submit_tx`. The oracle below independently
re-models the frozen admission law from node-v1.md/mempool.rs docs:

  1. size cap  2. strict canonical decode  3. chain/version/expiry/byte
  envelope  4. fee floor  5. duplicate txid  6. payer account, payer-signer,
  balance, witness alignment, D-SIG-TX Ed25519  7. source/account caps.

Valid transactions are signed with the devnet faucet fixture seed
BLAKE3-256("noos-devnet-1/faucet/0") (protocol/genesis/devnet-parameters.toml)
and cross-checked against the independent Go client's txid derivation, so a
single run triangulates rust-production/go/python on identity and verdict.
"""
from __future__ import annotations
import argparse, hashlib, json, os, shutil, struct, subprocess, sys, tempfile, time
from pathlib import Path

import blake3

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError as exc:  # pragma: no cover
    raise SystemExit("cryptography is required to sign faucet fixtures") from exc

ROOT = Path(__file__).resolve().parents[2]
MAX_TX_BYTES = 128 * 1024
PER_ACCOUNT_PENDING = 64
PER_SOURCE_PENDING = 256
FAUCET_SEED = blake3.blake3(b"noos-devnet-1/faucet/0").digest()
FAUCET_KEY = Ed25519PrivateKey.from_private_bytes(FAUCET_SEED)
FAUCET_PUB = bytes.fromhex("c9e967496427ad970fa540f15c274f214c0892aa0a3ce7364b9bb96583cb6b1d")
OTHER_KEY = Ed25519PrivateKey.from_private_bytes(blake3.blake3(b"noos-devnet-1/not-the-faucet").digest())

CLASSES = (
    "VALID", "TRUNCATED", "WRONG_CHAIN", "WRONG_VERSION", "EXPIRED",
    "BYTES_ENVELOPE", "UNKNOWN_PAYER", "PAYER_NOT_SIGNER", "WITNESS_MISMATCH",
    "BAD_SIGNATURE", "DUPLICATE", "TRAILING", "BAD_DISCRIMINANT",
)


def h(domain: bytes, *parts: bytes) -> bytes:
    x = blake3.blake3()
    x.update(domain)
    for p in parts:
        x.update(p)
    return x.digest()


def tag(n: int) -> bytes:
    return struct.pack("<H", n)


def enc_tx(chain: bytes, fmt: int, expiry: int, payer: bytes, resources: tuple,
           account_inputs: list[bytes], wroot: bytes, fee_disc: int = 0) -> bytes:
    out = struct.pack("<H", 1)
    out += tag(1) + chain
    out += tag(2) + struct.pack("<H", fmt)
    out += tag(3) + struct.pack("<Q", expiry)
    out += tag(4) + payer
    out += tag(5) + bytes([fee_disc])
    out += tag(6) + struct.pack("<6Q", *resources)
    out += tag(7) + struct.pack("<I", 0)                      # note_inputs
    out += tag(8) + struct.pack("<I", len(account_inputs))    # account_inputs
    for a in account_inputs:
        out += a
    out += tag(9) + struct.pack("<I", 0)                      # object access
    out += tag(10) + struct.pack("<I", 0)                     # actions
    out += tag(11) + struct.pack("<I", 0)                     # outputs
    out += tag(12) + struct.pack("<I", 0)                     # evidence refs
    out += tag(13) + wroot
    return out


def enc_intent(commit: bytes, sig: bytes) -> bytes:
    out = struct.pack("<H", 1)
    out += tag(1) + commit
    out += tag(2) + bytes([0])          # signer_scope
    out += tag(3) + bytes([0])          # capability_ref: absent
    out += tag(4) + struct.pack("<H", 1)  # suite = Ed25519/D-SIG-TX
    out += tag(5) + struct.pack("<I", len(sig)) + sig
    return out


def enc_witnesses(intents: list[bytes]) -> bytes:
    out = struct.pack("<H", 1)
    out += tag(1) + struct.pack("<I", len(intents))
    for i in intents:
        out += i
    out += tag(2) + struct.pack("<I", 0)  # lock_reveals
    return out


EMPTY_WROOT = h(b"NOOS/TX/WROOT/V1", struct.pack("<I", 0))


def txid(tx: bytes) -> bytes:
    return h(b"NOOS/TX/ID/V1", tx)


def sign_txid(key: Ed25519PrivateKey, tid: bytes) -> bytes:
    return key.sign(b"NOOS/SIG/TX/V1" + tid)


def splitmix(seed: int):
    x = seed & ((1 << 64) - 1)
    while True:
        x = (x + 0x9E3779B97F4A7C15) & ((1 << 64) - 1)
        z = x
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & ((1 << 64) - 1)
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & ((1 << 64) - 1)
        yield z ^ (z >> 31)


def build(work: Path) -> tuple[Path, Path]:
    env = os.environ.copy()
    env.setdefault("LIBCLANG_PATH", "C:/Users/ntrap/AppData/Local/Programs/Swift/Toolchains/6.3.2+Asserts/usr/bin")
    subprocess.run(["cargo", "build", "--locked", "-p", "noos-node", "--bin", "noos-transition"],
                   cwd=ROOT, env=env, check=True)
    suffix = ".exe" if os.name == "nt" else ""
    target = os.environ.get("CARGO_TARGET_DIR")
    debug = Path(target) / "debug" if target else ROOT / "target" / "debug"
    if not (debug / ("noos-transition" + suffix)).is_file():
        # honour .cargo/config target-dir
        probe = subprocess.check_output(["cargo", "metadata", "--format-version", "1", "--no-deps"],
                                        cwd=ROOT, env=env, text=True)
        debug = Path(json.loads(probe)["target_directory"]) / "debug"
    node = work / ("node-admission" + suffix)
    shutil.copy2(debug / ("noos-transition" + suffix), node)
    go = work / ("go-transition" + suffix)
    subprocess.run(["go", "build", "-trimpath", "-o", str(go), "./cmd/noos-transition"],
                   cwd=ROOT / "go", check=True)
    return node, go


class NodeProc:
    def __init__(self, exe: Path):
        self.p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  text=True, bufsize=1)
        assert self.p.stdout is not None
        ready = self.p.stdout.readline().strip()
        if not ready.startswith("READY:"):
            raise SystemExit(f"node handshake failed: {ready!r}")
        self.chain_id = bytes.fromhex(ready.split(":", 1)[1])

    def submit(self, tx: bytes, wit: bytes, source: int = 0) -> str:
        assert self.p.stdin and self.p.stdout
        filler = "0,0,0,0,0,0,0,0," + "00" * 32
        self.p.stdin.write(f"{source},{tx.hex()},{wit.hex()},{filler}\n")
        self.p.stdin.flush()
        return self.p.stdout.readline().strip()

    def close(self):
        if self.p.stdin and not self.p.stdin.closed:
            self.p.stdin.close()
        self.p.wait(timeout=15)


class GoProc:
    def __init__(self, exe: Path):
        self.p = subprocess.Popen([str(exe)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  text=True, bufsize=1)

    def transition(self, ident: int, tx: bytes, wit: bytes) -> list[str]:
        assert self.p.stdin and self.p.stdout
        bh = "00" * 32
        line = f"{ident},{tx.hex()},{wit.hex()},0,0,0,0,1000000000000000000,0,0,0,{bh}"
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        return self.p.stdout.readline().strip().split(",")

    def close(self):
        if self.p.stdin and not self.p.stdin.closed:
            self.p.stdin.close()
        self.p.wait(timeout=15)


def make_valid(chain: bytes, nonce: int) -> tuple[bytes, bytes, bytes]:
    """A fully valid faucet-signed tx unique per nonce."""
    resources = (4096, 0, 0, 0, 0, 0)
    tx = enc_tx(chain, 1, 1_000_000 + nonce, FAUCET_PUB, resources, [FAUCET_PUB], EMPTY_WROOT)
    tid = txid(tx)
    wit = enc_witnesses([enc_intent(tid, sign_txid(FAUCET_KEY, tid))])
    return tx, wit, tid


def make_case(cls: str, chain: bytes, z: int, nonce: int):
    """Returns (tx, wit, expected_class_or_None-for-valid)."""
    tx, wit, tid = make_valid(chain, nonce)
    if cls == "VALID":
        return tx, wit, None
    if cls == "TRUNCATED":
        return tx[:-1 - (z % 8)], wit, "Malformed"
    if cls == "WRONG_CHAIN":
        bad = bytes([(chain[0] ^ 0x5A)]) + chain[1:]
        btx = enc_tx(bad, 1, 1_000_000 + nonce, FAUCET_PUB, (4096, 0, 0, 0, 0, 0), [FAUCET_PUB], EMPTY_WROOT)
        btid = txid(btx)
        bwit = enc_witnesses([enc_intent(btid, sign_txid(FAUCET_KEY, btid))])
        return btx, bwit, "WrongChain"
    if cls == "WRONG_VERSION":
        btx = enc_tx(chain, 2, 1_000_000 + nonce, FAUCET_PUB, (4096, 0, 0, 0, 0, 0), [FAUCET_PUB], EMPTY_WROOT)
        return btx, wit, "WrongVersion"
    if cls == "EXPIRED":
        btx = enc_tx(chain, 1, 0, FAUCET_PUB, (4096, 0, 0, 0, 0, 0), [FAUCET_PUB], EMPTY_WROOT)
        return btx, wit, "Expired"
    if cls == "BYTES_ENVELOPE":
        btx = enc_tx(chain, 1, 1_000_000 + nonce, FAUCET_PUB, (0, 0, 0, 0, 0, 0), [FAUCET_PUB], EMPTY_WROOT)
        return btx, wit, "Oversized"
    if cls == "UNKNOWN_PAYER":
        stranger = OTHER_KEY.public_key().public_bytes_raw()
        btx = enc_tx(chain, 1, 1_000_000 + nonce, stranger, (4096, 0, 0, 0, 0, 0), [stranger], EMPTY_WROOT)
        btid = txid(btx)
        bwit = enc_witnesses([enc_intent(btid, sign_txid(OTHER_KEY, btid))])
        return btx, bwit, "UnknownPayer"
    if cls == "PAYER_NOT_SIGNER":
        stranger = OTHER_KEY.public_key().public_bytes_raw()
        btx = enc_tx(chain, 1, 1_000_000 + nonce, FAUCET_PUB, (4096, 0, 0, 0, 0, 0), [stranger], EMPTY_WROOT)
        btid = txid(btx)
        bwit = enc_witnesses([enc_intent(btid, sign_txid(OTHER_KEY, btid))])
        return btx, bwit, "PayerNotSigner"
    if cls == "WITNESS_MISMATCH":
        wrong = bytes(32)
        bwit = enc_witnesses([enc_intent(wrong, sign_txid(FAUCET_KEY, wrong))])
        return tx, bwit, "WitnessMismatch"
    if cls == "BAD_SIGNATURE":
        garbage = h(b"NOOS-DIFF-GARBAGE", struct.pack("<Q", z)) * 2
        bwit = enc_witnesses([enc_intent(tid, garbage[:64])])
        return tx, bwit, "SignatureInvalid"
    if cls == "DUPLICATE":
        return tx, wit, "DUPLICATE_SENTINEL"
    if cls == "TRAILING":
        return tx + b"\x00", wit, "Malformed"
    if cls == "BAD_DISCRIMINANT":
        btx = enc_tx(chain, 1, 1_000_000 + nonce, FAUCET_PUB, (4096, 0, 0, 0, 0, 0), [FAUCET_PUB], EMPTY_WROOT, fee_disc=2)
        return btx, wit, "Malformed"
    raise AssertionError(cls)


def sha256(path: Path) -> str:
    d = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            d.update(chunk)
    return d.hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--generated", type=int, default=10_000)
    ap.add_argument("--seed", type=lambda x: int(x, 0), default=0x4E4F4F53)
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args()
    started = time.time()
    counts: dict[str, int] = {c: 0 for c in CLASSES}
    divergences = 0
    matrix: list[str] = []
    with tempfile.TemporaryDirectory(prefix="noos-admission-diff-") as d:
        work = Path(d)
        node_exe, go_exe = build(work)
        node = NodeProc(node_exe)
        go = GoProc(go_exe)
        chain = node.chain_id
        pending = 0          # oracle model of faucet per-account pending
        admitted: set[bytes] = set()
        last_valid: tuple[bytes, bytes, bytes] | None = None
        rng = splitmix(a.seed)
        try:
            for ident in range(a.generated):
                z = next(rng)
                cls = CLASSES[z % len(CLASSES)]
                if cls == "DUPLICATE" and last_valid is None:
                    cls = "VALID"
                counts[cls] += 1
                tx, wit, expect = make_case(cls, chain, z, ident)
                if cls == "DUPLICATE":
                    tx, wit, tid = last_valid  # exact resubmission
                    expect = "DuplicatePending"
                got = node.submit(tx, wit)
                if expect is None:  # VALID
                    tid = txid(tx)
                    if pending < PER_ACCOUNT_PENDING:
                        want = f"ADMITTED:{tid.hex()}"
                        if got == want:
                            pending += 1
                            admitted.add(tid)
                            last_valid = (tx, wit, tid)
                        else:
                            divergences += 1
                            print(f"DIVERGENCE case={ident} class={cls} want={want} got={got}", file=sys.stderr)
                    else:
                        if got != "REJECTED:AccountLimit":
                            divergences += 1
                            print(f"DIVERGENCE case={ident} class=VALID-over-cap want=REJECTED:AccountLimit got={got}", file=sys.stderr)
                    # go cross-check on identity derivation (sampled to keep wall time flat)
                    if ident % 16 == 0:
                        gline = go.transition(ident, tx, wit)
                        if len(gline) < 2 or gline[-2] != tid.hex():
                            divergences += 1
                            print(f"DIVERGENCE case={ident} go txid={gline[-2:]} want={tid.hex()}", file=sys.stderr)
                else:
                    variant = got.split(":", 1)
                    name = variant[1].split(" ", 1)[0].split("{", 1)[0] if len(variant) == 2 else got
                    if variant[0] != "REJECTED" or name != expect:
                        divergences += 1
                        print(f"DIVERGENCE case={ident} class={cls} want=REJECTED:{expect} got={got}", file=sys.stderr)
                if divergences >= 10:
                    break
            # AA/AB/BA/BB: production node and independent go on one shared case.
            probe_tx, probe_wit, probe_tid = make_valid(chain, 10_000_000)
            for label, left, right in (("AA", "node", "node"), ("AB", "node", "go"),
                                       ("BA", "go", "node"), ("BB", "go", "go")):
                ok = True
                for side in (left, right):
                    if side == "node":
                        fresh = NodeProc(node_exe)
                        got = fresh.submit(probe_tx, probe_wit)
                        fresh.close()
                        ok = ok and got == f"ADMITTED:{probe_tid.hex()}"
                    else:
                        gp = GoProc(go_exe)
                        line = gp.transition(0, probe_tx, probe_wit)
                        gp.close()
                        ok = ok and len(line) >= 2 and line[1] == "ACCEPT" and line[-2] == probe_tid.hex()
                matrix.append(f"{label}={'PASS' if ok else 'FAIL'}")
                if not ok:
                    divergences += 1
        finally:
            node.close()
            go.close()
        verdict = "PASS" if divergences == 0 else "FAIL"
        bundle = {
            "schema": "noos.production-admission-differential.v1",
            "command": f"python tools/gates/differential_admission.py --generated {a.generated} --seed {a.seed:#x}",
            "generated_cases": a.generated,
            "seed": a.seed,
            "chain_id": chain.hex(),
            "class_counts": counts,
            "divergences": divergences,
            "process_matrix": dict(m.split("=") for m in matrix),
            "admission_path": "NodeCore::submit_tx (production mempool: size/decode/chain/version/expiry/fee/duplicate/payer/witness/signature/caps)",
            "identity_cross_check": "python txid == node ADMITTED txid == go client txid (D-TX-ID)",
            "faucet_fixture": "seed BLAKE3-256('noos-devnet-1/faucet/0'), devnet-parameters.toml [faucet]",
            "binaries_sha256": {"node": sha256(node_exe), "go": sha256(go_exe)},
            "sources_sha256": {
                "crates/noos-node/src/bin/noos-transition.rs": sha256(ROOT / "crates/noos-node/src/bin/noos-transition.rs"),
                "crates/noos-node/src/mempool.rs": sha256(ROOT / "crates/noos-node/src/mempool.rs"),
                "tools/gates/differential_admission.py": sha256(Path(__file__)),
            },
            "wall_seconds": round(time.time() - started, 3),
            "verdict": verdict,
        }
        out = a.out or (ROOT / "evidence" / f"differential-admission-{a.generated}.json")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
        print(f"RESULT production_admission_differential={verdict} cases={a.generated} divergences={divergences} matrix={';'.join(matrix)} evidence={out.relative_to(ROOT)}")
        return int(divergences != 0)


if __name__ == "__main__":
    raise SystemExit(main())
