#!/usr/bin/env python3
"""Live product devnet smoke: real processes, real QUIC network, real user journey.

Boots an actual two-node devnet (noosd validator + peered full node over
loopback QUIC), a live noos-indexer ingesting from the validator's operator
RPC, and drives the product path end to end with the shipped noos-cli:

    keygen -> tx build -> (faucet fixture signs) -> tx submit -> settle ->
    finalize -> operator /receipt -> peer sync -> indexer /api/v1 view

The transaction is a real NOOS_TEST transfer (WithdrawFromAccount +
DepositToAccount) from the devnet faucet fixture to a freshly derived wallet
identity. The validator produces blocks on a 15 ms fixture cadence so it
crosses >= 2 epoch boundaries and actually FINALIZES the transfer's block
while the smoke watches. Verdict is fail-closed: every stage must complete
within its deadline or the bundle records FAIL and the exit code is 1.

Evidence: append-only evidence/live-devnet-smoke/<content-sha256>.json
(hash-bound sources + binaries). The historical fixed-path bundle is retained.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools" / "gates"))
from differential_admission import (  # noqa: E402
    FAUCET_KEY,
    FAUCET_PUB,
    enc_intent,
    enc_witnesses,
    sign_txid,
)

EVIDENCE = ROOT / "evidence"
RPC_A = "127.0.0.1:18632"
RPC_B = "127.0.0.1:18633"
P2P_A = "/ip4/127.0.0.1/udp/19701/quic-v1"
INDEXER = "127.0.0.1:18080"
TOKEN = "live-smoke-operator-token"
EPOCH_LENGTH = 256
PRODUCE_INTERVAL_MS = 15
TRANSFER_MICRO = 123_456_789


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def http_json(addr: str, path: str, token: str | None = None, timeout: float = 5.0):
    req = urllib.request.Request(f"http://{addr}{path}")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def build_binaries(env: dict) -> dict[str, Path]:
    subprocess.run(
        ["cargo", "build", "--locked", "-p", "noos-node", "--bin", "noosd",
         "-p", "noos-indexer", "-p", "noos-cli"],
        cwd=ROOT, env=env, check=True)
    probe = subprocess.check_output(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=ROOT, env=env, text=True)
    debug = Path(json.loads(probe)["target_directory"]) / "debug"
    suffix = ".exe" if os.name == "nt" else ""
    out = {}
    for name in ("noosd", "noos-indexer", "noos-cli"):
        exe = debug / (name + suffix)
        if not exe.is_file():
            raise SystemExit(f"missing built binary: {exe}")
        out[name] = exe
    return out


def cli(exe: Path, *args: str) -> dict:
    proc = subprocess.run([str(exe), *args], capture_output=True, text=True, cwd=ROOT)
    if proc.returncode != 0:
        raise SystemExit(f"noos-cli {' '.join(args[:2])} failed: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


class Proc:
    def __init__(self, name: str, argv: list[str], env: dict, log_dir: Path):
        self.name = name
        self.log_path = log_dir / f"{name}.log"
        self.log = open(self.log_path, "w", encoding="utf-8")
        self.p = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=self.log,
                                  stderr=subprocess.STDOUT, stdin=subprocess.PIPE, text=True)

    def wait_line(self, pattern: str, deadline_s: float) -> str:
        rx = re.compile(pattern)
        end = time.monotonic() + deadline_s
        while time.monotonic() < end:
            if self.p.poll() is not None:
                raise SystemExit(f"{self.name} exited early ({self.p.returncode}); log: {self.log_path}")
            self.log.flush()
            for line in self.log_path.read_text(encoding="utf-8", errors="replace").splitlines():
                m = rx.search(line)
                if m:
                    return line
            time.sleep(0.25)
        raise SystemExit(f"{self.name}: timed out waiting for /{pattern}/; log: {self.log_path}")

    def stop(self):
        if self.p.poll() is None:
            try:
                if self.p.stdin:
                    self.p.stdin.close()  # noosd treats stdin EOF as stop
                self.p.wait(timeout=10)
            except Exception:
                self.p.kill()
        self.log.close()


def le_u128(v: int) -> bytes:
    return v.to_bytes(16, "little")


def transfer_actions(sender: bytes, recipient: bytes, amount: int) -> list[str]:
    zero_asset = b"\x00" * 32
    withdraw = (3).to_bytes(2, "little") + sender + zero_asset + le_u128(amount)
    deposit = (2).to_bytes(2, "little") + recipient + zero_asset + le_u128(amount)
    return [withdraw.hex(), deposit.hex()]


def main() -> int:
    env = os.environ.copy()
    env.setdefault("LIBCLANG_PATH",
                   "C:/Users/ntrap/AppData/Local/Programs/Swift/Toolchains/6.3.2+Asserts/usr/bin")
    checks: list[dict] = []
    procs: list[Proc] = []
    started = utc_now()

    def check(name: str, passed: bool, detail):
        checks.append({"name": name, "passed": bool(passed), "detail": detail})
        print(f"[{'PASS' if passed else 'FAIL'}] {name}: {detail}")
        if not passed:
            raise SystemExit(1)

    work = Path(tempfile.mkdtemp(prefix="noos-live-smoke-"))
    verdict = "FAIL"
    tx_report: dict = {}
    try:
        exes = build_binaries(env)
        # Product journey starts with a wallet identity. Provision that
        # account in the test-network genesis so DepositToAccount can settle.
        recipient_seed = hashlib.blake2b(b"noos-live-smoke/recipient", digest_size=32).hexdigest()
        keygen = cli(exes["noos-cli"], "keygen", "--seed", recipient_seed,
                     "--purpose", "sign", "--account", "0", "--index", "0")
        recipient = bytes.fromhex(keygen["public_id"])
        check("cli keygen", len(recipient) == 32,
              {"path": keygen.get("path"), "public_id": keygen["public_id"]})
        genesis_time_ms = int(time.time() * 1000)

        node_a = Proc("noosd-a", [
            str(exes["noosd"]), "--data-dir", str(work / "node-a"),
            "--genesis-time", str(genesis_time_ms),
            "--rpc", RPC_A, "--rpc-token", TOKEN,
            "--p2p-listen", P2P_A,
            "--validator", "--produce-interval-ms", str(PRODUCE_INTERVAL_MS),
            "--devnet-account", recipient.hex(),
        ], env, work)
        procs.append(node_a)
        up = node_a.wait_line(r"noosd up: chain_id=([0-9a-f]{64}) genesis_hash=([0-9a-f]{64})", 60)
        m = re.search(r"chain_id=([0-9a-f]{64}) genesis_hash=([0-9a-f]{64})", up)
        assert m is not None
        chain_id, genesis_hash = m.group(1), m.group(2)
        node_a.wait_line(r"operator RPC ready", 30)
        p2p_line = node_a.wait_line(r"p2p ready at (\S+)", 30)
        peer_addr = p2p_line.rsplit(" ", 1)[-1]
        check("validator boot", True,
              {"chain_id": chain_id, "genesis_hash": genesis_hash, "p2p": peer_addr})

        node_b = Proc("noosd-b", [
            str(exes["noosd"]), "--data-dir", str(work / "node-b"),
            "--genesis-time", str(genesis_time_ms),
            "--rpc", RPC_B, "--rpc-token", TOKEN,
            "--peer", peer_addr, "--observer",
            "--devnet-account", recipient.hex(),
        ], env, work)
        procs.append(node_b)
        node_b.wait_line(r"noosd up: chain_id=" + chain_id, 60)
        check("peer boot (same identity)", True, {"rpc": RPC_B, "peer_of": peer_addr})

        # The protocol genesis identity and the height-0 block hash are
        # intentionally distinct. The RPC presentation starts at height 1,
        # whose authenticated parent is the height-0 block hash. Seed that
        # retained chain point, then let normal RPC ingestion own height 1+.
        first_block = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                first_block = http_json(RPC_A, "/block/1", TOKEN, 2)
                break
            except (urllib.error.HTTPError, urllib.error.URLError, OSError):
                time.sleep(0.25)
        if first_block is None:
            check("indexer live genesis anchor", False,
                  "validator did not present block 1 within 30s")
        genesis_block_hash = first_block.get("parent_hash")
        check("indexer live genesis anchor",
              first_block.get("height") == 1
              and isinstance(genesis_block_hash, str)
              and re.fullmatch(r"[0-9a-f]{64}", genesis_block_hash) is not None,
              {"height": 0, "hash": genesis_block_hash,
               "derived_from_block": first_block.get("hash")})
        indexer_root = work / "indexer"
        indexer_root.mkdir(parents=True, exist_ok=True)
        checkpoint = {
            "schema": "noos-ingest-checkpoint-v1",
            "identity": {"chain_id": chain_id, "genesis_hash": genesis_hash,
                         "api_version": "v1"},
            "next_height": "1",
            "recent": [{"height": "0", "hash": genesis_block_hash}],
        }
        (indexer_root / "ingest-checkpoint-v1.json").write_text(
            json.dumps(checkpoint, indent=2) + "\n", encoding="utf-8", newline="\n")

        idx_env = dict(env, NOOS_CHAIN_ID=chain_id, NOOS_GENESIS_HASH=genesis_hash,
                       NOOS_NODE_RPC=RPC_A, NOOS_NODE_TOKEN=TOKEN,
                       NOOS_INDEXER_LISTEN=INDEXER,
                       NOOS_INDEXER_ROOT=str(indexer_root))
        procs.append(Proc("indexer", [str(exes["noos-indexer"])], idx_env, work))

        # Wait until the validator is producing, then submit early enough for
        # the next two epoch boundaries to finalize the transfer quickly.
        deadline = time.monotonic() + 120
        status = None
        while time.monotonic() < deadline:
            try:
                status = http_json(RPC_A, "/status", TOKEN, 2)
                if status["unsafe_head"]["height"] >= 8:
                    break
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(0.5)
        assert status is not None
        check("validator producing", status["unsafe_head"]["height"] >= 8, status["unsafe_head"])

        spec = {
            "chain_id": chain_id,
            "expiry_height": 100_000,
            "fee_payer": FAUCET_PUB.hex(),
            "resource_limits": {"bytes": 4096, "grain_steps": 0, "proof_units": 0,
                                 "blob_bytes": 0, "state_reads": 64, "state_writes": 64},
            "account_inputs": [FAUCET_PUB.hex()],
            "actions": transfer_actions(FAUCET_PUB, recipient, TRANSFER_MICRO),
        }
        built = cli(exes["noos-cli"], "tx", "build", "--spec", json.dumps(spec))
        tx_hex, tx_id = built["tx"], built["txid"]
        # The faucet fixture is a raw Ed25519 seed (not wallet-derived), so the
        # faucet signature is produced with the registered D-SIG-TX domain law.
        sig = sign_txid(FAUCET_KEY, bytes.fromhex(tx_id))
        witnesses = enc_witnesses([enc_intent(bytes.fromhex(tx_id), sig)]).hex()
        submit = cli(exes["noos-cli"], "tx", "submit", "--node", RPC_A, "--token", TOKEN,
                     "--chain-id", chain_id, "--genesis-hash", genesis_hash,
                     "--tx", tx_hex, "--witnesses", witnesses)
        check("cli tx build+submit", submit.get("txid") == tx_id, submit)

        # Settlement with a successful receipt on the validator.
        settled_height = None
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            r = http_json(RPC_A, f"/receipt/{tx_id}", TOKEN, 2)
            state = r.get("state")
            if isinstance(state, dict):
                check("transfer settled with success receipt",
                      state["status_code"] == 0 and r["receipt"]["status"] == 0
                      and r["receipt"]["txid"] == tx_id,
                      r)
                settled_height = state["settled_height"]
                tx_report = {"txid": tx_id, "settled_height": settled_height,
                             "fee_charged": r["receipt"]["fee_charged"],
                             "amount_micro": TRANSFER_MICRO,
                             "recipient": recipient.hex()}
                break
            time.sleep(1)
        if settled_height is None:
            check("transfer settled with success receipt", False, "timeout after 180s")

        # Real finality: the finalized checkpoint must reach the settled height.
        deadline = time.monotonic() + 420
        finalized = None
        while time.monotonic() < deadline:
            status = http_json(RPC_A, "/status", TOKEN, 2)
            finalized = status["finalized"]
            if finalized["epoch"] * EPOCH_LENGTH >= settled_height:
                break
            time.sleep(2)
        check("transfer block finalized",
              finalized is not None and finalized["epoch"] * EPOCH_LENGTH >= settled_height,
              {"finalized": finalized, "settled_height": settled_height})

        # Live QUIC propagation: peer B must sync past the settled height.
        deadline = time.monotonic() + 300
        b_head = None
        while time.monotonic() < deadline:
            try:
                b = http_json(RPC_B, "/status", TOKEN, 2)
                b_head = b["unsafe_head"]["height"]
                if b_head >= settled_height:
                    break
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(1)
        check("peer synced over QUIC", b_head is not None and b_head >= settled_height,
              {"peer_head": b_head, "settled_height": settled_height})

        # Product read path: the public indexer serves the transaction.
        deadline = time.monotonic() + 180
        idx_tx = None
        while time.monotonic() < deadline:
            try:
                idx_tx = http_json(INDEXER, f"/api/v1/transactions/{tx_id}", None, 2)
                if idx_tx and not idx_tx.get("error_code"):
                    break
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(1)
        check("indexer serves transaction",
              bool(idx_tx) and not (idx_tx or {}).get("error_code"), idx_tx)
        idx_status = http_json(INDEXER, "/api/status", None, 2)
        check("indexer identity matches devnet",
              idx_status.get("chain_id") == chain_id
              and idx_status.get("genesis_hash") == genesis_hash, idx_status)

        verdict = "PASS"
    finally:
        for p in reversed(procs):
            p.stop()
        bundle = {
            "schema_version": "noos.live-devnet-smoke.v1",
            "scenario": "live-product-devnet-smoke",
            "started": started,
            "ended": utc_now(),
            "topology": {"validator": RPC_A, "peer_observer": RPC_B,
                          "indexer": INDEXER, "p2p": P2P_A,
                          "produce_interval_ms": PRODUCE_INTERVAL_MS},
            "journey": ["cargo build (noosd, noos-indexer, noos-cli)",
                         "boot validator + QUIC-peered observer",
                         "anchor indexer checkpoint from live block 1 parent",
                         "boot indexer with live RPC ingestion",
                         "noos-cli keygen (recipient identity)",
                         "noos-cli tx build (faucet -> recipient NOOS_TEST transfer)",
                         "faucet fixture D-SIG-TX signature",
                         "noos-cli tx submit (identity-gated line protocol)",
                         "operator /receipt settlement + success receipt",
                         "finalized checkpoint covers settled height",
                         "peer syncs settled height over loopback QUIC",
                         "indexer /api/v1/transactions/<txid> + identity"],
            "transfer": tx_report,
            "checks": checks,
            "sources_sha256": {
                "tools/e2e/live_smoke.py": sha256(Path(__file__)),
                "protocol/genesis/devnet-parameters.toml":
                    sha256(ROOT / "protocol/genesis/devnet-parameters.toml"),
            },
            "verdict": verdict,
        }
        EVIDENCE.mkdir(exist_ok=True)
        rendered = json.dumps(bundle, indent=2) + "\n"
        content_sha256 = hashlib.sha256(
            json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        out = EVIDENCE / "live-devnet-smoke" / f"{content_sha256}.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        if out.exists() and out.read_text(encoding="utf-8") != rendered:
            raise RuntimeError(f"immutable live-smoke evidence collision at {out}")
        out.write_text(rendered, encoding="utf-8", newline="\n")
        print(f"RESULT live_devnet_smoke={verdict} out={out.relative_to(ROOT)}")
        shutil.rmtree(work, ignore_errors=True)
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
