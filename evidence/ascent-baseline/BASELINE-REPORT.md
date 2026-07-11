# Ascent Historical Substrate Baseline Report

- Date: 2026-07-10 (logs timestamped 2026-07-11 UTC)
- Repository: `C:/ascent` @ commit `76797791599e0f574d9b30056d9c241466e47dbd` (working tree clean before and after; see Integrity)
- Host: Windows 11 Home (win32 10.0.22000, x64)
- Toolchain: `rustc 1.96.1 (31fca3adb 2026-06-26)`, `cargo 1.96.1 (356927216 2026-06-26)` — resolved from `C:/ascent/rust-toolchain.toml` (`channel = "1.96.1"`), verified via `rustc --version` in `C:/ascent` before any run.
- Environment for every run: `RUST_BACKTRACE=1`, `ASCENT_TEST_TIME_MULTIPLIER=3`, cwd `C:/ascent`.
- Build isolation: `CARGO_TARGET_DIR=C:/tmp/ascent-baseline-target` was set for every command so that no build artifact was written under `C:/ascent`, preserving the historical tree byte-identical. This does not change any command's semantics; it only relocates the `target/` directory.

## Mandated baseline commands

| # | Command | Log | Exit code | Wall time | Verdict |
|---|---------|-----|-----------|-----------|---------|
| 1 | `cargo fmt --all -- --check` | `01-cargo-fmt-check.log` | 1 | 12.1 s | FAIL — INHERITED-DEFECT |
| 2 | `cargo clippy --workspace --all-targets -- -D warnings` | `02-cargo-clippy.log` | 101 | 25.3 s * | FAIL — INHERITED-DEFECT |
| 3 | `cargo test --workspace --exclude ascent-node` | `03-cargo-test-workspace.log` | 101 | 346.3 s | FAIL — INHERITED-DEFECT |
| 4 | `cargo test -p ascent-node -- --test-threads=1` | `04-cargo-test-ascent-node.log` | 101 | 556.0 s | FAIL — INHERITED-DEFECT |
| 5 | `cargo test --offline -p ascent-node --release -- --ignored devnet1_no_restart_migration_rehearsal --nocapture` | `05-cargo-test-migration-rehearsal.log` | 0 | 249.8 s | PASS |

\* Wall times reflect a shared incremental build cache in the redirected target directory across runs (an earlier aborted invocation of the same clippy command pre-warmed dependency compilation); they are not cold-build times.

## Inherited defects (recorded, NOT fixed — C:/ascent is read-only historical evidence)

Per the plan ("Historical substrate baseline"): each failure below is an **INHERITED-DEFECT** that blocks porting of the affected mechanism until the NOOSPHERE port independently repairs and proves it. Ascent itself is never edited.

### INHERITED-DEFECT-1: rustfmt drift (command 1, exit 1)
`cargo fmt --all -- --check` under pinned rustfmt 1.96.1 reports formatting diffs in:
- `crates/ascent-cli/src/operator.rs` — 3 hunks (lines ~1556, ~1628, ~3194; line-wrapping of `read_secret_borsh` / `write_encrypted_artifact` call sites).
- `crates/ascent-crypto/tests/x25519_rejection.rs` — reflow of the `LOW_ORDER_PUBLIC_KEYS` byte arrays.

Cosmetic only (no semantic change), consistent with the files having been formatted under a different rustfmt width configuration/version. Blocks porting of: `ascent-cli` operator/keystore flow patterns and `ascent-crypto` X25519 rejection test corpus, until the NOOSPHERE equivalents are formatted clean under their own pinned toolchain.

### INHERITED-DEFECT-2: clippy lint (command 2, exit 101)
Single lint, promoted to error by `-D warnings`:
- `clippy::double_must_use` on `pub fn dkg_x25519_shared_secret(...) -> Result<[u8; 32], DkgCryptoError>` at `crates/ascent-crypto/src/lib.rs:507` — `#[must_use]` attribute without message on a function already returning a `#[must_use]` type.

Compilation of `ascent-crypto` (lib and lib test) aborts under `-D warnings`; downstream crates were not linted in this invocation (clippy fail-fast). Blocks porting of: the `ascent-crypto` DKG X25519 shared-secret primitive (a named port source for `noos-crypto` in plan §3.2) until the NOOSPHERE port carries a clean, warning-free equivalent.

### INHERITED-DEFECT-3: consensus-core recovery test failure (command 3, exit 101)
- Failing test: `node::tests::staggered_boot_jump_recovers_dag_batch_ordering` (`ascent-consensus-core`, lib tests)
- Panic: `crates/ascent-consensus-core/src/node.rs:9736` — `v0 recovered without sliding its bootstrap window; this test no longer exercises the slide arm it pins`
- Suite result: `FAILED. 97 passed; 1 failed; 0 ignored` (124.4 s)
- Deterministic: reproduced identically in the supplementary sweep (`06-...log`).

The panic message indicates the test's pinned scenario no longer drives the bootstrap-window "slide" recovery arm — i.e., test-vs-implementation drift in the staggered-boot jump/recovery path. Blocks porting of: the deterministic DAG recovery / bootstrap-window / sync patterns of `ascent-consensus-core` (the plan's primary reuse anchor, §6.1 and "Critical files & anchors"), until the NOOSPHERE consensus port independently re-derives and proves the recovery behavior with its own tests.

Note: `cargo test` fail-fast aborted the remaining workspace targets in the mandated run; the supplementary no-fail-fast sweep (below) proves this is the only failing target in the workspace excluding `ascent-node`.

### INHERITED-DEFECT-4: node chain-view retention test failure (command 4, exit 101)
- Failing test: `tests::chain_view_small_retention_prunes_maps_and_keeps_live_state` (`ascent-node`, lib tests, `--test-threads=1`)
- Panic: `crates/ascent-node/src/lib.rs:14092` — `assertion failed: !view.objects.contains_key(&fixture.terminal_object_id)`
- Suite result: `FAILED. 90 passed; 1 failed; 1 ignored` (523.3 s)
- Deterministic: reproduced identically in the supplementary sweep (`07-...log`).

A terminal object survives in the chain-view `objects` map under small-retention pruning, i.e., the retention/prune path fails to evict a terminal object. Blocks porting of: the node chain-view retention/pruning pattern (relevant to the `noos-store` / node-runtime porting in plan §7), until the NOOSPHERE port independently implements and proves retention semantics.

### Command 5: PASS
`devnet1_no_restart_migration_rehearsal` (release, `--offline`, `--nocapture`) passed: `test result: ok. 1 passed; 0 failed; 0 ignored; 91 filtered out` in 171.09 s (release-profile `main.rs` unittests and doc-tests: 0 tests, ok). The devnet1 migration rehearsal — the strongest end-to-end historical evidence artifact — is healthy under the pinned toolchain.

## Supplementary evidence runs (beyond the mandated five)

Because the mandated `cargo test` invocations fail-fast, two clearly-labeled supplementary sweeps were run to bound the defect inventory:

| Log | Command | Exit | Wall | Result |
|-----|---------|------|------|--------|
| `06-supplementary-workspace-no-fail-fast.log` | `cargo test --workspace --exclude ascent-node --no-fail-fast` | 101 | 406.7 s | Only `-p ascent-consensus-core --lib` fails (same single test as DEFECT-3). All other targets pass: ascent-cli 26+3+1+2, ascent-cogitate 13, ascent-crypto 12+3, ascent-fuzz 0+2, ascent-receipts 19, ascent-sim-net 18 (2 ignored), ascent-state 99, ascent-types 43+3, ascent-verify 4+5, ascent-vm 11, ascent-wallet-core 43; all doc-tests ok. |
| `07-supplementary-ascent-node-no-fail-fast.log` | `cargo test -p ascent-node --no-fail-fast -- --test-threads=1` | 101 | 558.8 s | Only the lib target fails (same single test as DEFECT-4): 90 passed; 1 failed; 1 ignored. `main.rs` unittests and doc-tests: 0 tests, ok. |

Conclusion: the complete inherited-defect inventory of the historical substrate under Rust 1.96.1 is exactly the four items above (2 hygiene, 2 behavioral test failures), plus nothing hidden behind fail-fast.

## Integrity of C:/ascent (read-only mandate)

- Before runs: `git status --porcelain -uno` clean at `7679779…`; `Cargo.lock` sha256 `a60be4a9709c0b24a2eb6c1a33ad42aa8a6fdffc478731431969d04dea63466b`.
- All build artifacts were redirected to `C:/tmp/ascent-baseline-target` (outside C:/ascent).
- After runs: `Cargo.lock` sha256 identical. One test side effect was detected: an `ascent-sim-net` battery test regenerated the checked-in stats file `sims/wp07-battery.md` (+3/−3: `commits total` count and two latency-percentile rows). This is an inherent write performed by the mandated `cargo test` command itself, not an edit by this verification. The file was restored to its exact HEAD bytes via `git checkout -- sims/wp07-battery.md`; final `git status --porcelain` (including untracked files) is empty and HEAD is unchanged at `76797791599e0f574d9b30056d9c241466e47dbd`. The working tree is byte-identical to its pre-run state.
- Note for future baseline re-runs: the `sims/wp07-battery.md` self-rewrite is itself a reproducibility hazard (a test mutating a checked-in fixture) and should be treated as part of INHERITED-DEFECT scope for the sim-net battery pattern when it is ported.

## Log inventory

| File | Content |
|------|---------|
| `01-cargo-fmt-check.log` | full stdout+stderr, exit 1 |
| `02-cargo-clippy.log` | full stdout+stderr, exit 101 |
| `03-cargo-test-workspace.log` | full stdout+stderr, exit 101 |
| `04-cargo-test-ascent-node.log` | full stdout+stderr, exit 101 |
| `05-cargo-test-migration-rehearsal.log` | full stdout+stderr, exit 0 |
| `06-supplementary-workspace-no-fail-fast.log` | supplementary sweep, exit 101 |
| `07-supplementary-ascent-node-no-fail-fast.log` | supplementary sweep, exit 101 |

Each log begins with the exact command line and environment header and ends with a `[exit code: N] [wall time: T]` trailer appended by the verification harness; everything between is the verbatim merged stdout/stderr of the command.
