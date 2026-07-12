import test from "node:test"; import assert from "node:assert/strict";
import { generateKeyPairSync, sign as edSign } from "node:crypto";
import { readFile, rm, access } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { deriveSecret, derivationPath, pathHex, pathBytes, WalletDerivationError } from "./app/ui/core/derivation.mjs";
import { validateAddress, encodeAddress, displayGroups, AddressError } from "./app/ui/core/address.mjs";
import { verifyUpdateManifest, normalizeRuntime, signingBytes, PLATFORMS, ARCHES } from "./app/ui/core/manifest.mjs";
import { formatSubmissionResult } from "./app/ui/core/submission.mjs";
import { PRODUCT } from "./identity.mjs";
import { build } from "./app/build.mjs";

const walletRoot = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(walletRoot, "..");
const toHex = (bytes) => Buffer.from(bytes).toString("hex");
const readJson = async (path) => JSON.parse(await readFile(resolve(repoRoot, path), "utf8"));

// --- Derivation: cross-implementation parity with the frozen vectors -----
test("wallet app derivation matches every frozen derivation vector", async () => {
  const doc = await readJson("protocol/vectors/wallet/derivation-v1.json");
  assert.equal(doc.schema, "noos-wallet-derivation-v1");
  assert.ok(doc.cases.length >= 30, "vector corpus went missing");
  for (const c of doc.cases) {
    assert.equal(c.kind, "positive");
    const path = derivationPath(c.purpose, c.account, c.index, c.suite);
    assert.deepEqual(pathHex(path), c.path, `${c.name} path`);
    assert.equal(toHex(pathBytes(path)), c.bytes, `${c.name} bytes`);
    const secret = await deriveSecret(Buffer.from(c.seed, "hex"), c.purpose, c.account, c.index, c.suite);
    assert.equal(toHex(secret), c.derived_secret, `${c.name} secret`);
  }
});

test("wallet app derivation rejects aliasing and cross-purpose forgeries", async () => {
  const seed = Buffer.alloc(64, 1);
  // Non-hardenable component would alias two paths.
  assert.throws(() => derivationPath("sign", 2 ** 31, 0), /invalid_derivation_index/);
  assert.throws(() => derivationPath("sign", -1, 0), /invalid_derivation_index/);
  assert.throws(() => derivationPath("sign", 0.5, 0), /invalid_derivation_index/);
  // Purpose/suite shape is closed.
  assert.throws(() => derivationPath("umbra", 0, 0), /invalid_purpose/);
  assert.throws(() => derivationPath("sign", 0, 0, 9), /invalid_purpose/);
  assert.throws(() => derivationPath("spend-all", 0, 0), /invalid_purpose/);
  assert.ok(new WalletDerivationError("x") instanceof Error);
  // Purpose separation: same coordinates, different purposes, different keys.
  const signKey = await deriveSecret(seed, "sign", 0, 0);
  const viewKey = await deriveSecret(seed, "view", 0, 0);
  assert.notEqual(toHex(signKey), toHex(viewKey));
});

// --- Address: strict Bech32m against the frozen API vectors --------------
test("wallet app address check accepts exactly the canonical API vectors", async () => {
  const positive = await readJson("protocol/api/vectors/positive.json");
  const cases = (positive.vectors ?? positive.cases).filter((v) => v.kind === "address");
  assert.ok(cases.length >= 1, "canonical address vector missing");
  for (const c of cases) {
    const { payload5 } = validateAddress(c.value);
    // Round-trip: re-encoding the opaque payload reproduces the exact string.
    assert.equal(encodeAddress(payload5), c.value, c.id);
    const grouped = displayGroups(c.value);
    assert.ok(grouped.display.startsWith("noos1 "), "display keeps the HRP visible");
    assert.equal(grouped.payloadChars, c.value.length - "noos1".length - 6);
  }
});

test("wallet app address check rejects every negative API vector with its named error", async () => {
  const negative = await readJson("protocol/api/vectors/negative.json");
  const cases = (negative.vectors ?? negative.cases).filter((v) => v.kind === "address");
  assert.ok(cases.length >= 4, "negative address corpus went missing");
  for (const c of cases) {
    const expected = c.error === "noncanonical_address" ? "noncanonical_address" : c.error;
    assert.throws(() => validateAddress(c.value), new RegExp(expected), c.id);
  }
  // Historical protocol identity (HRP built from bytes; identity gate).
  const hist = Buffer.from("6d696e64", "hex").toString("utf8");
  assert.throws(() => validateAddress(`${hist}1qyqqqqgzqvzq2ps`), /wrong_protocol_identity/);
  // Own-address emission defines no layout: encoder refuses out-of-range payloads.
  assert.throws(() => encodeAddress([32]), /bad_charset/);
  assert.throws(() => encodeAddress(new Array(84).fill(0)), /bad_length/);
  assert.ok(new AddressError("x") instanceof Error);
});

// --- Update manifest: signature policy falsifiers ------------------------
const keypair = generateKeyPairSync("ed25519");
const updaterKeyHex = keypair.publicKey.export({ format: "jwk" }).x
  ? Buffer.from(keypair.publicKey.export({ format: "jwk" }).x, "base64url").toString("hex")
  : null;
const expected = { chain_id: "a".repeat(64), genesis_hash: "b".repeat(64), api_version: "v1" };
const runtime = normalizeRuntime("win32", "x64", "stable");

function signedManifest(overrides = {}, resign = true) {
  const manifest = {
    app_id: PRODUCT.bundleId,
    chain_id: expected.chain_id,
    genesis_hash: expected.genesis_hash,
    platform: "windows",
    arch: "x86_64",
    version: "1.2.3",
    channel: "stable",
    artifact_sha256: "d".repeat(64),
    signature: "0".repeat(128),
    ...overrides,
  };
  if (resign) manifest.signature = edSign(null, signingBytes(manifest), keypair.privateKey).toString("hex");
  return manifest;
}

test("wallet app accepts only a correctly signed manifest for this exact target", async () => {
  assert.ok(updaterKeyHex, "ed25519 raw public key export failed");
  const checked = await verifyUpdateManifest(signedManifest(), expected, runtime, updaterKeyHex);
  assert.equal(checked.version, "1.2.3");
  assert.deepEqual(runtime, { platform: "windows", arch: "x86_64", channel: "stable" });
  assert.ok(PLATFORMS.includes(runtime.platform) && ARCHES.includes(runtime.arch));
});

test("wallet app manifest falsifiers reject every forgery class", async () => {
  // Tampered artifact hash after signing: structure valid, signature dead.
  const tampered = signedManifest();
  tampered.artifact_sha256 = "e".repeat(64);
  await assert.rejects(verifyUpdateManifest(tampered, expected, runtime, updaterKeyHex), /bad_signature/);
  // Attacker-key resign of a rollback version.
  const attacker = generateKeyPairSync("ed25519");
  const resigned = signedManifest({ version: "0.0.1" }, false);
  resigned.signature = edSign(null, signingBytes(resigned), attacker.privateKey).toString("hex");
  await assert.rejects(verifyUpdateManifest(resigned, expected, runtime, updaterKeyHex), /bad_signature/);
  // Correctly signed manifest for the OTHER channel: wrong target here.
  await assert.rejects(
    verifyUpdateManifest(signedManifest({ channel: "beta" }), expected, runtime, updaterKeyHex),
    /wrong_update_target/,
  );
  // Correctly signed manifest for another platform/arch.
  await assert.rejects(
    verifyUpdateManifest(signedManifest({ platform: "linux" }), expected, runtime, updaterKeyHex),
    /wrong_update_target/,
  );
  await assert.rejects(
    verifyUpdateManifest(signedManifest({ arch: "aarch64" }), expected, runtime, updaterKeyHex),
    /wrong_update_target/,
  );
  // Wrong chain identity and wrong app id bind before the signature.
  await assert.rejects(
    verifyUpdateManifest(signedManifest({ chain_id: "c".repeat(64) }), expected, runtime, updaterKeyHex),
    /wrong_protocol_identity/,
  );
  await assert.rejects(
    verifyUpdateManifest(signedManifest({ app_id: "network.example.other" }), expected, runtime, updaterKeyHex),
    /wrong_protocol_identity/,
  );
  // Structural forgeries.
  await assert.rejects(
    verifyUpdateManifest(signedManifest({ artifact_sha256: "D".repeat(64) }), expected, runtime, updaterKeyHex),
    /invalid_update_manifest/,
  );
  await assert.rejects(
    verifyUpdateManifest(signedManifest({ signature: "zz" }, false), expected, runtime, updaterKeyHex),
    /invalid_update_manifest/,
  );
  await assert.rejects(
    verifyUpdateManifest(signedManifest({ version: "" }, false), expected, runtime, updaterKeyHex),
    /invalid_update_manifest/,
  );
  // Key policy: malformed or wrong-case keys never verify anything.
  await assert.rejects(verifyUpdateManifest(signedManifest(), expected, runtime, "zz"), /invalid_updater_key/);
  await assert.rejects(
    verifyUpdateManifest(signedManifest(), expected, runtime, updaterKeyHex.toUpperCase()),
    /invalid_updater_key/,
  );
  // Runtime vocabulary is closed.
  assert.throws(() => normalizeRuntime("win32", "x64", "nightly"), /wrong_update_target/);
  assert.throws(() => normalizeRuntime("beos", "x64", "stable"), /wrong_update_target/);
});

test("wallet UI renders only upstream protocol txid and accepted settlement state", () => {
  const txid = "a".repeat(64);
  assert.equal(formatSubmissionResult({ txid, state: "MEMPOOL", ignored: "not rendered" }), `txid: ${txid}\nstatus: MEMPOOL`);
  for (const response of [
    { txid, state: "REJECTED" },
    { txid, state: "REVERTED" },
    { txid: "A".repeat(64), state: "MEMPOOL" },
    { txid, state: "accepted" },
    { state: "MEMPOOL" },
    "network_failure",
  ]) {
    assert.throws(() => formatSubmissionResult(response), /submission_rejected|malformed_submit_response/);
  }
});

// --- Build: npm-free dist is complete and self-contained -----------------
test("wallet app build produces a self-contained dist without type syntax", async () => {
  const outDir = join(walletRoot, "app", "ui", "dist");
  await build(outDir);
  const mainJs = await readFile(join(outDir, "main.js"), "utf8");
  assert.ok(!mainJs.includes("interface "), "type declarations must be stripped");
  assert.match(mainJs, /"\.\/core\/address\.mjs"/, "core imports must be retargeted");
  assert.ok(!mainJs.includes('"../core/'), "no source-layout imports may survive");
  const manifestCore = await readFile(join(outDir, "core", "manifest.mjs"), "utf8");
  assert.match(manifestCore, /"\.\/identity\.mjs"/, "identity import must be vendored");
  for (const file of ["index.html", "styles.css", "core/identity.mjs", "core/derivation.mjs", "core/address.mjs", "core/submission.mjs"]) {
    await assert.doesNotReject(access(join(outDir, file)), `dist missing ${file}`);
  }
  // The vendored dist modules must actually load and agree with the source.
  const dist = await import(new URL(`file://${join(outDir, "core", "address.mjs").replaceAll("\\", "/")}`));
  assert.equal(dist.encodeAddress(validateAddress("noos1qyqqqqgzqvzq2ps8pqys5zcvp58q7yq3zgf3g9gkzuvpjxsmrsw3u8ct36na7").payload5),
    "noos1qyqqqqgzqvzq2ps8pqys5zcvp58q7yq3zgf3g9gkzuvpjxsmrsw3u8ct36na7");
});
