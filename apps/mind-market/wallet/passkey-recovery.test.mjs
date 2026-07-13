import assert from "node:assert/strict";
import { createHash, webcrypto } from "node:crypto";
import test from "node:test";

Object.defineProperty(globalThis, "crypto", { value: webcrypto, configurable: true });
Object.defineProperty(globalThis, "location", { value: { hostname: "wallet.example" }, configurable: true });
Object.defineProperty(globalThis, "PublicKeyCredential", { value: class PublicKeyCredential {}, configurable: true });

const rawId = Uint8Array.from({ length: 32 }, (_, index) => index + 1);
function resultFor(salt) {
  const digest = createHash("sha256").update("test-credential").update(salt).digest();
  return digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength);
}
function credentialFor(options) {
  const first = options.publicKey.extensions.prf.eval.first;
  return {
    rawId,
    getClientExtensionResults: () => ({ prf: { results: { first: resultFor(first) } } }),
  };
}
const credentials = {
  create: async (options) => credentialFor(options),
  get: async (options) => credentialFor(options),
};
Object.defineProperty(globalThis, "navigator", { value: { credentials }, configurable: true });

const recovery = await import("./passkey-recovery.js");
const binding = {
  password: "correct horse battery staple",
  chainId: "11".repeat(32),
  publicId: "22".repeat(32),
  vaultSchema: "harbor-wallet-v1",
  rpId: "wallet.example",
};

test("PRF passkey round trip recovers only the bound vault password", async () => {
  const record = await recovery.enrollPasskeyRecovery(binding);
  assert.equal(record.version, 1);
  assert.equal(record.chain_id, binding.chainId);
  assert.equal(record.public_id, binding.publicId);
  assert.notEqual(record.ciphertext, Buffer.from(binding.password).toString("hex"));
  const password = await recovery.recoverPasskeyPassword(record, binding);
  assert.equal(password, binding.password);
});

test("chain and origin substitutions fail before an assertion", async () => {
  const record = await recovery.enrollPasskeyRecovery(binding);
  await assert.rejects(
    recovery.recoverPasskeyPassword(record, { ...binding, chainId: "33".repeat(32) }),
    /passkey_recovery_binding_mismatch/,
  );
  await assert.rejects(
    recovery.recoverPasskeyPassword(record, { ...binding, rpId: "evil.example" }),
    /passkey_recovery_binding_mismatch/,
  );
});

test("an assertion without a PRF output cannot decrypt", async () => {
  const record = await recovery.enrollPasskeyRecovery(binding);
  const original = credentials.get;
  credentials.get = async () => ({ rawId, getClientExtensionResults: () => ({ prf: {} }) });
  await assert.rejects(recovery.recoverPasskeyPassword(record, binding), /passkey_prf_unavailable/);
  credentials.get = original;
});
