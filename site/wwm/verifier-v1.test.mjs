import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { canonicalJson } from "../neural-core-v3.mjs";
import { verifySignedEnvelope } from "./verifier-v1.mjs";

if (!globalThis.crypto) globalThis.crypto = webcrypto;

const DOMAIN = new TextEncoder().encode("NOOS/SIG/WWM/PUBLIC-INFERENCE/V1\0");

function concatBytes(...parts) {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

async function fixture(kind, value) {
  const pair = await webcrypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await webcrypto.subtle.exportKey("raw", pair.publicKey));
  const keyId = Buffer.from(await webcrypto.subtle.digest("SHA-256", publicKey)).toString("hex");
  const unsigned = { ...value, signing_key_id: keyId };
  const message = concatBytes(
    DOMAIN,
    new TextEncoder().encode(kind),
    new Uint8Array([0]),
    new TextEncoder().encode(canonicalJson(unsigned)),
  );
  const signature = new Uint8Array(await webcrypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, message));
  return {
    envelope: { ...unsigned, signature: Buffer.from(signature).toString("base64") },
    publicKeyBase64: Buffer.from(publicKey).toString("base64"),
    keyId,
  };
}

test("domain-separated Ed25519 envelopes verify and tampering fails", async () => {
  const signed = await fixture("QUOTE", {
    schema: "noos/wwm-quote/v2",
    quote_id: "11".repeat(32),
    maximum_fee_micro_noos: 0,
    production: false,
  });
  assert.equal(
    await verifySignedEnvelope(signed.envelope, "QUOTE", signed.publicKeyBase64, signed.keyId),
    true,
  );
  const tampered = { ...signed.envelope, maximum_fee_micro_noos: 1 };
  assert.equal(
    await verifySignedEnvelope(tampered, "QUOTE", signed.publicKeyBase64, signed.keyId),
    false,
  );
  assert.equal(
    await verifySignedEnvelope(signed.envelope, "RECEIPT", signed.publicKeyBase64, signed.keyId),
    false,
  );
});

test("an envelope cannot substitute an unpinned signing key", async () => {
  const signed = await fixture("STREAM-EVENT", {
    id: 1,
    type: "output.delta",
    data: { delta: "bounded" },
  });
  await assert.rejects(
    () => verifySignedEnvelope(signed.envelope, "STREAM-EVENT", signed.publicKeyBase64, "22".repeat(32)),
    /not pinned/,
  );
});
