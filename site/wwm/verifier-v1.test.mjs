import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { canonicalJson } from "../neural-core-v3.mjs";
import { verifyFinalizedSettlement, verifySignedEnvelope } from "./verifier-v1.mjs";

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

test("finalized settlement accepts a newer canonical proof snapshot", async () => {
  const hex32 = (byte) => byte.repeat(64);
  const jobId = hex32("1");
  const receiptId = hex32("2");
  const settlementId = hex32("3");
  const capsuleId = hex32("4");
  const executionProfileId = hex32("5");
  const outputRoot = hex32("6");
  const tokenHistoryRoot = hex32("7");
  const summaryHash = hex32("8");
  const currentHash = hex32("9");
  const currentRoot = hex32("a");
  const record = (kind, id, value) => ({
    schema: "noos/finalized-wwm-record/v1",
    trust_scope: "LOCAL_FULL_NODE_FINALIZED_STATE",
    kind,
    id,
    finalized_height: 30,
    finalized_hash: currentHash,
    objects_root: currentRoot,
    canonical_record_hex: "00",
    proof_hex: "01",
    record: value,
  });
  const records = {
    [`/api/wwm-record/job/${jobId}`]: record("job", jobId, {
      job_id: jobId,
      capsule_id: capsuleId,
      execution_profile_id: executionProfileId,
    }),
    [`/api/wwm-record/receipt/${receiptId}`]: record("receipt", receiptId, {
      receipt_id: receiptId,
      job_id: jobId,
      output_root: outputRoot,
      token_history_root: tokenHistoryRoot,
    }),
    [`/api/wwm-record/settlement/${settlementId}`]: record("settlement", settlementId, {
      settlement_id: settlementId,
      job_id: jobId,
      receipt_id: receiptId,
    }),
  };
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => new Response(JSON.stringify(records[url]), {
    status: records[url] ? 200 : 404,
    headers: { "Content-Type": "application/json" },
  });
  try {
    await verifyFinalizedSettlement({
      job_id: jobId,
      receipt_id: receiptId,
      capsule_id: capsuleId,
      execution_profile_id: executionProfileId,
      output_root: outputRoot,
      token_history_root: tokenHistoryRoot,
      output_tokens: 8,
      chain_anchor: summaryHash,
      chain_settlement: {
        schema: "noos/wwm-public-inference-chain-settlement/v1",
        job_id: jobId,
        receipt_id: receiptId,
        settlement_id: settlementId,
        finalized: {
          job: { finalized_height: 10, finalized_hash: hex32("b"), objects_root: hex32("c") },
          receipt: { finalized_height: 20, finalized_hash: summaryHash, objects_root: hex32("d") },
          settlement: { finalized_height: 20, finalized_hash: summaryHash, objects_root: hex32("d") },
        },
      },
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
});
