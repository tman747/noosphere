import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { webcrypto } from "node:crypto";

import {
  assertManifest,
  bytesToHex,
  canonicalJson,
  findCheck,
  validateGatewayHealth,
  validateIndexedTransaction,
  validateLifecycle,
  validateModelResolution,
  validateMonitorReadiness,
  verifyMonitorEnvelope,
} from "./neural-core-v3.mjs";

globalThis.crypto ??= webcrypto;

const manifest = assertManifest(
  JSON.parse(await readFile(new URL("./neural-manifest.json", import.meta.url), "utf8")),
);

test("selects the newest finalized activity and rejects duplicate lifecycle IDs", () => {
  assert.equal(manifest.inference, manifest.activity[0]);
  assert.equal(manifest.inference.sequence, Math.max(...manifest.activity.map((entry) => entry.sequence)));

  const duplicate = structuredClone(manifest);
  const newest = duplicate.activity[0];
  duplicate.activity = [
    {
      ...newest,
      sequence: newest.sequence + 1,
      label: "Duplicate neural pulse",
      included_height: newest.included_height + 1,
    },
    ...duplicate.activity,
  ];
  assert.throws(() => assertManifest(duplicate), /duplicate transaction_id/);

  const legacy = structuredClone(manifest);
  legacy.schema = "noos/neural-explorer-manifest/v2";
  assert.throws(() => assertManifest(legacy), /wrong neural manifest schema/);
});

function modelFixture() {
  const activeProfiles = Array.from({ length: 12 }, (_, index) => ({
    profile_id: index.toString(16).padStart(64, "0"),
    endpoint_root: (index + 20).toString(16).padStart(64, "0"),
    status: 0,
  }));
  const executorIds = Array.from(
    { length: 8 },
    (_, index) => (index + 40).toString(16).padStart(64, "0"),
  );
  return {
    schema: "noos/finalized-model-resolution/v1",
    trust_scope: "LOCAL_FULL_NODE_FINALIZED_STATE",
    chain_id: manifest.chain_id,
    genesis_hash: manifest.genesis_hash,
    selector: manifest.model.alias,
    registration_state: "ACTIVE_TESTNET",
    control_mode: "TESTNET",
    production_effect: "NONE",
    weights_on_chain: false,
    proofs_verified: true,
    proof_count: 17,
    finalized_height: 226304,
    finalized_hash: "11".repeat(32),
    objects_root: "12".repeat(32),
    canonical_resolution_body_hex: "00",
    finality_evidence_hex: "01",
    active: {
      artifact_id: manifest.model.artifact_id,
      artifact_sha256: manifest.model.artifact_sha256,
      manifest_root: manifest.model.manifest_root,
      capsule_id: manifest.model.capsule_id,
      execution_profile_id: manifest.model.execution_profile_id,
      query_policy_id: manifest.model.query_policy_id,
      availability_certificate_id: manifest.model.availability_certificate_id,
      fund_profile_id: manifest.model.fund_profile_id,
      model_name: manifest.model.name,
      availability_claim: "TESTNET_FIXTURE_ONLY",
      certificate_availability_state: 0,
      custodian_profiles: activeProfiles,
      executor_profile_ids: executorIds,
    },
  };
}

function proof(kind, id, record, suffix) {
  return {
    schema: "noos/finalized-wwm-record/v1",
    trust_scope: "LOCAL_FULL_NODE_FINALIZED_STATE",
    kind,
    id,
    finalized_height: 226304,
    finalized_hash: suffix.repeat(32),
    objects_root: (Number.parseInt(suffix, 16) + 1).toString(16).padStart(64, "0"),
    canonical_record_hex: "00",
    proof_hex: "01",
    record,
  };
}

function lifecycleFixture() {
  const job = proof(
    "job",
    manifest.inference.job_id,
    {
      job_id: manifest.inference.job_id,
      capsule_id: manifest.model.capsule_id,
      execution_profile_id: manifest.model.execution_profile_id,
      availability_certificate_id: manifest.model.availability_certificate_id,
      fund_profile_id: manifest.model.fund_profile_id,
      deadline_height: 230000,
    },
    "21",
  );
  const receipt = proof(
    "receipt",
    manifest.inference.receipt_id,
    {
      receipt_id: manifest.inference.receipt_id,
      job_id: manifest.inference.job_id,
      capsule_id: manifest.model.capsule_id,
      artifact_id: manifest.model.artifact_id,
      execution_profile_id: manifest.model.execution_profile_id,
      output_root: manifest.inference.output_root,
      token_history_root: manifest.inference.token_history_root,
      terminal_code: 0,
      anchor_height: 225792,
      anchor_block: "31".repeat(32),
    },
    "22",
  );
  const settlement = proof(
    "settlement",
    manifest.inference.settlement_id,
    {
      settlement_id: manifest.inference.settlement_id,
      job_id: manifest.inference.job_id,
      receipt_id: manifest.inference.receipt_id,
      fund_profile_id: manifest.model.fund_profile_id,
      settled_height: 225792,
    },
    "23",
  );
  return { job, receipt, settlement };
}

test("accepts the exact finalized model and WWM inference lifecycle", () => {
  const health = validateGatewayHealth(
    {
      schema: "noos/wwm-public-testnet-gateway/v1",
      environment: "public-testnet",
      production: false,
      promotion_effect: "NONE",
      status: "ok",
      node_source: "primary",
      chain_id: manifest.chain_id,
      genesis_hash: manifest.genesis_hash,
      unsafe_head: { height: 226400, hash: "01".repeat(32) },
      finalized: { epoch: 884, hash: "02".repeat(32) },
    },
    manifest,
  );
  assert.equal(health.node_source, "primary");
  assert.equal(validateModelResolution(modelFixture(), manifest).proof_count, 17);
  assert.equal(
    validateLifecycle(lifecycleFixture(), manifest).receipt.record.output_root,
    manifest.inference.output_root,
  );
  const indexed = validateIndexedTransaction(
    {
      txid: manifest.inference.transaction_id,
      state: "INCLUDED",
      fee: manifest.inference.fee_charged,
      inclusion: {
        height: String(manifest.inference.included_height),
        index: "0",
        hash: manifest.inference.included_block,
      },
    },
    manifest,
  );
  assert.equal(indexed.inclusion.height, String(manifest.inference.included_height));
});

test("rejects model or receipt data that diverges from manifest pins", () => {
  const wrongModel = modelFixture();
  wrongModel.active.artifact_sha256 = "ff".repeat(32);
  assert.throws(() => validateModelResolution(wrongModel, manifest), /artifact_sha256 mismatch/);

  const wrongReceipt = lifecycleFixture();
  wrongReceipt.receipt.record.output_root = "ee".repeat(32);
  assert.throws(() => validateLifecycle(wrongReceipt, manifest), /output root mismatch/);
});

test("verifies signed monitor readiness and rejects tampering", async () => {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const publicKey = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
  const signerKeyId = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey)));
  const payload = {
    schema: "noos/wwm-public-testnet-monitor-sample/v1",
    environment: "public-testnet",
    production: false,
    promotion_effect: "NONE",
    status: "ok",
    observed_at_utc: "2026-07-20T23:30:00Z",
    previous_sample_id: null,
    checks: [
      { name: "inference_worker", ok: true, latency_ms: 1, detail: { ready: true } },
      { name: "model_resolution", ok: true, latency_ms: 2, detail: {} },
      { name: "network_coherence", ok: true, latency_ms: 3, detail: {} },
    ],
  };
  const domain = new TextEncoder().encode("NOOS/SIG/WWM/V1\0PUBLIC-TESTNET-MONITOR-SAMPLE\0");
  const body = new TextEncoder().encode(canonicalJson(payload));
  const message = new Uint8Array(domain.length + body.length);
  message.set(domain);
  message.set(body, domain.length);
  const sampleId = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", message)));
  const signature = new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, pair.privateKey, message));
  const envelope = {
    ...payload,
    sample_id: sampleId,
    signer_key_id: signerKeyId,
    public_key_base64: Buffer.from(publicKey).toString("base64"),
    signature_base64: Buffer.from(signature).toString("base64"),
  };
  const verified = validateMonitorReadiness(await verifyMonitorEnvelope(envelope, signerKeyId));
  assert.equal(findCheck(verified, "inference_worker").detail.ready, true);

  const tampered = structuredClone(envelope);
  tampered.checks[0].detail.ready = false;
  await assert.rejects(() => verifyMonitorEnvelope(tampered, signerKeyId), /sample ID mismatch/);
});
