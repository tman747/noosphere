import {
  assertManifest,
  bytesToHex,
  canonicalJson,
  findCheck,
  validateModelResolution,
  verifyMonitorEnvelope,
} from "../neural-core-v3.mjs";

const CHAIN_ID = "0106bef48c350fd9633bac1718f8d9ecb1824c78bd127feee6405c65a63afa8b";
const GENESIS_HASH = "8c182c6e9d622f77f082332da1a514ecf061ef4c504b5dde466ca4c93e35167e";
const INFERENCE_PUBLIC_KEY_BASE64 = "9gTYubfLpYxvO6pkUkX97LXPxrJMArUMllxaOsoAi9g=";
const INFERENCE_SIGNING_KEY_ID = "1ad4d182db7efffd0e4435fdb748c793f38c2b0062150d00d05c3dda336ed1c6";
const SIGNING_DOMAIN = new TextEncoder().encode("NOOS/SIG/WWM/PUBLIC-INFERENCE/V1\0");
const HEX32 = /^[0-9a-f]{64}$/;
const U64 = /^(0|[1-9][0-9]{0,19})$/;
const RECEIPT_STATUSES = new Set(["COMPLETED", "CANCELLED", "FAILED", "NO_QUORUM"]);
const EVENT_TYPES = new Set(["output.delta", "evidence.updated", "receipt.completed"]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requireHex32(value, label) {
  invariant(typeof value === "string" && HEX32.test(value), `${label} is not hex32`);
  return value;
}

function base64ToBytes(value, label) {
  invariant(typeof value === "string" && /^[A-Za-z0-9+/]+={0,2}$/.test(value), `${label} is not canonical base64`);
  let decoded;
  try { decoded = atob(value); } catch { throw new Error(`${label} is not valid base64`); }
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
}

function concatBytes(...parts) {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const output = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.byteLength;
  }
  return output;
}

async function fetchJson(url) {
  const response = await fetch(url, {
    headers: { Accept: "application/json" },
    cache: "no-store",
  });
  invariant(response.ok, `proof source ${url} returned HTTP ${response.status}`);
  const value = await response.json();
  invariant(isRecord(value), `proof source ${url} is not an object`);
  return value;
}

export async function verifySignedEnvelope(
  value,
  kind,
  publicKeyBase64 = INFERENCE_PUBLIC_KEY_BASE64,
  expectedKeyId = INFERENCE_SIGNING_KEY_ID,
) {
  invariant(isRecord(value), `${kind} envelope is not an object`);
  invariant(value.signing_key_id === expectedKeyId, `${kind} signer is not pinned`);
  const publicKey = base64ToBytes(publicKeyBase64, `${kind} public key`);
  const signature = base64ToBytes(value.signature, `${kind} signature`);
  invariant(publicKey.byteLength === 32 && signature.byteLength === 64, `${kind} key or signature length is invalid`);
  const keyId = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey)));
  invariant(keyId === expectedKeyId, `${kind} public key ID mismatch`);
  const unsigned = Object.fromEntries(Object.entries(value).filter(([key]) => key !== "signature"));
  const message = concatBytes(
    SIGNING_DOMAIN,
    new TextEncoder().encode(kind),
    new Uint8Array([0]),
    new TextEncoder().encode(canonicalJson(unsigned)),
  );
  const key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, signature, message);
}

function validateGatewayProjection(resolution, model, sample) {
  invariant(isRecord(resolution), "gateway resolution projection is missing");
  invariant(
    resolution.chain_id === model.chain_id
      && resolution.genesis_hash === model.genesis_hash
      && resolution.finalized_height === model.finalized_height
      && resolution.finalized_hash === model.finalized_hash
      && resolution.objects_root === model.objects_root,
    "gateway projection does not match the local full-node resolution",
  );
  invariant(isRecord(resolution.proof_source), "gateway proof-source disclosure is missing");
  invariant(
    resolution.proof_source.schema === model.schema
      && resolution.proof_source.selector === model.selector
      && resolution.proof_source.trust_scope === "LOCAL_FULL_NODE_FINALIZED_STATE"
      && resolution.proof_source.proof_count === 17
      && resolution.proof_source.proofs_verified === true,
    "gateway proof-source disclosure is invalid",
  );
  const active = model.active;
  const projected = resolution.active;
  invariant(isRecord(projected), "gateway active projection is missing");
  invariant(
    resolution.pin_id === active.authorized_config_id
      && projected.activation_state === "ACTIVE"
      && projected.capsule_id === active.capsule_id
      && projected.execution_profile_id === active.execution_profile_id
      && projected.query_profile_id === active.query_policy_id
      && projected.artifact_sha256 === active.artifact_sha256
      && projected.artifact_length === active.artifact_bytes,
    "gateway active projection is not bound to the finalized graph",
  );
  invariant(Array.isArray(resolution.candidates) && resolution.candidates.length === 0, "unexpected dispatch candidate");

  const hosting = resolution.hosting;
  invariant(isRecord(hosting), "gateway hosting projection is missing");
  const exact = {
    artifact_id: active.artifact_id,
    manifest_root: active.manifest_root,
    runtime_root: active.runtime_root,
    artifact_sha256: active.artifact_sha256,
    source_bytes: active.artifact_bytes,
    stripe_count: active.stripe_count,
    availability_certificate_id: active.availability_certificate_id,
    certificate_issued_height: active.certificate_issued_height,
  };
  for (const [field, expected] of Object.entries(exact)) {
    invariant(hosting[field] === expected, `gateway hosting ${field} mismatch`);
  }
  invariant(
    hosting.encoded_bytes === 5_707_063_296
      && hosting.share_bytes === 1_047_552
      && hosting.position_count === 12
      && hosting.data_shards === 8
      && hosting.parity_shards === 4
      && hosting.reconstruction_threshold === 8
      && hosting.schedulable_minimum === 9,
    "gateway hosting geometry mismatch",
  );
  invariant(
    typeof hosting.certificate_valid_until_height === "string"
      && U64.test(hosting.certificate_valid_until_height)
      && BigInt(hosting.certificate_valid_until_height) >= BigInt(model.finalized_height),
    "gateway certificate horizon is invalid",
  );
  invariant(
    Array.isArray(hosting.custodians)
      && Array.isArray(active.custodian_profiles)
      && hosting.custodians.length === 12
      && active.custodian_profiles.length === 12,
    "gateway custody projection is incomplete",
  );
  hosting.custodians.forEach((row, position) => {
    const source = active.custodian_profiles[position];
    invariant(
      isRecord(row)
        && row.position === position
        && row.profile_id === source.profile_id
        && row.endpoint_root === source.endpoint_root
        && row.status === 0
        && source.status === 0,
      `gateway custodian position ${position} mismatch`,
    );
  });
  invariant(
    Array.isArray(hosting.executor_profile_ids)
      && hosting.executor_profile_ids.length === active.executor_profile_ids.length
      && hosting.executor_profile_ids.every((value, index) => value === active.executor_profile_ids[index]),
    "gateway executor projection mismatch",
  );
  invariant(isRecord(hosting.worker), "signed worker projection is missing");
  invariant(
    hosting.worker.source === "SIGNED_OPERATOR_MONITOR"
      && hosting.worker.monitor_sample_id === sample.sample_id
      && hosting.worker.monitor_signer_key_id === sample.signer_key_id,
    "worker projection is not bound to the signed monitor",
  );
  return hosting;
}

export async function verifyResolution(resolution, gatewayState) {
  invariant(isRecord(gatewayState), "gateway state envelope is missing");
  invariant(
    isRecord(gatewayState.signer)
      && gatewayState.signer.algorithm === "Ed25519"
      && gatewayState.signer.key_id === INFERENCE_SIGNING_KEY_ID
      && gatewayState.signer.public_key_base64 === INFERENCE_PUBLIC_KEY_BASE64,
    "gateway inference signer projection is not pinned",
  );
  const [manifestValue, model] = await Promise.all([
    fetchJson("/neural-manifest.json"),
    fetchJson("/api/model-resolution/bonsai-q1"),
  ]);
  const manifest = assertManifest(manifestValue);
  validateModelResolution(model, manifest);
  invariant(isRecord(gatewayState.monitor), "signed monitor envelope is missing from gateway state");
  const sample = await verifyMonitorEnvelope(gatewayState.monitor, manifest.monitor_signer_key_id);
  const worker = findCheck(sample, "inference_worker");
  const modelCheck = findCheck(sample, "model_resolution");
  invariant(
    worker.ok === true
      && isRecord(worker.detail)
      && worker.detail.ready === true
      && modelCheck.ok === true,
    "signed monitor does not admit interactive inference",
  );
  const hosting = validateGatewayProjection(resolution, model, sample);
  return Object.freeze({
    chain_id: model.chain_id,
    genesis_hash: model.genesis_hash,
    finalized_height: model.finalized_height,
    finalized_hash: model.finalized_hash,
    objects_root: model.objects_root,
    capsule_id: model.active.capsule_id,
    hosted_model: Object.freeze({ ...hosting }),
  });
}

export async function verifyQuote(quote, active) {
  invariant(isRecord(active), "active quote binding is missing");
  invariant(
    quote.production === false
      && quote.promotion_effect === "NONE"
      && quote.payment_mode === "SPONSORED"
      && quote.maximum_fee_micro_noos === 0
      && quote.capsule_id === active.capsule_id
      && quote.execution_profile_id === active.execution_profile_id
      && quote.query_profile_id === active.query_profile_id,
    "quote overclaims scope or mismatches the active capsule",
  );
  return verifySignedEnvelope(quote, "QUOTE");
}

export async function verifyStreamEvent(event, active, jobId) {
  invariant(isRecord(event) && isRecord(event.payload), "stream event is malformed");
  const payload = event.payload;
  invariant(EVENT_TYPES.has(payload.type), "stream event type is not closed");
  invariant(isRecord(payload.data), "stream event data is missing");
  if (payload.type === "output.delta") {
    invariant(
      payload.data.job_id === jobId
        && payload.data.capsule_id === active.capsule_id
        && payload.data.evidence_state === "PROVISIONAL_SIGNED"
        && typeof payload.data.delta === "string",
      "signed output delta binding is invalid",
    );
    requireHex32(payload.data.incremental_output_root, "incremental output root");
  } else if (payload.type === "receipt.completed") {
    invariant(payload.data.job_id === jobId, "terminal event job binding mismatch");
  }
  return verifySignedEnvelope(payload, "STREAM-EVENT");
}

export async function verifyReceipt(receipt, active) {
  invariant(isRecord(receipt), "receipt is not an object");
  invariant(
    receipt.schema === "noos/wwm-receipt/v2"
      && receipt.capsule_id === active.capsule_id
      && receipt.execution_profile_id === active.execution_profile_id
      && receipt.query_profile_id === active.query_profile_id
      && RECEIPT_STATUSES.has(receipt.terminal_status)
      && receipt.execution_scope === "OFF_CHAIN_INTERACTIVE_TESTNET"
      && receipt.settlement_state === "PENDING_CHAIN"
      && receipt.chain_anchor === null
      && receipt.production === false
      && receipt.promotion_effect === "NONE",
    "receipt scope or active-capsule binding is invalid",
  );
  if (receipt.terminal_status === "COMPLETED") {
    invariant(receipt.evidence_state === "PROVISIONAL_SIGNED", "completed receipt evidence is invalid");
    requireHex32(receipt.output_root, "receipt output root");
    requireHex32(receipt.token_history_root, "receipt token history root");
    invariant(Number.isSafeInteger(receipt.output_tokens) && receipt.output_tokens > 0 && receipt.output_tokens <= 16, "receipt output token count is invalid");
  } else {
    invariant(receipt.evidence_state === "NONE", "non-complete receipt must not claim output evidence");
  }
  return verifySignedEnvelope(receipt, "RECEIPT");
}

export const expectedIdentity = Object.freeze({ chain_id: CHAIN_ID, genesis_hash: GENESIS_HASH });

export const MindChainWwmVerifier = Object.freeze({
  expectedIdentity,
  verifyResolution,
  verifyQuote,
  verifyStreamEvent,
  verifyReceipt,
});

globalThis.MindChainWwmVerifier = MindChainWwmVerifier;
