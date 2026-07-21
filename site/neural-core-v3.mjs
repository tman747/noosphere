const HEX32 = /^[0-9a-f]{64}$/;
const HEX_BYTES = /^(?:[0-9a-f]{2})+$/;
const MONITOR_DOMAIN = new TextEncoder().encode("NOOS/SIG/WWM/V1\0PUBLIC-TESTNET-MONITOR-SAMPLE\0");
const OMITTED_MONITOR_FIELDS = new Set([
  "sample_id",
  "signer_key_id",
  "public_key_base64",
  "signature_base64",
]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isUint(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function requireHex32(value, label) {
  invariant(typeof value === "string" && HEX32.test(value), `${label} is not hex32`);
  return value;
}

function requireHexBytes(value, label) {
  invariant(typeof value === "string" && HEX_BYTES.test(value), `${label} is not canonical hexadecimal bytes`);
  return value;
}

function asciiJsonString(value) {
  return JSON.stringify(value).replace(/[\u007f-\uffff]/g, (character) =>
    `\\u${character.charCodeAt(0).toString(16).padStart(4, "0")}`,
  );
}

export function canonicalJson(value) {
  if (value === null) return "null";
  if (typeof value === "string") return asciiJsonString(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    invariant(Number.isFinite(value), "canonical JSON rejects non-finite numbers");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  invariant(isRecord(value), "canonical JSON accepts only JSON values");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${asciiJsonString(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}


export function bytesToHex(bytes) {
  return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
}

function base64ToBytes(value, label) {
  invariant(typeof value === "string" && /^[A-Za-z0-9+/]+={0,2}$/.test(value), `${label} is not canonical base64`);
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function concatBytes(left, right) {
  const output = new Uint8Array(left.length + right.length);
  output.set(left);
  output.set(right, left.length);
  return output;
}

export function shortHash(value, start = 8, end = 6) {
  if (typeof value !== "string" || value.length <= start + end + 1) return String(value ?? "—");
  return `${value.slice(0, start)}…${value.slice(-end)}`;
}

function validateInference(value, label) {
  invariant(isRecord(value), `${label} is not an object`);
  invariant(isUint(value.sequence) && value.sequence > 0, `${label} sequence is invalid`);
  invariant(
    typeof value.label === "string"
      && value.label.length >= 3
      && value.label.length <= 80
      && !/[\u0000-\u001f\u007f]/.test(value.label),
    `${label} label is invalid`,
  );
  for (const field of [
    "transaction_id",
    "included_block",
    "job_id",
    "receipt_id",
    "settlement_id",
    "prompt_commitment",
    "output_root",
    "token_history_root",
  ]) {
    requireHex32(value[field], `${label} ${field}`);
  }
  for (const field of ["input_tokens", "output_tokens", "output_bytes", "duration_milliseconds"]) {
    invariant(isUint(value[field]) && value[field] > 0, `${label} ${field} is invalid`);
  }
  invariant(isUint(value.included_height) && value.included_height > 0, `${label} included_height is invalid`);
  invariant(/^(0|[1-9][0-9]*)$/.test(value.fee_charged), `${label} fee_charged is invalid`);
  return value;
}

export function assertManifest(value) {
  invariant(isRecord(value), "neural manifest is not an object");
  invariant(value.schema === "noos/neural-explorer-manifest/v3", "wrong neural manifest schema");
  invariant(value.environment === "public-testnet", "wrong neural environment");
  invariant(value.production === false && value.promotion_effect === "NONE", "neural manifest is not fail-closed");
  requireHex32(value.chain_id, "chain_id");
  requireHex32(value.genesis_hash, "genesis_hash");
  requireHex32(value.monitor_signer_key_id, "monitor signer key ID");

  invariant(isRecord(value.model), "model pins are missing");
  invariant(value.model.alias === "bonsai-q1", "wrong model alias");
  invariant(value.model.name === "Bonsai-27B-Q1_0.gguf", "wrong model name");
  for (const field of [
    "artifact_id",
    "artifact_sha256",
    "manifest_root",
    "capsule_id",
    "execution_profile_id",
    "query_policy_id",
    "availability_certificate_id",
    "fund_profile_id",
  ]) {
    requireHex32(value.model[field], `model ${field}`);
  }

  invariant(
    Array.isArray(value.activity) && value.activity.length > 0 && value.activity.length <= 32,
    "neural activity must contain 1..32 finalized runs",
  );
  value.activity.forEach((inference, index) => validateInference(inference, `activity ${index}`));
  for (let index = 1; index < value.activity.length; index += 1) {
    invariant(
      value.activity[index - 1].sequence > value.activity[index].sequence,
      "neural activity sequences are not newest-first",
    );
    invariant(
      value.activity[index - 1].included_height >= value.activity[index].included_height,
      "neural activity heights are not newest-first",
    );
  }
  for (const field of ["transaction_id", "job_id", "receipt_id", "settlement_id"]) {
    invariant(
      new Set(value.activity.map((inference) => inference[field])).size === value.activity.length,
      `neural activity contains a duplicate ${field}`,
    );
  }

  invariant(isRecord(value.topology), "topology pins are missing");
  const topology = value.topology;
  invariant(
    topology.custody_positions === 12
      && topology.executor_profiles === 8
      && topology.selected_executors === 3
      && topology.reconstruction_threshold === 8,
    "topology pins are invalid",
  );
  invariant(Array.isArray(value.indexer_origins) && value.indexer_origins.length === 3, "manifest must name three indexers");
  invariant(value.indexer_origins.every((origin) => /^https:\/\/[a-z0-9.-]+$/.test(origin)), "manifest indexer origin is invalid");
  invariant(Array.isArray(value.disclosures) && value.disclosures.length >= 3, "manifest disclosures are incomplete");
  return { ...value, inference: value.activity[0] };
}

export function validateGatewayHealth(value, manifest) {
  invariant(isRecord(value), "gateway health is not an object");
  invariant(value.schema === "noos/wwm-public-testnet-gateway/v1", "wrong gateway schema");
  invariant(value.environment === "public-testnet", "wrong gateway environment");
  invariant(value.production === false && value.promotion_effect === "NONE", "gateway is not fail-closed");
  invariant(value.status === "ok" && value.node_source === "primary", "gateway primary node is not healthy");
  invariant(value.chain_id === manifest.chain_id && value.genesis_hash === manifest.genesis_hash, "gateway chain identity mismatch");
  invariant(isRecord(value.unsafe_head) && isUint(value.unsafe_head.height), "gateway head is malformed");
  invariant(isRecord(value.finalized) && isUint(value.finalized.epoch), "gateway finality is malformed");
  requireHex32(value.unsafe_head.hash, "gateway head hash");
  requireHex32(value.finalized.hash, "gateway finalized hash");
  return value;
}

export function validateModelResolution(value, manifest) {
  invariant(isRecord(value), "model resolution is not an object");
  invariant(value.schema === "noos/finalized-model-resolution/v1", "wrong model resolution schema");
  invariant(value.trust_scope === "LOCAL_FULL_NODE_FINALIZED_STATE", "wrong model trust scope");
  invariant(value.chain_id === manifest.chain_id && value.genesis_hash === manifest.genesis_hash, "model chain identity mismatch");
  invariant(value.selector === manifest.model.alias, "model selector mismatch");
  invariant(value.registration_state === "ACTIVE_TESTNET" && value.control_mode === "TESTNET", "model is not active testnet state");
  invariant(value.production_effect === "NONE" && value.weights_on_chain === false, "model resolution overclaims production or on-chain weights");
  invariant(value.proofs_verified === true && isUint(value.proof_count) && value.proof_count > 0, "model proofs are not verified");
  invariant(isUint(value.finalized_height), "model finalized height is invalid");
  requireHex32(value.finalized_hash, "model finalized hash");
  requireHex32(value.objects_root, "model objects root");
  requireHexBytes(value.canonical_resolution_body_hex, "canonical model resolution");
  requireHexBytes(value.finality_evidence_hex, "model finality evidence");

  const active = value.active;
  invariant(isRecord(active), "active model graph is missing");
  const exact = {
    artifact_id: manifest.model.artifact_id,
    artifact_sha256: manifest.model.artifact_sha256,
    manifest_root: manifest.model.manifest_root,
    capsule_id: manifest.model.capsule_id,
    execution_profile_id: manifest.model.execution_profile_id,
    query_policy_id: manifest.model.query_policy_id,
    availability_certificate_id: manifest.model.availability_certificate_id,
    fund_profile_id: manifest.model.fund_profile_id,
    model_name: manifest.model.name,
  };
  for (const [field, expected] of Object.entries(exact)) {
    invariant(active[field] === expected, `active model ${field} mismatch`);
  }
  invariant(active.availability_claim === "TESTNET_FIXTURE_ONLY", "model availability claim is not explicit");
  invariant(active.certificate_availability_state === 0, "model availability certificate is not live");
  invariant(Array.isArray(active.custodian_profiles) && active.custodian_profiles.length === manifest.topology.custody_positions, "custody topology mismatch");
  invariant(Array.isArray(active.executor_profile_ids) && active.executor_profile_ids.length === manifest.topology.executor_profiles, "executor topology mismatch");
  invariant(active.custodian_profiles.every((profile) => isRecord(profile) && HEX32.test(profile.profile_id) && HEX32.test(profile.endpoint_root) && profile.status === 0), "custody profile is malformed or inactive");
  invariant(active.executor_profile_ids.every((profileId) => HEX32.test(profileId)), "executor profile identity is malformed");
  return value;
}

export function validateWwmRecord(value, kind, identifier) {
  invariant(isRecord(value), `${kind} proof is not an object`);
  invariant(value.schema === "noos/finalized-wwm-record/v1", `wrong finalized ${kind} schema`);
  invariant(value.trust_scope === "LOCAL_FULL_NODE_FINALIZED_STATE", `wrong ${kind} trust scope`);
  invariant(value.kind === kind && value.id === identifier, `${kind} identity mismatch`);
  invariant(isUint(value.finalized_height), `${kind} finalized height is invalid`);
  requireHex32(value.finalized_hash, `${kind} finalized hash`);
  requireHex32(value.objects_root, `${kind} objects root`);
  requireHexBytes(value.canonical_record_hex, `canonical ${kind} record`);
  requireHexBytes(value.proof_hex, `${kind} sparse-Merkle proof`);
  invariant(isRecord(value.record), `${kind} record is missing`);
  return value;
}

export function validateLifecycle(records, manifest) {
  invariant(isRecord(records), "WWM lifecycle proofs are missing");
  const job = validateWwmRecord(records.job, "job", manifest.inference.job_id);
  const receipt = validateWwmRecord(records.receipt, "receipt", manifest.inference.receipt_id);
  const settlement = validateWwmRecord(records.settlement, "settlement", manifest.inference.settlement_id);
  const jobRecord = job.record;
  const receiptRecord = receipt.record;
  const settlementRecord = settlement.record;

  invariant(jobRecord.job_id === manifest.inference.job_id, "job record identity mismatch");
  invariant(jobRecord.capsule_id === manifest.model.capsule_id, "job capsule mismatch");
  invariant(jobRecord.execution_profile_id === manifest.model.execution_profile_id, "job execution profile mismatch");
  invariant(jobRecord.availability_certificate_id === manifest.model.availability_certificate_id, "job availability certificate mismatch");
  invariant(jobRecord.fund_profile_id === manifest.model.fund_profile_id, "job fund profile mismatch");

  invariant(receiptRecord.job_id === manifest.inference.job_id, "receipt job mismatch");
  invariant(receiptRecord.receipt_id === manifest.inference.receipt_id, "receipt identity mismatch");
  invariant(receiptRecord.capsule_id === manifest.model.capsule_id, "receipt capsule mismatch");
  invariant(receiptRecord.artifact_id === manifest.model.artifact_id, "receipt artifact mismatch");
  invariant(receiptRecord.execution_profile_id === manifest.model.execution_profile_id, "receipt execution profile mismatch");
  invariant(receiptRecord.output_root === manifest.inference.output_root, "receipt output root mismatch");
  invariant(receiptRecord.token_history_root === manifest.inference.token_history_root, "receipt token history mismatch");
  invariant(receiptRecord.terminal_code === 0, "receipt is not complete");
  invariant(isUint(receiptRecord.anchor_height) && HEX32.test(receiptRecord.anchor_block), "receipt anchor is malformed");

  invariant(settlementRecord.job_id === manifest.inference.job_id, "settlement job mismatch");
  invariant(settlementRecord.receipt_id === manifest.inference.receipt_id, "settlement receipt mismatch");
  invariant(settlementRecord.settlement_id === manifest.inference.settlement_id, "settlement identity mismatch");
  invariant(settlementRecord.fund_profile_id === manifest.model.fund_profile_id, "settlement fund profile mismatch");
  invariant(isUint(settlementRecord.settled_height) && settlementRecord.settled_height >= receiptRecord.anchor_height, "settlement height is invalid");
  return records;
}

export function validateIndexedTransaction(value, manifest) {
  invariant(isRecord(value), "indexed transaction is not an object");
  invariant(value.txid === manifest.inference.transaction_id, "indexed transaction identity mismatch");
  invariant(value.state === "INCLUDED" || value.state === "FINALIZED", "transaction is not included");
  invariant(isRecord(value.inclusion), "transaction inclusion is missing");
  requireHex32(value.inclusion.hash, "transaction block hash");
  invariant(/^(0|[1-9][0-9]*)$/.test(value.inclusion.height), "transaction height is not canonical");
  invariant(/^(0|[1-9][0-9]*)$/.test(value.inclusion.index), "transaction index is not canonical");
  invariant(/^(0|[1-9][0-9]*)$/.test(value.fee), "transaction fee is not canonical");
  invariant(value.inclusion.hash === manifest.inference.included_block, "transaction block mismatch");
  invariant(value.inclusion.height === String(manifest.inference.included_height), "transaction height mismatch");
  invariant(value.fee === manifest.inference.fee_charged, "transaction fee mismatch");
  return value;
}

export async function verifyMonitorEnvelope(value, expectedSignerKeyId) {
  invariant(isRecord(value), "network status sample is not an object");
  invariant(value.schema === "noos/wwm-public-testnet-monitor-sample/v1", "wrong network status schema");
  invariant(value.environment === "public-testnet" && value.production === false && value.promotion_effect === "NONE", "network status is not fail-closed testnet evidence");
  requireHex32(value.sample_id, "network status sample ID");
  requireHex32(value.signer_key_id, "network status signer ID");
  if (expectedSignerKeyId !== undefined) invariant(value.signer_key_id === expectedSignerKeyId, "unexpected network monitor signer");
  const publicKey = base64ToBytes(value.public_key_base64, "monitor public key");
  const signature = base64ToBytes(value.signature_base64, "monitor signature");
  invariant(publicKey.length === 32 && signature.length === 64, "monitor key or signature length is invalid");
  const keyId = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey)));
  invariant(keyId === value.signer_key_id, "monitor signer key ID mismatch");
  const payload = Object.fromEntries(
    Object.entries(value).filter(([key]) => !OMITTED_MONITOR_FIELDS.has(key)),
  );
  const message = concatBytes(MONITOR_DOMAIN, new TextEncoder().encode(canonicalJson(payload)));
  const sampleId = bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", message)));
  invariant(sampleId === value.sample_id, "monitor sample ID mismatch");
  const imported = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  invariant(await crypto.subtle.verify({ name: "Ed25519" }, imported, signature, message), "monitor signature is invalid");
  invariant(Array.isArray(value.checks), "network status checks are missing");
  return value;
}

export function findCheck(sample, name) {
  const check = sample.checks.find((candidate) => isRecord(candidate) && candidate.name === name);
  invariant(isRecord(check), `network check ${name} is missing`);
  return check;
}

export function validateMonitorReadiness(sample) {
  invariant(sample.status === "ok", "signed network status is not healthy");
  invariant(sample.checks.every((check) => isRecord(check) && check.ok === true), "a signed network check is failing");
  const inference = findCheck(sample, "inference_worker");
  const resolution = findCheck(sample, "model_resolution");
  const coherence = findCheck(sample, "network_coherence");
  invariant(isRecord(inference.detail) && inference.detail.ready === true, "inference worker is not ready");
  invariant(resolution.ok === true && coherence.ok === true, "model resolution or network coherence is failing");
  return sample;
}
