const PROMPT_DOMAIN = "NOOS/WWM/PROMPT-COMMITMENT/V2\0";
const MAX_PROMPT_BYTES = 48_000;
const MAX_OUTPUT_TOKENS = 512;
const PAYMENT_MODES = new Set(["SPONSORED", "PAID"]);
const TERMINAL_EVENT_TYPES = new Set(["receipt.completed"]);
export const BONSAI_HOSTING = Object.freeze({
  artifactId: "d3d1bcf9f704c58c695d7c0837be25a5cfbd7ff71b440bfc9be4a4a46bb528b0",
  manifestRoot: "80f211eb4ebfd26df62bdeac69bc663ca97664eaf179188af78d1288aee42de7",
  runtimeRoot: "690d9bbd8d44631fb971e0b0677e10c8d0bb1e08a743bb720eeaab728e30ba27",
  artifactSha256: "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0",
  sourceBytes: 3_803_452_480,
  encodedBytes: 5_707_063_296,
  shareBytes: 1_047_552,
  stripeCount: 454,
  positionCount: 12,
  dataShards: 8,
  parityShards: 4,
  reconstructionThreshold: 8,
  schedulableMinimum: 9,
});
const RECONSTRUCTION_STATES = new Set(["EMPTY", "VERIFYING", "DOWNLOADING", "RECONSTRUCTING", "READY", "FAILED"]);

export class WwmClientError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "WwmClientError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new WwmClientError(code, message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function requiredString(value, code) {
  if (typeof value !== "string" || value.length === 0) fail(code);
  return value;
}

function hash32(value, code) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) fail(code);
  return value;
}

function decimalId(value, code) {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,19})$/.test(value)) fail(code);
  return value;
}

function compareDecimalIds(left, right) {
  if (left.length !== right.length) return left.length < right.length ? -1 : 1;
  return left === right ? 0 : left < right ? -1 : 1;
}

function wholeNumber(value, code) {
  if (!Number.isSafeInteger(value) || value < 0) fail(code);
  return value;
}

function u64Decimal(value, code) {
  const parsed = decimalId(value, code);
  if (BigInt(parsed) > 18_446_744_073_709_551_615n) fail(code);
  return parsed;
}

function bytesToHex(bytes) {
  let output = "";
  for (const value of bytes) output += value.toString(16).padStart(2, "0");
  return output;
}

function randomHex(cryptoImpl, bytes) {
  const value = new Uint8Array(bytes);
  cryptoImpl.getRandomValues(value);
  return bytesToHex(value);
}

function joinBytes(...parts) {
  const length = parts.reduce((total, part) => total + part.byteLength, 0);
  const joined = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    joined.set(part, offset);
    offset += part.byteLength;
  }
  return joined;
}

export async function createPromptCommitment(prompt, cryptoImpl = globalThis.crypto, suppliedSalt) {
  if (!cryptoImpl?.subtle || typeof cryptoImpl.getRandomValues !== "function") fail("secure_crypto_unavailable");
  if (typeof prompt !== "string") fail("invalid_prompt");
  const normalized = prompt.replace(/\r\n/g, "\n").trim();
  const promptBytes = new TextEncoder().encode(normalized);
  if (promptBytes.byteLength === 0) fail("empty_prompt");
  if (promptBytes.byteLength > MAX_PROMPT_BYTES) fail("prompt_too_large");
  const salt = suppliedSalt === undefined
    ? (() => { const bytes = new Uint8Array(32); cryptoImpl.getRandomValues(bytes); return bytes; })()
    : suppliedSalt;
  if (!(salt instanceof Uint8Array) || salt.byteLength !== 32) fail("invalid_prompt_salt");
  const domain = new TextEncoder().encode(PROMPT_DOMAIN);
  const digest = await cryptoImpl.subtle.digest("SHA-256", joinBytes(domain, salt, promptBytes));
  return Object.freeze({
    commitment: bytesToHex(new Uint8Array(digest)),
    salt: bytesToHex(salt),
    normalizedPrompt: normalized,
    promptBytes: promptBytes.byteLength,
  });
}

async function jsonResponse(fetchImpl, url, options = {}) {
  const response = await fetchImpl(url, {
    ...options,
    headers: {
      Accept: "application/vnd.noos.wwm.v2+json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers ?? {}),
    },
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const code = isRecord(payload) && typeof payload.code === "string" ? payload.code : `http_${response.status}`;
    fail(code, isRecord(payload) && typeof payload.message === "string" ? payload.message : code);
  }
  if (!isRecord(payload)) fail("malformed_response");
  return payload;
}

function verifyExpectedIdentity(verified, expected) {
  if (!isRecord(verified)) fail("invalid_resolution_proof");
  const chainId = hash32(verified.chain_id, "invalid_resolution_chain_id");
  const genesisHash = hash32(verified.genesis_hash, "invalid_resolution_genesis_hash");
  if (expected?.chain_id && chainId !== expected.chain_id) fail("wrong_chain_identity");
  if (expected?.genesis_hash && genesisHash !== expected.genesis_hash) fail("wrong_genesis_identity");
}

export function validateActiveState(payload, verified, expectedIdentity) {
  if (payload.schema !== "noos/wwm-gateway/v2") fail("wrong_api_version");
  if (payload.enabled !== true) fail("admission_disabled");
  verifyExpectedIdentity(verified, expectedIdentity);
  if (!isRecord(payload.resolution) || !isRecord(payload.resolution.active)) fail("missing_active_config");
  const resolution = payload.resolution;
  const activeValue = resolution.active;
  const capsuleId = hash32(activeValue.capsule_id, "invalid_active_capsule");
  hash32(activeValue.execution_profile_id, "invalid_execution_profile");
  hash32(activeValue.query_profile_id, "invalid_query_profile");
  hash32(resolution.pin_id, "invalid_pin_id");
  hash32(resolution.finalized_hash, "invalid_finalized_hash");
  hash32(resolution.objects_root, "invalid_objects_root");
  if (activeValue.activation_state !== "ACTIVE") fail("active_config_not_active");
  if (activeValue.artifact_sha256 !== "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0"
    || activeValue.artifact_length !== 3_803_452_480) {
    fail("wrong_bonsai_artifact");
  }
  if (verified.capsule_id !== capsuleId
    || verified.chain_id !== resolution.chain_id
    || verified.genesis_hash !== resolution.genesis_hash
    || verified.finalized_hash !== resolution.finalized_hash
    || verified.objects_root !== resolution.objects_root) {
    fail("resolution_state_mismatch");
  }
  const candidates = Array.isArray(resolution.candidates) ? resolution.candidates : [];
  for (const candidate of candidates) {
    if (!isRecord(candidate)) fail("invalid_candidate");
    hash32(candidate.capsule_id, "invalid_candidate_capsule");
    if (candidate.activation_state !== "AUTHORIZED_NOT_ACTIVE" || candidate.capsule_id === capsuleId) {
      fail("candidate_dispatchable");
    }
  }
  const candidate = candidates.length === 0 ? null : Object.freeze({ ...candidates[0], dispatchable: false });
  return Object.freeze({
    ...activeValue,
    pin_id: resolution.pin_id,
    resolution_id: resolution.finalized_hash,
    control_state: "ACTIVE",
    dispatchable: true,
    candidate,
  });
}

export function validateHostedModelProof(resolution, verified) {
  if (!isRecord(resolution) || !isRecord(verified) || !isRecord(verified.hosted_model)) {
    fail("missing_hosted_model_proof");
  }
  const hosted = verified.hosted_model;
  const chainId = hash32(verified.chain_id, "invalid_hosted_chain_id");
  const genesisHash = hash32(verified.genesis_hash, "invalid_hosted_genesis_hash");
  const finalizedHash = hash32(verified.finalized_hash, "invalid_hosted_finalized_hash");
  const objectsRoot = hash32(verified.objects_root, "invalid_hosted_objects_root");
  const finalizedHeight = wholeNumber(verified.finalized_height, "invalid_hosted_finalized_height");
  if (finalizedHeight !== resolution.finalized_height) fail("hosted_finalized_height_mismatch");
  if (chainId !== resolution.chain_id
    || genesisHash !== resolution.genesis_hash
    || finalizedHash !== resolution.finalized_hash
    || objectsRoot !== resolution.objects_root) {
    fail("hosted_resolution_state_mismatch");
  }
  const capsuleId = hash32(hosted.capsule_id, "invalid_hosted_capsule");
  const artifactId = hash32(hosted.artifact_id, "invalid_hosted_artifact");
  const manifestRoot = hash32(hosted.manifest_root, "invalid_hosted_manifest");
  const runtimeRoot = hash32(hosted.runtime_root, "invalid_hosted_runtime");
  const certificateId = hash32(hosted.availability_certificate_id, "invalid_hosted_certificate");
  const artifactSha256 = hash32(hosted.artifact_sha256, "invalid_hosted_artifact_sha256");
  if (capsuleId !== verified.capsule_id
    || artifactId !== BONSAI_HOSTING.artifactId
    || manifestRoot !== BONSAI_HOSTING.manifestRoot
    || runtimeRoot !== BONSAI_HOSTING.runtimeRoot
    || artifactSha256 !== BONSAI_HOSTING.artifactSha256
    || hosted.source_bytes !== BONSAI_HOSTING.sourceBytes
    || hosted.encoded_bytes !== BONSAI_HOSTING.encodedBytes
    || hosted.share_bytes !== BONSAI_HOSTING.shareBytes
    || hosted.stripe_count !== BONSAI_HOSTING.stripeCount
    || hosted.position_count !== BONSAI_HOSTING.positionCount
    || hosted.data_shards !== BONSAI_HOSTING.dataShards
    || hosted.parity_shards !== BONSAI_HOSTING.parityShards
    || hosted.reconstruction_threshold !== BONSAI_HOSTING.reconstructionThreshold
    || hosted.schedulable_minimum !== BONSAI_HOSTING.schedulableMinimum
    || hosted.publisher_or_gateway_fallback !== false) {
    fail("wrong_bonsai_hosting_proof");
  }
  if (artifactSha256 !== resolution.active.artifact_sha256
    || hosted.source_bytes !== resolution.active.artifact_length) {
    fail("hosted_artifact_state_mismatch");
  }
  const issuedHeight = wholeNumber(hosted.certificate_issued_height, "invalid_certificate_issued_height");
  const validUntilHeight = u64Decimal(hosted.certificate_valid_until_height, "invalid_certificate_horizon");
  if (issuedHeight > finalizedHeight || BigInt(validUntilHeight) < BigInt(finalizedHeight)) {
    fail("expired_hosted_certificate");
  }
  if (!Array.isArray(hosted.custodians) || hosted.custodians.length !== BONSAI_HOSTING.positionCount) {
    fail("invalid_custodian_map");
  }
  const profiles = new Set();
  const endpoints = new Set();
  const custodians = hosted.custodians.map((row, position) => {
    if (!isRecord(row) || row.position !== position || row.live_at_certificate !== true) {
      fail("invalid_custodian_position");
    }
    const profileId = hash32(row.profile_id, "invalid_custodian_profile");
    const endpointRoot = hash32(row.endpoint_root, "invalid_custodian_endpoint");
    const regionId = hash32(row.region_id, "invalid_custodian_region");
    const providerRoot = hash32(row.provider_root, "invalid_custodian_provider");
    const operatorId = hash32(row.operator_id, "invalid_custodian_operator");
    const asn = wholeNumber(row.asn, "invalid_custodian_asn");
    if (asn === 0 || asn > 4_294_967_295 || profiles.has(profileId) || endpoints.has(endpointRoot)) {
      fail("duplicate_or_invalid_custodian");
    }
    profiles.add(profileId);
    endpoints.add(endpointRoot);
    return Object.freeze({
      position,
      profile_id: profileId,
      endpoint_root: endpointRoot,
      region_id: regionId,
      provider_root: providerRoot,
      operator_id: operatorId,
      asn,
      live_at_certificate: true,
    });
  });
  const reconstruction = hosted.reconstruction;
  if (!isRecord(reconstruction)
    || !RECONSTRUCTION_STATES.has(reconstruction.state)
    || reconstruction.source !== "FINALIZED_CUSTODIANS"
    || reconstruction.evidence_verified !== true
    || reconstruction.fallback_used !== false
    || reconstruction.total_bytes !== BONSAI_HOSTING.sourceBytes) {
    fail("invalid_reconstruction_evidence");
  }
  const verifiedBytes = wholeNumber(reconstruction.verified_bytes, "invalid_reconstruction_progress");
  if (verifiedBytes > reconstruction.total_bytes) fail("invalid_reconstruction_progress");
  if (reconstruction.state === "READY"
    && (verifiedBytes !== reconstruction.total_bytes
      || reconstruction.installed_sha256 !== BONSAI_HOSTING.artifactSha256)) {
    fail("invalid_ready_artifact");
  }
  return Object.freeze({
    chain_id: chainId,
    genesis_hash: genesisHash,
    finalized_height: finalizedHeight,
    finalized_hash: finalizedHash,
    objects_root: objectsRoot,
    capsule_id: capsuleId,
    artifact_id: artifactId,
    manifest_root: manifestRoot,
    runtime_root: runtimeRoot,
    artifact_sha256: artifactSha256,
    source_bytes: hosted.source_bytes,
    encoded_bytes: hosted.encoded_bytes,
    share_bytes: hosted.share_bytes,
    stripe_count: hosted.stripe_count,
    position_count: hosted.position_count,
    data_shards: hosted.data_shards,
    parity_shards: hosted.parity_shards,
    reconstruction_threshold: hosted.reconstruction_threshold,
    schedulable_minimum: hosted.schedulable_minimum,
    availability_certificate_id: certificateId,
    certificate_issued_height: issuedHeight,
    certificate_valid_until_height: validUntilHeight,
    custodians: Object.freeze(custodians),
    reconstruction: Object.freeze({ ...reconstruction, verified_bytes: verifiedBytes }),
    publisher_or_gateway_fallback: false,
    ready: reconstruction.state === "READY",
  });
}

function validateQuote(quote, request, active) {
  hash32(quote.quote_id, "invalid_quote_id");
  if (quote.schema !== "noos/wwm-quote/v2"
    || quote.request_id !== request.request_id
    || quote.pin_id !== active.pin_id
    || quote.capsule_id !== active.capsule_id
    || quote.execution_profile_id !== active.execution_profile_id
    || quote.query_profile_id !== active.query_profile_id
    || quote.prompt_commitment !== request.prompt_commitment
    || quote.input_tokens !== request.input_tokens
    || quote.maximum_output_tokens !== request.maximum_output_tokens
    || quote.payment_mode !== request.payment.mode
    || (request.payment.mode === "PAID" && quote.payment_reference !== request.payment.authorization)
    || (request.payment.mode === "SPONSORED"
      && (typeof quote.payment_reference !== "string" || quote.payment_reference.length === 0))) {
    fail("quote_binding_mismatch");
  }
  if (!Number.isSafeInteger(quote.maximum_fee_micro_noos) || quote.maximum_fee_micro_noos < 0
    || !Number.isSafeInteger(quote.expires_at_height) || quote.expires_at_height < 1) {
    fail("invalid_quote_bounds");
  }
  requiredString(quote.signature, "missing_quote_signature");
  return quote;
}

function validatePayment(payment) {
  if (!isRecord(payment) || !PAYMENT_MODES.has(payment.mode)) fail("invalid_payment_mode");
  if (payment.mode === "SPONSORED") {
    if (typeof payment.authorization !== "string") fail("invalid_sponsor_authorization");
    return;
  }
  if (typeof payment.authorization !== "string" || payment.authorization.trim().length === 0) {
    fail("missing_escrow_authorization");
  }
}

export function parseSseText(text, carry = "") {
  const combined = carry + text.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  const blocks = combined.split("\n\n");
  const remainder = blocks.pop() ?? "";
  const events = [];
  for (const block of blocks) {
    if (!block || block.startsWith(":")) continue;
    let id = null;
    let name = "message";
    const data = [];
    for (const line of block.split("\n")) {
      if (line.startsWith(":")) continue;
      const separator = line.indexOf(":");
      const field = separator < 0 ? line : line.slice(0, separator);
      const value = separator < 0 ? "" : line.slice(separator + 1).replace(/^ /, "");
      if (field === "id") id = value;
      else if (field === "event") name = value;
      else if (field === "data") data.push(value);
    }
    if (id === null || data.length === 0) fail("malformed_sse_event");
    decimalId(id, "invalid_sse_event_id");
    let payload;
    try { payload = JSON.parse(data.join("\n")); } catch { fail("malformed_sse_json"); }
    if (!isRecord(payload)) fail("malformed_sse_json");
    events.push({ id, name, payload });
  }
  return { events, remainder };
}

export class WwmV2Client {
  constructor({
    baseUrl = "/api/wwm/v2",
    expectedIdentity,
    verifier,
    fetchImpl = globalThis.fetch,
    cryptoImpl = globalThis.crypto,
  } = {}) {
    if (typeof fetchImpl !== "function") fail("fetch_unavailable");
    if (!verifier || typeof verifier.verifyResolution !== "function"
      || typeof verifier.verifyQuote !== "function"
      || typeof verifier.verifyStreamEvent !== "function"
      || typeof verifier.verifyReceipt !== "function") {
      fail("proof_verifier_required");
    }
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.expectedIdentity = expectedIdentity ?? null;
    this.verifier = verifier;
    this.fetchImpl = fetchImpl;
    this.cryptoImpl = cryptoImpl;
    this.state = null;
    this.active = null;
    this.hosted = null;
  }

  async loadState() {
    const payload = await jsonResponse(this.fetchImpl, `${this.baseUrl}/state`);
    const verified = await this.verifier.verifyResolution(payload.resolution);
    if (!verified) fail("invalid_resolution_proof");
    const active = validateActiveState(payload, verified, this.expectedIdentity);
    this.hosted = validateHostedModelProof(payload.resolution, verified);
    this.active = Object.freeze({ ...active, dispatchable: this.hosted.ready });
    this.state = Object.freeze(payload);
    return Object.freeze({
      state: this.state,
      active: this.active,
      candidate: this.active.candidate,
      hosted: this.hosted,
    });
  }

  async quote(prompt, {
    paymentMode = "SPONSORED",
    paymentAuthorization,
    maximumOutputTokens = 256,
    inputTokens,
    requestId,
    clientNonce,
  } = {}) {
    if (!this.active?.dispatchable) fail("state_not_loaded");
    if (!PAYMENT_MODES.has(paymentMode)) fail("invalid_payment_mode");
    if (!Number.isInteger(maximumOutputTokens) || maximumOutputTokens < 1 || maximumOutputTokens > MAX_OUTPUT_TOKENS) {
      fail("invalid_output_limit");
    }
    const commitment = await createPromptCommitment(prompt, this.cryptoImpl);
    const request = {
      request_id: requestId ?? randomHex(this.cryptoImpl, 16),
      pin_id: this.active.pin_id,
      capsule_id: this.active.capsule_id,
      execution_profile_id: this.active.execution_profile_id,
      query_profile_id: this.active.query_profile_id,
      prompt_commitment: commitment.commitment,
      input_tokens: inputTokens ?? Math.max(1, Math.ceil([...commitment.normalizedPrompt].length / 4)),
      maximum_output_tokens: maximumOutputTokens,
      payment: { mode: paymentMode, authorization: paymentAuthorization ?? "" },
      client_nonce: clientNonce ?? randomHex(this.cryptoImpl, 32),
    };
    const quote = await jsonResponse(this.fetchImpl, `${this.baseUrl}/quotes`, {
      method: "POST",
      body: JSON.stringify(request),
    });
    validateQuote(quote, request, this.active);
    if (!(await this.verifier.verifyQuote(quote, this.active))) fail("invalid_quote_signature");
    return Object.freeze({ quote, request, commitment });
  }

  async submit({ quote, request, commitment }, idempotencyKey) {
    if (!this.active?.dispatchable) fail("state_not_loaded");
    validateQuote(quote, request, this.active);
    if (quote.capsule_id !== this.active.capsule_id) fail("candidate_dispatch_forbidden");
    validatePayment(request.payment);
    const key = idempotencyKey ?? randomHex(this.cryptoImpl, 16);
    const body = {
      quote_id: quote.quote_id,
      prompt: commitment.normalizedPrompt,
      prompt_commitment: commitment.commitment,
      prompt_salt: commitment.salt,
    };
    const job = await jsonResponse(this.fetchImpl, `${this.baseUrl}/jobs`, {
      method: "POST",
      headers: { "Idempotency-Key": key },
      body: JSON.stringify(body),
    });
    hash32(job.job_id, "invalid_job_id");
    if (job.schema !== "noos/wwm-job/v2"
      || typeof job.replayed !== "boolean"
      || !["QUEUED", "RUNNING", "CANCEL_REQUESTED", "COMPLETED", "CANCELLED", "FAILED", "NO_QUORUM"].includes(job.status)) {
      fail("job_binding_mismatch");
    }
    return Object.freeze({ job, idempotencyKey: key });
  }

  async stream(jobId, onEvent, { signal, maxReconnects = 3 } = {}) {
    hash32(jobId, "invalid_job_id");
    if (!this.active) fail("state_not_loaded");
    let lastEventId = null;
    let reconnects = 0;
    for (;;) {
      let response;
      try {
        response = await this.fetchImpl(`${this.baseUrl}/jobs/${encodeURIComponent(jobId)}/stream`, {
          method: "GET",
          signal,
          headers: {
            Accept: "text/event-stream",
            ...(lastEventId === null ? {} : { "Last-Event-ID": lastEventId }),
          },
        });
      } catch (error) {
        if (signal?.aborted) throw error;
        if (reconnects >= maxReconnects) fail("stream_reconnect_exhausted");
        reconnects += 1;
        continue;
      }
      if (!response.ok || !response.body) fail(`stream_http_${response.status}`);
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let carry = "";
      let terminal = false;
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        const parsed = parseSseText(decoder.decode(value, { stream: true }), carry);
        carry = parsed.remainder;
        for (const event of parsed.events) {
          if (lastEventId !== null && compareDecimalIds(event.id, lastEventId) <= 0) fail("non_monotonic_sse_event");
          if (!Number.isSafeInteger(event.payload.id)
            || String(event.payload.id) !== event.id
            || event.payload.type !== event.name
            || !isRecord(event.payload.data)) {
            fail("stream_identity_mismatch");
          }
          if (!(await this.verifier.verifyStreamEvent(event, this.active, jobId))) fail("invalid_stream_signature");
          lastEventId = event.id;
          if (event.payload.type === "receipt.completed") {
            if (!(await this.verifier.verifyReceipt(event.payload.data, this.active))) fail("invalid_receipt_proof");
          }
          await onEvent(event);
          if (TERMINAL_EVENT_TYPES.has(event.payload.type)) {
            terminal = true;
            break;
          }
        }
        if (terminal) {
          await reader.cancel().catch(() => {});
          return lastEventId;
        }
      }
      if (carry.trim().length !== 0) fail("truncated_sse_event");
      if (reconnects >= maxReconnects) fail("stream_reconnect_exhausted");
      reconnects += 1;
    }
  }

  async cancel(jobId, reason = "USER_REQUESTED") {
    hash32(jobId, "invalid_job_id");
    const result = await jsonResponse(this.fetchImpl, `${this.baseUrl}/jobs/${encodeURIComponent(jobId)}/cancel`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    });
    if (result.job_id !== jobId || !["CANCEL_REQUESTED", "CANCELLED", "COMPLETED", "FAILED", "NO_QUORUM"].includes(result.status)) {
      fail("invalid_cancel_response");
    }
    return result;
  }

  async receipt(jobId) {
    hash32(jobId, "invalid_job_id");
    const result = await jsonResponse(this.fetchImpl, `${this.baseUrl}/jobs/${encodeURIComponent(jobId)}/receipt`);
    if (result.job_id !== jobId) fail("receipt_job_mismatch");
    if (!(await this.verifier.verifyReceipt(result, this.active))) fail("invalid_receipt_proof");
    return result;
  }
}

export const WWM_LIMITS = Object.freeze({ MAX_PROMPT_BYTES, MAX_OUTPUT_TOKENS });
