// Experimental noos/wwm-web-capacity/v1 browser advisory cache client.
// This module is storage-and-opt-in-repair only. It never enters production
// custody, never signs certificates, never earns rewards, and never runs
// inference, training, mining, or any downloaded code. Constructing it has
// zero side effects: no fetch, no storage estimation or allocation, no
// hashing, no heartbeat, and no upload happen before an explicit opt-in call.
import { BONSAI_HOSTING } from "./client.mjs";

export const WEB_CAPACITY = Object.freeze({
  schema: "noos/wwm-web-capacity/v1",
  consentVersion: "wwm-web-capacity-consent/v1",
  cacheDirectory: "noos-wwm-cache-v1",
  shareBytes: BONSAI_HOSTING.shareBytes,
  quotaChoicesShares: Object.freeze([16, 64, 256]),
  quotaFractionPercent: 10,
  maxAssignmentRows: 256,
  maxJsonBodyBytes: 65_536,
  maxDailyEgressBytes: 256 * BONSAI_HOSTING.shareBytes,
  downloadConcurrency: 2,
  browserExecution: "STORAGE_AND_OPT_IN_REPAIR_ONLY",
  participantClass: "BROWSER_ADVISORY_CACHE",
  admissionClass: "ChorusAdvisory",
  assignmentDomain: "NOOS/SIG/WWM-WEB-ASSIGNMENT/V1",
  restoreDomain: "NOOS/SIG/WWM-WEB-RESTORE-TASK/V1",
  chainBinding: Object.freeze({
    artifact_id: BONSAI_HOSTING.artifactId,
    manifest_root: BONSAI_HOSTING.manifestRoot,
  }),
});

export class WebCapacityError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "WebCapacityError";
    this.code = code;
  }
}

function fail(code, message) {
  throw new WebCapacityError(code, message);
}

function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hash32(value, code) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/.test(value)) fail(code);
  return value;
}

function wholeNumber(value, code) {
  if (!Number.isSafeInteger(value) || value < 0) fail(code);
  return value;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function canonicalHttpsOrigin(value, code = "invalid_canonical_origin") {
  if (typeof value !== "string" || value.length > 253) fail(code);
  let parsed;
  try { parsed = new URL(value); } catch { fail(code); }
  if (parsed.protocol !== "https:" || parsed.origin !== value || value.endsWith("/")) fail(code);
  return value;
}

// RFC 8785 canonical JSON for the bounded value domain used by this contract:
// null, booleans, strings, safe integers, arrays, and plain objects.
export function canonicalJson(value) {
  if (value === null || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) fail("non_canonical_number");
    return Object.is(value, -0) ? "0" : String(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  fail("non_canonical_value");
}

export async function verifySignedRecord(record, expectedDomain, expectedKeyHex, cryptoImpl = globalThis.crypto) {
  if (!cryptoImpl?.subtle) fail("secure_crypto_unavailable");
  if (!isRecord(record) || !isRecord(record.signature)) fail("missing_record_signature");
  const signature = record.signature;
  if (signature.suite !== "Ed25519") fail("wrong_signature_suite");
  if (signature.domain !== expectedDomain) fail("wrong_signature_domain");
  hash32(signature.public_key, "invalid_signature_key");
  if (signature.public_key !== expectedKeyHex) fail("wrong_coordinator_key");
  if (typeof signature.signature !== "string" || !/^[0-9a-f]{128}$/.test(signature.signature)) {
    fail("invalid_signature_encoding");
  }
  const { signature: _omitted, ...unsigned } = record;
  const domainBytes = new TextEncoder().encode(expectedDomain);
  const payloadBytes = new TextEncoder().encode(canonicalJson(unsigned));
  const message = new Uint8Array(domainBytes.byteLength + payloadBytes.byteLength);
  message.set(domainBytes, 0);
  message.set(payloadBytes, domainBytes.byteLength);
  let key;
  try {
    key = await cryptoImpl.subtle.importKey("raw", hexToBytes(signature.public_key), "Ed25519", false, ["verify"]);
  } catch {
    fail("ed25519_unavailable");
  }
  const valid = await cryptoImpl.subtle.verify("Ed25519", key, hexToBytes(signature.signature), message);
  if (valid !== true) fail("invalid_record_signature");
  return true;
}

// effective_bytes =
//   floor(min(user_limit, 10% * max(0, quota - usage)) / share_bytes) * share_bytes
// computed exactly in integers: min(10*user_limit, free) / (10*share_bytes).
export function computeEffectiveBytes({ quotaShares, quotaBytes, usageBytes }) {
  if (!WEB_CAPACITY.quotaChoicesShares.includes(quotaShares)) fail("invalid_quota_choice");
  wholeNumber(quotaBytes, "invalid_storage_estimate");
  wholeNumber(usageBytes, "invalid_storage_estimate");
  const userLimitBytes = quotaShares * WEB_CAPACITY.shareBytes;
  const freeBytes = Math.max(0, quotaBytes - usageBytes);
  const effectiveShares = Math.floor(
    Math.min(10 * userLimitBytes, freeBytes) / (10 * WEB_CAPACITY.shareBytes),
  );
  return Object.freeze({
    quotaShares,
    userLimitBytes,
    effectiveShares,
    effectiveBytes: effectiveShares * WEB_CAPACITY.shareBytes,
    participationPossible: effectiveShares >= 1,
  });
}

function validateChainBinding(binding, expected) {
  if (!isRecord(binding)) fail("invalid_chain_binding");
  hash32(binding.chain_id, "invalid_chain_binding");
  hash32(binding.genesis_hash, "invalid_chain_binding");
  hash32(binding.artifact_id, "invalid_chain_binding");
  hash32(binding.manifest_root, "invalid_chain_binding");
  if (binding.artifact_id !== WEB_CAPACITY.chainBinding.artifact_id
    || binding.manifest_root !== WEB_CAPACITY.chainBinding.manifest_root) {
    fail("wrong_artifact_binding");
  }
  if (expected?.chain_id && binding.chain_id !== expected.chain_id) fail("wrong_chain_identity");
  if (expected?.genesis_hash && binding.genesis_hash !== expected.genesis_hash) fail("wrong_genesis_identity");
  return Object.freeze({ ...binding });
}

const EXPERIMENT_STATES = new Set(["LOCAL_FIXTURE", "DEVNET", "PUBLIC_TESTNET_PILOT"]);

export function validateCoordinatorConfig(payload, expectedIdentity) {
  if (!isRecord(payload) || payload.schema !== WEB_CAPACITY.schema
    || payload.record_kind !== "COORDINATOR_CONFIG") {
    fail("wrong_config_schema");
  }
  const chainBinding = validateChainBinding(payload.chain_binding, expectedIdentity);
  const geometry = payload.geometry;
  if (!isRecord(geometry)
    || geometry.source_bytes !== BONSAI_HOSTING.sourceBytes
    || geometry.encoded_bytes !== BONSAI_HOSTING.encodedBytes
    || geometry.stripes !== BONSAI_HOSTING.stripeCount
    || geometry.positions !== BONSAI_HOSTING.positionCount
    || geometry.reconstruction_threshold !== BONSAI_HOSTING.reconstructionThreshold
    || geometry.schedulable_minimum !== BONSAI_HOSTING.schedulableMinimum
    || geometry.share_bytes !== WEB_CAPACITY.shareBytes
    || geometry.position_bytes !== BONSAI_HOSTING.stripeCount * WEB_CAPACITY.shareBytes
    || geometry.coordinate_count !== BONSAI_HOSTING.stripeCount * BONSAI_HOSTING.positionCount) {
    fail("wrong_geometry");
  }
  if (payload.experiment_state === "DISABLED" || payload.experiment_state === "CLOSED") {
    fail("experiment_disabled");
  }
  if (!EXPERIMENT_STATES.has(payload.experiment_state)) fail("unknown_experiment_state");
  const coordinatorKey = hash32(payload.coordinator_key, "invalid_coordinator_key");
  if (!Array.isArray(payload.source_allowlist) || payload.source_allowlist.length > 256) {
    fail("invalid_source_allowlist");
  }
  const allowlist = payload.source_allowlist.map((origin) => canonicalHttpsOrigin(origin, "invalid_source_origin"));
  if (new Set(allowlist).size !== allowlist.length) fail("duplicate_source_origin");
  if (!Array.isArray(payload.quota_choices_shares)
    || payload.quota_choices_shares.length !== 3
    || payload.quota_choices_shares.some((value, index) => value !== WEB_CAPACITY.quotaChoicesShares[index])) {
    fail("wrong_quota_choices");
  }
  const lifecycle = payload.static_cache_lifecycle;
  if (!isRecord(lifecycle)
    || lifecycle.host_refresh_max_seconds !== 60
    || lifecycle.expiry_effect !== "REMOVES_FUTURE_ASSIGNMENTS_ONLY"
    || lifecycle.public_share_license !== "Apache-2.0"
    || lifecycle.cached_bytes_may_remain_public !== true
    || lifecycle.third_party_cache_erasure_available !== false) {
    fail("wrong_cache_lifecycle_disclosure");
  }
  if (payload.production_custody !== false || payload.rewards !== false) fail("production_claims_forbidden");
  if (payload.browser_execution !== WEB_CAPACITY.browserExecution) fail("browser_execution_forbidden");
  return Object.freeze({
    chain_binding: chainBinding,
    experiment_state: payload.experiment_state,
    coordinator_key: coordinatorKey,
    source_allowlist: Object.freeze(allowlist),
    static_cache_lifecycle: Object.freeze({ ...lifecycle }),
    production_custody: false,
    rewards: false,
    browser_execution: WEB_CAPACITY.browserExecution,
  });
}

export function validateBrowserSession(payload, { origin, offer }) {
  if (!isRecord(payload) || payload.schema !== WEB_CAPACITY.schema
    || payload.record_kind !== "BROWSER_SESSION") {
    fail("wrong_session_schema");
  }
  if (payload.participant_class !== WEB_CAPACITY.participantClass
    || payload.admission_class !== WEB_CAPACITY.admissionClass
    || payload.production_custody !== false
    || payload.rewards !== false) {
    fail("session_authority_forbidden");
  }
  if (typeof payload.session_token !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(payload.session_token)) {
    fail("invalid_session_token");
  }
  hash32(payload.participant_id, "invalid_participant_id");
  if (payload.canonical_origin !== origin) fail("session_origin_mismatch");
  if (payload.quota_shares !== offer.quota_shares
    || payload.effective_bytes !== offer.effective_bytes
    || payload.storage_class !== offer.storage_class) {
    fail("session_offer_mismatch");
  }
  if (!isRecord(payload.upload_policy)
    || payload.upload_policy.enabled !== offer.upload_policy.enabled
    || payload.upload_policy.daily_egress_bytes !== offer.upload_policy.daily_egress_bytes) {
    fail("session_upload_policy_mismatch");
  }
  const issuedAt = wholeNumber(payload.issued_at, "invalid_session_horizon");
  const expiresAt = wholeNumber(payload.expires_at, "invalid_session_horizon");
  if (expiresAt <= issuedAt) fail("invalid_session_horizon");
  return Object.freeze({
    session_token: payload.session_token,
    participant_id: payload.participant_id,
    canonical_origin: payload.canonical_origin,
    quota_shares: payload.quota_shares,
    effective_bytes: payload.effective_bytes,
    storage_class: payload.storage_class,
    upload_policy: Object.freeze({ ...payload.upload_policy }),
    issued_at: issuedAt,
    expires_at: expiresAt,
  });
}

function validateShareRow(row, { config, code, requireSourceOrigin = true }) {
  if (!isRecord(row)) fail(code);
  if (!Number.isSafeInteger(row.stripe) || row.stripe < 0 || row.stripe > BONSAI_HOSTING.stripeCount - 1) fail(code);
  if (!Number.isSafeInteger(row.position) || row.position < 0 || row.position > BONSAI_HOSTING.positionCount - 1) fail(code);
  if (row.bytes !== WEB_CAPACITY.shareBytes) fail("wrong_share_length");
  hash32(row.transport_sha256, code);
  hash32(row.protocol_share_digest, code);
  hash32(row.probe_root, code);
  let url;
  try { url = new URL(row.url); } catch { fail(code); }
  if (url.protocol !== "https:") fail("wrong_share_origin");
  // Assignment rows declare source_origin; restore coordinates (InventoryRow)
  // carry only the url and never trigger a download, so no allowlist applies.
  const sourceOrigin = requireSourceOrigin
    ? canonicalHttpsOrigin(row.source_origin, "wrong_share_origin")
    : url.origin;
  if (url.origin !== sourceOrigin) fail("wrong_share_origin");
  if (requireSourceOrigin && !config.source_allowlist.includes(sourceOrigin)) {
    fail("share_origin_not_allowlisted");
  }
  return Object.freeze({ ...row, source_origin: sourceOrigin });
}

export async function validateAssignment(assignment, { config, session, origin, nowSeconds, cryptoImpl }) {
  if (!isRecord(assignment) || assignment.schema !== WEB_CAPACITY.schema
    || assignment.record_kind !== "SHARE_ASSIGNMENT") {
    fail("wrong_assignment_schema");
  }
  hash32(assignment.assignment_id, "invalid_assignment_id");
  if (assignment.participant_id !== session.participant_id) fail("wrong_assignment_participant");
  if (assignment.canonical_origin !== origin) fail("wrong_assignment_origin");
  validateChainBinding(assignment.chain_binding, config.chain_binding);
  const issuedAt = wholeNumber(assignment.issued_at, "invalid_assignment_horizon");
  const expiresAt = wholeNumber(assignment.expires_at, "invalid_assignment_horizon");
  if (issuedAt > nowSeconds || expiresAt <= nowSeconds) fail("assignment_expired");
  if (!Array.isArray(assignment.rows) || assignment.rows.length < 1
    || assignment.rows.length > WEB_CAPACITY.maxAssignmentRows) {
    fail("invalid_assignment_rows");
  }
  if (assignment.rows.length * WEB_CAPACITY.shareBytes > session.effective_bytes) {
    fail("assignment_exceeds_quota");
  }
  const coordinates = new Set();
  const rows = assignment.rows.map((row) => {
    const validated = validateShareRow(row, { config, code: "invalid_assignment_row" });
    const coordinate = `${validated.stripe}:${validated.position}`;
    if (coordinates.has(coordinate)) fail("duplicate_share_coordinate");
    coordinates.add(coordinate);
    return validated;
  });
  await verifySignedRecord(assignment, WEB_CAPACITY.assignmentDomain, config.coordinator_key, cryptoImpl);
  return Object.freeze(rows);
}

export async function validateRestoreTask(task, { config, session, origin, nowSeconds, cryptoImpl }) {
  if (!isRecord(task) || task.schema !== WEB_CAPACITY.schema || task.record_kind !== "RESTORE_TASK") {
    fail("wrong_restore_schema");
  }
  hash32(task.task_id, "invalid_restore_task_id");
  if (task.participant_id !== session.participant_id) fail("wrong_restore_participant");
  if (task.canonical_origin !== origin) fail("wrong_restore_origin");
  validateChainBinding(task.chain_binding, config.chain_binding);
  if (task.expected_bytes !== WEB_CAPACITY.shareBytes) fail("wrong_share_length");
  const issuedAt = wholeNumber(task.issued_at, "invalid_restore_horizon");
  const expiresAt = wholeNumber(task.expires_at, "invalid_restore_horizon");
  if (issuedAt > nowSeconds || expiresAt <= nowSeconds) fail("restore_task_expired");
  const coordinate = validateShareRow(task.coordinate, { config, code: "invalid_restore_coordinate", requireSourceOrigin: false });
  await verifySignedRecord(task, WEB_CAPACITY.restoreDomain, config.coordinator_key, cryptoImpl);
  return Object.freeze({ task_id: task.task_id, coordinate });
}

async function sha256Hex(cryptoImpl, bytes) {
  const digest = await cryptoImpl.subtle.digest("SHA-256", bytes);
  let output = "";
  for (const value of new Uint8Array(digest)) output += value.toString(16).padStart(2, "0");
  return output;
}

async function fetchOneShare(row, { fetchImpl, cryptoImpl, persist, signal }) {
  if (signal?.aborted) return "DOWNLOAD_ABORTED";
  let response;
  try {
    response = await fetchImpl(row.url, {
      method: "GET",
      mode: "cors",
      credentials: "omit",
      redirect: "error",
      cache: "no-store",
      signal,
    });
  } catch {
    return signal?.aborted ? "DOWNLOAD_ABORTED" : "NETWORK_UNAVAILABLE";
  }
  if (response.redirected === true) return "REDIRECT_REJECTED";
  if (typeof response.url === "string" && response.url.length > 0
    && new URL(response.url).origin !== row.source_origin) {
    return "WRONG_ORIGIN";
  }
  if (!response.ok) return "NETWORK_UNAVAILABLE";
  let bytes;
  try {
    bytes = new Uint8Array(await response.arrayBuffer());
  } catch {
    return signal?.aborted ? "DOWNLOAD_ABORTED" : "NETWORK_UNAVAILABLE";
  }
  if (bytes.byteLength !== WEB_CAPACITY.shareBytes) return "WRONG_LENGTH";
  if (await sha256Hex(cryptoImpl, bytes) !== row.transport_sha256) return "WRONG_DIGEST";
  try {
    await persist(row, bytes);
  } catch {
    return "STORAGE_UNAVAILABLE";
  }
  return null;
}

// Downloads assigned shares at a hard concurrency cap of 2. Each share is
// fetched without credentials, rejects redirects and cross-origin answers,
// requires the exact 1,047,552-byte length and transport SHA-256, and is only
// then handed to `persist` for an atomic bytes-plus-metadata write.
export async function downloadShares(rows, {
  fetchImpl = globalThis.fetch,
  cryptoImpl = globalThis.crypto,
  persist,
  signal,
  onProgress,
} = {}) {
  if (typeof persist !== "function") fail("persist_required");
  if (!cryptoImpl?.subtle) fail("secure_crypto_unavailable");
  const stored = [];
  const failed = [];
  let cursor = 0;
  async function lane() {
    for (;;) {
      const index = cursor;
      cursor += 1;
      if (index >= rows.length) return;
      const row = rows[index];
      const code = await fetchOneShare(row, { fetchImpl, cryptoImpl, persist, signal });
      if (code === null) stored.push(row);
      else failed.push({ stripe: row.stripe, position: row.position, code });
      onProgress?.({ stored: stored.length, failed: failed.length, total: rows.length });
    }
  }
  const lanes = Math.min(WEB_CAPACITY.downloadConcurrency, rows.length);
  await Promise.all(Array.from({ length: lanes }, lane));
  return Object.freeze({ stored: Object.freeze(stored), failed: Object.freeze(failed) });
}

export class EgressLedger {
  constructor(capBytes, nowMs) {
    wholeNumber(capBytes, "invalid_egress_cap");
    this.capBytes = capBytes;
    this.usedBytes = 0;
    this.dayKey = EgressLedger.#dayKey(nowMs);
  }

  static #dayKey(nowMs) {
    return new Date(nowMs).toISOString().slice(0, 10);
  }

  #roll(nowMs) {
    const key = EgressLedger.#dayKey(nowMs);
    if (key !== this.dayKey) {
      this.dayKey = key;
      this.usedBytes = 0;
    }
  }

  remaining(nowMs) {
    this.#roll(nowMs);
    return Math.max(0, this.capBytes - this.usedBytes);
  }

  charge(bytes, nowMs) {
    this.#roll(nowMs);
    if (this.usedBytes + bytes > this.capBytes) return false;
    this.usedBytes += bytes;
    return true;
  }
}

export class WebCapacityController {
  constructor({
    baseUrl = "/api/wwm-web-capacity/v1",
    origin,
    fetchImpl,
    cryptoImpl,
    openStore,
    estimateImpl,
    persistImpl,
    pageActive,
    downloader,
    expectedIdentity = null,
    now = Date.now,
  }) {
    // Constructor stores dependencies only. No network, storage, estimation,
    // hashing, worker, or timer activity may happen before optIn().
    if (typeof fetchImpl !== "function") fail("fetch_required");
    if (typeof openStore !== "function") fail("store_factory_required");
    if (typeof estimateImpl !== "function") fail("estimate_required");
    if (typeof pageActive !== "function") fail("page_activity_probe_required");
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.origin = canonicalHttpsOrigin(origin, "invalid_participant_origin");
    this.fetchImpl = fetchImpl;
    this.cryptoImpl = cryptoImpl ?? globalThis.crypto;
    this.openStore = openStore;
    this.estimateImpl = estimateImpl;
    this.persistImpl = persistImpl ?? null;
    this.pageActive = pageActive;
    this.downloader = downloader ?? null;
    this.expectedIdentity = expectedIdentity;
    this.now = now;
    this.config = null;
    this.session = null;
    this.store = null;
    this.egress = null;
    this.paused = false;
    this.abort = null;
    this.uploadedBytes = 0;
  }

  get optedIn() {
    return this.session !== null;
  }

  async #json(method, path, body) {
    const encoded = body === undefined ? undefined : JSON.stringify(body);
    if (encoded !== undefined && new TextEncoder().encode(encoded).byteLength > WEB_CAPACITY.maxJsonBodyBytes) {
      fail("request_body_too_large");
    }
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        mode: "cors",
        credentials: "omit",
        redirect: "error",
        cache: "no-store",
        signal: this.abort?.signal,
        headers: {
          Accept: "application/json",
          ...(encoded === undefined ? {} : { "Content-Type": "application/json" }),
        },
        ...(encoded === undefined ? {} : { body: encoded }),
      });
    } catch (error) {
      if (this.abort?.signal.aborted) fail("request_aborted");
      throw new WebCapacityError("coordinator_unreachable", error instanceof Error ? error.message : "coordinator_unreachable");
    }
    const payload = await response.json().catch(() => ({}));
    if (!response.ok) {
      const code = isRecord(payload) && isRecord(payload.error) && typeof payload.error.code === "string"
        ? payload.error.code
        : `http_${response.status}`;
      fail(code);
    }
    if (!isRecord(payload)) fail("malformed_response");
    return payload;
  }

  // The single explicit consent boundary. Everything with a side effect —
  // config fetch, storage open, quota estimation, offer, session — starts here
  // and nowhere else.
  async optIn({ quotaShares, uploadEnabled = false, dailyEgressBytes = 0 }) {
    if (this.session) fail("already_opted_in");
    if (!this.pageActive()) fail("page_not_active");
    if (uploadEnabled) {
      wholeNumber(dailyEgressBytes, "invalid_egress_cap");
      if (dailyEgressBytes < WEB_CAPACITY.shareBytes || dailyEgressBytes > WEB_CAPACITY.maxDailyEgressBytes) {
        fail("invalid_egress_cap");
      }
    } else {
      dailyEgressBytes = 0;
    }
    this.config = validateCoordinatorConfig(await this.#json("GET", "/config"), this.expectedIdentity);
    this.store = await this.openStore();
    const estimate = await this.estimateImpl();
    const quota = computeEffectiveBytes({
      quotaShares,
      quotaBytes: Math.floor(estimate?.quota ?? 0),
      usageBytes: Math.floor(estimate?.usage ?? 0),
    });
    if (!quota.participationPossible) {
      await this.#abortPartialOptIn(null);
      fail("insufficient_storage_for_one_share");
    }
    const offer = {
      schema: WEB_CAPACITY.schema,
      record_kind: "OFFER_REQUEST",
      canonical_origin: this.origin,
      consent_version: WEB_CAPACITY.consentVersion,
      quota_shares: quotaShares,
      effective_bytes: quota.effectiveBytes,
      storage_class: this.store.storageClass,
      upload_policy: { enabled: uploadEnabled, daily_egress_bytes: dailyEgressBytes },
      page_active: true,
    };
    // From here a coordinator session may exist server-side. Any failure below
    // must roll back local-first (delete the namespace, clear all state), then
    // revoke the partial session best-effort, so "no session, nothing stored"
    // stays truthful even when the coordinator is unreachable.
    const offerPayload = await this.#json("POST", "/offers", offer);
    try {
      const session = validateBrowserSession(offerPayload, { origin: this.origin, offer });
      await this.store.setMeta("session", {
        participant_id: session.participant_id,
        session_token: session.session_token,
        quota_shares: session.quota_shares,
        effective_bytes: session.effective_bytes,
        upload_policy: session.upload_policy,
      });
      this.session = session;
      this.egress = new EgressLedger(session.upload_policy.enabled ? session.upload_policy.daily_egress_bytes : 0, this.now());
      return Object.freeze({
        participantId: session.participant_id,
        storageClass: this.store.storageClass,
        estimatedQuotaBytes: Math.floor(estimate?.quota ?? 0),
        estimatedUsageBytes: Math.floor(estimate?.usage ?? 0),
        userLimitBytes: quota.userLimitBytes,
        effectiveBytes: quota.effectiveBytes,
        effectiveShares: quota.effectiveShares,
        actualStoredBytes: await this.store.usageBytes(),
        uploadEnabled: session.upload_policy.enabled,
        dailyEgressBytes: session.upload_policy.daily_egress_bytes,
      });
    } catch (error) {
      await this.#abortPartialOptIn(offerPayload);
      throw error;
    }
  }

  // Local-first rollback of a failed opt-in: the app-owned namespace and all
  // local state are removed unconditionally; a partial coordinator session is
  // then revoked best-effort, and its failure never blocks the rollback.
  async #abortPartialOptIn(offerPayload) {
    const token = typeof offerPayload?.session_token === "string"
      && /^[A-Za-z0-9_-]{43}$/.test(offerPayload.session_token)
      ? offerPayload.session_token
      : null;
    try { await this.store?.deleteNamespace(); } catch { /* namespace may be gone already */ }
    this.store = null;
    this.session = null;
    this.egress = null;
    if (token) {
      try {
        await this.#json("POST", "/revoke", {
          schema: WEB_CAPACITY.schema,
          record_kind: "REVOCATION_REQUEST",
          session_token: token,
          canonical_origin: this.origin,
          local_deletion_requested: true,
        });
      } catch { /* best effort only */ }
    }
    this.config = null;
  }

  // Repair egress can only be tightened after opt-in. Widening it would need a
  // fresh consent and a fresh offer, so it is intentionally not offered here.
  disableRepair() {
    if (!this.session) fail("not_opted_in");
    this.egress = new EgressLedger(0, this.now());
    this.session = Object.freeze({
      ...this.session,
      upload_policy: Object.freeze({ enabled: false, daily_egress_bytes: 0 }),
    });
  }

  // Storage persistence is a separate, explicit "keep these copies" action —
  // never bundled into opt-in.
  async keepCopies() {
    if (!this.session) fail("not_opted_in");
    if (typeof this.persistImpl !== "function") return "best effort";
    const granted = await this.persistImpl();
    return granted === true ? "persistent" : "best effort";
  }

  async #storedDigests() {
    const shares = await this.store.listShares();
    return shares.slice(0, WEB_CAPACITY.maxAssignmentRows).map((entry) => entry.protocol_share_digest);
  }

  // Outbound polling while the page is active. Never a background service,
  // never assumed reachability. Fails closed with zero network activity when
  // the page is hidden, paused, or not opted in.
  async heartbeat() {
    if (!this.session) fail("not_opted_in");
    if (this.paused) fail("paused");
    if (!this.pageActive()) fail("page_not_active");
    this.abort = new AbortController();
    const request = {
      schema: WEB_CAPACITY.schema,
      record_kind: "HEARTBEAT_REQUEST",
      session_token: this.session.session_token,
      canonical_origin: this.origin,
      page_active: true,
      stored_coordinate_digests: await this.#storedDigests(),
      available_bytes: Math.max(0, this.session.effective_bytes - await this.store.usageBytes()),
    };
    const response = await this.#json("POST", "/heartbeat", request);
    if (response.record_kind !== "HEARTBEAT_RESPONSE") fail("wrong_heartbeat_schema");
    if (response.assignment !== null && response.assignment !== undefined) {
      if (response.restore_task) fail("wrong_heartbeat_schema");
      return this.#handleAssignment(response.assignment);
    }
    if (response.restore_task !== null && response.restore_task !== undefined) {
      return this.#handleRestore(response.restore_task);
    }
    return Object.freeze({ kind: "idle" });
  }

  async #handleAssignment(assignment) {
    const rows = await validateAssignment(assignment, {
      config: this.config,
      session: this.session,
      origin: this.origin,
      nowSeconds: Math.floor(this.now() / 1000),
      cryptoImpl: this.cryptoImpl,
    });
    // A single assignment is bounded by validateAssignment, but distinct
    // coordinates across successive assignments would otherwise accumulate.
    // Re-assigned coordinates already held overwrite idempotently and cost no
    // new bytes; genuinely new coordinates must fit the REMAINING consented
    // capacity or the whole assignment fails closed.
    const held = new Set((await this.store.listShares()).map((entry) => `${entry.stripe}:${entry.position}`));
    const newRows = rows.filter((row) => !held.has(`${row.stripe}:${row.position}`));
    const remaining = Math.max(0, this.session.effective_bytes - await this.store.usageBytes());
    if (newRows.length * WEB_CAPACITY.shareBytes > remaining) fail("assignment_exceeds_quota");
    const run = this.downloader ?? ((assignedRows, options) => downloadShares(assignedRows, {
      ...options,
      fetchImpl: this.fetchImpl,
      cryptoImpl: this.cryptoImpl,
      persist: (row, bytes) => this.store.putShare(row, bytes),
    }));
    const result = await run(rows, { signal: this.abort.signal });
    return Object.freeze({ kind: "assignment", stored: result.stored, failed: result.failed });
  }

  async #handleRestore(task) {
    if (!this.session.upload_policy.enabled) {
      return Object.freeze({ kind: "restore", skipped: "EGRESS_DISABLED" });
    }
    const restore = await validateRestoreTask(task, {
      config: this.config,
      session: this.session,
      origin: this.origin,
      nowSeconds: Math.floor(this.now() / 1000),
      cryptoImpl: this.cryptoImpl,
    });
    const bytes = await this.store.getShare(restore.coordinate);
    if (bytes === null) return Object.freeze({ kind: "restore", skipped: "SHARE_EVICTED" });
    if (bytes.byteLength !== WEB_CAPACITY.shareBytes) {
      return Object.freeze({ kind: "restore", skipped: "WRONG_LENGTH" });
    }
    if (!this.egress.charge(WEB_CAPACITY.shareBytes, this.now())) {
      return Object.freeze({ kind: "restore", skipped: "EGRESS_CAP_EXCEEDED" });
    }
    let response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}/restores/${encodeURIComponent(restore.task_id)}`, {
        method: "PUT",
        mode: "cors",
        credentials: "omit",
        redirect: "error",
        signal: this.abort.signal,
        headers: {
          "Content-Type": "application/octet-stream",
          Authorization: `Bearer ${this.session.session_token}`,
        },
        body: bytes,
      });
    } catch {
      // The charge stands: bytes may have left the device before the failure.
      return Object.freeze({ kind: "restore", skipped: this.abort.signal.aborted ? "UPLOAD_ABORTED" : "NETWORK_UNAVAILABLE" });
    }
    if (!response.ok) return Object.freeze({ kind: "restore", skipped: "UPLOAD_REJECTED" });
    this.uploadedBytes += WEB_CAPACITY.shareBytes;
    return Object.freeze({ kind: "restore", uploaded: WEB_CAPACITY.shareBytes, task_id: restore.task_id });
  }

  // Pause aborts every outstanding download and upload immediately.
  pause() {
    this.paused = true;
    this.abort?.abort();
  }

  resume() {
    if (!this.session) fail("not_opted_in");
    this.paused = false;
  }

  // Deletes only the app-owned namespace and the local session token. It is
  // fully local-first and succeeds offline; coordinator revocation is a
  // best-effort follow-up whose failure never blocks deletion. Bytes this
  // browser already served publicly are Apache-2.0 model shares and may
  // remain in third-party caches; no erasure there is promised.
  async deleteAllCopies() {
    this.pause();
    const token = this.session?.session_token
      ?? (this.store ? (await this.store.getMeta("session"))?.session_token ?? null : null);
    if (this.store) await this.store.deleteNamespace();
    this.store = null;
    this.session = null;
    this.config = null;
    this.egress = null;
    this.paused = false;
    this.abort = null;
    let revoked = false;
    if (token) {
      try {
        await this.#json("POST", "/revoke", {
          schema: WEB_CAPACITY.schema,
          record_kind: "REVOCATION_REQUEST",
          session_token: token,
          canonical_origin: this.origin,
          local_deletion_requested: true,
        });
        revoked = true;
      } catch {
        revoked = false;
      }
    }
    return Object.freeze({ deleted: true, revoked });
  }
}
