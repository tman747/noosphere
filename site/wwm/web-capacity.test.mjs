import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import {
  WEB_CAPACITY,
  WebCapacityController,
  EgressLedger,
  canonicalJson,
  computeEffectiveBytes,
  downloadShares,
  validateAssignment,
  validateCoordinatorConfig,
} from "./web-capacity.mjs";
import { CAPACITY_NAMESPACE, openCapacityStore, purgeCapacityNamespace, shareKey } from "./web-capacity-store.mjs";

const SHARE = WEB_CAPACITY.shareBytes;
const ORIGIN = "https://mind.test";
const SOURCE_A = "https://shares-a.test";
const SOURCE_B = "https://shares-b.test";
const NOW_MS = 1_750_000_000_000;
const NOW_S = Math.floor(NOW_MS / 1000);
const h = (byte) => byte.repeat(64);
const TOKEN = "t".repeat(43);
const PARTICIPANT = h("7");

const hex = (bytes) => [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");

async function sha256Hex(bytes) {
  return hex(new Uint8Array(await webcrypto.subtle.digest("SHA-256", bytes)));
}

const keys = await webcrypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);
const COORDINATOR_KEY = hex(new Uint8Array(await webcrypto.subtle.exportKey("raw", keys.publicKey)));
const otherKeys = await webcrypto.subtle.generateKey("Ed25519", true, ["sign", "verify"]);

async function signRecord(record, domain, { privateKey = keys.privateKey, publicKeyHex = COORDINATOR_KEY } = {}) {
  const encoder = new TextEncoder();
  const domainBytes = encoder.encode(domain);
  const payloadBytes = encoder.encode(canonicalJson(record));
  const message = new Uint8Array(domainBytes.byteLength + payloadBytes.byteLength);
  message.set(domainBytes, 0);
  message.set(payloadBytes, domainBytes.byteLength);
  const signature = new Uint8Array(await webcrypto.subtle.sign("Ed25519", privateKey, message));
  return {
    ...record,
    signature: { suite: "Ed25519", domain, public_key: publicKeyHex, signature: hex(signature) },
  };
}

function chainBinding() {
  return {
    chain_id: h("1"),
    genesis_hash: h("2"),
    artifact_id: WEB_CAPACITY.chainBinding.artifact_id,
    manifest_root: WEB_CAPACITY.chainBinding.manifest_root,
  };
}

function coordinatorConfig(overrides = {}) {
  return {
    schema: WEB_CAPACITY.schema,
    record_kind: "COORDINATOR_CONFIG",
    chain_binding: chainBinding(),
    geometry: {
      source_bytes: 3_803_452_480,
      encoded_bytes: 5_707_063_296,
      stripes: 454,
      positions: 12,
      reconstruction_threshold: 8,
      schedulable_minimum: 9,
      share_bytes: SHARE,
      position_bytes: 475_588_608,
      coordinate_count: 5448,
    },
    experiment_state: "LOCAL_FIXTURE",
    coordinator_key: COORDINATOR_KEY,
    source_allowlist: [SOURCE_A, SOURCE_B],
    quota_choices_shares: [16, 64, 256],
    static_cache_lifecycle: {
      host_refresh_max_seconds: 60,
      expiry_effect: "REMOVES_FUTURE_ASSIGNMENTS_ONLY",
      public_share_license: "Apache-2.0",
      cached_bytes_may_remain_public: true,
      third_party_cache_erasure_available: false,
    },
    participant_classes: ["STATIC_HOST_SEEDER", "BROWSER_ADVISORY_CACHE"],
    production_custody: false,
    rewards: false,
    browser_execution: "STORAGE_AND_OPT_IN_REPAIR_ONLY",
    ...overrides,
  };
}

function shareBytesFor(stripe, position) {
  const bytes = new Uint8Array(SHARE);
  bytes.fill((stripe * 13 + position * 7 + 1) % 256);
  return bytes;
}

async function assignmentRow(stripe, position, origin = SOURCE_A) {
  const bytes = shareBytesFor(stripe, position);
  return {
    stripe,
    position,
    bytes: SHARE,
    transport_sha256: await sha256Hex(bytes),
    protocol_share_digest: h("a"),
    probe_root: h("b"),
    url: `${origin}/artifacts/shares/${stripe}/${position}`,
    source_origin: origin,
  };
}

async function signedAssignment(rows, overrides = {}, signOptions = {}) {
  return signRecord({
    schema: WEB_CAPACITY.schema,
    record_kind: "SHARE_ASSIGNMENT",
    assignment_id: h("3"),
    participant_id: PARTICIPANT,
    canonical_origin: ORIGIN,
    chain_binding: chainBinding(),
    issued_at: NOW_S - 60,
    expires_at: NOW_S + 3600,
    rows,
    ...overrides,
  }, WEB_CAPACITY.assignmentDomain, signOptions);
}

async function signedRestoreTask(coordinate, overrides = {}) {
  return signRecord({
    schema: WEB_CAPACITY.schema,
    record_kind: "RESTORE_TASK",
    task_id: h("4"),
    participant_id: PARTICIPANT,
    canonical_origin: ORIGIN,
    chain_binding: chainBinding(),
    coordinate,
    expected_bytes: SHARE,
    issued_at: NOW_S - 60,
    expires_at: NOW_S + 3600,
    ...overrides,
  }, WEB_CAPACITY.restoreDomain);
}

// --- fake OPFS -------------------------------------------------------------

class FakeWritable {
  constructor(file) { this.file = file; this.chunks = []; }
  async write(payload) { this.chunks.push(payload instanceof Uint8Array ? payload : new Uint8Array(payload)); }
  async close() {
    const total = this.chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
    const data = new Uint8Array(total);
    let offset = 0;
    for (const chunk of this.chunks) { data.set(chunk, offset); offset += chunk.byteLength; }
    this.file.data = data;
  }
  async abort() {}
}

class FakeFileHandle {
  constructor(name) { this.kind = "file"; this.name = name; this.data = null; }
  async createWritable() { return new FakeWritable(this); }
  async getFile() {
    if (this.data === null) throw new Error("NotFoundError");
    const data = this.data;
    return { size: data.byteLength, arrayBuffer: async () => data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) };
  }
}

class FakeDirectoryHandle {
  constructor(name) { this.kind = "directory"; this.name = name; this.children = new Map(); }
  async getDirectoryHandle(name, { create = false } = {}) {
    let child = this.children.get(name);
    if (!child) {
      if (!create) throw new Error("NotFoundError");
      child = new FakeDirectoryHandle(name);
      this.children.set(name, child);
    }
    return child;
  }
  async getFileHandle(name, { create = false } = {}) {
    let child = this.children.get(name);
    if (!child) {
      if (!create) throw new Error("NotFoundError");
      child = new FakeFileHandle(name);
      this.children.set(name, child);
    }
    return child;
  }
  async removeEntry(name) {
    if (!this.children.delete(name)) throw new Error("NotFoundError");
  }
  async *entries() {
    for (const [name, child] of this.children) {
      if (child.kind === "file" && child.data !== null) yield [name, child];
    }
  }
}

// --- fake IndexedDB ---------------------------------------------------------

function fakeRequest(resolver) {
  const request = { result: undefined, error: null, onsuccess: null, onerror: null };
  queueMicrotask(() => { request.result = resolver(); request.onsuccess?.(); });
  return request;
}

function fakeIndexedDb() {
  const databases = new Map();
  function makeDb(name) {
    const stores = new Map();
    return {
      name,
      objectStoreNames: { contains: (storeName) => stores.has(storeName) },
      createObjectStore(storeName, { keyPath }) { stores.set(storeName, { keyPath, rows: new Map() }); },
      close() {},
      transaction() {
        const transaction = { error: null, oncomplete: null, onerror: null, onabort: null };
        transaction.objectStore = (storeName) => {
          const store = stores.get(storeName);
          return {
            put: (value) => fakeRequest(() => { store.rows.set(value[store.keyPath], value); return value[store.keyPath]; }),
            get: (key) => fakeRequest(() => store.rows.get(key)),
            getAll: () => fakeRequest(() => [...store.rows.values()]),
          };
        };
        queueMicrotask(() => queueMicrotask(() => transaction.oncomplete?.()));
        return transaction;
      },
    };
  }
  return {
    open(name) {
      const request = { result: null, error: null, onupgradeneeded: null, onsuccess: null, onerror: null };
      queueMicrotask(() => {
        let db = databases.get(name);
        const isNew = !db;
        if (isNew) { db = makeDb(name); databases.set(name, db); }
        request.result = db;
        if (isNew) request.onupgradeneeded?.();
        request.onsuccess?.();
      });
      return request;
    },
    deleteDatabase(name) { return fakeRequest(() => { databases.delete(name); }); },
    has: (name) => databases.has(name),
  };
}

// --- controller harness ------------------------------------------------------

function jsonResponse(payload, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: { "Content-Type": "application/json" } });
}

function sessionFor(offer) {
  return {
    schema: WEB_CAPACITY.schema,
    record_kind: "BROWSER_SESSION",
    participant_class: "BROWSER_ADVISORY_CACHE",
    admission_class: "ChorusAdvisory",
    session_token: TOKEN,
    participant_id: PARTICIPANT,
    canonical_origin: ORIGIN,
    quota_shares: offer.quota_shares,
    effective_bytes: offer.effective_bytes,
    storage_class: offer.storage_class,
    upload_policy: offer.upload_policy,
    issued_at: NOW_S,
    expires_at: NOW_S + 86_400,
    production_custody: false,
    rewards: false,
  };
}

function harness({
  estimate = { quota: 100 * SHARE * 10, usage: 0 },
  heartbeatPayload = () => ({ schema: WEB_CAPACITY.schema, record_kind: "HEARTBEAT_RESPONSE", server_time: NOW_S, assignment: null, restore_task: null }),
  shareFetch = null,
  offline = { value: false },
  pageActive = { value: true },
} = {}) {
  const calls = { fetch: [], estimate: 0, persistRequests: 0, openStore: 0 };
  const root = new FakeDirectoryHandle("(root)");
  root.children.set("unrelated-origin-data", new FakeDirectoryHandle("unrelated-origin-data"));
  const router = async (url, options = {}) => {
    if (offline.value) throw new TypeError("fetch failed: offline");
    const target = String(url);
    calls.fetch.push({ url: target, options });
    if (target.startsWith(SOURCE_A) || target.startsWith(SOURCE_B)) {
      if (shareFetch) return shareFetch(target, options);
      const [, stripe, position] = target.match(/\/shares\/(\d+)\/(\d+)$/);
      return new Response(shareBytesFor(Number(stripe), Number(position)));
    }
    const path = new URL(target).pathname;
    if (path.endsWith("/config")) return jsonResponse(coordinatorConfig());
    if (path.endsWith("/offers")) return jsonResponse(sessionFor(JSON.parse(options.body)));
    if (path.endsWith("/heartbeat")) return jsonResponse(heartbeatPayload(JSON.parse(options.body)));
    if (path.includes("/restores/")) return jsonResponse({ schema: WEB_CAPACITY.schema, record_kind: "ACKNOWLEDGEMENT", accepted: true, server_time: NOW_S });
    if (path.endsWith("/revoke")) return jsonResponse({ schema: WEB_CAPACITY.schema, record_kind: "REVOCATION_RESPONSE", revoked: true, assignments_expired: true, local_deletion_authority: "CLIENT_ALWAYS_AVAILABLE_OFFLINE" });
    throw new Error(`unexpected path ${path}`);
  };
  const controller = new WebCapacityController({
    baseUrl: "https://mind.test/api/wwm-web-capacity/v1",
    origin: ORIGIN,
    fetchImpl: router,
    cryptoImpl: webcrypto,
    openStore: async () => { calls.openStore += 1; return openCapacityStore({ storage: { getDirectory: async () => root } }); },
    estimateImpl: async () => { calls.estimate += 1; return estimate; },
    persistImpl: async () => { calls.persistRequests += 1; return true; },
    pageActive: () => pageActive.value,
    expectedIdentity: { chain_id: h("1"), genesis_hash: h("2") },
    now: () => NOW_MS,
  });
  return { controller, calls, root, offline, pageActive };
}

// --- tests -------------------------------------------------------------------

test("constructing the panel controller causes zero pre-opt-in side effects", async () => {
  const { controller, calls } = harness();
  assert.equal(controller.optedIn, false);
  await assert.rejects(() => controller.heartbeat(), { code: "not_opted_in" });
  await assert.rejects(() => controller.keepCopies(), { code: "not_opted_in" });
  assert.throws(() => controller.resume(), { code: "not_opted_in" });
  assert.deepEqual(calls, { fetch: [], estimate: 0, persistRequests: 0, openStore: 0 });
});

test("effective bytes follow the exact formula, boundaries, and refusal", () => {
  // Free space dominates: 10% of free, floored to whole shares.
  assert.deepEqual(
    computeEffectiveBytes({ quotaShares: 64, quotaBytes: 25 * SHARE, usageBytes: 0 }),
    { quotaShares: 64, userLimitBytes: 64 * SHARE, effectiveShares: 2, effectiveBytes: 2 * SHARE, participationPossible: true },
  );
  // User limit dominates when free space is plentiful.
  assert.equal(computeEffectiveBytes({ quotaShares: 16, quotaBytes: 10_000 * SHARE, usageBytes: 0 }).effectiveShares, 16);
  assert.equal(computeEffectiveBytes({ quotaShares: 256, quotaBytes: 10_000 * SHARE, usageBytes: 0 }).effectiveBytes, 268_173_312);
  // Exact one-share boundary: 10% of free equals exactly one share.
  assert.equal(computeEffectiveBytes({ quotaShares: 16, quotaBytes: 10 * SHARE, usageBytes: 0 }).effectiveShares, 1);
  assert.equal(computeEffectiveBytes({ quotaShares: 16, quotaBytes: 10 * SHARE - 1, usageBytes: 0 }).participationPossible, false);
  // Usage subtracts before the 10% cut; negative free clamps to zero.
  assert.equal(computeEffectiveBytes({ quotaShares: 16, quotaBytes: 20 * SHARE, usageBytes: 10 * SHARE }).effectiveShares, 1);
  assert.equal(computeEffectiveBytes({ quotaShares: 16, quotaBytes: SHARE, usageBytes: 5 * SHARE }).participationPossible, false);
  assert.throws(() => computeEffectiveBytes({ quotaShares: 32, quotaBytes: SHARE, usageBytes: 0 }), { code: "invalid_quota_choice" });
});

test("opt-in refuses when less than one share fits, without creating a session", async () => {
  const { controller, calls } = harness({ estimate: { quota: 10 * SHARE - 1, usage: 0 } });
  await assert.rejects(
    () => controller.optIn({ quotaShares: 16 }),
    { code: "insufficient_storage_for_one_share" },
  );
  assert.equal(controller.optedIn, false);
  assert.deepEqual(calls.fetch.map((entry) => new URL(entry.url).pathname.split("/").pop()), ["config"]);
});

test("storage prefers OPFS, falls back to IndexedDB, and refuses silently degraded modes", async () => {
  const root = new FakeDirectoryHandle("(root)");
  const opfs = await openCapacityStore({ storage: { getDirectory: async () => root } });
  assert.equal(opfs.storageClass, "OPFS");
  const row = await assignmentRow(3, 5);
  await opfs.putShare(row, shareBytesFor(3, 5));
  assert.deepEqual(await opfs.getShare({ stripe: 3, position: 5 }), shareBytesFor(3, 5));
  assert.equal(await opfs.usageBytes(), SHARE);
  assert.equal((await opfs.listShares())[0].transport_sha256, row.transport_sha256);
  await opfs.setMeta("session", { session_token: TOKEN });
  assert.equal((await opfs.getMeta("session")).session_token, TOKEN);
  assert.ok(root.children.has(CAPACITY_NAMESPACE));

  const idb = fakeIndexedDb();
  const fallback = await openCapacityStore({
    storage: { getDirectory: async () => { throw new Error("SecurityError"); } },
    indexedDb: idb,
  });
  assert.equal(fallback.storageClass, "INDEXEDDB");
  await fallback.putShare(row, shareBytesFor(3, 5));
  assert.deepEqual(await fallback.getShare({ stripe: 3, position: 5 }), shareBytesFor(3, 5));
  assert.equal(await fallback.usageBytes(), SHARE);
  await fallback.deleteNamespace();
  assert.equal(idb.has(CAPACITY_NAMESPACE), false);

  await assert.rejects(() => openCapacityStore({}), { code: "no_eligible_storage" });
});

test("assignments are rejected on signature, key, origin, length, expiry, and duplicates", async () => {
  const config = validateCoordinatorConfig(coordinatorConfig(), { chain_id: h("1"), genesis_hash: h("2") });
  const session = { participant_id: PARTICIPANT, effective_bytes: 16 * SHARE };
  const context = { config, session, origin: ORIGIN, nowSeconds: NOW_S, cryptoImpl: webcrypto };
  const rows = [await assignmentRow(0, 0), await assignmentRow(1, 4, SOURCE_B)];
  const valid = await validateAssignment(await signedAssignment(rows), context);
  assert.equal(valid.length, 2);

  const tampered = await signedAssignment(rows);
  tampered.rows = [rows[0]];
  await assert.rejects(() => validateAssignment(tampered, context), { code: "invalid_record_signature" });
  const otherKeyHex = hex(new Uint8Array(await webcrypto.subtle.exportKey("raw", otherKeys.publicKey)));
  const wrongKey = await signedAssignment(rows, {}, { privateKey: otherKeys.privateKey, publicKeyHex: otherKeyHex });
  await assert.rejects(() => validateAssignment(wrongKey, context), { code: "wrong_coordinator_key" });
  await assert.rejects(
    async () => validateAssignment(await signedAssignment([{ ...rows[0], url: `${SOURCE_B}/artifacts/shares/0/0` }]), context),
    { code: "wrong_share_origin" },
  );
  await assert.rejects(
    async () => validateAssignment(await signedAssignment([{ ...rows[0], url: "https://evil.test/x", source_origin: "https://evil.test" }]), context),
    { code: "share_origin_not_allowlisted" },
  );
  await assert.rejects(
    async () => validateAssignment(await signedAssignment([{ ...rows[0], bytes: SHARE - 1 }]), context),
    { code: "wrong_share_length" },
  );
  await assert.rejects(
    async () => validateAssignment(await signedAssignment(rows, { expires_at: NOW_S - 1 }), context),
    { code: "assignment_expired" },
  );
  await assert.rejects(
    async () => validateAssignment(await signedAssignment([rows[0], { ...rows[1], stripe: 0, position: 0 }]), context),
    { code: "duplicate_share_coordinate" },
  );
  await assert.rejects(
    async () => validateAssignment(await signedAssignment(rows), { ...context, session: { ...session, effective_bytes: SHARE } }),
    { code: "assignment_exceeds_quota" },
  );
});

test("share downloads cap concurrency at 2 and verify origin, redirect, length, and digest", async () => {
  const rows = await Promise.all([0, 1, 2, 3, 4, 5].map((stripe) => assignmentRow(stripe, 0)));
  let inFlight = 0;
  let maxInFlight = 0;
  const persisted = [];
  const result = await downloadShares(rows, {
    cryptoImpl: webcrypto,
    persist: async (row) => { persisted.push(`${row.stripe}:${row.position}`); },
    fetchImpl: async (url) => {
      inFlight += 1;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 5));
      inFlight -= 1;
      const [, stripe] = String(url).match(/\/shares\/(\d+)\//);
      if (stripe === "1") return new Response(shareBytesFor(9, 9)); // wrong digest
      if (stripe === "2") return new Response(new Uint8Array(SHARE - 7)); // wrong length
      if (stripe === "3") { // redirected transport
        const response = new Response(shareBytesFor(3, 0));
        Object.defineProperty(response, "redirected", { value: true });
        return response;
      }
      if (stripe === "4") { // answer from a different origin
        const response = new Response(shareBytesFor(4, 0));
        Object.defineProperty(response, "url", { value: "https://evil.test/artifacts/shares/4/0" });
        return response;
      }
      return new Response(shareBytesFor(Number(stripe), 0));
    },
  });
  assert.equal(maxInFlight, 2);
  assert.deepEqual(persisted.sort(), ["0:0", "5:0"]);
  assert.deepEqual(
    result.failed.map(({ stripe, code }) => [stripe, code]).sort((a, b) => a[0] - b[0]),
    [[1, "WRONG_DIGEST"], [2, "WRONG_LENGTH"], [3, "REDIRECT_REJECTED"], [4, "WRONG_ORIGIN"]],
  );
});

test("heartbeats run only from an active page and never from a hidden or paused one", async () => {
  const pageActive = { value: true };
  const { controller, calls } = harness({ pageActive });
  await controller.optIn({ quotaShares: 16 });
  const baseline = calls.fetch.length;

  pageActive.value = false;
  await assert.rejects(() => controller.heartbeat(), { code: "page_not_active" });
  assert.equal(calls.fetch.length, baseline);

  pageActive.value = true;
  controller.pause();
  await assert.rejects(() => controller.heartbeat(), { code: "paused" });
  assert.equal(calls.fetch.length, baseline);

  controller.resume();
  assert.deepEqual(await controller.heartbeat(), { kind: "idle" });
  assert.equal(calls.fetch.length, baseline + 1);
  const body = JSON.parse(calls.fetch.at(-1).options.body);
  assert.equal(body.page_active, true);
  assert.equal(calls.fetch.at(-1).options.credentials, "omit");
});

test("repair egress is off by default: restore tasks are skipped without any upload", async () => {
  const restoreTask = await signedRestoreTask(await assignmentRow(2, 1));
  const { controller, calls } = harness({
    heartbeatPayload: () => ({ schema: WEB_CAPACITY.schema, record_kind: "HEARTBEAT_RESPONSE", server_time: NOW_S, assignment: null, restore_task: restoreTask }),
  });
  await controller.optIn({ quotaShares: 16 });
  assert.equal(controller.session.upload_policy.enabled, false);
  assert.deepEqual(await controller.heartbeat(), { kind: "restore", skipped: "EGRESS_DISABLED" });
  assert.equal(calls.fetch.filter((entry) => entry.url.includes("/restores/")).length, 0);
});

test("opt-in repair uploads stop hard at the daily egress cap", async () => {
  const restoreTask = await signedRestoreTask(await assignmentRow(2, 1));
  const { controller, calls } = harness({
    heartbeatPayload: () => ({ schema: WEB_CAPACITY.schema, record_kind: "HEARTBEAT_RESPONSE", server_time: NOW_S, assignment: null, restore_task: restoreTask }),
  });
  await controller.optIn({ quotaShares: 16, uploadEnabled: true, dailyEgressBytes: SHARE });
  await controller.store.putShare(await assignmentRow(2, 1), shareBytesFor(2, 1));

  const first = await controller.heartbeat();
  assert.equal(first.kind, "restore");
  assert.equal(first.uploaded, SHARE);
  const uploads = calls.fetch.filter((entry) => entry.url.includes("/restores/"));
  assert.equal(uploads.length, 1);
  assert.equal(uploads[0].options.method, "PUT");
  assert.equal(uploads[0].options.credentials, "omit");
  assert.equal(uploads[0].options.headers.Authorization, `Bearer ${controller.session.session_token}`);
  assert.equal(uploads[0].options.body.byteLength, SHARE);

  assert.deepEqual(await controller.heartbeat(), { kind: "restore", skipped: "EGRESS_CAP_EXCEEDED" });
  assert.equal(calls.fetch.filter((entry) => entry.url.includes("/restores/")).length, 1);
});

test("the egress ledger resets on a new UTC day", () => {
  const ledger = new EgressLedger(SHARE, NOW_MS);
  assert.equal(ledger.charge(SHARE, NOW_MS), true);
  assert.equal(ledger.charge(SHARE, NOW_MS), false);
  assert.equal(ledger.charge(SHARE, NOW_MS + 86_400_000), true);
});

test("pause aborts an in-flight assignment download immediately", async () => {
  const rows = [await assignmentRow(0, 0)];
  const assignment = await signedAssignment(rows, {}, {});
  const { controller } = harness({
    heartbeatPayload: () => ({ schema: WEB_CAPACITY.schema, record_kind: "HEARTBEAT_RESPONSE", server_time: NOW_S, assignment, restore_task: null }),
    shareFetch: (url, options) => new Promise((_, reject) => {
      options.signal.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")), { once: true });
    }),
  });
  await controller.optIn({ quotaShares: 16 });
  const pending = controller.heartbeat();
  await new Promise((resolve) => setTimeout(resolve, 10));
  controller.pause();
  const outcome = await pending;
  assert.equal(outcome.kind, "assignment");
  assert.deepEqual(outcome.stored, []);
  assert.deepEqual(outcome.failed, [{ stripe: 0, position: 0, code: "DOWNLOAD_ABORTED" }]);
});

test("deletion works fully offline and removes only the app-owned namespace and token", async () => {
  const offline = { value: false };
  const { controller, root, calls } = harness({ offline });
  await controller.optIn({ quotaShares: 16 });
  await controller.store.putShare(await assignmentRow(1, 2), shareBytesFor(1, 2));
  assert.ok(root.children.has(CAPACITY_NAMESPACE));
  assert.equal((await controller.store.getMeta("session")).session_token, TOKEN);

  offline.value = true;
  const fetchesBefore = calls.fetch.length;
  const outcome = await controller.deleteAllCopies();
  assert.deepEqual(outcome, { deleted: true, revoked: false });
  assert.equal(controller.optedIn, false);
  assert.equal(controller.session, null);
  assert.equal(root.children.has(CAPACITY_NAMESPACE), false);
  assert.ok(root.children.has("unrelated-origin-data"), "sibling origin data must survive");
  assert.equal(calls.fetch.length, fetchesBefore, "offline deletion performed no successful network call");
});

test("deletion revokes the session best-effort when the coordinator is reachable", async () => {
  const { controller, calls } = harness();
  await controller.optIn({ quotaShares: 16 });
  const outcome = await controller.deleteAllCopies();
  assert.deepEqual(outcome, { deleted: true, revoked: true });
  const revoke = calls.fetch.find((entry) => entry.url.endsWith("/revoke"));
  const body = JSON.parse(revoke.options.body);
  assert.equal(body.session_token, TOKEN);
  assert.equal(body.local_deletion_requested, true);
  assert.equal(revoke.options.credentials, "omit");
});

test("coordinator config is rejected without the truthful cache-lifecycle disclosure", () => {
  const identity = { chain_id: h("1"), genesis_hash: h("2") };
  assert.throws(
    () => validateCoordinatorConfig(coordinatorConfig({ static_cache_lifecycle: undefined }), identity),
    { code: "wrong_cache_lifecycle_disclosure" },
  );
  assert.throws(
    () => validateCoordinatorConfig(coordinatorConfig({
      static_cache_lifecycle: { ...coordinatorConfig().static_cache_lifecycle, third_party_cache_erasure_available: true },
    }), identity),
    { code: "wrong_cache_lifecycle_disclosure" },
  );
  assert.throws(
    () => validateCoordinatorConfig(coordinatorConfig({ rewards: true }), identity),
    { code: "production_claims_forbidden" },
  );
  assert.throws(
    () => validateCoordinatorConfig(coordinatorConfig({ browser_execution: "BROWSER_INFERENCE" }), identity),
    { code: "browser_execution_forbidden" },
  );
  assert.throws(
    () => validateCoordinatorConfig(coordinatorConfig({ experiment_state: "DISABLED" }), identity),
    { code: "experiment_disabled" },
  );
});

test("shareKey is stable and rejects malformed coordinates", () => {
  assert.equal(shareKey(453, 11), "s453-p11");
  assert.throws(() => shareKey(-1, 0), { code: "invalid_share_coordinate" });
});

test("a failure after the offer rolls back locally first and revokes the partial session", async () => {
  const { controller, calls, root } = harness();
  const originalOpen = controller.openStore;
  controller.openStore = async () => {
    const store = await originalOpen();
    const originalSetMeta = store.setMeta.bind(store);
    store.setMeta = async (name, value) => {
      if (name === "session") throw new Error("disk full");
      return originalSetMeta(name, value);
    };
    return store;
  };
  await assert.rejects(() => controller.optIn({ quotaShares: 16 }), { message: "disk full" });
  assert.equal(controller.optedIn, false);
  assert.equal(controller.store, null);
  assert.equal(root.children.has(CAPACITY_NAMESPACE), false, "namespace rolled back");
  const revoke = calls.fetch.find((entry) => entry.url.endsWith("/revoke"));
  assert.ok(revoke, "partial session revoked best-effort");
  assert.equal(JSON.parse(revoke.options.body).session_token, TOKEN);
});

test("post-offer rollback still deletes locally when the coordinator became unreachable", async () => {
  const offline = { value: false };
  const { controller, calls, root } = harness({ offline });
  const originalOpen = controller.openStore;
  controller.openStore = async () => {
    const store = await originalOpen();
    store.setMeta = async () => { offline.value = true; throw new Error("crash mid opt-in"); };
    return store;
  };
  await assert.rejects(() => controller.optIn({ quotaShares: 16 }), { message: "crash mid opt-in" });
  assert.equal(controller.optedIn, false);
  assert.equal(root.children.has(CAPACITY_NAMESPACE), false, "local deletion never depends on the network");
  assert.equal(calls.fetch.filter((entry) => entry.url.endsWith("/revoke")).length, 0);
});

test("assignments of new coordinates never accumulate past the remaining consented capacity", async () => {
  let round = 0;
  const { controller } = harness({
    estimate: { quota: 20 * SHARE, usage: 0 }, // effective quota: 2 shares
    heartbeatPayload: () => null, // replaced below per round
  });
  const fills = [
    await Promise.all([assignmentRow(0, 0), assignmentRow(1, 0)].map((p) => p)),
    await Promise.all([assignmentRow(2, 0), assignmentRow(3, 0)].map((p) => p)),
  ];
  const assignments = [await signedAssignment(fills[0]), await signedAssignment(fills[1])];
  controller.fetchImpl = (() => {
    const base = controller.fetchImpl;
    return async (url, options) => {
      if (String(url).includes("/heartbeat")) {
        const assignment = assignments[round];
        round += 1;
        return jsonResponse({ schema: WEB_CAPACITY.schema, record_kind: "HEARTBEAT_RESPONSE", server_time: NOW_S, assignment, restore_task: null });
      }
      return base(url, options);
    };
  })();
  await controller.optIn({ quotaShares: 16 });
  const first = await controller.heartbeat();
  assert.equal(first.stored.length, 2, "first assignment fills the quota");
  await assert.rejects(() => controller.heartbeat(), { code: "assignment_exceeds_quota" });
  assert.equal(await controller.store.usageBytes(), 2 * SHARE, "usage never exceeds consented bytes");
});

test("re-assigned coordinates already held overwrite idempotently within quota", async () => {
  const rows = [await assignmentRow(0, 0), await assignmentRow(1, 0)];
  const assignment = await signedAssignment(rows);
  const { controller } = harness({
    estimate: { quota: 20 * SHARE, usage: 0 },
    heartbeatPayload: () => ({ schema: WEB_CAPACITY.schema, record_kind: "HEARTBEAT_RESPONSE", server_time: NOW_S, assignment, restore_task: null }),
  });
  await controller.optIn({ quotaShares: 16 });
  assert.equal((await controller.heartbeat()).stored.length, 2);
  assert.equal((await controller.heartbeat()).stored.length, 2, "same coordinates re-accepted");
  assert.equal(await controller.store.usageBytes(), 2 * SHARE);
});

test("dormant purge deletes stale copies offline, session-less, touching only the app namespace", async () => {
  // Simulate an earlier visit that crashed after storing shares and a token.
  const root = new FakeDirectoryHandle("(root)");
  root.children.set("unrelated-origin-data", new FakeDirectoryHandle("unrelated-origin-data"));
  const earlier = await openCapacityStore({ storage: { getDirectory: async () => root } });
  await earlier.putShare(await assignmentRow(5, 5), shareBytesFor(5, 5));
  await earlier.setMeta("session", { session_token: TOKEN });

  let storageTouches = 0;
  const storage = { getDirectory: async () => { storageTouches += 1; return root; } };
  assert.equal(storageTouches, 0, "no storage access before the explicit purge call");
  const result = await purgeCapacityNamespace({ storage });
  assert.deepEqual(result, { removed: true, sessionToken: TOKEN });
  assert.equal(root.children.has(CAPACITY_NAMESPACE), false);
  assert.ok(root.children.has("unrelated-origin-data"), "only the app namespace is removed");

  // Nothing left: a second purge reports no earlier copies.
  assert.deepEqual(await purgeCapacityNamespace({ storage }), { removed: false, sessionToken: null });
});

test("dormant purge clears the IndexedDB fallback namespace as well", async () => {
  const idb = fakeIndexedDb();
  const earlier = await openCapacityStore({ storage: {}, indexedDb: idb });
  assert.equal(earlier.storageClass, "INDEXEDDB");
  await earlier.putShare(await assignmentRow(6, 1), shareBytesFor(6, 1));
  await earlier.setMeta("session", { session_token: TOKEN });
  const result = await purgeCapacityNamespace({ indexedDb: idb });
  assert.equal(result.removed, true);
  assert.equal(result.sessionToken, TOKEN);
  assert.equal(idb.has(CAPACITY_NAMESPACE), false);
});
