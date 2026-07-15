// App-owned browser storage for noos/wwm-web-capacity/v1 advisory share
// copies. Everything lives under one namespace — the OPFS directory
// `noos-wwm-cache-v1/` when available, otherwise the IndexedDB database of the
// same name — so "delete my copies" removes exactly this namespace, locally
// and offline, and nothing else on the origin.
export const CAPACITY_NAMESPACE = "noos-wwm-cache-v1";

export class WebCapacityStoreError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "WebCapacityStoreError";
    this.code = code;
  }
}

export function shareKey(stripe, position) {
  if (!Number.isSafeInteger(stripe) || !Number.isSafeInteger(position) || stripe < 0 || position < 0) {
    throw new WebCapacityStoreError("invalid_share_coordinate");
  }
  return `s${stripe}-p${position}`;
}

function shareMeta(row) {
  return {
    stripe: row.stripe,
    position: row.position,
    bytes: row.bytes,
    transport_sha256: row.transport_sha256,
    protocol_share_digest: row.protocol_share_digest,
    probe_root: row.probe_root,
    stored_at: Date.now(),
  };
}

async function bytesFromStored(value) {
  if (value instanceof Uint8Array) return value;
  if (typeof Blob === "function" && value instanceof Blob) return new Uint8Array(await value.arrayBuffer());
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  return null;
}

// Origin-private file system adapter. Share bytes commit atomically: an OPFS
// createWritable stages every write and publishes only on close, and the
// metadata sidecar — which is what marks a share as present — is written only
// after that close succeeds.
class OpfsCapacityStore {
  constructor(root, directory) {
    this.storageClass = "OPFS";
    this.root = root;
    this.directory = directory;
  }

  static async open(root) {
    const directory = await root.getDirectoryHandle(CAPACITY_NAMESPACE, { create: true });
    return new OpfsCapacityStore(root, directory);
  }

  async #writeFile(name, payload) {
    const handle = await this.directory.getFileHandle(name, { create: true });
    const writable = await handle.createWritable();
    try {
      await writable.write(payload);
    } catch (error) {
      await writable.abort?.().catch(() => {});
      throw error;
    }
    await writable.close();
  }

  async #readFile(name) {
    try {
      const handle = await this.directory.getFileHandle(name);
      const file = await handle.getFile();
      return new Uint8Array(await file.arrayBuffer());
    } catch {
      return null;
    }
  }

  async putShare(row, bytes) {
    const key = shareKey(row.stripe, row.position);
    await this.#writeFile(`${key}.bin`, bytes);
    await this.#writeFile(`${key}.meta.json`, new TextEncoder().encode(JSON.stringify(shareMeta(row))));
  }

  async getShare({ stripe, position }) {
    const key = shareKey(stripe, position);
    const meta = await this.#readFile(`${key}.meta.json`);
    if (meta === null) return null;
    return this.#readFile(`${key}.bin`);
  }

  async listShares() {
    const shares = [];
    for await (const [name] of this.directory.entries()) {
      if (!name.endsWith(".meta.json") || !name.startsWith("s")) continue;
      const raw = await this.#readFile(name);
      if (raw === null) continue;
      try {
        shares.push(JSON.parse(new TextDecoder().decode(raw)));
      } catch {
        // A torn metadata sidecar means the share never became present.
      }
    }
    shares.sort((left, right) => left.stripe - right.stripe || left.position - right.position);
    return shares;
  }

  async usageBytes() {
    let total = 0;
    for await (const [name, handle] of this.directory.entries()) {
      if (!name.endsWith(".bin")) continue;
      const file = await handle.getFile();
      total += file.size;
    }
    return total;
  }

  async getMeta(name) {
    const raw = await this.#readFile(`meta-${name}.json`);
    if (raw === null) return null;
    try {
      return JSON.parse(new TextDecoder().decode(raw));
    } catch {
      return null;
    }
  }

  async setMeta(name, value) {
    await this.#writeFile(`meta-${name}.json`, new TextEncoder().encode(JSON.stringify(value)));
  }

  async deleteNamespace() {
    await this.root.removeEntry(CAPACITY_NAMESPACE, { recursive: true });
  }
}

function requestDone(request) {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new WebCapacityStoreError("idb_request_failed"));
  });
}

function transactionDone(transaction) {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new WebCapacityStoreError("idb_transaction_failed"));
    transaction.onabort = () => reject(transaction.error ?? new WebCapacityStoreError("idb_transaction_aborted"));
  });
}

// IndexedDB fallback. Each share is one record holding blob plus metadata, so
// a single put in a single transaction is atomic by construction.
class IdbCapacityStore {
  constructor(idb, db) {
    this.storageClass = "INDEXEDDB";
    this.idb = idb;
    this.db = db;
  }

  static async open(idb) {
    const request = idb.open(CAPACITY_NAMESPACE, 1);
    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains("shares")) db.createObjectStore("shares", { keyPath: "key" });
      if (!db.objectStoreNames.contains("meta")) db.createObjectStore("meta", { keyPath: "name" });
    };
    const db = await requestDone(request);
    return new IdbCapacityStore(idb, db);
  }

  async putShare(row, bytes) {
    const transaction = this.db.transaction(["shares"], "readwrite");
    transaction.objectStore("shares").put({
      key: shareKey(row.stripe, row.position),
      blob: typeof Blob === "function" ? new Blob([bytes]) : bytes,
      byteLength: bytes.byteLength,
      meta: shareMeta(row),
    });
    await transactionDone(transaction);
  }

  async #getRecord(key) {
    const transaction = this.db.transaction(["shares"], "readonly");
    const record = await requestDone(transaction.objectStore("shares").get(key));
    return record ?? null;
  }

  async getShare({ stripe, position }) {
    const record = await this.#getRecord(shareKey(stripe, position));
    if (record === null) return null;
    return bytesFromStored(record.blob);
  }

  async #allRecords() {
    const transaction = this.db.transaction(["shares"], "readonly");
    const records = await requestDone(transaction.objectStore("shares").getAll());
    return records ?? [];
  }

  async listShares() {
    const records = await this.#allRecords();
    return records
      .map((record) => record.meta)
      .sort((left, right) => left.stripe - right.stripe || left.position - right.position);
  }

  async usageBytes() {
    const records = await this.#allRecords();
    return records.reduce((total, record) => total + (record.byteLength ?? 0), 0);
  }

  async getMeta(name) {
    const transaction = this.db.transaction(["meta"], "readonly");
    const record = await requestDone(transaction.objectStore("meta").get(name));
    return record ? record.value : null;
  }

  async setMeta(name, value) {
    const transaction = this.db.transaction(["meta"], "readwrite");
    transaction.objectStore("meta").put({ name, value });
    await transactionDone(transaction);
  }

  async deleteNamespace() {
    this.db.close();
    await requestDone(this.idb.deleteDatabase(CAPACITY_NAMESPACE));
  }
}

// Prefer OPFS; fall back to IndexedDB blobs; otherwise the participant is
// ineligible — there is no silent third storage path.
export async function openCapacityStore({ storage, indexedDb } = {}) {
  if (storage && typeof storage.getDirectory === "function") {
    try {
      const root = await storage.getDirectory();
      return await OpfsCapacityStore.open(root);
    } catch {
      // OPFS unavailable or denied: attempt the declared IndexedDB fallback.
    }
  }
  if (indexedDb && typeof indexedDb.open === "function") {
    return IdbCapacityStore.open(indexedDb);
  }
  throw new WebCapacityStoreError("no_eligible_storage");
}

// Session-less, offline-capable purge for copies left behind by an earlier
// visit (crash, reload, cleared page state). It touches storage only when
// called, opens and removes ONLY the app-owned noos-wwm-cache-v1 namespace in
// both backends, needs no coordinator or session, and returns any recoverable
// session token so the caller may attempt a best-effort revocation.
export async function purgeCapacityNamespace({ storage, indexedDb } = {}) {
  let sessionToken = null;
  let removed = false;
  if (storage && typeof storage.getDirectory === "function") {
    try {
      const root = await storage.getDirectory();
      try {
        const directory = await root.getDirectoryHandle(CAPACITY_NAMESPACE);
        try {
          const handle = await directory.getFileHandle("meta-session.json");
          const file = await handle.getFile();
          const parsed = JSON.parse(new TextDecoder().decode(new Uint8Array(await file.arrayBuffer())));
          if (typeof parsed?.session_token === "string") sessionToken = parsed.session_token;
        } catch {
          // No readable session metadata; deletion proceeds regardless.
        }
        await root.removeEntry(CAPACITY_NAMESPACE, { recursive: true });
        removed = true;
      } catch {
        // Namespace absent in OPFS.
      }
    } catch {
      // OPFS unavailable; the IndexedDB backend is still purged below.
    }
  }
  if (indexedDb && typeof indexedDb.open === "function") {
    try {
      const db = await requestDone(indexedDb.open(CAPACITY_NAMESPACE, 1));
      if (db.objectStoreNames.contains("meta")) {
        try {
          const transaction = db.transaction(["meta"], "readonly");
          const record = await requestDone(transaction.objectStore("meta").get("session"));
          if (typeof record?.value?.session_token === "string" && sessionToken === null) {
            sessionToken = record.value.session_token;
          }
          removed = true;
        } catch {
          // Unreadable metadata; deletion proceeds regardless.
        }
      }
      db.close();
      await requestDone(indexedDb.deleteDatabase(CAPACITY_NAMESPACE));
    } catch {
      // IndexedDB unavailable; nothing further to purge.
    }
  }
  return Object.freeze({ removed, sessionToken });
}
