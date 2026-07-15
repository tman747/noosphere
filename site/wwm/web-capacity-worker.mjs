// Dedicated module worker for noos/wwm-web-capacity/v1 share downloads.
// It is created by the page only after the visitor's explicit opt-in click and
// does nothing until it receives a message: no fetch, no storage, no hashing.
// It only ever downloads coordinator-signed, page-validated share rows,
// verifies exact length and transport SHA-256, and persists opaque bytes.
// It never evaluates, compiles, or executes downloaded content, and it stops
// with the page: no background sync, no inbound connections, no timers.
import { downloadShares } from "./web-capacity.mjs";
import { openCapacityStore } from "./web-capacity-store.mjs";

let store = null;
let abort = null;

async function ensureStore() {
  if (store === null) {
    store = await openCapacityStore({
      storage: self.navigator?.storage,
      indexedDb: self.indexedDB,
    });
  }
  return store;
}

async function handleDownload({ id, rows }) {
  const capacityStore = await ensureStore();
  abort = new AbortController();
  const result = await downloadShares(rows, {
    fetchImpl: self.fetch.bind(self),
    cryptoImpl: self.crypto,
    signal: abort.signal,
    persist: (row, bytes) => capacityStore.putShare(row, bytes),
    onProgress: (progress) => self.postMessage({ op: "progress", id, ...progress }),
  });
  self.postMessage({
    op: "done",
    id,
    stored: result.stored.map(({ stripe, position }) => ({ stripe, position })),
    failed: result.failed,
  });
}

self.addEventListener("message", (event) => {
  const message = event.data;
  if (!message || typeof message !== "object") return;
  if (message.op === "pause") {
    abort?.abort();
    return;
  }
  if (message.op === "download") {
    handleDownload(message).catch((error) => {
      self.postMessage({
        op: "error",
        id: message.id,
        code: typeof error?.code === "string" ? error.code : "worker_download_failed",
      });
    });
  }
});
