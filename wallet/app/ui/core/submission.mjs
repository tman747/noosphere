const HASH64 = /^[0-9a-f]{64}$/;
const ACCEPTED_STATES = new Set(["MEMPOOL", "INCLUDED", "JUSTIFIED", "FINALIZED"]);

/**
 * Treat the shell response as untrusted UI input. Only a protocol txid and a
 * non-rejected settlement state are renderable as success.
 */
export function formatSubmissionResult(value) {
  if (!value || typeof value !== "object") throw new Error("malformed_submit_response");
  const { txid, state } = value;
  if (typeof txid !== "string" || !HASH64.test(txid) || typeof state !== "string") {
    throw new Error("malformed_submit_response");
  }
  if (!ACCEPTED_STATES.has(state)) throw new Error("submission_rejected");
  return `txid: ${txid}\nstatus: ${state}`;
}
