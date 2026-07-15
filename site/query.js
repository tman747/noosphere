import { WwmV2Client, WwmClientError } from "./wwm/client.mjs";
import { WebCapacityController, WebCapacityError } from "./wwm/web-capacity.mjs";
import { openCapacityStore, purgeCapacityNamespace } from "./wwm/web-capacity-store.mjs";

const nodes = {
  form: document.getElementById("query-form"),
  input: document.getElementById("query-input"),
  inputCount: document.getElementById("query-count"),
  inputError: document.getElementById("query-error"),
  outputLimit: document.getElementById("output-limit"),
  submit: document.getElementById("query-submit"),
  activation: document.getElementById("activation-label"),
  networkState: document.getElementById("network-state"),
  pinChain: document.getElementById("pin-chain"),
  pinModel: document.getElementById("pin-model"),
  pinControl: document.getElementById("pin-control"),
  pinCandidate: document.getElementById("pin-candidate"),
  pinProof: document.getElementById("pin-proof"),
  pinDisclosure: document.getElementById("pin-disclosure"),
  hostedPanel: document.getElementById("hosted-proof-panel"),
  hostedPanelState: document.getElementById("hosted-panel-state"),
  hostedChainGenesis: document.getElementById("hosted-chain-genesis"),
  hostedFinalized: document.getElementById("hosted-finalized"),
  hostedCapsule: document.getElementById("hosted-capsule"),
  hostedArtifact: document.getElementById("hosted-artifact"),
  hostedManifest: document.getElementById("hosted-manifest"),
  hostedSourceBytes: document.getElementById("hosted-source-bytes"),
  hostedEncodedBytes: document.getElementById("hosted-encoded-bytes"),
  hostedGeometry: document.getElementById("hosted-geometry"),
  hostedSchedulability: document.getElementById("hosted-schedulability"),
  hostedCustodianMap: document.getElementById("hosted-custodian-map"),
  hostedReconstructionState: document.getElementById("hosted-reconstruction-state"),
  hostedReconstructionProgress: document.getElementById("hosted-reconstruction-progress"),
  hostedReconstructionCopy: document.getElementById("hosted-reconstruction-copy"),
  hostedRuntimeRoot: document.getElementById("hosted-runtime-root"),
  hostedCertificate: document.getElementById("hosted-certificate"),
  hostedCertificateHorizon: document.getElementById("hosted-certificate-horizon"),
  hostedFallback: document.getElementById("hosted-fallback"),
  hostedJobLink: document.getElementById("hosted-job-link"),
  hostedReceiptLink: document.getElementById("hosted-receipt-link"),
  hostedSettlementLink: document.getElementById("hosted-settlement-link"),
  hostedProofDisclosure: document.getElementById("hosted-proof-disclosure"),
  paymentLabel: document.getElementById("payment-label"),
  quoteCeiling: document.getElementById("quote-ceiling"),
  escrowLabel: document.getElementById("escrow-label"),
  escrowHelp: document.getElementById("escrow-help"),
  escrowAuthorization: document.getElementById("escrow-authorization"),
  status: document.getElementById("query-status"),
  answerEmpty: document.getElementById("answer-empty"),
  answerLoading: document.getElementById("answer-loading"),
  answerResult: document.getElementById("answer-result"),
  answerCopy: document.getElementById("answer-copy"),
  answerFinality: document.getElementById("answer-finality"),
  cancelJob: document.getElementById("cancel-job"),
  receiptToggle: document.getElementById("receipt-toggle"),
  receiptDrawer: document.getElementById("receipt-drawer"),
  receiptClose: document.getElementById("receipt-close"),
  receiptFacts: document.getElementById("receipt-facts"),
  receiptJson: document.getElementById("receipt-json"),
  capacityPanel: document.getElementById("capacity-panel"),
  capacityState: document.getElementById("capacity-state"),
  capacityForm: document.getElementById("capacity-form"),
  capacityRepair: document.getElementById("capacity-repair"),
  capacityEgressCap: document.getElementById("capacity-egress-cap"),
  capacityEstimated: document.getElementById("capacity-estimated"),
  capacityEffective: document.getElementById("capacity-effective"),
  capacityActual: document.getElementById("capacity-actual"),
  capacityClass: document.getElementById("capacity-class"),
  capacityOptIn: document.getElementById("capacity-opt-in"),
  capacityError: document.getElementById("capacity-error"),
  capacityControls: document.getElementById("capacity-controls"),
  capacityKeep: document.getElementById("capacity-keep"),
  capacityPause: document.getElementById("capacity-pause"),
  capacityDelete: document.getElementById("capacity-delete"),
  capacityPersistence: document.getElementById("capacity-persistence"),
  capacityNote: document.getElementById("capacity-note"),
  capacityDormantControls: document.getElementById("capacity-dormant-controls"),
  capacityPurge: document.getElementById("capacity-purge"),
};

const runtime = {
  client: null,
  active: null,
  hosted: null,
  currentJobId: null,
  streamAbort: null,
  answer: "",
  receipt: null,
  busy: false,
};

function shortHash(value) {
  return typeof value === "string" && value.length >= 16 ? `${value.slice(0, 8)}…${value.slice(-6)}` : "Not verified";
}

function formatBytes(bytes) {
  return (bytes / 1_000_000_000).toFixed(3);
}

function formatDecimal(value) {
  return String(value).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

function renderHash(node, value) {
  node.textContent = shortHash(value);
  node.title = value;
}

function renderProofLink(node, href, label, title) {
  const link = document.createElement("a");
  link.href = href;
  link.textContent = label;
  link.title = title;
  node.replaceChildren(link);
}

function renderCustodian(row) {
  const item = document.createElement("li");
  const position = document.createElement("span");
  const identity = document.createElement("span");
  const profile = document.createElement("strong");
  const domain = document.createElement("small");
  const status = document.createElement("span");
  position.textContent = String(row.position + 1).padStart(2, "0");
  profile.textContent = shortHash(row.profile_id);
  profile.title = row.profile_id;
  domain.textContent = `AS${row.asn} · ${shortHash(row.region_id)} · ${shortHash(row.provider_root)}`;
  domain.title = `endpoint ${row.endpoint_root} · operator ${row.operator_id}`;
  status.textContent = "Certified";
  identity.append(profile, domain);
  item.append(position, identity, status);
  return item;
}

function renderHostedProof(hosted) {
  runtime.hosted = hosted;
  nodes.hostedPanel.setAttribute("aria-busy", "false");
  nodes.hostedPanelState.className = `state-flag ${hosted.ready ? "state-ready" : "state-pending"}`;
  nodes.hostedPanelState.textContent = hosted.ready ? "17 leaves + runtime" : hosted.reconstruction.state;
  nodes.hostedSourceBytes.textContent = formatBytes(hosted.source_bytes);
  nodes.hostedEncodedBytes.textContent = formatBytes(hosted.encoded_bytes);
  nodes.hostedChainGenesis.textContent = `${shortHash(hosted.chain_id)} / ${shortHash(hosted.genesis_hash)}`;
  nodes.hostedChainGenesis.title = `${hosted.chain_id} / ${hosted.genesis_hash}`;
  nodes.hostedFinalized.textContent = `#${formatDecimal(hosted.finalized_height)} · ${shortHash(hosted.finalized_hash)}`;
  nodes.hostedFinalized.title = hosted.finalized_hash;
  renderHash(nodes.hostedCapsule, hosted.capsule_id);
  renderHash(nodes.hostedArtifact, hosted.artifact_id);
  renderHash(nodes.hostedManifest, hosted.manifest_root);
  nodes.hostedGeometry.textContent = `${hosted.data_shards}+${hosted.parity_shards} · ${formatDecimal(hosted.stripe_count)} stripes · ${formatDecimal(hosted.share_bytes)} B/share`;
  nodes.hostedSchedulability.textContent = `${hosted.schedulable_minimum} / ${hosted.position_count}`;
  nodes.hostedCustodianMap.replaceChildren(...hosted.custodians.map(renderCustodian));
  const reconstruction = hosted.reconstruction;
  nodes.hostedReconstructionState.textContent = reconstruction.state;
  nodes.hostedReconstructionProgress.max = reconstruction.total_bytes;
  nodes.hostedReconstructionProgress.value = reconstruction.verified_bytes;
  const percent = Math.floor((reconstruction.verified_bytes / reconstruction.total_bytes) * 100);
  nodes.hostedReconstructionProgress.textContent = `${percent}%`;
  nodes.hostedReconstructionCopy.textContent = `${formatDecimal(reconstruction.verified_bytes)} of ${formatDecimal(reconstruction.total_bytes)} bytes independently verified from finalized custodians.`;
  renderHash(nodes.hostedRuntimeRoot, hosted.runtime_root);
  renderHash(nodes.hostedCertificate, hosted.availability_certificate_id);
  nodes.hostedCertificateHorizon.textContent = `#${formatDecimal(hosted.certificate_issued_height)} → #${formatDecimal(hosted.certificate_valid_until_height)}`;
  nodes.hostedFallback.textContent = "FALSE · disabled";
  nodes.hostedFallback.classList.add("proof-good");
  nodes.hostedProofDisclosure.textContent = hosted.ready
    ? "Verified: finalized 17-leaf model graph, 12-position certificate, exact Bonsai geometry, read-only reconstructed GGUF, and pinned Prism runtime. Publisher and gateway artifact fallback are disabled. Validators do not store model weights."
    : `The chain proof is verified, but executor reconstruction is ${reconstruction.state.toLowerCase()}. Query admission remains closed.`;
}

function blockHostedProof(message) {
  runtime.hosted = null;
  nodes.hostedPanel.setAttribute("aria-busy", "false");
  nodes.hostedPanelState.className = "state-flag state-blocked";
  nodes.hostedPanelState.textContent = "Unproved";
  nodes.hostedProofDisclosure.textContent = `${message} No hosting label or fallback is shown.`;
}

function errorText(error) {
  if (error instanceof WwmClientError) return error.code.replaceAll("_", " ");
  if (error instanceof Error) return error.message;
  return "The request failed.";
}

function announce(message) {
  nodes.status.textContent = "";
  requestAnimationFrame(() => { nodes.status.textContent = message; });
}

function setError(message) {
  nodes.inputError.textContent = message;
  nodes.inputError.hidden = !message;
  nodes.input.setAttribute("aria-invalid", message ? "true" : "false");
  if (message) announce(message);
}

function setNetwork(kind, label) {
  nodes.networkState.className = `state-flag state-${kind}`;
  nodes.networkState.textContent = label;
}

function setBusy(busy, label = "Request quote and start remote job") {
  runtime.busy = busy;
  nodes.input.disabled = busy;
  nodes.outputLimit.disabled = busy;
  nodes.escrowAuthorization.disabled = busy;
  document.querySelectorAll('input[name="payment-mode"]').forEach((input) => { input.disabled = busy; });
  nodes.submit.disabled = busy || !runtime.active;
  nodes.submit.querySelector("span").textContent = busy ? label : "Request quote and start remote job";
  nodes.form.setAttribute("aria-busy", String(busy));
}

function showAnswer(view) {
  nodes.answerEmpty.hidden = view !== "empty";
  nodes.answerLoading.hidden = view !== "loading";
  nodes.answerResult.hidden = view !== "result";
}

function updateCount() {
  nodes.inputCount.textContent = `${[...nodes.input.value].length.toLocaleString()} / 12,000`;
  if (nodes.input.value) setError("");
}

function selectedPaymentMode() {
  return document.querySelector('input[name="payment-mode"]:checked')?.value ?? "SPONSORED";
}

function updatePaymentMode() {
  const paid = selectedPaymentMode() === "PAID";
  nodes.escrowLabel.hidden = !paid;
  nodes.escrowHelp.hidden = !paid;
  nodes.paymentLabel.textContent = paid ? "Paid escrow" : "Sponsored";
  document.querySelectorAll(".finality-choice").forEach((choice) => {
    choice.classList.toggle("selected", Boolean(choice.querySelector("input")?.checked));
  });
}

function containsSecret(value) {
  if (Array.isArray(value)) return value.some(containsSecret);
  if (!value || typeof value !== "object") return false;
  return Object.entries(value).some(([key, nested]) => {
    const normalized = key.toLowerCase().replaceAll("-", "_");
    return ["seed", "seed_hex", "mnemonic", "private_key", "secret_key", "spending_key"].includes(normalized)
      || containsSecret(nested);
  });
}

function paymentAuthorization() {
  if (selectedPaymentMode() === "SPONSORED") return "";
  let authorization;
  try { authorization = JSON.parse(nodes.escrowAuthorization.value); } catch { throw new WwmClientError("invalid_escrow_authorization_json"); }
  if (!authorization || typeof authorization !== "object" || Array.isArray(authorization)) {
    throw new WwmClientError("invalid_escrow_authorization");
  }
  if (containsSecret(authorization)) throw new WwmClientError("wallet_secret_forbidden");
  return JSON.stringify(authorization);
}

function renderEvidence(label) {
  const allowed = new Set(["PROVISIONAL_SIGNED", "MATCHED_QUORUM", "MINORITY_DISAGREEMENT", "NO_QUORUM"]);
  if (!allowed.has(label)) throw new WwmClientError("unknown_evidence_state");
  nodes.answerFinality.textContent = label;
  nodes.answerFinality.className = `finality-badge evidence-${label.toLowerCase().replaceAll("_", "-")}`;
  announce(`Execution evidence updated: ${label.replaceAll("_", " ")}.`);
}

function fact(label, value) {
  const wrapper = document.createElement("div");
  const term = document.createElement("dt");
  const description = document.createElement("dd");
  term.textContent = label;
  description.textContent = value;
  wrapper.append(term, description);
  return wrapper;
}

function renderReceipt(receipt) {
  runtime.receipt = receipt;
  if (typeof receipt.evidence_state === "string" && receipt.evidence_state !== "NONE") {
    renderEvidence(receipt.evidence_state);
  }
  nodes.receiptFacts.replaceChildren(
    fact("Job", shortHash(receipt.job_id)),
    fact("Capsule", shortHash(receipt.capsule_id)),
    fact("Evidence", String(receipt.evidence_state ?? "Not declared")),
    fact("Terminal code", String(receipt.terminal_status ?? "Not declared")),
    fact("Chain anchor", String(receipt.chain_anchor ?? "UNANCHORED")),
    fact("Settlement", String(receipt.settlement_state ?? "Not declared")),
  );
  nodes.receiptJson.textContent = JSON.stringify(receipt, null, 2);
  nodes.receiptToggle.disabled = false;
  nodes.cancelJob.disabled = true;
  const receiptPath = `${runtime.client.baseUrl}/jobs/${encodeURIComponent(receipt.job_id)}/receipt`;
  renderProofLink(nodes.hostedReceiptLink, receiptPath, shortHash(receipt.job_id), `Receipt ${receipt.job_id}`);
  renderProofLink(
    nodes.hostedSettlementLink,
    `${receiptPath}#settlement`,
    receipt.chain_anchor ? `${receipt.settlement_state} · ${shortHash(receipt.chain_anchor)}` : String(receipt.settlement_state ?? "PENDING_CHAIN"),
    receipt.chain_anchor ?? "Settlement anchor pending",
  );
  announce(`Verified terminal receipt. Settlement state: ${receipt.settlement_state ?? "not declared"}.`);
}

function toggleReceipt(open) {
  const next = typeof open === "boolean" ? open : nodes.receiptDrawer.hidden;
  nodes.receiptDrawer.hidden = !next;
  nodes.receiptToggle.setAttribute("aria-expanded", String(next));
  if (next) nodes.receiptClose.focus();
}

async function loadState() {
  setNetwork("pending", "Checking proof");
  nodes.activation.textContent = "Fail closed";
  nodes.submit.disabled = true;
  const verifier = globalThis.MindChainWwmVerifier;
  if (!verifier) {
    setNetwork("blocked", "Verifier unavailable");
    nodes.pinDisclosure.textContent = "No independent browser light-client verifier is installed. Gateway proofs_verified flags are ignored; dispatch remains disabled.";
    blockHostedProof("Independent finalized-state verifier unavailable.");
    announce("Independent light-client verifier unavailable. Query disabled.");
    return;
  }
  try {
    runtime.client = new WwmV2Client({
      verifier,
      expectedIdentity: verifier.expectedIdentity,
      baseUrl: "/api/wwm/v2",
    });
    const { state, active, candidate, hosted } = await runtime.client.loadState();
    renderHostedProof(hosted);
    runtime.active = active.dispatchable ? active : null;
    nodes.pinChain.textContent = `${shortHash(hosted.chain_id)} / ${shortHash(hosted.genesis_hash)}`;
    nodes.pinModel.textContent = shortHash(active.capsule_id);
    nodes.pinControl.textContent = "ACTIVE · remote executor edge";
    nodes.pinCandidate.textContent = candidate
      ? `${shortHash(candidate.capsule_id)} · AUTHORIZED, NOT ACTIVE · cannot dispatch`
      : "None published";
    nodes.pinProof.textContent = `Verified resolution ${shortHash(active.resolution_id)}`;
    nodes.pinDisclosure.textContent = state.disclosure
      ?? "Only the proof-verified active capsule may dispatch. A published candidate remains inspectable and non-dispatchable.";
    if (!hosted.ready) {
      nodes.activation.textContent = `${hosted.reconstruction.state} · admission closed`;
      setNetwork("pending", "Executor preparing");
      announce("Finalized model graph verified. Executor reconstruction is not ready; query disabled.");
      return;
    }
    nodes.activation.textContent = "ACTIVE · hosted remote";
    nodes.activation.classList.add("active");
    setNetwork("ready", "Hosted model active");
    setBusy(false);
    announce("MindChain-hosted Bonsai and its finalized custodian proof verified. Remote quoting is available.");
  } catch (error) {
    runtime.active = null;
    runtime.client = null;
    setNetwork("blocked", "Proof rejected");
    nodes.pinDisclosure.textContent = `Verification failed: ${errorText(error)}. No fallback route will be attempted.`;
    blockHostedProof(`Hosted-model verification failed: ${errorText(error)}.`);
    announce("Finalized state verification failed. Query disabled.");
  }
}

async function submitQuery(event) {
  event.preventDefault();
  setError("");
  if (!runtime.client || !runtime.active) {
    setError("Active finalized state has not been independently verified.");
    return;
  }
  const prompt = nodes.input.value.replace(/\r\n/g, "\n").trim();
  if (!prompt) {
    setError("Write a specific question before requesting a quote.");
    nodes.input.focus();
    return;
  }
  runtime.streamAbort?.abort();
  runtime.answer = "";
  runtime.receipt = null;
  runtime.currentJobId = null;
  nodes.answerCopy.textContent = "";
  nodes.receiptFacts.replaceChildren();
  nodes.receiptJson.textContent = "";
  nodes.receiptToggle.disabled = true;
  nodes.cancelJob.disabled = true;
  toggleReceipt(false);
  showAnswer("loading");
  setBusy(true, "Requesting bound quote");
  try {
    const paymentMode = selectedPaymentMode();
    const quoted = await runtime.client.quote(prompt, {
      paymentMode,
      paymentAuthorization: paymentAuthorization(),
      maximumOutputTokens: Number(nodes.outputLimit.value),
    });
    nodes.quoteCeiling.textContent = `${quoted.quote.maximum_fee_micro_noos} micro-NOOS`;
    announce(`Quote received. Maximum fee ${quoted.quote.maximum_fee_micro_noos} micro-NOOS. Opening one active-capsule job.`);
    setBusy(true, "Opening active-capsule job");
    const { job } = await runtime.client.submit(quoted);
    runtime.currentJobId = job.job_id;
    renderProofLink(
      nodes.hostedJobLink,
      `${runtime.client.baseUrl}/jobs/${encodeURIComponent(job.job_id)}/stream`,
      shortHash(job.job_id),
      `Job ${job.job_id}`,
    );
    nodes.hostedReceiptLink.textContent = "Awaiting terminal receipt";
    nodes.hostedSettlementLink.textContent = "Awaiting chain settlement";
    runtime.streamAbort = new AbortController();
    nodes.cancelJob.disabled = false;
    showAnswer("result");
    nodes.answerFinality.textContent = "AWAITING_SIGNED_EVENT";
    nodes.answerFinality.className = "finality-badge";
    await runtime.client.stream(job.job_id, async (streamEvent) => {
      const payload = streamEvent.payload;
      const data = payload.data;
      if (payload.type === "output.delta") {
        if (typeof data.delta !== "string" || typeof data.evidence_state !== "string") {
          throw new WwmClientError("unsigned_output_delta");
        }
        runtime.answer += data.delta;
        nodes.answerCopy.textContent = runtime.answer;
        renderEvidence(data.evidence_state);
      } else if (payload.type === "evidence.updated") {
        renderEvidence(data.evidence_state);
      } else if (payload.type === "receipt.completed") {
        renderReceipt(data);
      } else {
        throw new WwmClientError("unknown_stream_event");
      }
    }, { signal: runtime.streamAbort.signal });
  } catch (error) {
    if (runtime.streamAbort?.signal.aborted) return;
    setError(`${errorText(error)}. No alternate route or local fallback was attempted.`);
    if (!runtime.answer) showAnswer("empty");
  } finally {
    setBusy(false);
    nodes.cancelJob.disabled = !runtime.currentJobId || Boolean(runtime.receipt);
  }
}

async function cancelCurrentJob() {
  if (!runtime.client || !runtime.currentJobId || runtime.receipt) return;
  nodes.cancelJob.disabled = true;
  nodes.cancelJob.setAttribute("aria-busy", "true");
  try {
    await runtime.client.cancel(runtime.currentJobId);
    announce("Cancellation accepted. The executor will emit a terminal receipt or refund record.");
  } catch (error) {
    setError(`Cancellation failed: ${errorText(error)}. The client did not submit another job.`);
    nodes.cancelJob.disabled = false;
  } finally {
    nodes.cancelJob.removeAttribute("aria-busy");
  }
}

nodes.input.addEventListener("input", updateCount);
nodes.form.addEventListener("submit", submitQuery);
document.querySelectorAll('input[name="payment-mode"]').forEach((input) => input.addEventListener("change", updatePaymentMode));
nodes.cancelJob.addEventListener("click", () => { void cancelCurrentJob(); });
nodes.receiptToggle.addEventListener("click", () => toggleReceipt());
nodes.receiptClose.addEventListener("click", () => { toggleReceipt(false); nodes.receiptToggle.focus(); });
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !nodes.receiptDrawer.hidden) {
    event.preventDefault();
    toggleReceipt(false);
    nodes.receiptToggle.focus();
  }
});
window.addEventListener("beforeunload", () => {
  runtime.streamAbort?.abort();
  capacity.controller?.pause();
  capacity.worker?.postMessage({ op: "pause" });
}, { once: true });

// Web capacity — browser advisory cache. Everything below the opt-in click is
// inert: no worker, no controller, no storage estimate, no fetch, no hashing.
const capacity = {
  controller: null,
  worker: null,
  timer: null,
  workerSeq: 0,
  storedShares: 0,
  heartbeatBusy: false,
};
const CAPACITY_HEARTBEAT_MS = 45_000;

function selectedQuotaShares() {
  return Number(document.querySelector('input[name="capacity-quota"]:checked')?.value ?? 16);
}

function setCapacityState(kind, label) {
  nodes.capacityState.className = `state-flag state-${kind}`;
  nodes.capacityState.textContent = label;
}

function setCapacityError(message) {
  nodes.capacityError.textContent = message;
  nodes.capacityError.hidden = !message;
}

function setCapacityNote(message) {
  nodes.capacityNote.textContent = message;
}

// Pure DOM state before opt-in: label text and radio highlight only.
function updateCapacityChoice() {
  const shares = selectedQuotaShares();
  nodes.capacityOptIn.querySelector("span").textContent = `Opt in — lend up to ${shares} shares`;
  document.querySelectorAll('#capacity-quota .finality-choice').forEach((choice) => {
    choice.classList.toggle("selected", Boolean(choice.querySelector("input")?.checked));
  });
}

function updateCapacityRepairChoice() {
  nodes.capacityEgressCap.disabled = !nodes.capacityRepair.checked || capacity.controller !== null;
}

function renderCapacityBytes(summary) {
  nodes.capacityEstimated.textContent = `${formatDecimal(Math.max(0, summary.estimatedQuotaBytes - summary.estimatedUsageBytes))} bytes (estimate)`;
  nodes.capacityEffective.textContent = `${formatDecimal(summary.effectiveBytes)} bytes · ${summary.effectiveShares} shares`;
  nodes.capacityClass.textContent = summary.storageClass === "OPFS" ? "OPFS · app directory" : "IndexedDB · fallback";
}

async function renderCapacityActual() {
  if (!capacity.controller?.store) return;
  const actual = await capacity.controller.store.usageBytes();
  const shares = await capacity.controller.store.listShares();
  capacity.storedShares = shares.length;
  nodes.capacityActual.textContent = `${formatDecimal(actual)} bytes · ${shares.length} shares (actual)`;
}

function capacityErrorText(error) {
  if (error instanceof WebCapacityError) return error.code.replaceAll("_", " ");
  if (error instanceof Error) return error.message;
  return "The request failed.";
}

function capacityPageActive() {
  return document.visibilityState === "visible";
}

// Bridges controller download requests to the dedicated worker, which fetches
// at concurrency 2, verifies length + transport SHA-256, and persists bytes.
function capacityWorkerDownloader(rows, { signal } = {}) {
  return new Promise((resolve, reject) => {
    capacity.workerSeq += 1;
    const id = capacity.workerSeq;
    const worker = capacity.worker;
    const onAbort = () => worker.postMessage({ op: "pause" });
    const onMessage = (event) => {
      const message = event.data;
      if (!message || message.id !== id) return;
      if (message.op === "progress") {
        setCapacityNote(`Verifying and storing shares: ${message.stored} stored, ${message.failed} failed of ${message.total}.`);
        return;
      }
      worker.removeEventListener("message", onMessage);
      signal?.removeEventListener("abort", onAbort);
      if (message.op === "done") resolve({ stored: message.stored, failed: message.failed });
      else reject(new WebCapacityError(message.code ?? "worker_download_failed"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    worker.addEventListener("message", onMessage);
    worker.postMessage({ op: "download", id, rows });
  });
}

async function capacityHeartbeatTick() {
  const controller = capacity.controller;
  if (!controller || controller.paused || capacity.heartbeatBusy || !capacityPageActive()) return;
  capacity.heartbeatBusy = true;
  try {
    const outcome = await controller.heartbeat();
    if (outcome.kind === "assignment") {
      await renderCapacityActual();
      setCapacityNote(`Assignment complete: ${outcome.stored.length} shares stored, ${outcome.failed.length} rejected. Polling continues only while this page stays open.`);
    } else if (outcome.kind === "restore") {
      setCapacityNote(outcome.uploaded
        ? `Restore upload sent: ${formatDecimal(outcome.uploaded)} bytes against your daily cap.`
        : `Restore task skipped: ${String(outcome.skipped).replaceAll("_", " ").toLowerCase()}.`);
    }
  } catch (error) {
    if (capacity.controller) setCapacityNote(`Heartbeat paused: ${capacityErrorText(error)}. No retry happens off this page.`);
  } finally {
    capacity.heartbeatBusy = false;
  }
}

async function capacityOptIn(event) {
  event.preventDefault();
  if (capacity.controller) return;
  setCapacityError("");
  nodes.capacityOptIn.disabled = true;
  setCapacityState("pending", "Opting in");
  try {
    if (!("Worker" in window)) throw new WebCapacityError("worker_unavailable");
    capacity.worker = new Worker(new URL("./wwm/web-capacity-worker.mjs", import.meta.url), { type: "module" });
    const controller = new WebCapacityController({
      baseUrl: "/api/wwm-web-capacity/v1",
      origin: location.origin,
      fetchImpl: (...args) => fetch(...args),
      cryptoImpl: crypto,
      openStore: () => openCapacityStore({ storage: navigator.storage, indexedDb: indexedDB }),
      estimateImpl: () => navigator.storage.estimate(),
      persistImpl: () => navigator.storage.persist(),
      pageActive: capacityPageActive,
      downloader: capacityWorkerDownloader,
      expectedIdentity: runtime.hosted
        ? { chain_id: runtime.hosted.chain_id, genesis_hash: runtime.hosted.genesis_hash }
        : null,
    });
    const summary = await controller.optIn({
      quotaShares: selectedQuotaShares(),
      uploadEnabled: nodes.capacityRepair.checked,
      dailyEgressBytes: nodes.capacityRepair.checked ? Number(nodes.capacityEgressCap.value) : 0,
    });
    capacity.controller = controller;
    renderCapacityBytes(summary);
    await renderCapacityActual();
    nodes.capacityPanel.dataset.state = "active";
    setCapacityState("ready", "Advisory cache active");
    nodes.capacityControls.hidden = false;
    nodes.capacityPersistence.hidden = false;
    nodes.capacityForm.querySelectorAll('input[name="capacity-quota"]').forEach((input) => { input.disabled = true; });
    nodes.capacityRepair.disabled = true;
    nodes.capacityEgressCap.disabled = true;
    nodes.capacityDormantControls.hidden = true;
    setCapacityNote(summary.uploadEnabled
      ? `Opted in. Repair uploads capped at ${formatDecimal(summary.dailyEgressBytes)} bytes per day. Heartbeats run only while this page is open.`
      : "Opted in. Repair uploads stay off. Heartbeats run only while this page is open.");
    capacity.timer = setInterval(() => { void capacityHeartbeatTick(); }, CAPACITY_HEARTBEAT_MS);
    void capacityHeartbeatTick();
  } catch (error) {
    capacity.worker?.terminate();
    capacity.worker = null;
    capacity.controller = null;
    nodes.capacityOptIn.disabled = false;
    setCapacityState("blocked", "Not participating");
    setCapacityError(`Opt-in failed: ${capacityErrorText(error)}. Local capacity state was cleared; any partially created session was revoked where the coordinator was reachable.`);
    setCapacityNote("Dormant. This page has made no storage estimate, download, hash, heartbeat, or upload for web capacity.");
  }
}

async function capacityKeepCopies() {
  if (!capacity.controller) return;
  nodes.capacityKeep.disabled = true;
  try {
    const mode = await capacity.controller.keepCopies();
    nodes.capacityPersistence.textContent = mode === "persistent"
      ? "Persistence granted: the browser will avoid evicting these copies."
      : "Persistence declined by the browser: copies remain best effort and evictable.";
  } finally {
    nodes.capacityKeep.disabled = false;
  }
}

function capacityTogglePause() {
  const controller = capacity.controller;
  if (!controller) return;
  if (controller.paused) {
    controller.resume();
    nodes.capacityPause.textContent = "Pause";
    nodes.capacityPanel.dataset.state = "active";
    setCapacityState("ready", "Advisory cache active");
    setCapacityNote("Resumed. Heartbeats run only while this page is open.");
  } else {
    controller.pause();
    capacity.worker?.postMessage({ op: "pause" });
    nodes.capacityPause.textContent = "Resume";
    nodes.capacityPanel.dataset.state = "paused";
    setCapacityState("pending", "Paused");
    setCapacityNote("Paused. Outstanding downloads and uploads were aborted; nothing runs until you resume.");
  }
}

// Deletion is local-first and works offline: it removes only the app-owned
// noos-wwm-cache-v1 namespace and session token, then tries a best-effort
// revoke. Publicly served Apache-2.0 share bytes may remain in third-party
// caches; the UI never promises erasure there.
async function capacityDeleteCopies() {
  const controller = capacity.controller;
  if (!controller) return;
  nodes.capacityDelete.disabled = true;
  clearInterval(capacity.timer);
  capacity.timer = null;
  capacity.worker?.postMessage({ op: "pause" });
  try {
    const result = await controller.deleteAllCopies();
    capacity.worker?.terminate();
    capacity.worker = null;
    capacity.controller = null;
    capacity.storedShares = 0;
    nodes.capacityPanel.dataset.state = "dormant";
    setCapacityState("pending", "Dormant");
    nodes.capacityControls.hidden = true;
    nodes.capacityPersistence.hidden = true;
    nodes.capacityPersistence.textContent = "Copies are best effort until you choose “Keep copies”.";
    nodes.capacityActual.textContent = "0 bytes";
    nodes.capacityEstimated.textContent = "Not measured";
    nodes.capacityEffective.textContent = "Not measured";
    nodes.capacityClass.textContent = "Not opened";
    nodes.capacityOptIn.disabled = false;
    nodes.capacityPause.textContent = "Pause";
    nodes.capacityForm.querySelectorAll('input[name="capacity-quota"]').forEach((input) => { input.disabled = false; });
    nodes.capacityRepair.disabled = false;
    nodes.capacityDormantControls.hidden = false;
    updateCapacityRepairChoice();
    setCapacityNote(result.revoked
      ? "Deleted. Local copies and session token are gone; the coordinator revoked the session."
      : "Deleted. Local copies and session token are gone. The coordinator was unreachable, but local deletion never depends on it.");
  } finally {
    nodes.capacityDelete.disabled = false;
  }
}

// Session-less deletion for copies left behind by a crash or reload: touches
// storage only on click, removes only the app-owned noos-wwm-cache-v1
// namespace in both backends, works offline without coordinator or session,
// and never promises erasure from third-party caches.
async function capacityPurgeStale() {
  if (capacity.controller) return;
  nodes.capacityPurge.disabled = true;
  setCapacityError("");
  try {
    const result = await purgeCapacityNamespace({ storage: navigator.storage, indexedDb: indexedDB });
    if (result.sessionToken) {
      try {
        await fetch("/api/wwm-web-capacity/v1/revoke", {
          method: "POST",
          mode: "cors",
          credentials: "omit",
          redirect: "error",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            schema: "noos/wwm-web-capacity/v1",
            record_kind: "REVOCATION_REQUEST",
            session_token: result.sessionToken,
            canonical_origin: location.origin,
            local_deletion_requested: true,
          }),
        });
      } catch {
        // Best effort only; local deletion above is already complete.
      }
    }
    nodes.capacityActual.textContent = "0 bytes";
    setCapacityNote(result.removed
      ? "Earlier copies deleted. Only the app-owned noos-wwm-cache-v1 namespace and its session token were removed; bytes already served publicly may remain in third-party caches."
      : "No earlier copies were found. Nothing was stored under noos-wwm-cache-v1.");
  } finally {
    nodes.capacityPurge.disabled = false;
  }
}

nodes.capacityForm.addEventListener("submit", (event) => { void capacityOptIn(event); });
document.querySelectorAll('input[name="capacity-quota"]').forEach((input) => input.addEventListener("change", updateCapacityChoice));
nodes.capacityRepair.addEventListener("change", updateCapacityRepairChoice);
nodes.capacityKeep.addEventListener("click", () => { void capacityKeepCopies(); });
nodes.capacityPause.addEventListener("click", capacityTogglePause);
nodes.capacityDelete.addEventListener("click", () => { void capacityDeleteCopies(); });
nodes.capacityPurge.addEventListener("click", () => { void capacityPurgeStale(); });
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible" && capacity.controller && !capacity.controller.paused) {
    void capacityHeartbeatTick();
  }
});

updateCount();
updatePaymentMode();
showAnswer("empty");
updateCapacityChoice();
updateCapacityRepairChoice();
void loadState();
