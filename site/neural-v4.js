import {
  assertManifest,
  shortHash,
  validateGatewayHealth,
  validateIndexedTransaction,
  validateLifecycle,
  validateModelResolution,
  validateMonitorReadiness,
  verifyMonitorEnvelope,
} from "./neural-core-v3.mjs";

const SVG_NS = "http://www.w3.org/2000/svg";
const RETRY_DELAY_MS = 6_000;
const STAGES = [
  "Input committed",
  "Custody available",
  "Model resident",
  "Executors ran",
  "Output committed",
  "Lifecycle finalized",
];

const elements = {
  instrument: document.querySelector(".neural-instrument"),
  liveRibbon: document.querySelector(".live-ribbon"),
  liveState: document.querySelector("#live-state"),
  finalizedHeight: document.querySelector("#finalized-height"),
  proofState: document.querySelector("#proof-state"),
  monitorTime: document.querySelector("#monitor-time"),
  instrumentSummary: document.querySelector("#instrument-summary"),
  graphPending: document.querySelector("#graph-pending"),
  pendingDetail: document.querySelector("#pending-detail"),
  edgeLayer: document.querySelector("#edge-layer"),
  nodeLayer: document.querySelector("#node-layer"),
  graphHeight: document.querySelector("#graph-height"),
  graphRoot: document.querySelector("#graph-root"),
  metricCustody: document.querySelector("#metric-custody"),
  metricExecutors: document.querySelector("#metric-executors"),
  metricOutput: document.querySelector("#metric-output"),
  replayStage: document.querySelector("#replay-stage"),
  replaySlider: document.querySelector("#replay-slider"),
  replayPrevious: document.querySelector("#replay-previous"),
  replayPlay: document.querySelector("#replay-play"),
  replayNext: document.querySelector("#replay-next"),
  inspectorNumber: document.querySelector("#inspector-number"),
  inspectorKind: document.querySelector("#inspector-kind"),
  inspectorTitle: document.querySelector("#inspector-title"),
  inspectorCopy: document.querySelector("#inspector-copy"),
  inspectorLabelA: document.querySelector("#inspector-label-a"),
  inspectorValueA: document.querySelector("#inspector-value-a"),
  inspectorLabelB: document.querySelector("#inspector-label-b"),
  inspectorValueB: document.querySelector("#inspector-value-b"),
  inspectorLabelC: document.querySelector("#inspector-label-c"),
  inspectorValueC: document.querySelector("#inspector-value-c"),
  copyIdentity: document.querySelector("#copy-identity"),
  disclosureList: document.querySelector("#disclosure-list"),
  footerIdentity: document.querySelector("#footer-identity"),
  transactionLink: document.querySelector("#transaction-link"),
  indexerSummary: document.querySelector("#indexer-summary"),
  indexerList: document.querySelector("#indexer-list"),
  activitySummary: document.querySelector("#activity-summary"),
  activityList: document.querySelector("#activity-list"),
  fatalBanner: document.querySelector("#fatal-banner"),
  fatalMessage: document.querySelector("#fatal-message"),
  retryLoad: document.querySelector("#retry-load"),
};

const proofElements = Object.fromEntries(
  ["model", "job", "receipt", "settlement"].map((kind) => [
    kind,
    {
      row: document.querySelector(`[data-proof="${kind}"]`),
      state: document.querySelector(`#proof-${kind}-state`),
      button: document.querySelector(`[data-download="${kind}"]`),
    },
  ]),
);

const state = {
  manifest: null,
  gateway: null,
  model: null,
  monitor: null,
  records: null,
  activities: [],
  indexers: [],
  graphNodes: [],
  graphEdges: [],
  selectedNode: null,
  stage: 0,
  view: "all",
  playTimer: null,
  retryTimer: null,
  loading: false,
};

class HttpError extends Error {
  constructor(url, status, detail) {
    super(`${url} returned HTTP ${status}${detail ? `: ${detail}` : ""}`);
    this.status = status;
  }
}

async function fetchJson(url) {
  const response = await fetch(url, {
    cache: "no-store",
    headers: { Accept: "application/json" },
  });
  if (!response.ok) {
    let detail = "";
    try {
      const body = await response.json();
      detail = body?.error?.detail || body?.error?.message || body?.message || "";
    } catch {
      detail = "";
    }
    throw new HttpError(url, response.status, detail);
  }
  const value = await response.json();
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${url} returned a non-object`);
  }
  return value;
}

function setText(element, value) {
  element.textContent = String(value);
}

function formatHeight(value) {
  return `#${Number(value).toLocaleString("en-US")}`;
}

function formatMonitorTime(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "Signature valid";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function renderManifest(manifest) {
  setText(elements.metricCustody, manifest.topology.custody_positions);
  setText(elements.metricExecutors, manifest.topology.executor_profiles);
  setText(elements.metricOutput, manifest.inference.output_tokens);
  setText(document.querySelector("#proof-model-id"), shortHash(manifest.model.capsule_id, 12, 10));
  setText(document.querySelector("#proof-job-id"), shortHash(manifest.inference.job_id, 12, 10));
  setText(document.querySelector("#proof-receipt-id"), shortHash(manifest.inference.output_root, 12, 10));
  setText(document.querySelector("#proof-settlement-id"), shortHash(manifest.inference.settlement_id, 12, 10));
  elements.transactionLink.href = `${manifest.indexer_origins[1]}/api/v1/transactions/${manifest.inference.transaction_id}`;
  elements.disclosureList.replaceChildren(
    ...manifest.disclosures.map((disclosure) => {
      const item = document.createElement("li");
      item.textContent = disclosure;
      return item;
    }),
  );
  setText(
    elements.footerIdentity,
    `${shortHash(manifest.chain_id, 10, 8)} / genesis ${shortHash(manifest.genesis_hash, 10, 8)}`,
  );
}
function renderActivity(activities, manifest) {
  const rows = activities.map(({ inference, records }, index) => {
    const item = document.createElement("li");
    item.className = "activity-row";
    if (index === 0) item.classList.add("is-latest");

    const sequence = document.createElement("span");
    sequence.className = "activity-sequence";
    sequence.textContent = String(inference.sequence).padStart(2, "0");

    const identity = document.createElement("div");
    identity.className = "activity-identity";
    const label = document.createElement("span");
    label.textContent = index === 0 ? `${inference.label} / graph above` : inference.label;
    const title = document.createElement("strong");
    title.textContent = `Job ${shortHash(inference.job_id, 10, 8)}`;
    identity.append(label, title);

    const execution = document.createElement("div");
    execution.className = "activity-fact";
    const executionLabel = document.createElement("span");
    executionLabel.textContent = "Execution";
    const executionValue = document.createElement("strong");
    executionValue.textContent = `${(inference.duration_milliseconds / 1_000).toFixed(1)}s / ${inference.output_tokens} tokens`;
    execution.append(executionLabel, executionValue);

    const commitment = document.createElement("div");
    commitment.className = "activity-fact activity-commitment";
    const commitmentLabel = document.createElement("span");
    commitmentLabel.textContent = "Output root";
    const commitmentValue = document.createElement("code");
    commitmentValue.textContent = shortHash(inference.output_root, 12, 10);
    commitment.append(commitmentLabel, commitmentValue);

    const finality = document.createElement("div");
    finality.className = "activity-finality";
    const dot = document.createElement("i");
    dot.setAttribute("aria-hidden", "true");
    const recordHeight = Math.min(
      records.job.finalized_height,
      records.receipt.finalized_height,
      records.settlement.finalized_height,
    );
    const finalityText = document.createElement("strong");
    finalityText.textContent = `Finalized ${formatHeight(recordHeight)}`;
    finality.append(dot, finalityText);

    const link = document.createElement("a");
    link.href = `${manifest.indexer_origins[1]}/api/v1/transactions/${inference.transaction_id}`;
    link.target = "_blank";
    link.rel = "noreferrer";
    link.textContent = "Open transaction";

    item.append(sequence, identity, execution, commitment, finality, link);
    return item;
  });
  elements.activityList.replaceChildren(...rows);
  setText(
    elements.activitySummary,
    `${activities.length} finalized neural ${activities.length === 1 ? "run" : "runs"}`,
  );
}


function renderIndexerResults(results) {
  const items = results.map((result, index) => {
    const item = document.createElement("li");
    const name = document.createElement("span");
    const status = document.createElement("strong");
    name.textContent = `Seed 0${index + 1}`;
    if (result.ok) {
      item.classList.add("is-verified");
      status.textContent = `Included #${Number(result.value.inclusion.height).toLocaleString("en-US")}`;
    } else {
      status.textContent = "Unavailable";
    }
    item.append(name, status);
    return item;
  });
  elements.indexerList.replaceChildren(...items);
  const verified = results.filter((result) => result.ok).length;
  setText(elements.indexerSummary, `Verified ${verified} / ${results.length}`);
}

async function fetchIndexers(manifest) {
  const path = `/api/v1/transactions/${manifest.inference.transaction_id}`;
  const settled = await Promise.allSettled(
    manifest.indexer_origins.map((origin) => fetchJson(origin + path)),
  );
  const results = settled.map((result) => {
    if (result.status === "rejected") return { ok: false, error: result.reason };
    try {
      return { ok: true, value: validateIndexedTransaction(result.value, manifest) };
    } catch (error) {
      return { ok: false, error };
    }
  });
  renderIndexerResults(results);
  if (results.some((result) => !result.ok)) {
    throw new Error("not all three public indexers confirm the inference transaction");
  }
  return results;
}

function pendingFinality(indexers) {
  const included = indexers.find((result) => result.ok)?.value?.inclusion?.height;
  setText(
    elements.pendingDetail,
    included
      ? `Included at #${Number(included).toLocaleString("en-US")}. Waiting for finalized sparse-Merkle proofs.`
      : "Waiting for finalized sparse-Merkle proofs.",
  );
  setText(elements.liveState, "INCLUDED / FINALIZING");
  setText(elements.proofState, "Awaiting finality");
  setText(elements.instrumentSummary, "The live worker completed this inference and all public indexes include it. The explorer will unlock when its on-chain records finalize.");
  elements.liveRibbon.classList.remove("is-live");
  elements.graphPending.classList.remove("is-hidden");
  elements.graphPending.setAttribute("aria-hidden", "false");
  elements.instrument.setAttribute("aria-busy", "true");
}

function showFailure(error, pending = false) {
  elements.fatalBanner.hidden = false;
  setText(
    elements.fatalMessage,
    pending
      ? "The transaction is included; finalized proofs are not available yet. Retrying automatically."
      : `${error.message || "Verification failed"}. Retrying automatically.`,
  );
}

function clearFailure() {
  elements.fatalBanner.hidden = true;
}

function scheduleRetry() {
  window.clearTimeout(state.retryTimer);
  state.retryTimer = window.setTimeout(() => loadLiveData(), RETRY_DELAY_MS);
}

function proofRecordUrls(inference) {
  return {
    job: `/api/wwm-record/job/${inference.job_id}`,
    receipt: `/api/wwm-record/receipt/${inference.receipt_id}`,
    settlement: `/api/wwm-record/settlement/${inference.settlement_id}`,
  };
}

async function fetchActivityProofs(manifest) {
  return Promise.all(
    manifest.activity.map(async (inference) => {
      const urls = proofRecordUrls(inference);
      const [job, receipt, settlement] = await Promise.all([
        fetchJson(urls.job),
        fetchJson(urls.receipt),
        fetchJson(urls.settlement),
      ]);
      const records = validateLifecycle(
        { job, receipt, settlement },
        { ...manifest, inference },
      );
      return { inference, records };
    }),
  );
}

async function loadLiveData() {
  if (state.loading) return;
  state.loading = true;
  window.clearTimeout(state.retryTimer);
  try {
    const manifest = assertManifest(await fetchJson("neural-manifest.json"));
    state.manifest = manifest;
    renderManifest(manifest);

    const [gateway, model, monitorEnvelope, indexers] = await Promise.all([
      fetchJson("/healthz").then((value) => validateGatewayHealth(value, manifest)),
      fetchJson(`/api/model-resolution/${manifest.model.alias}`).then((value) => validateModelResolution(value, manifest)),
      fetchJson("/api/network-status").then(async (value) =>
        validateMonitorReadiness(await verifyMonitorEnvelope(value, manifest.monitor_signer_key_id))),
      fetchIndexers(manifest),
    ]);
    state.gateway = gateway;
    state.model = model;
    state.monitor = monitorEnvelope;
    state.indexers = indexers;
    setText(elements.finalizedHeight, formatHeight(gateway.finalized.epoch * 256));
    setText(elements.monitorTime, formatMonitorTime(monitorEnvelope.observed_at_utc));

    let activities;
    try {
      activities = await fetchActivityProofs(manifest);
    } catch (error) {
      if (error instanceof HttpError && error.status === 404) {
        pendingFinality(indexers);
        showFailure(error, true);
        scheduleRetry();
        return;
      }
      throw error;
    }

    state.activities = activities;
    state.records = activities[0].records;
    renderActivity(activities, manifest);
    renderVerified();
    clearFailure();
  } catch (error) {
    console.error("Neural explorer verification failed", error);
    setText(elements.liveState, "PROOF UNAVAILABLE");
    setText(elements.proofState, "Fail closed");
    elements.liveRibbon.classList.remove("is-live");
    elements.graphPending.classList.remove("is-hidden");
    elements.graphPending.setAttribute("aria-hidden", "false");
    elements.instrument.setAttribute("aria-busy", "true");
    showFailure(error, false);
    scheduleRetry();
  } finally {
    state.loading = false;
  }
}

function markProof(kind, text) {
  const item = proofElements[kind];
  item.row.classList.add("is-verified");
  item.state.textContent = text;
  item.button.disabled = false;
}

function renderVerified() {
  const { manifest, gateway, model, monitor, records, activities } = state;
  const recordHeight = Math.min(
    records.job.finalized_height,
    records.receipt.finalized_height,
    records.settlement.finalized_height,
  );
  elements.liveRibbon.classList.add("is-live");
  setText(elements.liveState, "LIVE / TESTNET");
  setText(elements.finalizedHeight, formatHeight(Math.max(recordHeight, gateway.finalized.epoch * 256)));
  setText(elements.proofState, "Full node verified");
  setText(elements.monitorTime, formatMonitorTime(monitor.observed_at_utc));
  setText(elements.instrumentSummary, `The exact model graph is active and ${activities.length} finalized neural ${activities.length === 1 ? "run is" : "runs are"} available below.`);
  setText(elements.graphHeight, `Finalized ${formatHeight(recordHeight)}`);
  setText(elements.graphRoot, `Objects ${shortHash(records.receipt.objects_root, 8, 6)}`);
  elements.graphPending.classList.add("is-hidden");
  elements.graphPending.setAttribute("aria-hidden", "true");
  elements.instrument.setAttribute("aria-busy", "false");

  markProof("model", `${model.proof_count} leaves verified`);
  markProof("job", `Finalized ${formatHeight(records.job.finalized_height)}`);
  markProof("receipt", `Finalized ${formatHeight(records.receipt.finalized_height)}`);
  markProof("settlement", `Finalized ${formatHeight(records.settlement.finalized_height)}`);
  buildGraph();
  setStage(0);
}

function svgElement(name, attributes = {}) {
  const element = document.createElementNS(SVG_NS, name);
  for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
  return element;
}

function nodeInfo(id, kind, label, x, y, stage, details) {
  return { id, kind, label, x, y, stage, details };
}

function buildGraph() {
  const { manifest, model, records } = state;
  const nodes = [];
  for (let index = 0; index < manifest.inference.input_tokens; index += 1) {
    nodes.push(nodeInfo(
      `input-${index}`,
      "input",
      `IN ${String(index + 1).padStart(2, "0")}`,
      95,
      215 + index * 82,
      0,
      {
        title: `Committed input slot ${index + 1}`,
        copy: "The chain stores a client commitment and token bounds, never the prompt text.",
        identity: manifest.inference.prompt_commitment,
        labelA: "Prompt commitment",
        valueA: manifest.inference.prompt_commitment,
        labelB: "Bound",
        valueB: `${manifest.inference.input_tokens} input tokens`,
        labelC: "Privacy",
        valueC: "Prompt text absent on chain",
      },
    ));
  }

  model.active.custodian_profiles.forEach((profile, index) => {
    const angle = -Math.PI * 0.82 + (index / (model.active.custodian_profiles.length - 1)) * Math.PI * 1.64;
    nodes.push(nodeInfo(
      `custody-${index}`,
      "custody",
      `C${String(index + 1).padStart(2, "0")}`,
      505 + Math.cos(angle) * 235,
      305 + Math.sin(angle) * 225,
      1,
      {
        title: `Custody position ${String(index + 1).padStart(2, "0")}`,
        copy: "A finalized active profile in the twelve-position availability certificate.",
        identity: profile.profile_id,
        labelA: "Profile ID",
        valueA: profile.profile_id,
        labelB: "Endpoint root",
        valueB: profile.endpoint_root,
        labelC: "Certificate state",
        valueC: profile.status === 0 ? "Active testnet position" : `Status ${profile.status}`,
      },
    ));
  });

  nodes.push(nodeInfo(
    "model",
    "model",
    "BONSAI 27B",
    505,
    305,
    2,
    {
      title: "Bonsai-27B Q1 capsule",
      copy: "The resident off-chain GGUF selected by a finalized capsule, policy, custody certificate, and execution profile.",
      identity: manifest.model.capsule_id,
      labelA: "Capsule ID",
      valueA: manifest.model.capsule_id,
      labelB: "Artifact SHA-256",
      valueB: manifest.model.artifact_sha256,
      labelC: "Resolution",
      valueC: `Active testnet / ${model.proof_count} leaves verified`,
    },
  ));

  model.active.executor_profile_ids.forEach((profileId, index) => {
    const column = index % 2;
    const row = Math.floor(index / 2);
    nodes.push(nodeInfo(
      `executor-${index}`,
      "executor",
      `E${String(index + 1).padStart(2, "0")}`,
      785 + column * 105,
      155 + row * 105,
      3,
      {
        title: `Executor profile ${String(index + 1).padStart(2, "0")}`,
        copy: index < manifest.topology.selected_executors
          ? "Selected by this bounded testnet job and bound to the finalized execution profile."
          : "Available in the finalized executor set; not selected for this receipt.",
        identity: profileId,
        labelA: "Executor ID",
        valueA: profileId,
        labelB: "Execution profile",
        valueB: manifest.model.execution_profile_id,
        labelC: "Job role",
        valueC: index < manifest.topology.selected_executors ? "Selected" : "Available",
      },
    ));
  });

  for (let index = 0; index < manifest.inference.output_tokens; index += 1) {
    nodes.push(nodeInfo(
      `output-${index}`,
      "output",
      String(index + 1).padStart(2, "0"),
      1000 + (index % 4) * 52,
      220 + Math.floor(index / 4) * 58,
      4,
      {
        title: `Committed output slot ${String(index + 1).padStart(2, "0")}`,
        copy: "Token text remains off chain. The receipt binds the complete output and token history commitments.",
        identity: manifest.inference.output_root,
        labelA: "Output root",
        valueA: manifest.inference.output_root,
        labelB: "Token history root",
        valueB: manifest.inference.token_history_root,
        labelC: "Receipt state",
        valueC: "Complete / finalized",
      },
    ));
  }

  const proofNodes = [
    ["proof-job", "JOB", 380, records.job, manifest.inference.job_id, 0, "Committed request", "The bounded job ties the client commitment to the active capsule, policy, and selected executors."],
    ["proof-receipt", "RECEIPT", 600, records.receipt, manifest.inference.receipt_id, 4, "Output receipt", "The execution receipt binds the exact output and token history roots without publishing token text."],
    ["proof-settlement", "SETTLED", 820, records.settlement, manifest.inference.settlement_id, 5, "Closed lifecycle", "The fixture settlement closes the job lifecycle with zero reserved, paid, and refunded value."],
  ];
  proofNodes.forEach(([id, label, x, proof, identity, stage, title, copy]) => {
    nodes.push(nodeInfo(
      id,
      "proof",
      label,
      x,
      610,
      stage,
      {
        title,
        copy,
        identity,
        labelA: "Record ID",
        valueA: identity,
        labelB: "Objects root",
        valueB: proof.objects_root,
        labelC: "Finalized checkpoint",
        valueC: `${formatHeight(proof.finalized_height)} / ${shortHash(proof.finalized_hash, 10, 8)}`,
      },
    ));
  });

  const byId = new Map(nodes.map((node) => [node.id, node]));
  const edges = [];
  const connect = (from, to, kind, stage) => edges.push({ from, to, kind, stage });
  for (let index = 0; index < manifest.inference.input_tokens; index += 1) connect(`input-${index}`, "model", "signal", 0);
  for (let index = 0; index < model.active.custodian_profiles.length; index += 1) connect(`custody-${index}`, "model", "custody", 1);
  for (let index = 0; index < model.active.executor_profile_ids.length; index += 1) connect("model", `executor-${index}`, "signal", 3);
  for (let index = 0; index < manifest.inference.output_tokens; index += 1) connect(`executor-${index % manifest.topology.selected_executors}`, `output-${index}`, "signal", 4);
  connect("proof-job", "model", "proof", 0);
  connect("model", "proof-receipt", "proof", 4);
  connect("proof-receipt", "proof-settlement", "proof", 5);

  elements.edgeLayer.replaceChildren();
  elements.nodeLayer.replaceChildren();
  addGraphLabels();
  edges.forEach((edge, index) => {
    const source = byId.get(edge.from);
    const target = byId.get(edge.to);
    const middleX = (source.x + target.x) / 2;
    const path = svgElement("path", {
      d: `M ${source.x} ${source.y} C ${middleX} ${source.y}, ${middleX} ${target.y}, ${target.x} ${target.y}`,
      class: `graph-edge edge-${edge.kind}`,
      "data-stage": edge.stage,
      "data-kind": edge.kind,
      "data-edge": index,
    });
    elements.edgeLayer.append(path);
    edge.element = path;
  });
  nodes.forEach((node, index) => {
    const group = svgElement("g", {
      class: `graph-node kind-${node.kind}`,
      transform: `translate(${node.x} ${node.y})`,
      tabindex: "0",
      role: "button",
      "aria-label": `${node.details.title}. ${node.details.valueC}`,
      "data-stage": node.stage,
      "data-kind": node.kind,
      "data-node": node.id,
    });
    const isCompact = ["custody", "input", "output"].includes(node.kind);
    if (isCompact) {
      const radius = node.kind === "output" ? 13 : node.kind === "custody" ? 16 : 19;
      group.append(svgElement("circle", { class: "node-shape", r: radius }));
      const text = svgElement("text", { "text-anchor": "middle", y: radius + 17 });
      text.textContent = node.label;
      group.append(text);
    } else {
      const width = node.kind === "model" ? 126 : node.kind === "proof" ? 104 : 58;
      const height = node.kind === "model" ? 64 : node.kind === "proof" ? 42 : 42;
      group.append(svgElement("rect", {
        class: "node-shape",
        x: -width / 2,
        y: -height / 2,
        width,
        height,
      }));
      const text = svgElement("text", { "text-anchor": "middle", y: 4 });
      text.textContent = node.label;
      group.append(text);
    }
    group.addEventListener("click", () => selectNode(node));
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectNode(node);
      }
    });
    elements.nodeLayer.append(group);
    node.element = group;
    node.number = index + 1;
  });
  state.graphNodes = nodes;
  state.graphEdges = edges;
  selectNode(byId.get("model"));
  applyView();
}

function addGraphLabels() {
  const labels = [
    [55, 92, "Committed input"],
    [380, 64, "Certified custody"],
    [770, 64, "Executor set"],
    [1000, 165, "Output slots"],
    [340, 555, "Finalized lifecycle"],
  ];
  labels.forEach(([x, y, text]) => {
    const label = svgElement("text", { x, y, class: "graph-label" });
    label.textContent = text;
    elements.nodeLayer.append(label);
  });
}

function selectNode(node) {
  if (!node) return;
  state.selectedNode?.element?.classList.remove("is-selected");
  state.selectedNode = node;
  node.element?.classList.add("is-selected");
  const { details } = node;
  setText(elements.inspectorNumber, String(node.number).padStart(2, "0"));
  setText(elements.inspectorKind, node.kind);
  setText(elements.inspectorTitle, details.title);
  setText(elements.inspectorCopy, details.copy);
  setText(elements.inspectorLabelA, details.labelA);
  setText(elements.inspectorValueA, details.valueA);
  setText(elements.inspectorLabelB, details.labelB);
  setText(elements.inspectorValueB, details.valueB);
  setText(elements.inspectorLabelC, details.labelC);
  setText(elements.inspectorValueC, details.valueC);
  elements.copyIdentity.disabled = false;
}

function setStage(nextStage) {
  const stage = Math.max(0, Math.min(STAGES.length - 1, Number(nextStage)));
  state.stage = stage;
  elements.replaySlider.value = String(stage);
  setText(elements.replayStage, `${String(stage + 1).padStart(2, "0")} / 06 — ${STAGES[stage]}`);
  state.graphNodes.forEach((node) => node.element?.classList.toggle("is-active", node.stage === stage));
  state.graphEdges.forEach((edge) => edge.element?.classList.toggle("edge-active", edge.stage === stage));
}

function stopReplay() {
  window.clearInterval(state.playTimer);
  state.playTimer = null;
  elements.replayPlay.setAttribute("aria-pressed", "false");
  elements.replayPlay.textContent = "Play";
}

function toggleReplay() {
  if (state.playTimer) {
    stopReplay();
    return;
  }
  elements.replayPlay.setAttribute("aria-pressed", "true");
  elements.replayPlay.textContent = "Pause";
  state.playTimer = window.setInterval(() => {
    if (state.stage === STAGES.length - 1) {
      setStage(0);
    } else {
      setStage(state.stage + 1);
    }
  }, 1_450);
}

function applyView() {
  const visibleNode = (kind) => {
    if (state.view === "all") return true;
    if (state.view === "signal") return ["input", "model", "executor", "output"].includes(kind);
    return ["model", "output", "proof"].includes(kind);
  };
  const visibleEdge = (kind) => state.view === "all" || state.view === kind || (state.view === "proof" && kind === "signal");
  state.graphNodes.forEach((node) => {
    if (node.element) node.element.style.display = visibleNode(node.kind) ? "" : "none";
  });
  state.graphEdges.forEach((edge) => {
    if (edge.element) edge.element.style.display = visibleEdge(edge.kind) ? "" : "none";
  });
}

function downloadJson(filename, value) {
  const blob = new Blob([`${JSON.stringify(value, null, 2)}\n`], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1_000);
}

function downloadProof(kind) {
  if (!state.records || !state.model || !state.manifest) return;
  if (kind === "model") {
    downloadJson("mindchain-bonsai-finalized-resolution.json", state.model);
    return;
  }
  downloadJson(`mindchain-neural-${kind}-proof.json`, state.records[kind]);
}

for (const button of document.querySelectorAll(".view-button")) {
  button.addEventListener("click", () => {
    state.view = button.dataset.view;
    for (const candidate of document.querySelectorAll(".view-button")) {
      const active = candidate === button;
      candidate.classList.toggle("is-active", active);
      candidate.setAttribute("aria-pressed", String(active));
    }
    applyView();
  });
}

for (const [kind, item] of Object.entries(proofElements)) {
  item.button.addEventListener("click", () => downloadProof(kind));
}

elements.replaySlider.addEventListener("input", () => {
  stopReplay();
  setStage(elements.replaySlider.value);
});
elements.replayPrevious.addEventListener("click", () => {
  stopReplay();
  setStage(state.stage - 1);
});
elements.replayNext.addEventListener("click", () => {
  stopReplay();
  setStage(state.stage + 1);
});
elements.replayPlay.addEventListener("click", toggleReplay);
elements.copyIdentity.addEventListener("click", async () => {
  if (!state.selectedNode) return;
  try {
    await navigator.clipboard.writeText(state.selectedNode.details.identity);
    elements.copyIdentity.textContent = "Copied";
    window.setTimeout(() => { elements.copyIdentity.textContent = "Copy full identity"; }, 1_200);
  } catch {
    elements.copyIdentity.textContent = "Clipboard unavailable";
  }
});
elements.retryLoad.addEventListener("click", () => loadLiveData());

loadLiveData();
