(() => {
  "use strict";

  const API_ROOT = "/api/wwm/v1";
  const STATE_TIMEOUT_MS = 20_000;
  const MAX_PROMPT_BYTES = 48_000;

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
    pinSnapshot: document.getElementById("pin-snapshot"),
    pinReaders: document.getElementById("pin-readers"),
    pinDisclosure: document.getElementById("pin-disclosure"),
    quoteCeiling: document.getElementById("quote-ceiling"),
    paymentLabel: document.getElementById("payment-label"),
    answerEmpty: document.getElementById("answer-empty"),
    answerLoading: document.getElementById("answer-loading"),
    answerResult: document.getElementById("answer-result"),
    answerCopy: document.getElementById("answer-copy"),
    answerFinality: document.getElementById("answer-finality"),
    answerWarning: document.getElementById("answer-warning"),
    receiptToggle: document.getElementById("receipt-toggle"),
    receiptDrawer: document.getElementById("receipt-drawer"),
    receiptClose: document.getElementById("receipt-close"),
    receiptFacts: document.getElementById("receipt-facts"),
    sourceList: document.getElementById("source-list"),
    receiptJson: document.getElementById("receipt-json")
  };

  const state = {
    pin: null,
    enabled: false,
    testOnly: false,
    availableFinality: new Set(["SOFT"]),
    busy: false,
    stream: null,
    answer: "",
    receipt: null
  };

  function shortHash(value) {
    if (typeof value !== "string" || value.length < 16) return "Not pinned";
    return `${value.slice(0, 8)}…${value.slice(-6)}`;
  }

  function setNetworkState(kind, label) {
    nodes.networkState.className = `state-flag state-${kind}`;
    nodes.networkState.textContent = label;
  }

  function setError(message) {
    nodes.inputError.textContent = message;
    nodes.inputError.hidden = !message;
    nodes.input.setAttribute("aria-invalid", message ? "true" : "false");
  }

  function setBusy(busy, label = "Requesting bounded quote") {
    state.busy = busy;
    nodes.input.disabled = busy;
    nodes.outputLimit.disabled = busy;
    document.querySelectorAll('input[name="finality"]').forEach((input) => {
      input.disabled = busy || !state.availableFinality.has(input.value);
    });
    nodes.submit.disabled = busy || !state.enabled || !state.pin;
    nodes.submit.querySelector("span").textContent = busy ? label : "Request quote and ask";
    nodes.form.setAttribute("aria-busy", String(busy));
  }

  function showAnswerState(view) {
    nodes.answerEmpty.hidden = view !== "empty";
    nodes.answerLoading.hidden = view !== "loading";
    nodes.answerResult.hidden = view !== "result";
  }

  function updateInputCount() {
    const length = nodes.input.value.length;
    nodes.inputCount.textContent = `${length.toLocaleString()} / 12,000`;
    if (length > 0) setError("");
  }

  function selectedFinality() {
    const selected = document.querySelector('input[name="finality"]:checked');
    return selected ? selected.value : "SOFT";
  }

  function selectedMode() {
    const selected = document.querySelector('input[name="compute-mode"]:checked');
    return selected ? selected.value : "public";
  }

  async function fetchJson(url, options = {}, timeoutMs = STATE_TIMEOUT_MS) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          "Accept": "application/json",
          ...(options.body ? { "Content-Type": "application/json" } : {}),
          ...(options.headers || {})
        }
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        const message = typeof payload.error === "string" ? payload.error : `Gateway returned HTTP ${response.status}.`;
        throw new Error(message);
      }
      return payload;
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function hashText(text) {
    const bytes = new TextEncoder().encode(text);
    if (bytes.byteLength > MAX_PROMPT_BYTES) {
      throw new Error("This question is too large after UTF-8 encoding. Keep it below 48,000 bytes.");
    }
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return bytesToHex(new Uint8Array(digest));
  }

  function randomHex(length) {
    const bytes = crypto.getRandomValues(new Uint8Array(length));
    return bytesToHex(bytes);
  }

  function bytesToHex(bytes) {
    return Array.from(bytes, (value) => value.toString(16).padStart(2, "0")).join("");
  }

  function estimatedInputTokens(text) {
    let characters = 0;
    for (const _character of text) characters += 1;
    return Math.max(1, Math.ceil(characters / 4));
  }

  function validPin(payload) {
    const pin = payload && payload.pin;
    if (!pin || typeof pin !== "object") return false;
    const reads = Array.isArray(pin.agreeing_endpoints) ? pin.agreeing_endpoints : [];
    const clusters = Array.isArray(pin.agreeing_control_clusters) ? pin.agreeing_control_clusters : [];
    const uniqueReads = new Set(reads);
    const uniqueClusters = new Set(clusters);
    const loopback = ["localhost", "127.0.0.1", "::1"].includes(window.location.hostname);
    const singleNodeTest = payload.test_only === true
      && pin.pin_mode === "TEST_SINGLE_NODE"
      && loopback;
    const minimum = singleNodeTest ? 1 : 2;
    return typeof pin.pin_id === "string"
      && typeof pin.chain_id === "string"
      && typeof pin.genesis_hash === "string"
      && typeof pin.capsule_id === "string"
      && typeof pin.knowledge_snapshot_id === "string"
      && uniqueReads.size >= minimum
      && uniqueClusters.size >= minimum;
  }

  async function loadState() {
    setNetworkState("pending", "Checking");
    try {
      const payload = await fetchJson(`${API_ROOT}/state`);
      if (!validPin(payload)) {
        throw new Error("Gateway state did not contain a valid finalized-state pin.");
      }
      state.pin = payload.pin;
      state.enabled = payload.enabled === true;
      state.testOnly = payload.test_only === true;
      state.availableFinality = new Set(
        Array.isArray(payload.available_finality) ? payload.available_finality : ["SOFT"]
      );
      setBusy(false);
      nodes.pinChain.textContent = `${shortHash(payload.pin.chain_id)} / ${shortHash(payload.pin.genesis_hash)}`;
      nodes.pinModel.textContent = shortHash(payload.pin.capsule_id);
      nodes.pinSnapshot.textContent = shortHash(payload.pin.knowledge_snapshot_id);
      nodes.pinReaders.textContent = `${new Set(payload.pin.agreeing_endpoints).size} / ${payload.minimum_state_endpoints || 3}`;
      if (state.enabled) {
        setNetworkState("ready", state.testOnly ? "Test pinned" : "Pinned");
        nodes.activation.textContent = state.testOnly ? "Local model · test only" : "Public test profile";
        nodes.activation.classList.add("active");
        nodes.submit.disabled = false;
        nodes.submit.querySelector("span").textContent = "Request quote and ask";
        nodes.pinDisclosure.textContent = payload.disclosure || "A quote must preserve this exact finalized-state pin.";
      } else {
        setNetworkState("blocked", "Disabled");
        nodes.activation.textContent = "Evidence gate closed";
        nodes.submit.disabled = true;
        nodes.submit.querySelector("span").textContent = "Public query not activated";
        nodes.pinDisclosure.textContent = payload.disclosure || "State is inspectable, but the public query control remains disabled until its evidence gates pass.";
      }
    } catch (error) {
      state.pin = null;
      state.enabled = false;
      setNetworkState("blocked", "Unavailable");
      nodes.activation.textContent = "Fail closed";
      nodes.pinDisclosure.textContent = error instanceof Error ? error.message : "Independent state pinning failed.";
      nodes.submit.disabled = true;
      nodes.submit.querySelector("span").textContent = "Pin state to continue";
    }
  }

  function normalizedQuestion() {
    return nodes.input.value.replace(/\r\n/g, "\n").trim();
  }

  function renderFinality(finality) {
    const allowed = new Set(["SOFT", "ANCHORED", "ASSURED"]);
    const label = allowed.has(finality) ? finality : "SOFT";
    nodes.answerFinality.textContent = label;
    nodes.answerFinality.className = `finality-badge finality-${label.toLowerCase()}`;
  }

  function closeStream() {
    if (state.stream) {
      state.stream.close();
      state.stream = null;
    }
  }

  function appendToken(token) {
    if (typeof token !== "string") return;
    state.answer += token;
    nodes.answerCopy.textContent = state.answer;
    showAnswerState("result");
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
    state.receipt = receipt;
    nodes.receiptFacts.replaceChildren(
      fact("Job", shortHash(receipt.job_id)),
      fact("Quote", shortHash(receipt.quote_id)),
      fact("Model", shortHash(receipt.capsule_id)),
      fact("Snapshot", shortHash(receipt.knowledge_snapshot_id)),
      fact("Finality", receipt.actual_finality || "SOFT"),
      fact("Charged", `${Number(receipt.charged_micro_noos || 0).toLocaleString()} micro-NOOS`)
    );
    nodes.sourceList.replaceChildren();
    const sources = Array.isArray(receipt.sources) ? receipt.sources : [];
    if (sources.length === 0) {
      const item = document.createElement("li");
      item.textContent = "No retrieval sources were declared for this answer.";
      nodes.sourceList.append(item);
    } else {
      sources.forEach((source) => {
        const item = document.createElement("li");
        const title = document.createElement("strong");
        const detail = document.createElement("span");
        title.textContent = source.title || shortHash(source.mindlink_id);
        detail.textContent = source.citation || `MindLink ${shortHash(source.mindlink_id)}`;
        item.append(title, detail);
        nodes.sourceList.append(item);
      });
    }
    nodes.receiptJson.textContent = JSON.stringify(receipt, null, 2);
    renderFinality(receipt.actual_finality);
  }

  function openStream(streamUrl) {
    closeStream();
    if (typeof streamUrl !== "string" || !streamUrl.startsWith(`${API_ROOT}/`)) {
      throw new Error("Gateway returned an invalid same-origin stream URL.");
    }
    state.stream = new EventSource(streamUrl);
    state.stream.addEventListener("token", (event) => {
      try {
        const payload = JSON.parse(event.data);
        appendToken(payload.token);
      } catch {
        closeStream();
        setError("The executor stream returned malformed token data.");
      }
    });
    state.stream.addEventListener("finality", (event) => {
      try {
        const payload = JSON.parse(event.data);
        renderFinality(payload.actual_finality);
      } catch {
        renderFinality("SOFT");
      }
    });
    state.stream.addEventListener("receipt", (event) => {
      try {
        const receipt = JSON.parse(event.data);
        renderReceipt(receipt);
        nodes.answerWarning.textContent = "Receipt received. Execution assurance remains separate from factual accuracy.";
      } catch {
        setError("The gateway returned a malformed receipt.");
      } finally {
        closeStream();
        setBusy(false);
      }
    });
    state.stream.addEventListener("gateway-error", (event) => {
      let message = "The committee stopped before a receipt was available. No direct fallback was attempted.";
      try {
        const payload = JSON.parse(event.data);
        if (typeof payload.error === "string") message = payload.error;
      } catch {
        // The fixed disclosure above is safer than rendering malformed data.
      }
      closeStream();
      setBusy(false);
      setError(message);
    });
    state.stream.onerror = () => {
      if (!state.receipt) {
        closeStream();
        setBusy(false);
        setError("The committee stream connection failed. The client did not retry through a direct or unpinned route.");
      }
    };
  }

  async function submitQuery(event) {
    event.preventDefault();
    setError("");
    if (!state.enabled || !state.pin) {
      setError("Public query is not activated on this gateway.");
      return;
    }
    if (selectedMode() !== "public") {
      setError("The selected compute privacy profile is unavailable. No downgrade was attempted.");
      return;
    }
    const prompt = normalizedQuestion();
    if (!prompt) {
      setError("Write a specific question before requesting a quote.");
      nodes.input.focus();
      return;
    }

    closeStream();
    state.answer = "";
    state.receipt = null;
    nodes.answerCopy.textContent = "";
    nodes.receiptDrawer.hidden = true;
    nodes.receiptToggle.setAttribute("aria-expanded", "false");
    showAnswerState("loading");
    setBusy(true);

    try {
      await loadState();
      if (!state.enabled || !state.pin) {
        throw new Error("A current finalized-state pin is required before quoting.");
      }
      setBusy(true);
      const promptCommitment = await hashText(prompt);
      const clientNonce = randomHex(32);
      const quote = await fetchJson(`${API_ROOT}/quotes`, {
        method: "POST",
        body: JSON.stringify({
          pin_id: state.pin.pin_id,
          prompt_commitment: promptCommitment,
          client_nonce: clientNonce,
          input_tokens: estimatedInputTokens(prompt),
          compute_profile: "P0_OPEN",
          requested_finality: selectedFinality(),
          maximum_output_tokens: Number(nodes.outputLimit.value),
          sponsor_requested: true
        })
      });
      if (quote.pin_id !== state.pin.pin_id || typeof quote.quote_id !== "string") {
        throw new Error("The quote did not preserve the pinned finalized state.");
      }
      nodes.quoteCeiling.textContent = `${Number(quote.maximum_fee_micro_noos).toLocaleString()} micro-NOOS`;
      nodes.paymentLabel.textContent = quote.sponsor_id ? "Sponsor reserved" : "Requester escrow";
      setBusy(true, "Opening committee job");
      const job = await fetchJson(`${API_ROOT}/jobs`, {
        method: "POST",
        body: JSON.stringify({
          quote_id: quote.quote_id,
          prompt,
          prompt_commitment: promptCommitment,
          client_nonce: clientNonce
        })
      });
      if (typeof job.job_id !== "string") {
        throw new Error("The gateway did not return a valid job identifier.");
      }
      openStream(job.stream_url || `${API_ROOT}/jobs/${encodeURIComponent(job.job_id)}/stream`);
    } catch (error) {
      closeStream();
      setBusy(false);
      showAnswerState("empty");
      setError(error instanceof Error ? error.message : "The gateway could not open this query.");
    }
  }

  function toggleReceipt(open) {
    const next = typeof open === "boolean" ? open : nodes.receiptDrawer.hidden;
    nodes.receiptDrawer.hidden = !next;
    nodes.receiptToggle.setAttribute("aria-expanded", String(next));
    if (next) nodes.receiptClose.focus();
  }

  nodes.input.addEventListener("input", updateInputCount);
  nodes.form.addEventListener("submit", submitQuery);
  nodes.receiptToggle.addEventListener("click", () => toggleReceipt());
  nodes.receiptClose.addEventListener("click", () => {
    toggleReceipt(false);
    nodes.receiptToggle.focus();
  });
  document.querySelectorAll(".mode-choice input, .finality-choice input").forEach((input) => {
    input.addEventListener("change", () => {
      const parent = input.closest("fieldset");
      if (!parent) return;
      parent.querySelectorAll(".mode-choice, .finality-choice").forEach((choice) => {
        const choiceInput = choice.querySelector("input");
        choice.classList.toggle("selected", Boolean(choiceInput && choiceInput.checked));
      });
    });
  });
  window.addEventListener("beforeunload", closeStream, { once: true });

  updateInputCount();
  showAnswerState("empty");
  loadState();
})();
