/* Foundry — MindChain token launch.
   Talks only to the same-origin gateway:
     GET  /api/config
     GET  /api/assets
     POST /api/launch {symbol,name,decimals,total_supply,initial_noos,initial_tokens,fee_bps}
   Amounts on the wire are integer base-unit decimal strings. */

"use strict";

const U128_MAX = (1n << 128n) - 1n;
const NOOS_ASSET_ID = "0".repeat(64);
const DEFAULT_NOOS_DECIMALS = 6;

const state = {
  noosDecimals: DEFAULT_NOOS_DECIMALS,
  noosSymbol: "NOOS",
  assetCount: null,
  submitting: false,
};

const $ = (id) => document.getElementById(id);

const els = {
  chainDot: $("chain-dot"),
  chainName: $("chain-name"),
  chainMeta: $("chain-meta"),
  ordinal: $("launch-ordinal"),
  form: $("launch-form"),
  symbol: $("f-symbol"),
  name: $("f-name"),
  decimals: $("f-decimals"),
  supply: $("f-supply"),
  noos: $("f-noos"),
  tokens: $("f-tokens"),
  fee: $("f-fee"),
  supplyBase: $("supply-base"),
  banner: $("form-banner"),
  launchBtn: $("btn-launch"),
  receipt: $("receipt"),
  receiptSub: $("receipt-sub"),
  receiptList: $("receipt-list"),
  againBtn: $("btn-again"),
  allocFill: $("alloc-fill"),
  sShare: $("s-share"),
  sPrice: $("s-price"),
  sPool: $("s-pool"),
  sRetained: $("s-retained"),
  sNoos: $("s-noos"),
  sFee: $("s-fee"),
  sNote: $("s-note"),
  assetList: $("asset-list"),
  refreshBtn: $("btn-refresh"),
};

/* ---------------- numeric helpers ---------------- */

/** Parse a human decimal string into base units. Throws Error with a user message. */
function parseAmount(text, decimals, label) {
  const cleaned = text.replace(/[\s_,]/g, "");
  if (cleaned === "") throw new Error(`${label} is required.`);
  if (!/^\d*(\.\d*)?$/.test(cleaned) || cleaned === ".") {
    throw new Error(`${label} must be a plain decimal number.`);
  }
  const [whole = "", frac = ""] = cleaned.split(".");
  if (frac.length > decimals) {
    throw new Error(
      decimals === 0
        ? `${label} must be a whole number (0 decimals).`
        : `${label} allows at most ${decimals} fractional digit${decimals === 1 ? "" : "s"}.`
    );
  }
  const base = BigInt((whole || "0") + frac.padEnd(decimals, "0"));
  if (base > U128_MAX) throw new Error(`${label} exceeds the maximum representable amount.`);
  return base;
}

/** Format base units as a human amount with group separators. */
function formatUnits(base, decimals) {
  const s = base.toString().padStart(decimals + 1, "0");
  const cut = s.length - decimals;
  const whole = s.slice(0, cut).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  const frac = decimals > 0 ? s.slice(cut).replace(/0+$/, "") : "";
  return frac ? `${whole}.${frac}` : whole;
}

function formatBaseString(str, decimals) {
  try {
    return formatUnits(BigInt(str), decimals);
  } catch {
    return str;
  }
}

function shortHex(hex) {
  return hex.length > 16 ? `${hex.slice(0, 8)}\u2026${hex.slice(-6)}` : hex;
}

/* ---------------- gateway ---------------- */

async function api(path, options) {
  let res;
  try {
    res = await fetch(path, { cache: "no-store", ...options });
  } catch {
    throw new Error("Gateway unreachable. Is the local MindChain gateway running on this origin?");
  }
  let body = null;
  try {
    body = await res.json();
  } catch {
    /* non-JSON body */
  }
  if (!res.ok || (body && typeof body.error === "string")) {
    const msg = body && typeof body.error === "string" ? body.error : `Gateway error (HTTP ${res.status}).`;
    throw new Error(msg);
  }
  if (body === null) throw new Error("Gateway returned a malformed response.");
  return body;
}

/* ---------------- chain identity ---------------- */

async function loadConfig() {
  els.chainDot.dataset.state = "loading";
  els.chainName.classList.add("skeleton-text");
  els.chainName.textContent = "connecting";
  els.chainMeta.textContent = "querying local gateway";
  try {
    const cfg = await api("/api/config");
    const name =
      cfg.chain || cfg.chain_name || cfg.network || cfg.name || cfg.chain_id || "MindChain";
    const nd = Number(cfg.noos_decimals ?? cfg.native_decimals);
    if (Number.isInteger(nd) && nd >= 0 && nd <= 18) state.noosDecimals = nd;
    if (typeof cfg.noos_symbol === "string" && cfg.noos_symbol) state.noosSymbol = cfg.noos_symbol;

    const meta = [];
    if (cfg.chain_id && cfg.chain_id !== name) meta.push(`id ${cfg.chain_id}`);
    if (cfg.height !== undefined) meta.push(`height ${cfg.height}`);
    if (cfg.version) meta.push(`v${String(cfg.version).replace(/^v/, "")}`);
    meta.push(`${state.noosSymbol} \u00d7 10^-${state.noosDecimals}`);

    els.chainDot.dataset.state = "online";
    els.chainName.classList.remove("skeleton-text");
    els.chainName.textContent = String(name);
    els.chainMeta.textContent = meta.join(" \u00b7 ");
  } catch (err) {
    els.chainDot.dataset.state = "offline";
    els.chainName.classList.remove("skeleton-text");
    els.chainName.textContent = "gateway offline";
    els.chainMeta.textContent = err.message;
  }
  renderSummary();
}

/* ---------------- registry ---------------- */

function renderRegistrySkeleton() {
  els.assetList.setAttribute("aria-busy", "true");
  els.assetList.innerHTML = "";
  for (let i = 0; i < 3; i += 1) {
    const li = document.createElement("li");
    li.className = "skeleton-row";
    li.innerHTML = '<div class="skeleton-bar"></div><div class="skeleton-bar"></div>';
    els.assetList.append(li);
  }
}

function registryMessage(text, isError) {
  els.assetList.innerHTML = "";
  const li = document.createElement("li");
  li.className = `registry-state${isError ? " is-error" : ""}`;
  const p = document.createElement("p");
  p.textContent = text;
  li.append(p);
  if (isError) {
    const retry = document.createElement("button");
    retry.type = "button";
    retry.className = "btn-ghost btn-small";
    retry.textContent = "Retry";
    retry.addEventListener("click", loadAssets);
    li.append(retry);
  }
  els.assetList.append(li);
}

async function loadAssets() {
  renderRegistrySkeleton();
  try {
    const body = await api("/api/assets");
    const assets = Array.isArray(body) ? body : Array.isArray(body.assets) ? body.assets : [];
    const user = assets.filter((a) => a && a.asset_id !== NOOS_ASSET_ID);
    state.assetCount = user.length;
    els.ordinal.textContent = String(user.length + 1).padStart(3, "0");
    els.assetList.setAttribute("aria-busy", "false");

    if (user.length === 0) {
      registryMessage(
        "The registry is empty. The asset you launch here will be the first one on this chain.",
        false
      );
      return;
    }

    els.assetList.innerHTML = "";
    for (const asset of user.slice().reverse().slice(0, 8)) {
      const decimals = Number.isInteger(asset.decimals) ? asset.decimals : 0;
      const li = document.createElement("li");
      li.className = "asset-item";

      const line = document.createElement("div");
      line.className = "asset-line";
      const sym = document.createElement("span");
      sym.className = "asset-symbol";
      sym.textContent = asset.symbol || "?";
      const supply = document.createElement("span");
      supply.className = "asset-supply";
      supply.textContent = `${formatBaseString(String(asset.total_supply ?? "0"), decimals)} supply`;
      line.append(sym, supply);

      const sub = document.createElement("div");
      sub.className = "asset-sub";
      const name = document.createElement("span");
      name.className = "asset-name";
      name.textContent = asset.name || "";
      const id = document.createElement("span");
      id.className = "asset-id";
      id.textContent = shortHex(String(asset.asset_id || ""));
      id.title = String(asset.asset_id || "");
      sub.append(name, id);

      li.append(line, sub);
      els.assetList.append(li);
    }
  } catch (err) {
    els.assetList.setAttribute("aria-busy", "false");
    registryMessage(err.message, true);
  }
}

/* ---------------- validation ---------------- */

function fieldError(input, id, message) {
  const el = $(id);
  if (message) {
    el.textContent = message;
    el.hidden = false;
    input.setAttribute("aria-invalid", "true");
  } else {
    el.textContent = "";
    el.hidden = true;
    input.removeAttribute("aria-invalid");
  }
}

/** Validate the whole form. Returns { values, errors } where values holds
    everything that parsed and errors maps field key -> message. */
function readForm() {
  const values = {};
  const errors = {};

  const symbol = els.symbol.value.trim();
  if (!symbol) errors.symbol = "Symbol is required.";
  else if (!/^[A-Z0-9]{1,12}$/.test(symbol)) {
    errors.symbol = "Use 1\u201312 characters: uppercase A\u2013Z and digits only.";
  } else values.symbol = symbol;

  const name = els.name.value.trim();
  const nameBytes = new TextEncoder().encode(name).length;
  if (!name) errors.name = "Name is required.";
  else if (nameBytes > 64) errors.name = `Name is ${nameBytes} bytes of UTF-8; the limit is 64.`;
  else values.name = name;

  const decRaw = els.decimals.value.trim();
  let decimals = null;
  if (!/^\d+$/.test(decRaw)) errors.decimals = "Decimals must be a whole number.";
  else {
    decimals = Number(decRaw);
    if (decimals > 18) errors.decimals = "Decimals must be between 0 and 18.";
    else values.decimals = decimals;
  }

  if (values.decimals !== undefined) {
    try {
      const supply = parseAmount(els.supply.value, values.decimals, "Total supply");
      if (supply === 0n) throw new Error("Total supply must be greater than zero.");
      values.total_supply = supply;
    } catch (err) {
      errors.supply = err.message;
    }

    try {
      const tokens = parseAmount(els.tokens.value, values.decimals, "Token deposit");
      if (tokens === 0n) throw new Error("Token deposit must be greater than zero.");
      if (values.total_supply !== undefined && tokens > values.total_supply) {
        throw new Error("Token deposit cannot exceed the total supply.");
      }
      values.initial_tokens = tokens;
    } catch (err) {
      errors.tokens = err.message;
    }
  }

  try {
    const noos = parseAmount(els.noos.value, state.noosDecimals, `${state.noosSymbol} deposit`);
    if (noos === 0n) throw new Error(`${state.noosSymbol} deposit must be greater than zero.`);
    values.initial_noos = noos;
  } catch (err) {
    errors.noos = err.message;
  }

  const feeRaw = els.fee.value.trim();
  if (!/^\d+$/.test(feeRaw)) errors.fee = "Fee must be a whole number of basis points.";
  else {
    const fee = Number(feeRaw);
    if (fee > 1000) errors.fee = "Fee must be between 0 and 1000 basis points (0\u201310%).";
    else values.fee_bps = fee;
  }

  return { values, errors };
}

function showFieldErrors(errors, all) {
  const map = [
    ["symbol", els.symbol, "e-symbol"],
    ["name", els.name, "e-name"],
    ["decimals", els.decimals, "e-decimals"],
    ["supply", els.supply, "e-supply"],
    ["noos", els.noos, "e-noos"],
    ["tokens", els.tokens, "e-tokens"],
    ["fee", els.fee, "e-fee"],
  ];
  for (const [key, input, errId] of map) {
    if (all || input.dataset.touched === "true") fieldError(input, errId, errors[key] || "");
  }
}

/* ---------------- live allocation summary ---------------- */

function renderSummary() {
  const { values } = readForm();
  const noosSym = state.noosSymbol;

  // Base-unit readout for the supply field.
  if (values.decimals !== undefined && values.total_supply !== undefined) {
    els.supplyBase.textContent =
      `= ${values.total_supply.toString()} base units (10^-${values.decimals} per unit)`;
  } else {
    els.supplyBase.textContent = "";
  }

  els.sFee.textContent =
    values.fee_bps !== undefined ? `${(values.fee_bps / 100).toFixed(2)}%` : "\u2014";
  els.sNoos.textContent =
    values.initial_noos !== undefined
      ? `${formatUnits(values.initial_noos, state.noosDecimals)} ${noosSym}`
      : "\u2014";
  els.sPool.textContent =
    values.initial_tokens !== undefined && values.decimals !== undefined
      ? formatUnits(values.initial_tokens, values.decimals)
      : "\u2014";

  const complete =
    values.decimals !== undefined &&
    values.total_supply !== undefined &&
    values.initial_tokens !== undefined &&
    values.initial_noos !== undefined;

  if (!complete) {
    els.sShare.textContent = "\u2014";
    els.sPrice.textContent = "\u2014";
    els.sRetained.textContent = "\u2014";
    els.allocFill.style.width = "0%";
    els.sNote.textContent =
      "Fill the form to preview how the fixed supply splits between the pool and your account.";
    return;
  }

  const { total_supply: supply, initial_tokens: tokens, initial_noos: noos, decimals } = values;

  // Pool share of supply, in hundredths of a percent.
  const shareBp2 = (tokens * 10000n) / supply;
  const sharePct = `${(Number(shareBp2) / 100).toFixed(2)}%`;
  els.sShare.textContent = sharePct;
  els.allocFill.style.width = `${Math.min(100, Number(shareBp2) / 100)}%`;

  els.sRetained.textContent = formatUnits(supply - tokens, decimals);

  // Opening price: NOOS base units per whole token, shown in NOOS.
  const priceBase = (noos * 10n ** BigInt(decimals)) / tokens;
  els.sPrice.textContent = `${formatUnits(priceBase, state.noosDecimals)} ${noosSym} / token`;

  els.sNote.textContent =
    `${formatUnits(tokens, decimals)} tokens (${sharePct} of supply) enter the pool against ` +
    `${formatUnits(noos, state.noosDecimals)} ${noosSym}; ` +
    `${formatUnits(supply - tokens, decimals)} tokens stay in your account.`;
}

/* ---------------- submission ---------------- */

function setBanner(message) {
  if (message) {
    els.banner.textContent = message;
    els.banner.hidden = false;
  } else {
    els.banner.textContent = "";
    els.banner.hidden = true;
  }
}

function setBusy(busy) {
  state.submitting = busy;
  els.launchBtn.disabled = busy;
  els.launchBtn.dataset.busy = busy ? "true" : "false";
  els.launchBtn.querySelector(".btn-label").textContent = busy ? "Launching\u2026" : "Launch asset";
}

const RECEIPT_LABELS = {
  asset_id: "Asset ID",
  pool_id: "Pool ID",
  receipt: "Receipt",
  receipt_id: "Receipt",
  tx_id: "Transaction",
  txid: "Transaction",
  height: "Height",
  status: "Status",
};

function receiptRow(label, value, copyable) {
  const row = document.createElement("div");
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  const span = document.createElement("span");
  span.className = "receipt-value";
  span.textContent = value;
  dd.append(span);
  if (copyable && navigator.clipboard) {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "btn-copy";
    btn.textContent = "Copy";
    btn.setAttribute("aria-label", `Copy ${label.toLowerCase()}`);
    btn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(value);
        btn.dataset.copied = "true";
        btn.textContent = "Copied";
        setTimeout(() => {
          btn.dataset.copied = "false";
          btn.textContent = "Copy";
        }, 1600);
      } catch {
        /* clipboard denied; value remains selectable */
      }
    });
    dd.append(btn);
  }
  row.append(dt, dd);
  return row;
}

function renderReceipt(response, submitted) {
  els.receiptList.innerHTML = "";
  els.receiptSub.textContent =
    `${submitted.symbol} \u00b7 ${formatBaseString(submitted.total_supply, submitted.decimals)} fixed supply \u00b7 ` +
    `pool fee ${(submitted.fee_bps / 100).toFixed(2)}%`;

  const seen = new Set();
  const ordered = ["asset_id", "pool_id", "receipt", "receipt_id", "tx_id", "txid", "height", "status"];
  const keys = [
    ...ordered.filter((k) => response[k] !== undefined),
    ...Object.keys(response).filter((k) => !ordered.includes(k)),
  ];

  for (const key of keys) {
    if (seen.has(key)) continue;
    seen.add(key);
    const raw = response[key];
    if (raw === null || raw === undefined || typeof raw === "object") continue;
    const value = String(raw);
    const label = RECEIPT_LABELS[key] || key.replace(/_/g, " ");
    receiptRowAppend(label, value);
  }

  function receiptRowAppend(label, value) {
    const copyable = /^[0-9a-fA-F]{16,}$/.test(value);
    els.receiptList.append(receiptRow(label, value, copyable));
  }

  els.receipt.hidden = false;
  els.receipt.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

async function submitLaunch(event) {
  event.preventDefault();
  if (state.submitting) return;

  for (const input of [els.symbol, els.name, els.decimals, els.supply, els.noos, els.tokens, els.fee]) {
    input.dataset.touched = "true";
  }

  const { values, errors } = readForm();
  showFieldErrors(errors, true);
  if (Object.keys(errors).length > 0) {
    setBanner("Fix the highlighted fields before launching.");
    const firstBad = els.form.querySelector('[aria-invalid="true"]');
    if (firstBad) firstBad.focus();
    return;
  }

  const payload = {
    symbol: values.symbol,
    name: values.name,
    decimals: values.decimals,
    total_supply: values.total_supply.toString(),
    initial_noos: values.initial_noos.toString(),
    initial_tokens: values.initial_tokens.toString(),
    fee_bps: values.fee_bps,
  };

  setBanner(null);
  setBusy(true);
  try {
    const response = await api("/api/launch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    renderReceipt(response, payload);
    els.form.reset();
    els.decimals.value = "6";
    els.fee.value = "30";
    for (const input of [els.symbol, els.name, els.decimals, els.supply, els.noos, els.tokens, els.fee]) {
      delete input.dataset.touched;
      input.removeAttribute("aria-invalid");
    }
    showFieldErrors({}, true);
    syncFeePresets();
    renderSummary();
    loadAssets();
  } catch (err) {
    setBanner(err.message);
  } finally {
    setBusy(false);
  }
}

/* ---------------- wiring ---------------- */

function syncFeePresets() {
  const current = els.fee.value.trim();
  for (const btn of document.querySelectorAll(".fee-preset")) {
    btn.setAttribute("aria-pressed", btn.dataset.bps === current ? "true" : "false");
  }
}

function onFieldInput(event) {
  const input = event.target;
  if (input === els.symbol) {
    const pos = input.selectionStart;
    input.value = input.value.toUpperCase();
    if (pos !== null) input.setSelectionRange(pos, pos);
  }
  input.dataset.touched = "true";
  const { errors } = readForm();
  showFieldErrors(errors, false);
  if (!els.banner.hidden && Object.keys(errors).length === 0) setBanner(null);
  if (input === els.fee) syncFeePresets();
  renderSummary();
}

function init() {
  for (const input of [els.symbol, els.name, els.decimals, els.supply, els.noos, els.tokens, els.fee]) {
    input.addEventListener("input", onFieldInput);
    input.addEventListener("blur", () => {
      if (input.value.trim() !== "") input.dataset.touched = "true";
      const { errors } = readForm();
      showFieldErrors(errors, false);
    });
  }

  for (const btn of document.querySelectorAll(".fee-preset")) {
    btn.addEventListener("click", () => {
      els.fee.value = btn.dataset.bps;
      els.fee.dataset.touched = "true";
      syncFeePresets();
      const { errors } = readForm();
      showFieldErrors(errors, false);
      renderSummary();
    });
  }

  els.form.addEventListener("submit", submitLaunch);
  els.refreshBtn.addEventListener("click", loadAssets);
  els.againBtn.addEventListener("click", () => {
    els.receipt.hidden = true;
    els.symbol.focus();
  });

  syncFeePresets();
  renderSummary();
  loadConfig();
  loadAssets();
}

init();
