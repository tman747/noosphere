"use strict";

/* Current — constant-product exchange over the MindChain local gateway.
   All amounts are integer base units carried as decimal strings; math is BigInt. */

(function () {
  const NOOS_ID = "0".repeat(64);
  const BPS = 10000n;

  // ---------- state ----------

  const state = {
    config: null,           // {chain_id, genesis_hash, account, noos_asset}
    assets: new Map(),      // asset_id -> {asset_id, symbol, name, decimals, ...}
    pools: [],              // [{pool_id, asset_0, asset_1, reserve_0, reserve_1, fee_bps, creator}]
    selectedPoolId: null,
    reversed: false,        // false: pay asset_0 -> receive asset_1
    slippageBps: 50n,
    balance: null,          // BigInt balance of the current input asset, or null while unknown
    balanceAsset: null,     // asset id the balance belongs to
    balanceSeq: 0,          // guards stale balance responses
    submitting: false,
  };

  // ---------- dom ----------

  const $ = (id) => document.getElementById(id);

  const el = {
    identitySkeleton: $("identity-skeleton"),
    identityBody: $("identity-body"),
    identityError: $("identity-error"),
    identityChain: $("identity-chain"),
    identityAccount: $("identity-account"),
    footerGenesis: $("footer-genesis"),
    poolsSkeleton: $("pools-skeleton"),
    poolsError: $("pools-error"),
    poolsErrorText: $("pools-error-text"),
    poolsRetry: $("pools-retry"),
    poolsEmpty: $("pools-empty"),
    poolList: $("pool-list"),
    refreshPools: $("refresh-pools"),
    form: $("swap-form"),
    amountIn: $("amount-in"),
    amountOut: $("amount-out"),
    amountHint: $("amount-hint"),
    assetInChip: $("asset-in-chip"),
    assetOutChip: $("asset-out-chip"),
    balanceDisplay: $("balance-display"),
    maxBtn: $("max-btn"),
    flipBtn: $("flip-btn"),
    quoteDetails: $("quote-details"),
    detailRate: $("detail-rate"),
    detailImpact: $("detail-impact"),
    detailMin: $("detail-min"),
    detailFee: $("detail-fee"),
    detailReserves: $("detail-reserves"),
    slippageInput: $("slippage-input"),
    slippageHint: $("slippage-hint"),
    slipButtons: Array.from(document.querySelectorAll(".slip-btn")),
    swapBtn: $("swap-btn"),
    swapStatus: $("swap-status"),
  };

  // ---------- helpers: fetch ----------

  async function api(path, options) {
    const res = await fetch(path, options);
    let body = null;
    try {
      body = await res.json();
    } catch (_) {
      /* non-JSON body */
    }
    if (!res.ok) {
      const msg = body && typeof body.error === "string"
        ? body.error
        : `Gateway error (HTTP ${res.status})`;
      throw new Error(msg);
    }
    if (body && typeof body.error === "string") throw new Error(body.error);
    return body;
  }

  // ---------- helpers: amounts ----------

  // Parse a human decimal string into base units. Returns BigInt or null.
  function parseAmount(text, decimals) {
    const t = text.trim();
    if (!/^\d+(\.\d+)?$|^\.\d+$/.test(t)) return null;
    const [rawInt = "0", rawFrac = ""] = t.split(".");
    if (rawFrac.length > decimals) return null; // more precision than the asset supports
    const frac = rawFrac.padEnd(decimals, "0");
    try {
      return BigInt(rawInt + frac || "0");
    } catch (_) {
      return null;
    }
  }

  // Format base units as a human decimal string, trimming trailing zeros.
  function formatAmount(units, decimals, maxFrac) {
    const neg = units < 0n;
    const abs = neg ? -units : units;
    const s = abs.toString().padStart(decimals + 1, "0");
    const intPart = s.slice(0, s.length - decimals) || "0";
    let fracPart = decimals > 0 ? s.slice(s.length - decimals) : "";
    if (typeof maxFrac === "number") fracPart = fracPart.slice(0, maxFrac);
    fracPart = fracPart.replace(/0+$/, "");
    const grouped = intPart.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    return (neg ? "-" : "") + grouped + (fracPart ? "." + fracPart : "");
  }

  // Full-precision, ungrouped form suitable for putting back into the input.
  function formatAmountPlain(units, decimals) {
    const s = units.toString().padStart(decimals + 1, "0");
    const intPart = s.slice(0, s.length - decimals) || "0";
    const fracPart = decimals > 0 ? s.slice(s.length - decimals).replace(/0+$/, "") : "";
    return intPart + (fracPart ? "." + fracPart : "");
  }

  function shortHex(id) {
    if (typeof id !== "string" || id.length <= 13) return id || "";
    return id.slice(0, 6) + "\u2026" + id.slice(-6);
  }

  // ---------- helpers: assets & pools ----------

  const NOOS_META = { symbol: "NOOS_TEST", name: "NOOS Test", decimals: 6 };

  function assetMeta(assetId) {
    const known = state.assets.get(assetId);
    if (known) return known;
    if (assetId === NOOS_ID || (state.config && assetId === state.config.noos_asset)) {
      return { asset_id: assetId, ...NOOS_META };
    }
    return { asset_id: assetId, symbol: shortHex(assetId), name: "Unknown asset", decimals: 0 };
  }

  function selectedPool() {
    return state.pools.find((p) => p.pool_id === state.selectedPoolId) || null;
  }

  // Sides for the current direction: pay side first.
  function poolSides(pool) {
    const a0 = { asset: pool.asset_0, reserve: BigInt(pool.reserve_0) };
    const a1 = { asset: pool.asset_1, reserve: BigInt(pool.reserve_1) };
    return state.reversed ? [a1, a0] : [a0, a1];
  }

  // ---------- quoting ----------

  // Constant-product exact-input quote with fee, integer flooring throughout.
  function quote(pool, amountIn) {
    const [inSide, outSide] = poolSides(pool);
    const fee = BigInt(pool.fee_bps);
    const effective = (amountIn * (BPS - fee)) / BPS;
    if (effective <= 0n || inSide.reserve <= 0n || outSide.reserve <= 0n) return null;
    const amountOut = (outSide.reserve * effective) / (inSide.reserve + effective);
    if (amountOut <= 0n) return null;

    // Price impact in bps: 10000 - execPrice/spotPrice, floored.
    // execPrice/spotPrice = (out/in) / (rOut/rIn) = out*rIn / (in*rOut)
    const ratioBps = (amountOut * inSide.reserve * BPS) / (amountIn * outSide.reserve);
    let impactBps = BPS - ratioBps;
    if (impactBps < 0n) impactBps = 0n;
    if (impactBps > BPS) impactBps = BPS;

    const minOut = (amountOut * (BPS - state.slippageBps)) / BPS;
    return { amountOut, minOut, impactBps, effective, inSide, outSide };
  }

  // Rate string: 1 <in> = x <out>, computed on reserves scaled to display decimals.
  function rateString(pool) {
    const [inSide, outSide] = poolSides(pool);
    const inMeta = assetMeta(inSide.asset);
    const outMeta = assetMeta(outSide.asset);
    if (inSide.reserve <= 0n) return "\u2014";
    // out per one whole unit of in, at spot: rOut * 10^dIn / rIn, in out base units.
    const oneIn = 10n ** BigInt(inMeta.decimals);
    const spotOut = (outSide.reserve * oneIn) / inSide.reserve;
    return `1 ${inMeta.symbol} \u2248 ${formatAmount(spotOut, outMeta.decimals, 6)} ${outMeta.symbol}`;
  }

  // ---------- rendering: identity ----------

  function renderIdentity() {
    el.identitySkeleton.hidden = true;
    if (!state.config) {
      el.identityError.hidden = false;
      el.identityBody.hidden = true;
      return;
    }
    el.identityError.hidden = true;
    el.identityBody.hidden = false;
    el.identityChain.textContent = state.config.chain_id;
    el.identityAccount.textContent = shortHex(state.config.account);
    el.identityAccount.title = state.config.account;
    el.footerGenesis.textContent = state.config.genesis_hash
      ? "genesis " + shortHex(state.config.genesis_hash)
      : "";
  }

  // ---------- rendering: pools ----------

  function renderPools() {
    el.poolsSkeleton.hidden = true;
    el.poolsError.hidden = true;

    if (state.pools.length === 0) {
      el.poolsEmpty.hidden = false;
      el.poolList.hidden = true;
      return;
    }

    el.poolsEmpty.hidden = true;
    el.poolList.hidden = false;
    el.poolList.textContent = "";

    for (const pool of state.pools) {
      const m0 = assetMeta(pool.asset_0);
      const m1 = assetMeta(pool.asset_1);
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.className = "pool-item";
      btn.setAttribute("role", "option");
      btn.setAttribute("aria-selected", String(pool.pool_id === state.selectedPoolId));
      btn.dataset.poolId = pool.pool_id;

      const pair = document.createElement("div");
      pair.className = "pool-pair";
      const pairName = document.createElement("span");
      pairName.textContent = `${m0.symbol} / ${m1.symbol}`;
      const fee = document.createElement("span");
      fee.className = "pool-fee";
      fee.textContent = (Number(pool.fee_bps) / 100).toFixed(2).replace(/\.?0+$/, "") + "% fee";
      pair.append(pairName, fee);

      const reserves = document.createElement("div");
      reserves.className = "pool-reserves";
      reserves.textContent =
        `${formatAmount(BigInt(pool.reserve_0), m0.decimals, 4)} ${m0.symbol} \u00b7 ` +
        `${formatAmount(BigInt(pool.reserve_1), m1.decimals, 4)} ${m1.symbol}`;

      btn.append(pair, reserves);
      btn.addEventListener("click", () => selectPool(pool.pool_id));
      li.appendChild(btn);
      el.poolList.appendChild(li);
    }
  }

  function showPoolsError(message) {
    el.poolsSkeleton.hidden = true;
    el.poolsEmpty.hidden = true;
    el.poolList.hidden = true;
    el.poolsError.hidden = false;
    el.poolsErrorText.textContent = message;
  }

  // ---------- rendering: swap form ----------

  function setHint(text, isError) {
    el.amountHint.textContent = text || "";
    el.amountHint.classList.toggle("is-error", Boolean(isError));
  }

  function setSubmit(label, enabled) {
    el.swapBtn.textContent = label;
    el.swapBtn.disabled = !enabled;
    el.swapBtn.classList.toggle("is-busy", false);
  }

  function clearQuoteDetails() {
    el.quoteDetails.hidden = true;
    el.amountOut.textContent = "0";
    el.amountOut.classList.remove("has-value");
  }

  function renderSwap() {
    const pool = selectedPool();

    if (!pool) {
      el.amountIn.disabled = true;
      el.flipBtn.disabled = true;
      el.maxBtn.hidden = true;
      el.assetInChip.textContent = "\u2014";
      el.assetOutChip.textContent = "\u2014";
      el.balanceDisplay.textContent = "\u2014";
      clearQuoteDetails();
      setHint("");
      setSubmit(state.pools.length === 0 ? "No pools available" : "Select a pool", false);
      return;
    }

    const [inSide, outSide] = poolSides(pool);
    const inMeta = assetMeta(inSide.asset);
    const outMeta = assetMeta(outSide.asset);

    el.amountIn.disabled = state.submitting;
    el.flipBtn.disabled = state.submitting;
    el.assetInChip.textContent = inMeta.symbol;
    el.assetOutChip.textContent = outMeta.symbol;

    // Balance line
    if (state.balanceAsset === inSide.asset && state.balance !== null) {
      el.balanceDisplay.textContent =
        `Balance: ${formatAmount(state.balance, inMeta.decimals, 6)}`;
      el.maxBtn.hidden = state.balance <= 0n;
    } else {
      el.balanceDisplay.textContent = "Balance: \u2026";
      el.maxBtn.hidden = true;
    }

    // Validate input and compute quote
    const raw = el.amountIn.value;
    el.amountIn.classList.remove("is-invalid");

    if (raw.trim() === "") {
      clearQuoteDetails();
      setHint("");
      setSubmit("Enter an amount", false);
      return;
    }

    const amountIn = parseAmount(raw, inMeta.decimals);
    if (amountIn === null) {
      el.amountIn.classList.add("is-invalid");
      clearQuoteDetails();
      const wellFormed = /^(\d+(\.\d+)?|\.\d+)$/.test(raw.trim());
      setHint(wellFormed
        ? `${inMeta.symbol} supports up to ${inMeta.decimals} decimal place${inMeta.decimals === 1 ? "" : "s"}.`
        : "Enter a plain decimal number.", true);
      setSubmit("Invalid amount", false);
      return;
    }

    if (amountIn === 0n) {
      clearQuoteDetails();
      setHint("");
      setSubmit("Enter an amount", false);
      return;
    }

    const q = quote(pool, amountIn);
    if (!q) {
      clearQuoteDetails();
      setHint("Amount is too small to produce any output at the pool fee.", true);
      setSubmit("Amount too small", false);
      return;
    }

    // Quote display
    el.amountOut.textContent = formatAmount(q.amountOut, outMeta.decimals);
    el.amountOut.classList.add("has-value");

    el.quoteDetails.hidden = false;
    el.detailRate.textContent = rateString(pool);
    const impactPct = (Number(q.impactBps) / 100).toFixed(2);
    el.detailImpact.textContent = impactPct + "%";
    el.detailImpact.classList.toggle("warn", q.impactBps >= 300n);
    el.detailImpact.classList.toggle("ok", q.impactBps < 100n);
    el.detailMin.textContent =
      `${formatAmount(q.minOut, outMeta.decimals)} ${outMeta.symbol}`;
    el.detailFee.textContent =
      (Number(pool.fee_bps) / 100).toFixed(2).replace(/\.?0+$/, "") + "%";
    el.detailReserves.textContent =
      `${formatAmount(q.inSide.reserve, inMeta.decimals, 4)} ${inMeta.symbol} \u00b7 ` +
      `${formatAmount(q.outSide.reserve, outMeta.decimals, 4)} ${outMeta.symbol}`;

    if (state.submitting) {
      setHint("");
      el.swapBtn.textContent = "Swapping\u2026";
      el.swapBtn.disabled = true;
      el.swapBtn.classList.add("is-busy");
      return;
    }

    if (q.minOut <= 0n) {
      setHint("Slippage tolerance floors the minimum received to zero.", true);
      setSubmit("Quote below slippage floor", false);
      return;
    }

    // Balance validation
    if (state.balanceAsset === inSide.asset && state.balance !== null && amountIn > state.balance) {
      setHint(`You hold ${formatAmount(state.balance, inMeta.decimals)} ${inMeta.symbol}.`, true);
      setSubmit(`Insufficient ${inMeta.symbol}`, false);
      return;
    }

    setHint(q.impactBps >= 300n
      ? "High price impact: this trade moves the pool price noticeably."
      : "");
    setSubmit(`Swap ${inMeta.symbol} for ${outMeta.symbol}`, true);
  }

  // ---------- status card ----------

  function showStatus(kind, title, detail) {
    el.swapStatus.textContent = "";
    const card = document.createElement("div");
    card.className = "status-card " + kind;
    const t = document.createElement("span");
    t.className = "status-title";
    t.textContent = title;
    card.appendChild(t);
    if (detail) {
      const d = document.createElement("span");
      d.className = "status-detail";
      d.textContent = detail;
      card.appendChild(d);
    }
    el.swapStatus.appendChild(card);
  }

  function clearStatus() {
    el.swapStatus.textContent = "";
  }

  // ---------- data loading ----------

  async function loadIdentity() {
    try {
      state.config = await api("/api/config");
    } catch (_) {
      state.config = null;
    }
    renderIdentity();
  }

  async function loadMarket() {
    el.poolsSkeleton.hidden = false;
    el.poolsError.hidden = true;
    el.poolsEmpty.hidden = true;
    el.poolList.hidden = true;
    try {
      const [assets, pools] = await Promise.all([api("/api/assets"), api("/api/pools")]);
      state.assets = new Map(
        (assets.items || []).map((a) => [a.asset_id, a])
      );
      state.pools = pools.items || [];
      if (state.selectedPoolId && !selectedPool()) {
        state.selectedPoolId = null;
        state.balance = null;
        state.balanceAsset = null;
      }
      renderPools();
      renderSwap();
    } catch (err) {
      showPoolsError(err.message || "Could not load the market.");
      renderSwap();
    }
  }

  async function loadBalance() {
    const pool = selectedPool();
    if (!pool) return;
    const [inSide] = poolSides(pool);
    const assetId = inSide.asset;
    const seq = ++state.balanceSeq;
    state.balance = null;
    state.balanceAsset = null;
    renderSwap();
    try {
      const res = await api(`/api/balance?asset=${encodeURIComponent(assetId)}`);
      if (seq !== state.balanceSeq) return; // superseded
      state.balance = BigInt(res.balance);
      state.balanceAsset = assetId;
    } catch (_) {
      if (seq !== state.balanceSeq) return;
      state.balance = null;
      state.balanceAsset = null;
    }
    renderSwap();
  }

  // ---------- interactions ----------

  function selectPool(poolId) {
    if (state.submitting) return;
    if (state.selectedPoolId === poolId) return;
    state.selectedPoolId = poolId;
    state.reversed = false;
    clearStatus();
    for (const btn of el.poolList.querySelectorAll(".pool-item")) {
      btn.setAttribute("aria-selected", String(btn.dataset.poolId === poolId));
    }
    renderSwap();
    loadBalance();
    el.amountIn.focus();
  }

  el.flipBtn.addEventListener("click", () => {
    if (state.submitting || !selectedPool()) return;
    state.reversed = !state.reversed;
    clearStatus();
    renderSwap();
    loadBalance();
  });

  el.amountIn.addEventListener("input", () => {
    clearStatus();
    renderSwap();
  });

  el.maxBtn.addEventListener("click", () => {
    const pool = selectedPool();
    if (!pool || state.balance === null) return;
    const [inSide] = poolSides(pool);
    if (state.balanceAsset !== inSide.asset) return;
    el.amountIn.value = formatAmountPlain(state.balance, assetMeta(inSide.asset).decimals);
    clearStatus();
    renderSwap();
    el.amountIn.focus();
  });

  el.refreshPools.addEventListener("click", loadMarket);
  el.poolsRetry.addEventListener("click", loadMarket);

  // Slippage
  function setSlippage(bps, fromPreset) {
    state.slippageBps = bps;
    for (const btn of el.slipButtons) {
      btn.classList.toggle("is-active", fromPreset && BigInt(btn.dataset.bps) === bps);
    }
    el.slippageHint.hidden = true;
    el.slippageInput.classList.remove("is-invalid");
    renderSwap();
  }

  for (const btn of el.slipButtons) {
    btn.addEventListener("click", () => {
      el.slippageInput.value = "";
      setSlippage(BigInt(btn.dataset.bps), true);
    });
  }

  el.slippageInput.addEventListener("input", () => {
    const raw = el.slippageInput.value.trim();
    if (raw === "") {
      setSlippage(50n, true);
      el.slipButtons.forEach((b) => b.classList.toggle("is-active", b.dataset.bps === "50"));
      return;
    }
    const m = /^(\d{1,2})(?:\.(\d{1,2}))?$/.exec(raw);
    if (!m) {
      el.slippageInput.classList.add("is-invalid");
      el.slippageHint.hidden = false;
      el.slippageHint.textContent = "Slippage must be a percentage between 0 and 50, up to two decimals.";
      el.slippageHint.classList.add("is-error");
      return;
    }
    const bps = BigInt(m[1]) * 100n + BigInt((m[2] || "").padEnd(2, "0") || "0");
    if (bps > 5000n) {
      el.slippageInput.classList.add("is-invalid");
      el.slippageHint.hidden = false;
      el.slippageHint.textContent = "Slippage above 50% is not allowed.";
      el.slippageHint.classList.add("is-error");
      return;
    }
    for (const b of el.slipButtons) b.classList.remove("is-active");
    setSlippage(bps, false);
  });

  // ---------- submit ----------

  el.form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (state.submitting) return;

    const pool = selectedPool();
    if (!pool) return;
    const [inSide, outSide] = poolSides(pool);
    const inMeta = assetMeta(inSide.asset);
    const outMeta = assetMeta(outSide.asset);

    const amountIn = parseAmount(el.amountIn.value, inMeta.decimals);
    if (amountIn === null || amountIn === 0n) return;
    const q = quote(pool, amountIn);
    if (!q || q.minOut <= 0n) return;
    if (state.balanceAsset === inSide.asset && state.balance !== null && amountIn > state.balance) return;

    state.submitting = true;
    clearStatus();
    renderSwap();

    try {
      const receipt = await api("/api/swap", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          pool_id: pool.pool_id,
          asset_in: inSide.asset,
          amount_in: amountIn.toString(),
          min_amount_out: q.minOut.toString(),
        }),
      });
      state.submitting = false;
      el.amountIn.value = "";
      const received = receipt && typeof receipt.amount_out === "string"
        ? formatAmount(BigInt(receipt.amount_out), outMeta.decimals)
        : null;
      showStatus(
        "success",
        "Swap confirmed",
        received !== null
          ? `Paid ${formatAmount(amountIn, inMeta.decimals)} ${inMeta.symbol}, received ${received} ${outMeta.symbol}.`
          : `Paid ${formatAmount(amountIn, inMeta.decimals)} ${inMeta.symbol} into ${inMeta.symbol}/${outMeta.symbol}.`
      );
      await loadMarket();
      loadBalance();
    } catch (err) {
      state.submitting = false;
      showStatus("error", "Swap failed", err.message || "The gateway rejected the swap.");
      renderSwap();
    }
  });

  // ---------- boot ----------

  loadIdentity();
  loadMarket();
})();
