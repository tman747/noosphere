"use strict";

const $ = (selector) => document.querySelector(selector);
const state = { config: null, defi: null, busy: false };
const ORACLE_SCALE = 1_000_000_000n;

function bigint(value, fallback = 0n) {
  try { return BigInt(value); } catch { return fallback; }
}
function short(value) { return value ? `${value.slice(0, 8)}…${value.slice(-6)}` : "—"; }
function format(value) { return bigint(value).toLocaleString("en-US"); }
function text(tag, value, className) {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className) node.className = className;
  return node;
}
function setNotice(message, kind = "") {
  const notice = $("#notice");
  notice.textContent = message;
  notice.className = `notice ${kind}`.trim();
}
function selectedPool() {
  return state.defi?.pools.find((pool) => pool.pool_id === $("#pool").value);
}
function selectedMarket() {
  return state.defi?.lending_markets.find((market) => market.market_id === $("#market").value);
}
function stableFor(market) {
  return state.defi?.stable_assets.find((asset) => asset.asset_id === market?.stable_asset);
}
function ownDebt(market) {
  return state.defi?.debt_positions.find((position) => position.market_id === market?.market_id && position.owner === state.config?.account);
}
function oraclePrice(market) {
  if (!market) return null;
  const feed = state.defi.oracle_feeds.find((item) => item.feed_id === market.oracle_feed_id);
  if (!feed) return null;
  const head = bigint(state.config.head.height);
  const maxAge = bigint(feed.max_age_blocks);
  const reporters = new Set(feed.reporters);
  const reports = state.defi.oracle_reports
    .filter((report) => report.feed_id === feed.feed_id && reporters.has(report.reporter) && bigint(report.observed_height) <= head && head - bigint(report.observed_height) <= maxAge)
    .map((report) => bigint(report.price_q9) * (10000n - bigint(report.confidence_bps)) / 10000n)
    .sort((a, b) => a < b ? -1 : a > b ? 1 : 0);
  if (reports.length < 2) return null;
  return reports.length === 2 ? reports[0] : reports[Math.floor(reports.length / 2)];
}
function readout(rows) {
  const fragment = document.createDocumentFragment();
  for (const [label, value] of rows) {
    const row = text("p", "");
    row.append(text("span", label), text("b", value));
    fragment.append(row);
  }
  return fragment;
}
function populateSelect(selector, items, valueKey, label) {
  const select = $(selector);
  const previous = select.value;
  select.replaceChildren();
  if (!items.length) {
    const option = text("option", "No records available");
    option.disabled = true;
    option.selected = true;
    select.append(option);
    return;
  }
  for (const item of items) {
    const option = text("option", label(item));
    option.value = item[valueKey];
    select.append(option);
  }
  if (items.some((item) => item[valueKey] === previous)) select.value = previous;
}
function renderPool() {
  const pool = selectedPool();
  const target = $("#pool-readout");
  target.replaceChildren();
  if (!pool) { target.append(text("p", "No pool selected.")); return; }
  const own = state.defi.liquidity_positions.find((position) => position.pool_id === pool.pool_id && position.provider === state.config.account);
  target.append(readout([
    ["Asset 0 reserve", format(pool.reserve_0)], ["Asset 1 reserve", format(pool.reserve_1)],
    ["Total shares", format(pool.total_shares)], ["Owned shares", format(own?.shares || 0)],
    ["Swap fee", `${pool.fee_bps} bps`], ["Pool ID", short(pool.pool_id)],
  ]));
  updateLiquidityQuotes();
}
function updateLiquidityQuotes() {
  const pool = selectedPool();
  if (!pool) return;
  const add = new FormData($("#add-form"));
  const max0 = bigint(add.get("max_amount_0"));
  const max1 = bigint(add.get("max_amount_1"));
  const reserve0 = bigint(pool.reserve_0), reserve1 = bigint(pool.reserve_1), total = bigint(pool.total_shares);
  const shares = reserve0 && reserve1 ? (max0 * total / reserve0 < max1 * total / reserve1 ? max0 * total / reserve0 : max1 * total / reserve1) : 0n;
  $("#add-quote").textContent = max0 > 0n && max1 > 0n ? `Ledger estimate: up to ${shares.toLocaleString()} shares. Final amounts are rounded up and bounded by your maxima.` : "Enter both maximum amounts to preview non-dilutive shares.";
  const remove = new FormData($("#remove-form"));
  const burn = bigint(remove.get("shares"));
  $("#remove-quote").textContent = burn > 0n && total > 0n ? `Ledger estimate: ${format(reserve0 * burn / total)} asset 0 and ${format(reserve1 * burn / total)} asset 1.` : "Only shares owned by the connected account can be burned.";
}
function renderMarket() {
  const market = selectedMarket();
  const target = $("#market-readout");
  target.replaceChildren();
  if (!market) { target.append(text("p", "No market selected.")); return; }
  const position = ownDebt(market);
  const stable = stableFor(market);
  const price = oraclePrice(market);
  const collateral = bigint(position?.collateral), debt = bigint(position?.debt);
  const collateralValue = price === null ? null : collateral * price / ORACLE_SCALE;
  const borrowLimit = collateralValue === null ? null : collateralValue * bigint(market.collateral_factor_bps) / 10000n;
  target.append(readout([
    ["Stable asset", stable ? `${stable.symbol} / ${short(stable.asset_id)}` : short(market.stable_asset)],
    ["Conservative price", price === null ? "Unavailable — actions fail closed" : `${price.toLocaleString()} q9`],
    ["Your collateral", collateral.toLocaleString()], ["Your debt", debt.toLocaleString()],
    ["Borrow limit", borrowLimit === null ? "Unavailable" : borrowLimit.toLocaleString()],
    ["Liquidation threshold", `${market.liquidation_threshold_bps} bps`],
    ["Market debt", `${format(market.total_debt)} / ${format(market.debt_ceiling)}`],
    ["Market ID", short(market.market_id)],
  ]));
}
function renderPositions() {
  const target = $("#positions");
  target.replaceChildren();
  const records = [];
  for (const position of state.defi.liquidity_positions) {
    if (position.provider !== state.config.account) continue;
    records.push(["Liquidity position", short(position.position_id), ["Pool", short(position.pool_id)], ["Shares", format(position.shares)]]);
  }
  for (const position of state.defi.debt_positions) {
    const owned = position.owner === state.config.account ? "Your debt position" : "External debt position";
    records.push([owned, short(position.position_id), ["Collateral", format(position.collateral)], ["Debt", format(position.debt)]]);
  }
  for (const payment of state.defi.private_payments || []) {
    const paymentStatus = [\"Open\", \"Claimed\", \"Refunded\"][payment.status] || \"Unknown\";
    const paymentKind = [\"General\", \"Agent\", \"Invoice\", \"Commerce\"][payment.payment_kind] || \"Unknown\";
    records.push([`Private payment / ${paymentStatus}`, short(payment.payment_id), [\"Amount\", format(payment.amount)], [\"Kind\", paymentKind]]);
  }
  if (!records.length) { target.append(text("p", "No liquidity or debt positions exist.", "empty")); return; }
  for (const record of records) {
    const card = text("article", "", "position");
    const id = text("div", ""); id.append(text("span", record[0]), text("code", record[1]));
    const first = text("div", ""); first.append(text("span", record[2][0]), text("b", record[2][1]));
    const second = text("div", ""); second.append(text("span", record[3][0]), text("b", record[3][1]));
    card.append(id, first, second); target.append(card);
  }
}
function render() {
  $("#account").textContent = state.config.account;
  $("#pool-count").textContent = state.defi.pools.length;
  $("#market-count").textContent = state.defi.lending_markets.length;
  $(\"#payment-count\").textContent = (state.defi.private_payments || []).length;
  populateSelect("#pool", state.defi.pools, "pool_id", (pool) => `${short(pool.asset_0)} / ${short(pool.asset_1)} · ${pool.fee_bps} bps`);
  populateSelect("#market", state.defi.lending_markets, "market_id", (market) => `${stableFor(market)?.symbol || "STABLE"} · ${short(market.collateral_asset)}`);
  renderPool(); renderMarket(); renderPositions();
}
async function responseJson(response) {
  const body = await response.json().catch(() => ({ error: `HTTP ${response.status}` }));
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`);
  return body;
}
async function refresh() {
  if (state.busy) return;
  state.busy = true; $("#refresh").disabled = true; setNotice("Reading finalized application state…");
  try {
    const [configResponse, defiResponse] = await Promise.all([fetch("/api/config", { cache: "no-store" }), fetch("/api/defi", { cache: "no-store" })]);
    state.config = await responseJson(configResponse); state.defi = await responseJson(defiResponse);
    render();
    $("#network").classList.add("online"); $("#network span").textContent = `Height ${state.config.head.height}`;
    setNotice("Consensus state synchronized. Quotes are estimates; ledger limits remain authoritative.", "success");
  } catch (error) {
    $("#network").classList.remove("online"); $("#network span").textContent = "Unavailable";
    setNotice(error.message, "error");
  } finally { state.busy = false; $("#refresh").disabled = false; }
}
async function submit(action) {
  if (state.busy) return;
  state.busy = true;
  document.querySelectorAll("button").forEach((button) => { button.disabled = true; });
  setNotice(`Submitting ${action.type.replaceAll("_", " ")}…`);
  try {
    const result = await responseJson(await fetch("/api/defi/action", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(action) }));
    setNotice(`Settled transaction ${short(result.txid)}. Refreshing consensus state…`, "success");
    state.busy = false; await refresh();
  } catch (error) { setNotice(error.message, "error"); }
  finally { state.busy = false; document.querySelectorAll("button").forEach((button) => { button.disabled = false; }); }
}
function fields(form) { return Object.fromEntries(new FormData(form).entries()); }
$("#pool").addEventListener("change", renderPool);
$("#market").addEventListener("change", renderMarket);
$("#add-form").addEventListener("input", updateLiquidityQuotes);
$("#remove-form").addEventListener("input", updateLiquidityQuotes);
$("#add-form").addEventListener("submit", (event) => { event.preventDefault(); submit({ type: "add_liquidity", pool_id: selectedPool().pool_id, ...fields(event.currentTarget) }); });
$("#remove-form").addEventListener("submit", (event) => { event.preventDefault(); submit({ type: "remove_liquidity", pool_id: selectedPool().pool_id, ...fields(event.currentTarget) }); });
document.querySelectorAll("form[data-action]").forEach((form) => form.addEventListener("submit", (event) => { event.preventDefault(); submit({ type: form.dataset.action, market_id: selectedMarket().market_id, ...fields(form) }); }));
$("#liquidate-form").addEventListener("submit", (event) => { event.preventDefault(); submit({ type: "liquidate_position", market_id: selectedMarket().market_id, ...fields(event.currentTarget) }); });
$("#refresh").addEventListener("click", refresh);
refresh();
