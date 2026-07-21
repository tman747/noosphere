import { enrollPasskeyRecovery, passkeyRecoverySupported, recoverPasskeyPassword } from "./passkey-recovery.js";

"use strict";

const $ = (selector) => document.querySelector(selector);
const DB_NAME = "harbor-wallet-v1";
const STORE = "vault";
const VAULT_KEY = "primary";
const RECOVERY_KEY = "passkey-recovery";
const PBKDF2_ROUNDS = 310000;
const NOOS = "00".repeat(32);
const CHAIN_ID = "0106bef48c350fd9633bac1718f8d9ecb1824c78bd127feee6405c65a63afa8b";
const GENESIS_HASH = "8c182c6e9d622f77f082332da1a514ecf061ef4c504b5dde466ca4c93e35167e";
const state = { privateKey: null, account: null, vault: null, config: null, assets: [], defi: null, psmMarkets: [], installPrompt: null, busy: false };

function bytesToHex(bytes) { return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join(""); }
function hexToBytes(hex) { if (!/^(?:[0-9a-f]{2})+$/.test(hex)) throw new Error("Invalid canonical hex"); return Uint8Array.from(hex.match(/../g), (value) => parseInt(value, 16)); }
function randomBytes(length) { return crypto.getRandomValues(new Uint8Array(length)); }
function status(message, error = false) { const node = $("#auth-status"); node.textContent = message; node.className = error ? "status error" : "status"; }
function notice(message, error = false) { const node = $("#notice"); node.textContent = message; node.className = error ? "notice error" : "notice"; }
function setBusy(busy) { state.busy = busy; document.querySelectorAll("button").forEach((button) => { button.disabled = busy; }); }

function openDb() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}
async function storeGet(key) { const db = await openDb(); return new Promise((resolve, reject) => { const request = db.transaction(STORE).objectStore(STORE).get(key); request.onsuccess = () => resolve(request.result || null); request.onerror = () => reject(request.error); }); }
async function storePut(key, value) { const db = await openDb(); return new Promise((resolve, reject) => { const request = db.transaction(STORE, "readwrite").objectStore(STORE).put(value, key); request.onsuccess = () => resolve(); request.onerror = () => reject(request.error); }); }
async function vaultGet() { return storeGet(VAULT_KEY); }
async function vaultPut(value) { return storePut(VAULT_KEY, value); }
async function passwordKey(password, salt) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: PBKDF2_ROUNDS, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function encryptPrivate(pkcs8, password, publicId, spki) {
  const salt = randomBytes(16), iv = randomBytes(12), key = await passwordKey(password, salt);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: new TextEncoder().encode(publicId) }, key, pkcs8);
  return { schema: "harbor-wallet-v1", kdf: "PBKDF2-SHA256", rounds: PBKDF2_ROUNDS, cipher: "AES-256-GCM", public_id: publicId, public_spki: bytesToHex(spki), salt: bytesToHex(salt), iv: bytesToHex(iv), ciphertext: bytesToHex(ciphertext), created_at: new Date().toISOString() };
}
async function decryptVault(vault, password) {
  if (vault?.schema !== "harbor-wallet-v1" || vault.rounds !== PBKDF2_ROUNDS || !/^[0-9a-f]{64}$/.test(vault.public_id) || !/^(?:[0-9a-f]{2})+$/.test(vault.public_spki)) throw new Error("Unsupported or malformed Harbor vault");
  const spki = hexToBytes(vault.public_spki);
  if (bytesToHex(spki.slice(-32)) !== vault.public_id) throw new Error("Vault public identity does not match its verification key");
  const key = await passwordKey(password, hexToBytes(vault.salt));
  try {
    const clear = await crypto.subtle.decrypt({ name: "AES-GCM", iv: hexToBytes(vault.iv), additionalData: new TextEncoder().encode(vault.public_id) }, key, hexToBytes(vault.ciphertext));
    const [privateKey, publicKey] = await Promise.all([
      crypto.subtle.importKey("pkcs8", clear, { name: "Ed25519" }, false, ["sign"]),
      crypto.subtle.importKey("spki", spki, { name: "Ed25519" }, false, ["verify"]),
    ]);
    const challenge = randomBytes(32);
    const signature = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, challenge);
    if (!await crypto.subtle.verify({ name: "Ed25519" }, publicKey, signature, challenge)) throw new Error("Vault key pair mismatch");
    return privateKey;
  } catch { throw new Error("Wrong password, altered backup, or mismatched key pair"); }
}
async function createWallet(password) {
  if (!crypto.subtle) throw new Error("WebCrypto is unavailable in this browser");
  let pair;
  try { pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]); }
  catch { throw new Error("Ed25519 wallet keys require Safari 17 or newer on iPhone."); }
  const [pkcs8, spki] = await Promise.all([crypto.subtle.exportKey("pkcs8", pair.privateKey), crypto.subtle.exportKey("spki", pair.publicKey)]);
  const publicId = bytesToHex(new Uint8Array(spki).slice(-32));
  const vault = await encryptPrivate(pkcs8, password, publicId, spki);
  await vaultPut(vault);
  state.vault = vault; state.account = publicId;
  state.privateKey = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
}
async function unlock(vault, password) { state.privateKey = await decryptVault(vault, password); state.vault = vault; state.account = vault.public_id; }
async function json(response) { const body = await response.json().catch(() => ({ error: `HTTP ${response.status}` })); if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`); return body; }
async function post(path, body) { return json(await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })); }
function format(value) { try { return BigInt(value).toLocaleString("en-US"); } catch { return "—"; } }
function short(value) { return `${value.slice(0, 8)}…${value.slice(-6)}`; }

function assetName(assetId) {
  const asset = state.assets.find((item) => item.asset_id === assetId);
  return asset ? `${asset.symbol || "ASSET"} · ${short(assetId)}` : short(assetId);
}

function selectedPsmMarket() {
  return state.psmMarkets.find((item) => item.market_id === $("#psm-market").value) || null;
}

async function refreshPsmView() {
  const safetyByMarket = new Map((state.defi?.stable_safety || []).map((item) => [item.market_id, item]));
  state.psmMarkets = (state.defi?.lending_markets || [])
    .filter((market) => safetyByMarket.has(market.market_id))
    .map((market) => ({ ...market, safety: safetyByMarket.get(market.market_id) }));
  const marketSelect = $("#psm-market");
  const previous = marketSelect.value;
  marketSelect.replaceChildren(...state.psmMarkets.map((market) => {
    const option = document.createElement("option");
    option.value = market.market_id;
    option.textContent = `${assetName(market.collateral_asset)} → ${assetName(market.stable_asset)}`;
    return option;
  }));
  if (state.psmMarkets.some((market) => market.market_id === previous)) marketSelect.value = previous;
  $("#psm-empty").classList.toggle("hidden", state.psmMarkets.length !== 0);
  await updatePsmSelection();
}

async function updatePsmSelection() {
  const market = selectedPsmMarket();
  const minting = $("#psm-kind").value === "psm_mint";
  $("#psm-stable-reserve").textContent = market ? format(market.safety.stable_reserve) : "—";
  $("#psm-collateral-reserve").textContent = market ? format(market.safety.collateral_reserve) : "—";
  $("#psm-debt").textContent = market ? format(market.safety.psm_debt) : "—";
  $("#psm-fee").textContent = market ? `${format(market.safety.psm_fee_bps)} bps` : "—";
  $("#psm-output-asset").textContent = market ? assetName(minting ? market.stable_asset : market.collateral_asset) : "—";
  $("#psm-input-balance").textContent = "—";
  if (!market || !state.account) return;
  const inputAsset = minting ? market.collateral_asset : market.stable_asset;
  try {
    const balance = await json(await fetch(`/api/balance?account=${state.account}&asset=${inputAsset}`, { cache: "no-store" }));
    $("#psm-input-balance").textContent = `${format(balance.amount || balance.balance || 0)} · ${assetName(inputAsset)}`;
  } catch {
    $("#psm-input-balance").textContent = "Unavailable";
  }
}

async function loadNetwork() {
  state.config = await json(await fetch("/api/config", { cache: "no-store" }));
  if (state.config.chain_id !== CHAIN_ID || state.config.genesis_hash !== GENESIS_HASH || state.config.production !== false) {
    throw new Error("Wallet gateway returned the wrong public-testnet identity");
  }
  const [assets, defi] = await Promise.all([
    json(await fetch("/api/assets", { cache: "no-store" })).catch(() => ({ items: [] })),
    json(await fetch("/api/defi", { cache: "no-store" })).catch(() => ({ stable_assets: [], lending_markets: [], stable_safety: [] })),
  ]);
  state.defi = defi;
  state.assets = [{ asset_id: NOOS, symbol: "NOOS_TEST", name: "Valueless MindChain test asset" }, ...assets.items, ...defi.stable_assets];
  const unique = new Map(state.assets.map((asset) => [asset.asset_id, asset])); state.assets = [...unique.values()];
  const select = $("#asset"); select.replaceChildren(...state.assets.map((asset) => { const option = document.createElement("option"); option.value = asset.asset_id; option.textContent = `${asset.symbol || "ASSET"} · ${short(asset.asset_id)}`; return option; }));
  $("#height").textContent = format(state.config.head.height);
  $("#network").classList.add("online"); $("#network span").textContent = `Public testnet · ${state.config.head.height}`;
  await refreshPsmView();
}
async function refresh() {
  if (!state.account) return;
  setBusy(true); notice("Reading this valueless public-testnet account…");
  try {
    await loadNetwork();
    const balance = await json(await fetch(`/api/balance?account=${state.account}&asset=${NOOS}`, { cache: "no-store" }));
    $("#noos-balance").textContent = format(balance.amount || balance.balance || 0);
    notice("Account synchronized. Back up the encrypted vault before clearing Safari data.");
  } catch (error) { notice(error.message, true); $("#network").classList.remove("online"); $("#network span").textContent = "Unavailable"; }
  finally { setBusy(false); }
}
function showWallet() { $("#unlock-view").classList.add("hidden"); $("#wallet-view").classList.remove("hidden"); $("#account").textContent = state.account; queueMicrotask(refresh); }
function showAuth(tab = "unlock") { $("#wallet-view").classList.add("hidden"); $("#unlock-view").classList.remove("hidden"); document.querySelector(`[data-tab=${tab}]`)?.click(); }

async function reviewTransaction(title, entries) {
  const review = $("#review"); review.replaceChildren();
  $("#review-title").textContent = title;
  for (const [label, value] of entries) {
    const dt = document.createElement("dt"), dd = document.createElement("dd"); dt.textContent = label; dd.textContent = value; review.append(dt, dd);
  }
  const dialog = $("#confirm-dialog");
  $("#confirm-sign").disabled = false;
  dialog.querySelector('button[value="cancel"]').disabled = false;
  dialog.showModal();
  return new Promise((resolve) => dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true }));
}

async function signSimulateSubmit(built) {
  notice("Signing transaction locally for exact state simulation…");
  const signature = bytesToHex(await crypto.subtle.sign({ name: "Ed25519" }, state.privateKey, hexToBytes(built.signing_message)));
  const envelope = { account: state.account, tx: built.tx, txid: built.txid, signature };
  const prediction = await post("/api/wallet/simulate", envelope);
  if (prediction.txid !== built.txid || prediction.accepted !== true || Number(prediction.status) !== 0) {
    throw new Error(`Simulation refused this transaction (status ${prediction.status ?? "unknown"}). No transaction was submitted.`);
  }
  notice(`Simulation passed. Predicted fee ${format(prediction.fee_charged)}. Submitting…`);
  return post("/api/wallet/submit", envelope);
}
async function sendPayment(form) {
  if (!state.config) await loadNetwork();
  const values = Object.fromEntries(new FormData(form).entries());
  if (!/^[0-9a-f]{64}$/.test(values.recipient) || !/^[0-9]+$/.test(values.amount) || BigInt(values.amount) < 1n) throw new Error("Recipient or amount is invalid");
  notice("Building unsigned canonical transaction…");
  const built = await post("/api/wallet/build", { account: state.account, recipient: values.recipient, asset: values.asset, amount: values.amount });
  if (built.chain_id !== state.config.chain_id || built.genesis_hash !== state.config.genesis_hash) throw new Error("Unsigned builder returned the wrong chain identity");
  if (!await reviewTransaction("Sign this transfer?", [["From", state.account], ["To", values.recipient], ["Asset", values.asset], ["Amount", values.amount], ["Transaction ID", built.txid], ["Chain", built.chain_id]])) { notice("Transaction cancelled before signing."); return; }
  const settled = await signSimulateSubmit(built);
  form.reset();
  await refresh();
  notice(`Included ${settled.txid} at height ${settled.receipt?.inclusion?.height ?? "pending"} on the public testnet.`);
}

async function convertPsm(form) {
  if (!state.config) await loadNetwork();
  const values = Object.fromEntries(new FormData(form).entries());
  const market = selectedPsmMarket();
  if (!market || market.market_id !== values.market_id) throw new Error("Selected stability market is unavailable");
  if (!/^[0-9]+$/.test(values.amount) || BigInt(values.amount) < 1n || !/^[0-9]+$/.test(values.min_output) || BigInt(values.min_output) < 1n) {
    throw new Error("Input and minimum output must be positive base-unit amounts");
  }
  notice("Building unsigned reserve conversion…");
  const built = await post("/api/wallet/build-action", {
    account: state.account,
    type: values.type,
    market_id: values.market_id,
    amount: values.amount,
    min_output: values.min_output,
  });
  if (built.chain_id !== state.config.chain_id || built.genesis_hash !== state.config.genesis_hash) throw new Error("Unsigned builder returned the wrong chain identity");
  const minting = values.type === "psm_mint";
  const expectedAction = minting
    ? { type: "psm_mint", owner: state.account, market_id: values.market_id, collateral_in: values.amount, min_stable_out: values.min_output }
    : { type: "psm_redeem", owner: state.account, market_id: values.market_id, stable_in: values.amount, min_collateral_out: values.min_output };
  if (JSON.stringify(built.action) !== JSON.stringify(expectedAction)) throw new Error("Unsigned builder changed the requested reserve conversion");
  const direction = minting ? "Collateral → stable" : "Stable → collateral";
  if (!await reviewTransaction("Sign this reserve conversion?", [["Account", state.account], ["Direction", direction], ["Market", values.market_id], ["Input", values.amount], ["Minimum output", values.min_output], ["Transaction ID", built.txid], ["Chain", built.chain_id]])) {
    notice("Reserve conversion cancelled before signing.");
    return;
  }
  const settled = await signSimulateSubmit(built);
  notice(`Reserve conversion ${short(settled.txid)} settled after successful simulation.`);
  form.reset();
  await refresh();
}

document.querySelectorAll("[data-tab]").forEach((button) => button.addEventListener("click", () => { document.querySelectorAll("[data-tab]").forEach((item) => item.classList.toggle("active", item === button)); for (const id of ["create", "unlock", "import"]) $(`#${id}-form`).classList.toggle("hidden", id !== button.dataset.tab); status(""); }));
$("#create-form").addEventListener("submit", async (event) => { event.preventDefault(); const values = new FormData(event.currentTarget); if (values.get("password") !== values.get("confirm")) return status("Passwords do not match.", true); setBusy(true); try { await createWallet(values.get("password")); showWallet(); } catch (error) { status(error.message, true); } finally { setBusy(false); } });
$("#unlock-form").addEventListener("submit", async (event) => { event.preventDefault(); const password = new FormData(event.currentTarget).get("password"); setBusy(true); try { const vault = await vaultGet(); if (!vault) throw new Error("No local vault exists. Create or import one first."); await unlock(vault, password); showWallet(); } catch (error) { status(error.message, true); } finally { setBusy(false); } });
$("#import-form").addEventListener("submit", async (event) => { event.preventDefault(); setBusy(true); try { const data = new FormData(event.currentTarget); const vault = JSON.parse(await data.get("vault").text()); await unlock(vault, data.get("password")); await vaultPut(vault); showWallet(); } catch (error) { status(error.message, true); } finally { setBusy(false); } });
$("#passkey-unlock").addEventListener("click", async () => {
  setBusy(true);
  try {
    const [vault, recovery] = await Promise.all([vaultGet(), storeGet(RECOVERY_KEY)]);
    if (!vault || !recovery) throw new Error("Passkey recovery is not enrolled on this device.");
    const config = await json(await fetch("/api/config", { cache: "no-store" }));
    const password = await recoverPasskeyPassword(recovery, {
      chainId: config.chain_id,
      publicId: vault.public_id,
      vaultSchema: vault.schema,
    });
    await unlock(vault, password);
    showWallet();
  } catch (error) { status(error.message, true); }
  finally { setBusy(false); }
});
$("#passkey-enroll").addEventListener("click", async () => {
  setBusy(true);
  const passwordInput = $("#passkey-password");
  try {
    if (!passkeyRecoverySupported()) throw new Error("This browser does not support passkey recovery.");
    const password = passwordInput.value;
    await decryptVault(state.vault, password);
    if (!state.config) await loadNetwork();
    const recovery = await enrollPasskeyRecovery({
      password,
      chainId: state.config.chain_id,
      publicId: state.vault.public_id,
      vaultSchema: state.vault.schema,
    });
    await storePut(RECOVERY_KEY, recovery);
    notice("Passkey recovery enabled for this origin, chain, account, and vault version.");
  } catch (error) { notice(error.message, true); }
  finally { passwordInput.value = ""; setBusy(false); }
});
$("#send-form").addEventListener("submit", async (event) => { event.preventDefault(); if (state.busy) return; setBusy(true); try { await sendPayment(event.currentTarget); } catch (error) { notice(error.message, true); } finally { setBusy(false); } });
$("#psm-form").addEventListener("submit", async (event) => { event.preventDefault(); if (state.busy) return; setBusy(true); try { await convertPsm(event.currentTarget); } catch (error) { notice(error.message, true); } finally { setBusy(false); } });
$("#psm-market").addEventListener("change", updatePsmSelection);
$("#psm-kind").addEventListener("change", updatePsmSelection);
$("#faucet").addEventListener("click", async () => {
  setBusy(true);
  try {
    const result = await post("/api/wallet/faucet", { account: state.account, amount: "1000000" });
    await refresh();
    notice(`Received 1,000,000 valueless NOOS_TEST in ${result.txid} at height ${result.receipt?.inclusion?.height ?? "pending"}.`);
  } catch (error) { notice(error.message, true); }
  finally { setBusy(false); }
});
$("#refresh").addEventListener("click", refresh);
$("#copy-account").addEventListener("click", async () => { await navigator.clipboard.writeText(state.account); notice("Account public key copied."); });
$("#backup").addEventListener("click", () => { const blob = new Blob([JSON.stringify(state.vault, null, 2)], { type: "application/json" }); const link = document.createElement("a"); link.href = URL.createObjectURL(blob); link.download = `harbor-wallet-${state.account.slice(0, 8)}.json`; link.click(); URL.revokeObjectURL(link.href); notice("Encrypted backup created. Keep it with the password; never share either."); });
$("#lock").addEventListener("click", () => { state.privateKey = null; state.account = null; showAuth("unlock"); });
window.addEventListener("beforeinstallprompt", (event) => { event.preventDefault(); state.installPrompt = event; $("#install").hidden = false; });
$("#install").addEventListener("click", async () => { if (!state.installPrompt) return notice("On iPhone Safari: tap Share, then Add to Home Screen."); await state.installPrompt.prompt(); state.installPrompt = null; });
if ("serviceWorker" in navigator) navigator.serviceWorker.register("/wallet/sw.js", { updateViaCache: "none" });
vaultGet().then((vault) => { state.vault = vault; showAuth(vault ? "unlock" : "create"); }).catch((error) => status(error.message, true));
