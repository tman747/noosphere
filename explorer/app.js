import { evidenceView, statusView } from "./render.mjs";
const $ = (id) => document.getElementById(id);
let base = "";
const apiHeaders = { Accept: "application/vnd.noos.v1+json" };
function text(value) { return document.createTextNode(String(value)); }
async function request(path) {
  const response = await fetch(`${base}${path}`, { headers: apiHeaders });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.code ? `${body.code}: ${body.message}` : `HTTP ${response.status}`);
  return body;
}
function renderCoordinates(status) { const view=statusView(status); $("unsafe").textContent=view.unsafe; $("justified").textContent=view.justified; $("finalized").textContent=view.finalized; }
async function connect(event) {
  event?.preventDefault(); base = $("endpoint").value.replace(/\/$/, ""); $("connection").textContent = "Loading identity…";
  try {
    const status = await request("/api/status");
    if (!/^[0-9a-f]{64}$/.test(status.chain_id) || !/^[0-9a-f]{64}$/.test(status.genesis_hash) || status.api_version !== "v1") throw new Error("wrong_protocol_identity: malformed status identity");
    renderCoordinates(status);
    $("connection").textContent = `Connected · release ${status.release_version} · freshness ${status.freshness_ms} ms`;
    await Promise.all([loadBlocks(), loadEvidence()]);
  } catch (error) { $("connection").textContent = `Connection refused · ${error.message}`; renderCoordinates({}); }
}
async function loadBlocks() {
  const body = $("blocks"); body.replaceChildren();
  try {
    const page = await request("/api/v1/blocks?limit=20");
    if (!page.items.length) { const row = body.insertRow(); const cell = row.insertCell(); cell.colSpan = 4; cell.className = "empty"; cell.textContent = "No indexed blocks at this snapshot."; return; }
    for (const block of page.items) {
      const row = body.insertRow();
      for (const [value, cls] of [[block.height, ""], [block.hash, "hash"], [block.slot, ""], [block.transaction_count, ""]]) { const cell = row.insertCell(); cell.className = cls; cell.append(text(value)); if (cls) cell.title = value; }
    }
  } catch (error) { const row = body.insertRow(); const cell = row.insertCell(); cell.colSpan = 4; cell.className = "empty"; cell.textContent = error.message; }
}
async function loadEvidence() {
  const host = $("evidence"); host.replaceChildren(); const id = $("mechanism").value;
  try {
    const value = await request(`/api/v1/evidence/${encodeURIComponent(id)}`);
    for (const dimension of evidenceView(value)) { const badge = document.createElement("div"); badge.className = "badge"; badge.dataset.disabled = String(dimension.key === "enabled" && dimension.value === "DISABLED"); const name = document.createElement("span"); name.textContent = dimension.label; const status = document.createElement("strong"); status.textContent = dimension.value; badge.append(name,status); host.append(badge); }
  } catch (error) { const p=document.createElement("p"); p.className="empty"; p.textContent=error.message; host.append(p); }
}
$("endpoint-form").addEventListener("submit",connect); $("refresh").addEventListener("click",loadBlocks); $("load-evidence").addEventListener("click",loadEvidence);
