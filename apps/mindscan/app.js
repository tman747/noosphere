const $ = (id) => document.getElementById(id);
const hex64 = /^[0-9a-f]{64}$/;
const height = /^(0|[1-9][0-9]{0,19})$/;

function short(value, size = 13) {
  if (!value || value.length <= size * 2 + 1) return value || "—";
  return `${value.slice(0, size)}…${value.slice(-size)}`;
}

async function api(path) {
  const response = await fetch(path, { headers: { Accept: "application/json" } });
  const body = await response.json().catch(() => ({ error: "malformed_response" }));
  if (!response.ok) {
    const error = new Error(body.detail || body.error || `Request failed (${response.status})`);
    error.status = response.status;
    throw error;
  }
  return body;
}

function setPoint(prefix, point) {
  $(`${prefix}-height`).textContent = point?.height ?? "0";
  $(`${prefix}-hash`).textContent = point?.hash ? short(point.hash, 10) : "Not reported";
  $(`${prefix}-hash`).title = point?.hash || "";
}

function renderStatus(status) {
  $("chain-id").textContent = short(status.chain_id, 12);
  $("chain-id").title = status.chain_id || "";
  $("genesis-hash").textContent = short(status.genesis_hash, 12);
  $("genesis-hash").title = status.genesis_hash || "";
  $("generation").textContent = status.indexed_generation || "0";
  setPoint("unsafe", status.unsafe_head);
  setPoint("justified", status.justified);
  setPoint("finalized", status.finalized);
  const live = $("live");
  live.className = status.ready ? "live ready" : "live";
  live.querySelector("span").textContent = status.ready ? "Index ready" : (status.readiness || "Syncing");
}

function blockRow(block, index) {
  const row = document.createElement("article");
  row.className = "block";
  row.style.setProperty("--i", index);
  row.tabIndex = 0;
  row.setAttribute("role", "button");
  row.setAttribute("aria-label", `Inspect block ${block.height}`);
  row.innerHTML = `<strong></strong><code></code><span></span><span></span><b>VIEW</b>`;
  row.children[0].textContent = `#${block.height}`;
  row.children[1].textContent = short(block.hash, 11);
  row.children[1].title = block.hash;
  row.children[2].textContent = `Slot ${block.slot}`;
  row.children[3].textContent = `${block.transaction_count} tx`;
  const open = () => showRecord(`Block ${block.height}`, block);
  row.addEventListener("click", open);
  row.addEventListener("keydown", (event) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); open(); }
  });
  return row;
}

async function loadBlocks() {
  const container = $("blocks");
  try {
    const page = await api("/api/blocks?limit=18");
    container.replaceChildren();
    if (!Array.isArray(page.items) || page.items.length === 0) {
      const empty = document.createElement("p");
      empty.className = "empty";
      empty.textContent = "No indexed blocks yet. The explorer will populate after the first canonical block is persisted.";
      container.append(empty);
      return;
    }
    page.items.forEach((block, index) => container.append(blockRow(block, index)));
  } catch (error) {
    container.innerHTML = "";
    const empty = document.createElement("p");
    empty.className = "empty";
    empty.textContent = `Recent blocks unavailable: ${error.message}`;
    container.append(empty);
  }
}

function showRecord(title, record) {
  $("result-title").textContent = title;
  $("result-body").textContent = JSON.stringify(record, null, 2);
  $("result").hidden = false;
  $("result").scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}

async function lookup(raw) {
  const query = raw.trim().toLowerCase();
  if (!height.test(query) && !hex64.test(query)) throw new Error("Enter a canonical height or 64 lowercase hexadecimal characters.");
  if (height.test(query)) return ["Block", await api(`/api/block/${query}`)];
  try {
    return ["Block", await api(`/api/block/${query}`)];
  } catch (error) {
    if (error.status !== 404) throw error;
  }
  return ["Transaction", await api(`/api/transaction/${query}`)];
}

function rewriteApplicationHosts() {
  document.querySelectorAll("a[href^='http://localhost:']").forEach((link) => {
    const target = new URL(link.href);
    target.hostname = location.hostname;
    link.href = target.toString();
  });
}

async function refresh() {
  try {
    renderStatus(await api("/api/status"));
  } catch (error) {
    const live = $("live");
    live.className = "live error";
    live.querySelector("span").textContent = "Indexer unavailable";
  }
  await loadBlocks();
}

$("search").addEventListener("submit", async (event) => {
  event.preventDefault();
  const help = $("search-help");
  help.className = "";
  help.textContent = "Looking up canonical index state…";
  try {
    const [kind, record] = await lookup($("query").value);
    showRecord(`${kind} record`, record);
    help.textContent = "Record loaded from the durable public index.";
  } catch (error) {
    help.className = "error";
    help.textContent = error.message;
  }
});
$("refresh").addEventListener("click", refresh);
$("close-result").addEventListener("click", () => { $("result").hidden = true; });
rewriteApplicationHosts();
refresh();
setInterval(refresh, 10_000);
