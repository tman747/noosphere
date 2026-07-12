const $ = (id) => document.getElementById(id);
const stateNames = ["OPEN", "CLAIMED", "SUBMITTED", "SETTLED", "CANCELLED"];
let helping = false;
let helperAbort = false;

async function request(path, options = {}) {
  const response = await fetch(path, { cache: "no-store", ...options });
  const value = await response.json();
  if (!response.ok) throw new Error(value.detail || value.error || `HTTP ${response.status}`);
  return value;
}

function short(value) {
  return typeof value === "string" && value.length > 18 ? `${value.slice(0, 9)}…${value.slice(-7)}` : value;
}

function row(primary, secondary, state, index) {
  const item = document.createElement("div");
  item.className = "data-row";
  item.style.setProperty("--i", index);
  const code = document.createElement("code");
  code.title = primary;
  code.textContent = short(primary);
  const small = document.createElement("small");
  small.textContent = secondary;
  const badge = document.createElement("span");
  badge.className = `state ${state.toLowerCase()}`;
  badge.textContent = state;
  item.append(code, small, badge);
  return item;
}

async function refresh() {
  try {
    const [config, workerData, jobData] = await Promise.all([
      request("/api/config"), request("/api/workers"), request("/api/jobs")
    ]);
    $("chain-state").textContent = `LIVE / ${short(config.chain_id)}`;
    const workers = workerData.items || [];
    const jobs = jobData.items || [];
    $("worker-count").textContent = workers.filter((item) => item.active === 1).length;
    $("open-count").textContent = jobs.filter((item) => item.state === 0).length;
    $("settled-count").textContent = jobs.filter((item) => item.state === 3).length;

    const jobsNode = $("jobs");
    jobsNode.className = "data-list";
    jobsNode.replaceChildren();
    if (!jobs.length) {
      jobsNode.innerHTML = '<div class="empty">No shards yet. Open a batch to begin.</div>';
    } else {
      jobs.slice().reverse().forEach((job, index) => {
        jobsNode.append(row(job.job_id, `${job.units} units / escrow ${job.escrow}`, stateNames[job.state] || "UNKNOWN", index));
      });
    }

    const workersNode = $("workers");
    workersNode.className = "data-list";
    workersNode.replaceChildren();
    if (!workers.length) {
      workersNode.innerHTML = '<div class="empty">No workers have registered.</div>';
    } else {
      workers.forEach((worker, index) => {
        const engine = worker.capabilities & 2 ? "CPU + GPU" : "CPU";
        workersNode.append(row(worker.worker, `${engine} / ${worker.jobs_completed} settled`, worker.active === 1 ? "ACTIVE" : "OFFLINE", index));
      });
    }
  } catch (error) {
    $("chain-state").textContent = "CHAIN UNAVAILABLE";
    $("jobs").className = "data-list";
    $("jobs").innerHTML = `<div class="empty">${error.message}</div>`;
  }
}

$("job-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.currentTarget.querySelector("button");
  const status = $("form-status");
  button.disabled = true;
  status.className = "form-status";
  status.textContent = "Signing and settling each open-job transaction…";
  try {
    const value = await request("/api/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json", "Authorization": `Bearer ${$("admin-token").value}` },
      body: JSON.stringify({
        shard_count: Number($("shards").value), units_per_shard: Number($("units").value),
        rounds: Number($("rounds").value), max_price_per_unit: Number($("price").value)
      })
    });
    status.textContent = `${value.jobs.length} shards opened; ${value.maximum_escrow} micro-NOOS maximum escrow.`;
    await refresh();
  } catch (error) {
    status.className = "form-status error";
    status.textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

function mix(seed, index, rounds) {
  let value = (seed ^ index ^ 0x9e3779b9) >>> 0;
  for (let round = 0; round < rounds; round += 1) {
    value ^= value << 13;
    value ^= value >>> 17;
    value ^= value << 5;
    value = (Math.imul(value >>> 0, 0x85ebca6b) + 0xc2b2ae35) >>> 0;
  }
  return value >>> 0;
}

async function digestResults(values) {
  const prefix = new TextEncoder().encode("NOOS/COMPUTE/MIX32/RESULT/V1");
  const bytes = new Uint8Array(prefix.length + values.byteLength);
  bytes.set(prefix);
  bytes.set(new Uint8Array(values.buffer, values.byteOffset, values.byteLength), prefix.length);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  return [...digest].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function cpuCompute(payload) {
  const values = new Uint32Array(payload.units);
  const batch = 32;
  for (let offset = 0; offset < payload.units; offset += batch) {
    const end = Math.min(payload.units, offset + batch);
    for (let index = offset; index < end; index += 1) {
      values[index] = mix(payload.seed, payload.start + index, payload.rounds);
    }
    await new Promise((resolve) => setTimeout(resolve, 0));
    if (helperAbort) throw new Error("helper stopped");
  }
  return digestResults(values);
}

async function gpuCompute(payload) {
  const adapter = await navigator.gpu.requestAdapter({ powerPreference: "high-performance" });
  if (!adapter) throw new Error("WebGPU adapter unavailable");
  const device = await adapter.requestDevice();
  const shader = device.createShaderModule({ code: `
struct Params { seed:u32, start:u32, units:u32, rounds:u32 }
@group(0) @binding(0) var<uniform> p: Params;
@group(0) @binding(1) var<storage, read_write> out: array<u32>;
@compute @workgroup_size(64)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let i = gid.x;
  if (i >= p.units) { return; }
  var v = p.seed ^ (p.start + i) ^ 0x9e3779b9u;
  for (var r = 0u; r < p.rounds; r = r + 1u) {
    v = v ^ (v << 13u); v = v ^ (v >> 17u); v = v ^ (v << 5u);
    v = v * 0x85ebca6bu + 0xc2b2ae35u;
  }
  out[i] = v;
}` });
  const paramData = new Uint32Array([payload.seed, payload.start, payload.units, payload.rounds]);
  const params = device.createBuffer({ size: 16, usage: GPUBufferUsage.UNIFORM | GPUBufferUsage.COPY_DST });
  device.queue.writeBuffer(params, 0, paramData);
  const size = Math.max(4, payload.units * 4);
  const output = device.createBuffer({ size, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC });
  const readback = device.createBuffer({ size, usage: GPUBufferUsage.COPY_DST | GPUBufferUsage.MAP_READ });
  const pipeline = device.createComputePipeline({ layout: "auto", compute: { module: shader, entryPoint: "main" } });
  const group = device.createBindGroup({ layout: pipeline.getBindGroupLayout(0), entries: [
    { binding: 0, resource: { buffer: params } }, { binding: 1, resource: { buffer: output } }
  ] });
  const encoder = device.createCommandEncoder();
  const pass = encoder.beginComputePass();
  pass.setPipeline(pipeline); pass.setBindGroup(0, group); pass.dispatchWorkgroups(Math.ceil(payload.units / 64)); pass.end();
  encoder.copyBufferToBuffer(output, 0, readback, 0, size);
  device.queue.submit([encoder.finish()]);
  await readback.mapAsync(GPUMapMode.READ);
  const values = new Uint32Array(readback.getMappedRange().slice(0));
  const root = await digestResults(values);
  readback.unmap(); device.destroy();
  return root;
}

async function helperLoop() {
  helperAbort = false;
  while (helping && !helperAbort) {
    try {
      $("helper-log").textContent = "Looking for an open shard…";
      const payload = await request("/api/helper/claim", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
      if (payload.idle) {
        $("helper-log").textContent = "No open shards. Waiting for work.";
        await new Promise((resolve) => setTimeout(resolve, 3500));
        continue;
      }
      $("helper-log").textContent = `Computing ${payload.units} units from shard ${short(payload.job_id)}.`;
      const started = performance.now();
      let root;
      if (navigator.gpu) {
        root = await gpuCompute(payload);
        $("engine").textContent = "WEBGPU";
      } else {
        root = await cpuCompute(payload);
        $("engine").textContent = "CPU FALLBACK";
      }
      const seconds = (performance.now() - started) / 1000;
      $("throughput").textContent = `${Math.round(payload.units / seconds).toLocaleString()} UNIT/S`;
      $("helper-log").textContent = "Result committed. Waiting for independent verification and settlement…";
      const settled = await request("/api/helper/result", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ job_id: payload.job_id, result_root: root }) });
      $("helper-log").textContent = `Settled ${short(settled.settlement_txid)}. Looking for another shard.`;
      await refresh();
    } catch (error) {
      if (!helperAbort) $("helper-log").textContent = `Worker error: ${error.message}. Retrying.`;
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
  }
}

$("helper-toggle").addEventListener("click", () => {
  helping = !helping;
  helperAbort = !helping;
  $("helper-toggle").classList.toggle("running", helping);
  $("helper-toggle").textContent = helping ? "Stop helping" : "Start helping";
  if (helping) helperLoop();
});
$("refresh").addEventListener("click", refresh);
$("engine").textContent = navigator.gpu ? "WEBGPU READY" : "CPU FALLBACK";
const refreshTimer = setInterval(refresh, 6000);
window.addEventListener("beforeunload", () => { clearInterval(refreshTimer); helperAbort = true; });
refresh();
