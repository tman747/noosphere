import test from "node:test";
import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { createPromptCommitment, parseSseText, validateHostedModelProof, WwmV2Client } from "./client.mjs";

const h = (byte) => byte.repeat(64);
const IDS = Object.freeze({
  chain: h("1"), genesis: h("2"), capsule: h("3"), execution: h("4"), query: h("5"),
  finalized: h("6"), pin: h("7"), quote: h("8"), job: h("9"), candidate: h("a"), objects: h("b"),
});

const hashIndex = (index) => index.toString(16).padStart(2, "0").repeat(32);

function hostedModel(overrides = {}) {
  return {
    capsule_id: IDS.capsule,
    artifact_id: "d3d1bcf9f704c58c695d7c0837be25a5cfbd7ff71b440bfc9be4a4a46bb528b0",
    manifest_root: "80f211eb4ebfd26df62bdeac69bc663ca97664eaf179188af78d1288aee42de7",
    runtime_root: "690d9bbd8d44631fb971e0b0677e10c8d0bb1e08a743bb720eeaab728e30ba27",
    availability_certificate_id: hashIndex(240),
    artifact_sha256: "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0",
    source_bytes: 3_803_452_480,
    encoded_bytes: 5_707_063_296,
    share_bytes: 1_047_552,
    stripe_count: 454,
    position_count: 12,
    data_shards: 8,
    parity_shards: 4,
    reconstruction_threshold: 8,
    schedulable_minimum: 9,
    certificate_issued_height: 40,
    certificate_valid_until_height: "18446744073709551615",
    custodians: Array.from({ length: 12 }, (_, position) => ({
      position,
      profile_id: hashIndex(position + 1),
      endpoint_root: hashIndex(position + 21),
      status: 0,
    })),
    executor_profile_ids: Array.from({ length: 8 }, (_, position) => hashIndex(position + 81)),
    worker: {
      state: "READY",
      source: "SIGNED_OPERATOR_MONITOR",
      monitor_sample_id: hashIndex(200),
      monitor_signer_key_id: hashIndex(201),
    },
    ...overrides,
  };
}

function resolution(overrides = {}) {
  return {
    schema: "noos/finalized-model-resolution/v1",
    chain_id: IDS.chain,
    genesis_hash: IDS.genesis,
    finalized_height: 41,
    finalized_hash: IDS.finalized,
    objects_root: IDS.objects,
    pin_id: IDS.pin,
    proofs_verified: true,
    active: {
      capsule_id: IDS.capsule,
      model_name: "Bonsai-27B-Q1_0.gguf",
      artifact_sha256: "17ef842e47450caeb8eaa3ebfbbab5d2f2278b62b79be107985fb69a2f819aa0",
      artifact_length: 3_803_452_480,
      execution_profile_id: IDS.execution,
      query_profile_id: IDS.query,
      activation_state: "ACTIVE",
    },
    candidates: [{
      capsule_id: IDS.candidate,
      model_name: "review candidate",
      artifact_sha256: h("c"), artifact_length: 1,
      execution_profile_id: h("d"), query_profile_id: h("e"),
      activation_state: "AUTHORIZED_NOT_ACTIVE",
    }],
    executors: [{ executor_id: "edge-1", control_cluster_id: "cluster-1", region: "r1", https_origin: "https://edge.test", protocol_version: 2, registry_epoch: 1, active: true }],
    fee_schedule_id: h("c"), fund_profile_id: h("d"), service_directory_id: h("e"), registry_vector_id: h("f"),
    ...overrides,
  };
}

function state(overrides = {}) {
  return { schema: "noos/wwm-gateway/v2", enabled: true, resolution: resolution(), sponsor_grant: "grant-17", ...overrides };
}

function verifier(overrides = {}) {
  return {
    async verifyResolution() {
      return {
        chain_id: IDS.chain,
        genesis_hash: IDS.genesis,
        capsule_id: IDS.capsule,
        finalized_height: 41,
        finalized_hash: IDS.finalized,
        objects_root: IDS.objects,
        hosted_model: hostedModel(),
      };
    },
    async verifyQuote(quote) { return quote.signature !== "bad"; },
    async verifyStreamEvent(event) { return event.payload.data.signature !== "bad"; },
    async verifyReceipt(receipt) { return receipt.signature !== "bad"; },
    ...overrides,
  };
}

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload), { status, headers: { "Content-Type": "application/json" } });
}

function quoteFor(request) {
  return {
    schema: "noos/wwm-quote/v2",
    quote_id: IDS.quote,
    request_id: request.request_id,
    pin_id: IDS.pin,
    capsule_id: IDS.capsule,
    execution_profile_id: IDS.execution,
    query_profile_id: IDS.query,
    prompt_commitment: request.prompt_commitment,
    input_tokens: request.input_tokens,
    maximum_output_tokens: request.maximum_output_tokens,
    payment_mode: request.payment.mode,
    payment_reference: request.payment.authorization || "tenant-grant-17",
    expires_at_height: 99,
    maximum_fee_micro_noos: 17,
    signature: "valid-quote-signature",
  };
}

async function clientWithRouter(router, verify = verifier()) {
  const client = new WwmV2Client({
    baseUrl: "https://edge.test/api/wwm/v2",
    expectedIdentity: { chain_id: IDS.chain, genesis_hash: IDS.genesis },
    verifier: verify,
    fetchImpl: router,
    cryptoImpl: webcrypto,
  });
  await client.loadState();
  return client;
}

test("salted prompt commitments are fresh, exact, and bounded", async () => {
  const saltA = new Uint8Array(32).fill(1);
  const saltB = new Uint8Array(32).fill(2);
  const first = await createPromptCommitment("same prompt", webcrypto, saltA);
  const replay = await createPromptCommitment("same prompt", webcrypto, saltA);
  const fresh = await createPromptCommitment("same prompt", webcrypto, saltB);
  assert.equal(first.commitment, replay.commitment);
  assert.notEqual(first.commitment, fresh.commitment);
  assert.equal(first.salt, "01".repeat(32));
  await assert.rejects(() => createPromptCommitment("x".repeat(12_001), webcrypto), { code: "prompt_too_large" });
});

test("wrong identity and failed finalized proof stop before quote", async () => {
  const wrong = new WwmV2Client({
    expectedIdentity: { chain_id: h("f"), genesis_hash: IDS.genesis }, verifier: verifier(), cryptoImpl: webcrypto,
    fetchImpl: async () => json(state()),
  });
  await assert.rejects(() => wrong.loadState(), { code: "wrong_chain_identity" });
  const badProof = new WwmV2Client({
    expectedIdentity: { chain_id: IDS.chain, genesis_hash: IDS.genesis },
    verifier: verifier({ async verifyResolution() { return false; } }), cryptoImpl: webcrypto,
    fetchImpl: async () => json(state()),
  });
  await assert.rejects(() => badProof.loadState(), { code: "invalid_resolution_proof" });
});

test("hosted model proof binds exact geometry, chain positions, executors, and signed worker state", async () => {
  const verified = await verifier().verifyResolution();
  const hosted = validateHostedModelProof(resolution(), verified);
  assert.equal(hosted.source_bytes, 3_803_452_480);
  assert.equal(hosted.encoded_bytes, 5_707_063_296);
  assert.equal(hosted.custodians.length, 12);
  assert.equal(hosted.executor_profile_ids.length, 8);
  assert.equal(hosted.reconstruction_threshold, 8);
  assert.equal(hosted.schedulable_minimum, 9);
  assert.equal(hosted.worker.state, "READY");
  assert.equal(hosted.worker.source, "SIGNED_OPERATOR_MONITOR");

  await assert.rejects(
    () => clientWithRouter(async () => json(state()), verifier({
      async verifyResolution() {
        return { ...verified, hosted_model: hostedModel({ worker: { ...hostedModel().worker, source: "GATEWAY_LABEL" } }) };
      },
    })),
    { code: "invalid_worker_evidence" },
  );
  const duplicate = hostedModel();
  duplicate.custodians[1].profile_id = duplicate.custodians[0].profile_id;
  await assert.rejects(
    () => clientWithRouter(async () => json(state()), verifier({
      async verifyResolution() { return { ...verified, hosted_model: duplicate }; },
    })),
    { code: "duplicate_custodian" },
  );
});

test("authorized candidate remains visible and cannot be quoted or dispatched", async () => {
  const calls = [];
  const client = await clientWithRouter(async (url, options = {}) => {
    calls.push(String(url));
    if (String(url).endsWith("/state")) return json(state());
    const request = JSON.parse(options.body);
    return json({ ...quoteFor(request), capsule_id: IDS.candidate });
  });
  assert.equal(client.active.candidate.activation_state, "AUTHORIZED_NOT_ACTIVE");
  assert.equal(client.active.candidate.dispatchable, false);
  await assert.rejects(() => client.quote("candidate must not run", { paymentAuthorization: "grant-17" }), { code: "quote_binding_mismatch" });
  assert.equal(calls.filter((url) => url.endsWith("/jobs")).length, 0);
});

test("sponsored and paid quote/job paths preserve active pin and salt", async () => {
  const requests = [];
  const router = async (url, options = {}) => {
    const path = new URL(String(url)).pathname;
    if (path.endsWith("/state")) return json(state());
    if (path.endsWith("/quotes")) {
      const request = JSON.parse(options.body); requests.push({ kind: "quote", request });
      return json(quoteFor(request));
    }
    if (path.endsWith("/jobs")) {
      const request = JSON.parse(options.body); requests.push({ kind: "job", request, headers: options.headers });
      return json({ schema: "noos/wwm-job/v2", job_id: IDS.job, status: "RUNNING", replayed: false });
    }
    throw new Error(`unexpected ${path}`);
  };
  const client = await clientWithRouter(router);
  const sponsored = await client.quote("sponsor", { paymentMode: "SPONSORED" });
  await client.submit(sponsored);
  const paid = await client.quote("paid", { paymentMode: "PAID", paymentAuthorization: "native-escrow-17" });
  await client.submit(paid);
  const quotes = requests.filter((entry) => entry.kind === "quote").map((entry) => entry.request);
  assert.deepEqual(quotes.map((request) => request.payment.mode), ["SPONSORED", "PAID"]);
  assert.ok(quotes.every((request) => request.pin_id === IDS.pin && request.capsule_id === IDS.capsule));
  const jobs = requests.filter((entry) => entry.kind === "job");
  assert.ok(jobs.every((entry) => /^[0-9a-f]{64}$/.test(entry.request.prompt_salt)));
  assert.ok(jobs.every((entry) => /^[0-9a-f]{32}$/.test(entry.headers["Idempotency-Key"])));
});

test("bad quote signature rejects before job submission", async () => {
  let jobs = 0;
  const client = await clientWithRouter(async (url, options = {}) => {
    if (String(url).endsWith("/state")) return json(state());
    if (String(url).endsWith("/quotes")) return json({ ...quoteFor(JSON.parse(options.body)), signature: "bad" });
    jobs += 1;
    return json({});
  });
  await assert.rejects(() => client.quote("signed", { paymentAuthorization: "grant-17" }), { code: "invalid_quote_signature" });
  assert.equal(jobs, 0);
});

test("canonical SSE resumes with Last-Event-ID and never reruns job", async () => {
  const calls = [];
  const delta = { id: 1, type: "output.delta", data: { delta: "Bon", evidence_state: "PROVISIONAL_SIGNED", signature: "valid" } };
  const receipt = { job_id: IDS.job, capsule_id: IDS.capsule, evidence_state: "MATCHED_QUORUM", terminal_status: "COMPLETED", settlement_state: "FINALIZED_PAID", signature: "valid" };
  const terminal = { id: 2, type: "receipt.completed", data: receipt };
  const event = (value) => `id: ${value.id}\nevent: ${value.type}\ndata: ${JSON.stringify(value)}\n\n`;
  const client = await clientWithRouter(async (url, options = {}) => {
    const path = new URL(String(url)).pathname; calls.push({ path, options });
    if (path.endsWith("/state")) return json(state());
    if (path.endsWith("/stream")) {
      if (!options.headers["Last-Event-ID"]) return new Response(event(delta));
      assert.equal(options.headers["Last-Event-ID"], "1");
      return new Response(event(terminal));
    }
    throw new Error(`unexpected ${path}`);
  });
  const observed = [];
  assert.equal(await client.stream(IDS.job, (item) => observed.push(item)), "2");
  assert.deepEqual(observed.map((item) => item.payload.type), ["output.delta", "receipt.completed"]);
  assert.equal(calls.filter(({ path }) => path.endsWith("/stream")).length, 2);
  assert.equal(calls.filter(({ path }) => path.endsWith("/jobs")).length, 0);
});

test("browser-native fetch keeps its receiver and drains a terminal stream", async () => {
  const terminal = { id: 1, type: "receipt.completed", data: { job_id: IDS.job, capsule_id: IDS.capsule, evidence_state: "PROVISIONAL_SIGNED", terminal_status: "COMPLETED", settlement_state: "PENDING_CHAIN", signature: "valid" } };
  const bytes = new TextEncoder().encode(`id: 1\nevent: receipt.completed\ndata: ${JSON.stringify(terminal)}\n\n`);
  let reads = 0;
  let cancelled = false;
  function browserFetch(url) {
    assert.equal(this, globalThis);
    const path = new URL(String(url)).pathname;
    if (path.endsWith("/state")) return Promise.resolve(json(state()));
    if (path.endsWith("/stream")) {
      return Promise.resolve({
        ok: true,
        status: 200,
        body: {
          getReader() {
            return {
              async read() {
                reads += 1;
                return reads === 1 ? { value: bytes, done: false } : { value: undefined, done: true };
              },
              async cancel() {
                cancelled = true;
              },
            };
          },
        },
      });
    }
    throw new Error(`unexpected ${path}`);
  }
  const client = await clientWithRouter(browserFetch);
  assert.equal(await client.stream(IDS.job, () => {}), "1");
  assert.equal(reads, 2);
  assert.equal(cancelled, false);
});

test("wrong event signature, cancel, and receipt proof fail closed without fallback", async () => {
  const bad = { id: 1, type: "output.delta", data: { delta: "x", evidence_state: "PROVISIONAL_SIGNED", signature: "bad" } };
  const text = `id: 1\nevent: output.delta\ndata: ${JSON.stringify(bad)}\n\n`;
  let streamCalls = 0;
  const client = await clientWithRouter(async (url) => {
    const path = new URL(String(url)).pathname;
    if (path.endsWith("/state")) return json(state());
    streamCalls += 1;
    return new Response(text);
  });
  await assert.rejects(() => client.stream(IDS.job, () => {}), { code: "invalid_stream_signature" });
  assert.equal(streamCalls, 1);

  const terminal = await clientWithRouter(async (url, options = {}) => {
    const path = new URL(String(url)).pathname;
    if (path.endsWith("/state")) return json(state());
    if (path.endsWith("/cancel")) return json({ schema: "noos/wwm-cancel/v2", job_id: IDS.job, status: "CANCELLED" });
    return json({ job_id: IDS.job, capsule_id: IDS.capsule, settlement_state: "FINALIZED_REFUNDED", signature: "bad" });
  });
  assert.equal((await terminal.cancel(IDS.job)).status, "CANCELLED");
  await assert.rejects(() => terminal.receipt(IDS.job), { code: "invalid_receipt_proof" });
});

test("SSE parser rejects malformed and noncanonical IDs", () => {
  assert.throws(() => parseSseText("id: 01\ndata: {}\n\n"), { code: "invalid_sse_event_id" });
  assert.throws(() => parseSseText("data: {}\n\n"), { code: "malformed_sse_event" });
});
