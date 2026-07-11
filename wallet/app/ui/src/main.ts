// MindChain Wallet UI glue. Vanilla TypeScript, no framework. Derivation and
// transaction signing ALWAYS go through the Rust `noos-wallet` core via Tauri
// commands; the browser-side cores handle only public verification surfaces
// (address checksum, manifest verification) and are mirrored by node tests.
import { validateAddress, displayGroups, AddressError } from "../core/address.mjs";
import { verifyUpdateManifest, normalizeRuntime } from "../core/manifest.mjs";

type Invoke = (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;

interface DeriveResponse {
  path: string[];
  bytes: string;
  public_id: string;
  verifying_key: string | null;
}

interface SignResponse {
  amount: string;
  fee: string;
  change: string;
  inputs: string[];
  body: string;
  signature: string;
  verifying_key: string;
  txid: string;
}

function findInvoke(): Invoke | null {
  const w: unknown = globalThis;
  if (w && typeof w === "object" && "__TAURI__" in w) {
    const tauri: unknown = w.__TAURI__;
    if (tauri && typeof tauri === "object" && "core" in tauri) {
      const core: unknown = tauri.core;
      if (core && typeof core === "object" && "invoke" in core && typeof core.invoke === "function") {
        // Well-known Tauri global whose call signature the runtime guarantees.
        const invoke = core.invoke.bind(core) as Invoke;
        return invoke;
      }
    }
  }
  return null;
}

function el<T extends HTMLElement>(id: string, kind: new () => T): T {
  const node = document.getElementById(id);
  if (!(node instanceof kind)) throw new Error(`missing element #${id}`);
  return node;
}

function show(out: HTMLOutputElement, ok: boolean, text: string): void {
  out.textContent = text;
  out.className = ok ? "ok" : "err";
}

function errorCode(e: unknown): string {
  if (e instanceof AddressError) return e.code;
  if (e && typeof e === "object" && "code" in e && typeof e.code === "string") return e.code;
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return "unknown_error";
}

function isDeriveResponse(v: unknown): v is DeriveResponse {
  return !!v && typeof v === "object" && "path" in v && "public_id" in v;
}

function isSignResponse(v: unknown): v is SignResponse {
  return !!v && typeof v === "object" && "txid" in v && "signature" in v;
}

const invoke = findInvoke();
const HASH64 = /^[0-9a-f]{64}$/;

const status = el("shell-status", HTMLParagraphElement);
status.textContent = invoke
  ? "Desktop shell connected: derivation and signing available."
  : "Browser preview: address and manifest checks only. Derivation and signing require the desktop shell.";

const expectedChain = el("expected-chain", HTMLInputElement);
const expectedGenesis = el("expected-genesis", HTMLInputElement);
const actualChain = el("actual-chain", HTMLInputElement);
const actualGenesis = el("actual-genesis", HTMLInputElement);

function identity(chain: HTMLInputElement, genesis: HTMLInputElement): { chain_id: string; genesis_hash: string; api_version: number } {
  if (!HASH64.test(chain.value) || !HASH64.test(genesis.value)) {
    throw new Error("invalid_expected_identity");
  }
  return { chain_id: chain.value, genesis_hash: genesis.value, api_version: 1 };
}

// --- Derivation ---------------------------------------------------------
const purpose = el("purpose", HTMLSelectElement);
const suiteLabel = el("suite-label", HTMLLabelElement);
purpose.addEventListener("change", () => {
  suiteLabel.hidden = purpose.value !== "umbra";
});

const deriveBtn = el("derive-btn", HTMLButtonElement);
const deriveOut = el("derive-out", HTMLOutputElement);
deriveBtn.disabled = !invoke;
deriveBtn.addEventListener("click", () => {
  void (async () => {
    if (!invoke) return;
    try {
      const req = {
        seed_hex: el("seed", HTMLInputElement).value,
        purpose: purpose.value,
        suite: purpose.value === "umbra" ? Number(el("suite", HTMLInputElement).value) : null,
        account: Number(el("account", HTMLInputElement).value),
        index: Number(el("index", HTMLInputElement).value),
      };
      const res = await invoke("derive_authority_cmd", { req });
      if (!isDeriveResponse(res)) throw new Error("malformed_shell_response");
      const lines = [
        `path: ${res.path.join(" / ")}`,
        `authority id: ${res.public_id}`,
        res.verifying_key ? `verifying key: ${res.verifying_key}` : "verifying key: (non-spend purpose exposes none)",
        "address emission: OWNER_BLOCKED pending identity-v1 amendment 1",
      ];
      show(deriveOut, true, lines.join("\n"));
    } catch (e) {
      show(deriveOut, false, errorCode(e));
    }
  })();
});

// --- Address ------------------------------------------------------------
const addressBtn = el("address-btn", HTMLButtonElement);
const addressOut = el("address-out", HTMLOutputElement);
addressBtn.addEventListener("click", () => {
  void (async () => {
    const value = el("address-input", HTMLInputElement).value.trim();
    try {
      validateAddress(value);
      const grouped = displayGroups(value);
      let shellNote = "";
      if (invoke) {
        // Cross-check the JS verdict against the Rust core.
        await invoke("validate_address_cmd", { address: value });
        shellNote = "\nshell cross-check: rust core agrees";
      }
      show(addressOut, true, `checksum OK\n${grouped.display}\npayload: ${grouped.payloadChars} chars (opaque; layout owner-blocked)${shellNote}`);
    } catch (e) {
      show(addressOut, false, `rejected: ${errorCode(e)}`);
    }
  })();
});

// --- Transaction --------------------------------------------------------
interface NoteInput { id: string; amount: string }
function parseNotes(raw: string): NoteInput[] {
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error("invalid_notes");
  return parsed.map((item: unknown): NoteInput => {
    if (!item || typeof item !== "object" || !("id" in item) || !("amount" in item)) throw new Error("invalid_notes");
    const { id, amount } = item;
    if (typeof id !== "string" || typeof amount !== "string") throw new Error("invalid_notes");
    return { id, amount };
  });
}

const signBtn = el("sign-btn", HTMLButtonElement);
const signOut = el("sign-out", HTMLOutputElement);
signBtn.disabled = !invoke;
signBtn.addEventListener("click", () => {
  void (async () => {
    if (!invoke) return;
    try {
      const zero = { proof_units: "0", state_reads: "0", state_writes: "0", blob_bytes: "0" };
      const req = {
        seed_hex: el("seed", HTMLInputElement).value,
        account: Number(el("account", HTMLInputElement).value),
        index: Number(el("index", HTMLInputElement).value),
        expected: identity(expectedChain, expectedGenesis),
        actual: identity(actualChain, actualGenesis),
        notes: parseNotes(el("notes", HTMLTextAreaElement).value),
        amount: el("amount", HTMLInputElement).value,
        resources: { bytes: el("res-bytes", HTMLInputElement).value, grain_steps: el("res-steps", HTMLInputElement).value, ...zero },
        prices: { bytes: el("price-bytes", HTMLInputElement).value, grain_steps: el("price-steps", HTMLInputElement).value, ...zero },
      };
      const res = await invoke("build_and_sign_cmd", { req });
      if (!isSignResponse(res)) throw new Error("malformed_shell_response");
      const lines = [
        `txid: ${res.txid}`,
        `amount: ${res.amount}  fee: ${res.fee}  change: ${res.change}`,
        `inputs: ${res.inputs.join(", ")}`,
        `verifying key: ${res.verifying_key}`,
        `signature: ${res.signature}`,
      ];
      show(signOut, true, lines.join("\n"));
    } catch (e) {
      show(signOut, false, errorCode(e));
    }
  })();
});

// --- Update manifest ----------------------------------------------------
const manifestBtn = el("manifest-btn", HTMLButtonElement);
const manifestOut = el("manifest-out", HTMLOutputElement);
manifestBtn.addEventListener("click", () => {
  void (async () => {
    try {
      const manifestRaw = el("manifest", HTMLTextAreaElement).value;
      const manifest: unknown = JSON.parse(manifestRaw);
      const expected = identity(expectedChain, expectedGenesis);
      const hostPlatform = navigator.userAgent.includes("Windows") ? "windows"
        : navigator.userAgent.includes("Mac") ? "macos" : "linux";
      const runtime = normalizeRuntime(hostPlatform, "x86_64", el("channel", HTMLSelectElement).value);
      const keyHex = el("updater-key", HTMLInputElement).value.trim();
      await verifyUpdateManifest(manifest, expected, runtime, keyHex);
      let shellNote = "";
      if (invoke) {
        await invoke("verify_update_manifest_cmd", {
          manifestJson: manifestRaw,
          expected: { chain_id: expected.chain_id, genesis_hash: expected.genesis_hash },
          runtime,
          updaterKeyHex: keyHex,
        });
        shellNote = "\nshell cross-check: rust verifier agrees";
      }
      show(manifestOut, true, `manifest accepted for ${runtime.platform}/${runtime.arch} (${runtime.channel})${shellNote}`);
    } catch (e) {
      show(manifestOut, false, `rejected: ${errorCode(e)}`);
    }
  })();
});
