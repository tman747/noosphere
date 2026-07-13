// MindChain Wallet UI glue. Vanilla TypeScript, no framework. Derivation and
// transaction signing ALWAYS go through the Rust `noos-wallet` core via Tauri
// commands; the browser-side cores handle only public verification surfaces
// (address checksum, manifest verification) and are mirrored by node tests.
import { validateAddress, displayGroups, AddressError } from "../core/address.mjs";
import { verifyUpdateManifest, normalizeRuntime } from "../core/manifest.mjs";
import { formatSubmissionResult } from "../core/submission.mjs";

type Invoke = (cmd: string, args?: Record<string, unknown>) => Promise<unknown>;

interface DeriveResponse {
  path: string[];
  bytes: string;
  public_id: string;
  verifying_key: string | null;
}

interface ChainProfile {
  id: string;
  label: string;
  chain_id: string;
  genesis_hash: string;
  api_version: string;
  api_base_url: string;
  max_freshness_ms: string;
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

function showPending(out: HTMLOutputElement, text: string): void {
  out.textContent = text;
  out.className = "pending";
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

function isChainProfile(v: unknown): v is ChainProfile {
  return !!v && typeof v === "object"
    && "id" in v && typeof v.id === "string"
    && "chain_id" in v && typeof v.chain_id === "string"
    && "genesis_hash" in v && typeof v.genesis_hash === "string"
    && "api_base_url" in v && typeof v.api_base_url === "string";
}

const invoke = findInvoke();
const status = el("shell-status", HTMLParagraphElement);
status.textContent = invoke
  ? "Desktop shell connected: OS-vault custody, derivation, and signing available."
  : "Browser preview: address checks only. Seed import, derivation, submission, and identity-bound manifest checks require the native shell.";

const profileSelect = el("chain-profile", HTMLSelectElement);
const profileOut = el("profile-out", HTMLOutputElement);
const refreshStatusBtn = el("refresh-status-btn", HTMLButtonElement);
let profiles: ChainProfile[] = [];
let activeProfile: ChainProfile | null = null;

function expectedIdentity(): { chain_id: string; genesis_hash: string } {
  if (!activeProfile) throw new Error("chain_profile_unavailable");
  return { chain_id: activeProfile.chain_id, genesis_hash: activeProfile.genesis_hash };
}

function renderProfile(): void {
  activeProfile = profiles.find((profile) => profile.id === profileSelect.value) ?? null;
  if (!activeProfile) {
    show(profileOut, false, "chain_profile_unavailable");
    return;
  }
  show(profileOut, true, [
    `chain id: ${activeProfile.chain_id}`,
    `genesis: ${activeProfile.genesis_hash}`,
    `public API: ${activeProfile.api_base_url}`,
    `maximum status age: ${activeProfile.max_freshness_ms} ms`,
  ].join("\n"));
}

profileSelect.addEventListener("change", renderProfile);
refreshStatusBtn.disabled = true;
refreshStatusBtn.addEventListener("click", () => {
  void (async () => {
    if (!invoke || !activeProfile) return;
    refreshStatusBtn.disabled = true;
    refreshStatusBtn.setAttribute("aria-busy", "true");
    showPending(profileOut, "Checking the configured public API identity…");
    try {
      const response = await invoke("check_chain_status_cmd", { profileId: activeProfile.id });
      if (!response || typeof response !== "object"
        || !("unsafe_height" in response) || typeof response.unsafe_height !== "string"
        || !("next_output_birth_height" in response) || typeof response.next_output_birth_height !== "string"
        || !("freshness_ms" in response) || typeof response.freshness_ms !== "string") {
        throw new Error("malformed_status");
      }
      show(profileOut, true, [
        `chain id: ${activeProfile.chain_id}`,
        `genesis: ${activeProfile.genesis_hash}`,
        `public API: ${activeProfile.api_base_url}`,
        `unsafe height: ${response.unsafe_height}`,
        `required output birth height now: ${response.next_output_birth_height}`,
        `status age: ${response.freshness_ms} ms`,
      ].join("\n"));
    } catch (e) {
      show(profileOut, false, errorCode(e));
    } finally {
      refreshStatusBtn.disabled = false;
      refreshStatusBtn.removeAttribute("aria-busy");
    }
  })();
});

// --- Native seed vault --------------------------------------------------
const walletIdInput = el("wallet-id", HTMLInputElement);
const seedInput = el("seed", HTMLInputElement);
const importSeedBtn = el("import-seed-btn", HTMLButtonElement);
const deleteWalletBtn = el("delete-wallet-btn", HTMLButtonElement);
const vaultOut = el("vault-out", HTMLOutputElement);
importSeedBtn.disabled = !invoke;
deleteWalletBtn.disabled = !invoke;

function walletId(): string {
  const value = walletIdInput.value.trim();
  if (!/^[a-z0-9_-]{3,64}$/.test(value)) throw new Error("invalid_wallet_id");
  return value;
}

importSeedBtn.addEventListener("click", () => {
  void (async () => {
    if (!invoke) return;
    importSeedBtn.disabled = true;
    try {
      const handle = await invoke("import_seed_cmd", {
        req: { wallet_id: walletId(), seed_hex: seedInput.value },
      });
      seedInput.value = "";
      if (!handle || typeof handle !== "object" || !("protection" in handle)) {
        throw new Error("malformed_secure_store_response");
      }
      show(vaultOut, true, `wallet imported\\nprotection: ${String(handle.protection)}\\nseed export to page: disabled`);
    } catch (e) {
      show(vaultOut, false, errorCode(e));
    } finally {
      seedInput.value = "";
      importSeedBtn.disabled = false;
    }
  })();
});

deleteWalletBtn.addEventListener("click", () => {
  void (async () => {
    if (!invoke) return;
    deleteWalletBtn.disabled = true;
    try {
      await invoke("delete_wallet_cmd", { walletId: walletId() });
      show(vaultOut, true, "wallet seed deleted from OS vault");
    } catch (e) {
      show(vaultOut, false, errorCode(e));
    } finally {
      deleteWalletBtn.disabled = false;
    }
  })();
});

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
        wallet_id: walletId(),
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
const submitBtn = el("submit-btn", HTMLButtonElement);
const submitOut = el("submit-out", HTMLOutputElement);
submitBtn.disabled = true;
submitBtn.addEventListener("click", () => {
  void (async () => {
    if (!invoke || !activeProfile) return;
    submitBtn.disabled = true;
    submitBtn.setAttribute("aria-busy", "true");
    showPending(submitOut, "Checking live identity and note funds before local signing…");
    try {
      const req = {
        profile_id: activeProfile.id,
        wallet_id: walletId(),
        account: Number(el("account", HTMLInputElement).value),
        index: Number(el("index", HTMLInputElement).value),
        signer_scope: Number(el("signer-scope", HTMLInputElement).value),
        transaction_spec: el("transaction-spec", HTMLTextAreaElement).value,
      };
      const res = await invoke("submit_transaction_cmd", { req });
      show(submitOut, true, formatSubmissionResult(res));
    } catch (e) {
      show(submitOut, false, errorCode(e));
    } finally {
      submitBtn.disabled = false;
      submitBtn.removeAttribute("aria-busy");
    }
  })();
});

// --- Update manifest ----------------------------------------------------
const manifestBtn = el("manifest-btn", HTMLButtonElement);
const manifestOut = el("manifest-out", HTMLOutputElement);
manifestBtn.disabled = true;
manifestBtn.addEventListener("click", () => {
  void (async () => {
    try {
      const manifestRaw = el("manifest", HTMLTextAreaElement).value;
      const manifest: unknown = JSON.parse(manifestRaw);
      const expected = expectedIdentity();
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

void (async () => {
  if (!invoke) return;
  showPending(profileOut, "Loading configured chain profile…");
  try {
    const result = await invoke("chain_profiles_cmd");
    if (!Array.isArray(result) || result.length === 0 || !result.every(isChainProfile)) {
      throw new Error("chain_profile_unavailable");
    }
    profiles = result;
    profileSelect.replaceChildren(...profiles.map((profile) => {
      const option = document.createElement("option");
      option.value = profile.id;
      option.textContent = profile.label;
      return option;
    }));
    renderProfile();
    refreshStatusBtn.disabled = false;
    submitBtn.disabled = false;
    manifestBtn.disabled = false;
  } catch (e) {
    show(profileOut, false, errorCode(e));
    refreshStatusBtn.disabled = true;
    submitBtn.disabled = true;
    manifestBtn.disabled = true;
  }
})();
