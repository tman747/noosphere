// Update-manifest verification, JS mirror of
// wallet/app/src-tauri/src/manifest.rs. Structural and identity/target
// binding reuses wallet/identity.mjs (single convention); this layer adds the
// template target vocabulary, channel pinning, and the detached Ed25519
// updater signature per the wallet/product-identity.json policy.
import { PRODUCT, validateUpdateManifest, WalletIdentityError } from "../../../identity.mjs";

export const PLATFORMS = Object.freeze(["windows", "linux", "macos"]);
export const ARCHES = Object.freeze(["x86_64", "aarch64"]);
export const UPDATE_SIGNING_DOMAIN = "NOOS/WALLET/UPDATE/V1";
export const UPDATER_PUBLIC_KEY_ENV = "NOOS_WALLET_UPDATER_PUBLIC_KEY";
const HEX64 = /^[0-9a-f]{64}$/;
const HEX128 = /^[0-9a-f]{128}$/;
const SIGNED_FIELDS = Object.freeze([
  "app_id", "chain_id", "genesis_hash", "platform", "arch", "version", "channel", "artifact_sha256",
]);

export function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

// Canonical signing bytes: domain line then key=value lines in template
// order; every byte of every bound field is covered, signature excluded.
export function signingBytes(manifest) {
  const lines = [UPDATE_SIGNING_DOMAIN, ...SIGNED_FIELDS.map((k) => `${k}=${manifest[k]}`)];
  return new TextEncoder().encode(lines.join("\n"));
}

// Map host identifiers onto the frozen template vocabulary.
export function normalizeRuntime(platform, arch, channel) {
  const platforms = { win32: "windows", windows: "windows", linux: "linux", darwin: "macos", macos: "macos" };
  const arches = { x64: "x86_64", x86_64: "x86_64", arm64: "aarch64", aarch64: "aarch64" };
  const p = platforms[platform];
  const a = arches[arch];
  if (!p || !a || !PRODUCT.channels.includes(channel)) throw new WalletIdentityError("wrong_update_target");
  return Object.freeze({ platform: p, arch: a, channel });
}

// Full verification. Throws WalletIdentityError with the same stable codes
// as the Rust verifier: invalid_update_manifest, wrong_protocol_identity,
// wrong_update_target, invalid_updater_key, bad_signature.
export async function verifyUpdateManifest(manifest, expected, runtime, publicKeyHex) {
  const checked = validateUpdateManifest(manifest, expected, runtime);
  if (!PLATFORMS.includes(manifest.platform) || !ARCHES.includes(manifest.arch)) {
    throw new WalletIdentityError("wrong_update_target");
  }
  // The channel is pinned to this installation, not merely a known name: a
  // correctly signed manifest for another channel is a wrong target.
  if (manifest.channel !== runtime.channel) throw new WalletIdentityError("wrong_update_target");
  if (!HEX128.test(manifest.signature)) throw new WalletIdentityError("invalid_update_manifest");
  if (typeof publicKeyHex !== "string" || !HEX64.test(publicKeyHex)) {
    throw new WalletIdentityError("invalid_updater_key");
  }
  let ok = false;
  try {
    const key = await globalThis.crypto.subtle.importKey(
      "raw", fromHex(publicKeyHex), { name: "Ed25519" }, false, ["verify"],
    );
    ok = await globalThis.crypto.subtle.verify(
      { name: "Ed25519" }, key, fromHex(manifest.signature), signingBytes(manifest),
    );
  } catch {
    throw new WalletIdentityError("invalid_updater_key");
  }
  if (!ok) throw new WalletIdentityError("bad_signature");
  return checked;
}
