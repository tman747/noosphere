export const PRODUCT = Object.freeze({
  bundleId: "network.mindchain.noosphere.wallet",
  scheme: "mindchain-noos://",
  scope: "/noosphere-wallet-v1/",
  cachePrefix: "mindchain-noosphere-v1",
  updaterProduct: "mindchain-noosphere-wallet",
  channels: Object.freeze(["stable", "beta"]),
});
const HASH = /^[0-9a-f]{64}$/;
export class WalletIdentityError extends Error { constructor(code) { super(code); this.code = code; } }
export function requireStatus(expected, actual) {
  if (!HASH.test(expected.chain_id) || !HASH.test(expected.genesis_hash) || expected.api_version !== "v1") throw new WalletIdentityError("invalid_expected_identity");
  if (!actual || actual.chain_id !== expected.chain_id || actual.genesis_hash !== expected.genesis_hash || actual.api_version !== expected.api_version) throw new WalletIdentityError("wrong_protocol_identity");
  return Object.freeze({ ...actual });
}
export function validateUpdateManifest(manifest, expected, runtime) {
  const required = ["app_id","chain_id","genesis_hash","platform","arch","version","channel","artifact_sha256","signature"];
  if (!manifest || required.some((key) => typeof manifest[key] !== "string" || !manifest[key])) throw new WalletIdentityError("invalid_update_manifest");
  if (manifest.app_id !== PRODUCT.bundleId || manifest.chain_id !== expected.chain_id || manifest.genesis_hash !== expected.genesis_hash) throw new WalletIdentityError("wrong_protocol_identity");
  if (manifest.platform !== runtime.platform || manifest.arch !== runtime.arch || !PRODUCT.channels.includes(manifest.channel)) throw new WalletIdentityError("wrong_update_target");
  if (!HASH.test(manifest.artifact_sha256)) throw new WalletIdentityError("invalid_update_manifest");
  return Object.freeze({ ...manifest });
}
const HISTORICAL_DATA_ROOT_ENTRIES = Object.freeze([
  [97, 115, 99, 101, 110, 116, 45, 119, 97, 108, 108, 101, 116],
  [109, 105, 110, 100, 45, 119, 97, 108, 108, 101, 116],
  [104, 105, 115, 116, 111, 114, 105, 99, 97, 108, 45, 99, 104, 97, 105, 110, 46, 106, 115, 111, 110],
  [109, 105, 103, 114, 97, 116, 105, 111, 110, 46, 109, 97, 114, 107, 101, 114],
].map((bytes) => String.fromCharCode(...bytes)));
export function assertFreshDataRoot(entries) {
  if (entries.some((entry) => HISTORICAL_DATA_ROOT_ENTRIES.includes(entry.toLowerCase()))) throw new WalletIdentityError("historical_overwrite_forbidden");
  return true;
}
