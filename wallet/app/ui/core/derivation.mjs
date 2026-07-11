// NOOS wallet derivation, JS parity implementation of crates/noos-wallet
// derive_authority: HKDF-SHA256 over the master seed with the frozen salt and
// a path-bound info string. Exists for cross-implementation vector parity
// (protocol/vectors/wallet/derivation-v1.json) and local UI cross-checks;
// inside the desktop shell derivation always goes through the Rust command.
const encoder = new TextEncoder();
export const WALLET_SALT = encoder.encode("NOOS/HKDF/WALLET/SALT/V1");
export const WALLET_INFO = encoder.encode("NOOS/HKDF/WALLET/V1");
export const NOOS_NAMESPACE = 0x4e4f4f53;
export const WALLET_VERSION = 1;
export const HARDENED = 0x80000000;
const PURPOSES = Object.freeze({ sign: 1, view: 2, umbra: 3, agent: 4, recovery: 5 });

export class WalletDerivationError extends Error {
  constructor(code) { super(code); this.code = code; }
}

function hardened(n) {
  if (!Number.isInteger(n) || n < 0 || n >= HARDENED) throw new WalletDerivationError("invalid_derivation_index");
  return (n | HARDENED) >>> 0;
}

export function derivationPath(purpose, account, index, suite = null) {
  const number = PURPOSES[purpose];
  if (!number) throw new WalletDerivationError("invalid_purpose");
  if ((purpose === "umbra") !== (suite !== null)) throw new WalletDerivationError("invalid_purpose");
  const path = [hardened(NOOS_NAMESPACE), hardened(WALLET_VERSION), hardened(number)];
  if (purpose === "umbra") path.push(hardened(suite));
  path.push(hardened(account), hardened(index));
  return path;
}

export function pathHex(path) {
  return path.map((c) => `0x${c.toString(16).padStart(8, "0")}`);
}

export function pathBytes(path) {
  const out = new Uint8Array(path.length * 4);
  const view = new DataView(out.buffer);
  path.forEach((c, i) => view.setUint32(i * 4, c, false));
  return out;
}

export async function deriveSecret(seed, purpose, account, index, suite = null) {
  const path = derivationPath(purpose, account, index, suite);
  const components = pathBytes(path);
  const info = new Uint8Array(WALLET_INFO.length + components.length);
  info.set(WALLET_INFO, 0);
  info.set(components, WALLET_INFO.length);
  const key = await globalThis.crypto.subtle.importKey("raw", seed, "HKDF", false, ["deriveBits"]);
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: WALLET_SALT, info },
    key,
    256,
  );
  return new Uint8Array(bits);
}
