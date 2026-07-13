"use strict";

const VERSION = 1;
const DOMAIN = "NOOS/HARBOR/PASSKEY-RECOVERY/V1";

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function hexToBytes(hex) {
  if (!/^(?:[0-9a-f]{2})+$/.test(hex)) throw new Error("malformed_passkey_recovery");
  return Uint8Array.from(hex.match(/../g), (value) => Number.parseInt(value, 16));
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of new Uint8Array(bytes)) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function fromBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("malformed_passkey_recovery");
  const base64 = value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function binding(record) {
  return new TextEncoder().encode(JSON.stringify([
    DOMAIN,
    record.version,
    record.chain_id,
    record.public_id,
    record.rp_id,
    record.credential_id,
    record.vault_schema,
  ]));
}

async function wrappingKey(prfOutput, prfSalt, boundData, usage) {
  const material = await crypto.subtle.importKey("raw", prfOutput, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: prfSalt, info: boundData },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

function prfResult(credential) {
  const first = credential?.getClientExtensionResults?.()?.prf?.results?.first;
  if (!(first instanceof ArrayBuffer) && !ArrayBuffer.isView(first)) {
    throw new Error("passkey_prf_unavailable");
  }
  return new Uint8Array(first);
}

export function passkeyRecoverySupported() {
  return !!globalThis.PublicKeyCredential && !!navigator.credentials && !!crypto?.subtle;
}

export async function enrollPasskeyRecovery({ password, chainId, publicId, vaultSchema, rpId = location.hostname }) {
  if (!passkeyRecoverySupported()) throw new Error("passkey_unavailable");
  if (typeof password !== "string" || password.length < 12) throw new Error("invalid_recovery_password");
  if (!/^[0-9a-f]{64}$/.test(chainId) || !/^[0-9a-f]{64}$/.test(publicId)) throw new Error("invalid_recovery_binding");
  if (!rpId || rpId !== location.hostname) throw new Error("passkey_origin_mismatch");

  const prfSalt = crypto.getRandomValues(new Uint8Array(32));
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rp: { id: rpId, name: "Harbor Wallet" },
      user: {
        id: crypto.getRandomValues(new Uint8Array(32)),
        name: `wallet-${publicId.slice(0, 12)}`,
        displayName: `Harbor ${publicId.slice(0, 8)}`,
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }],
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required",
      },
      timeout: 120000,
      attestation: "none",
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  if (!credential) throw new Error("passkey_creation_cancelled");

  const record = {
    version: VERSION,
    chain_id: chainId,
    public_id: publicId,
    rp_id: rpId,
    credential_id: toBase64Url(credential.rawId),
    vault_schema: vaultSchema,
    prf_salt: bytesToHex(prfSalt),
    iv: "",
    ciphertext: "",
    created_at: new Date().toISOString(),
  };
  const aad = binding(record);
  const key = await wrappingKey(prfResult(credential), prfSalt, aad, "encrypt");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, additionalData: aad },
    key,
    new TextEncoder().encode(password),
  );
  record.iv = bytesToHex(iv);
  record.ciphertext = bytesToHex(ciphertext);
  return record;
}

export async function recoverPasskeyPassword(record, { chainId, publicId, vaultSchema, rpId = location.hostname }) {
  if (!passkeyRecoverySupported()) throw new Error("passkey_unavailable");
  if (record?.version !== VERSION
      || record.chain_id !== chainId
      || record.public_id !== publicId
      || record.vault_schema !== vaultSchema
      || record.rp_id !== rpId
      || rpId !== location.hostname) {
    throw new Error("passkey_recovery_binding_mismatch");
  }
  const prfSalt = hexToBytes(record.prf_salt);
  if (prfSalt.length !== 32) throw new Error("malformed_passkey_recovery");
  const credential = await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId,
      allowCredentials: [{ type: "public-key", id: fromBase64Url(record.credential_id) }],
      userVerification: "required",
      timeout: 120000,
      extensions: { prf: { eval: { first: prfSalt } } },
    },
  });
  if (!credential || toBase64Url(credential.rawId) !== record.credential_id) {
    throw new Error("passkey_credential_mismatch");
  }
  const aad = binding(record);
  const key = await wrappingKey(prfResult(credential), prfSalt, aad, "decrypt");
  try {
    const clear = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: hexToBytes(record.iv), additionalData: aad },
      key,
      hexToBytes(record.ciphertext),
    );
    return new TextDecoder("utf-8", { fatal: true }).decode(clear);
  } catch {
    throw new Error("passkey_recovery_failed");
  }
}
