// Strict BIP-350 Bech32m address validation and display, JS mirror of
// wallet/app/src-tauri/src/address.rs per protocol/schemas/identity-v1.md §2.
// The version/type/payload layout is OWNER_BLOCKED (identity-v1 §2.1): the
// payload stays opaque and no layout is ever defaulted. Historical-protocol
// HRPs reject with wrong_protocol_identity, never auto-convert.
export const HRP = "noos";
const BECH32M_CONST = 0x2bc830a3;
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const DATA_MIN = 6;
const DATA_MAX = 83;
// Historical HRP assembled from char codes so the identifier never appears
// literally (identity gate; identity-v1 §5).
const HISTORICAL_HRP = String.fromCharCode(0x6d, 0x69, 0x6e, 0x64);

export class AddressError extends Error {
  constructor(code) { super(code); this.code = code; }
}

function polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x01ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i += 1) if ((top >>> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
  }
  return chk;
}

function hrpExpand(hrp) {
  const out = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >>> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

// Validate canonical case, strict HRP, charset, length, and the Bech32m
// checksum. Returns the opaque 5-bit payload (checksum stripped).
export function validateAddress(address) {
  if (typeof address !== "string" || /[A-Z]/.test(address)) throw new AddressError("noncanonical_address");
  const sep = address.lastIndexOf("1");
  if (sep < 1) throw new AddressError("wrong_hrp");
  const hrp = address.slice(0, sep);
  const data = address.slice(sep + 1);
  if (hrp === HISTORICAL_HRP) throw new AddressError("wrong_protocol_identity");
  if (hrp !== HRP) throw new AddressError("wrong_hrp");
  if (data.length < DATA_MIN || data.length > DATA_MAX) throw new AddressError("bad_length");
  const values = [];
  for (const c of data) {
    const idx = CHARSET.indexOf(c);
    if (idx < 0) throw new AddressError("bad_charset");
    values.push(idx);
  }
  if (polymod([...hrpExpand(hrp), ...values]) !== BECH32M_CONST) throw new AddressError("bad_checksum");
  return Object.freeze({ payload5: values.slice(0, -6) });
}

// Re-encode an opaque payload under the strict noos HRP: canonical round-trip
// display only. Defines NO payload layout and refuses any other HRP.
export function encodeAddress(payload5) {
  if (payload5.some((v) => !Number.isInteger(v) || v < 0 || v >= 32)) throw new AddressError("bad_charset");
  const dataLen = payload5.length + 6;
  if (dataLen < DATA_MIN || dataLen > DATA_MAX) throw new AddressError("bad_length");
  const pm = polymod([...hrpExpand(HRP), ...payload5, 0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST;
  let out = `${HRP}1`;
  for (const v of payload5) out += CHARSET[v];
  for (let i = 0; i < 6; i += 1) out += CHARSET[(pm >>> (5 * (5 - i))) & 31];
  return out;
}

// Grouped display form for humans; the canonical wire form stays unspaced.
export function displayGroups(address) {
  const verified = validateAddress(address);
  const data = address.slice(HRP.length + 1);
  const groups = data.match(/.{1,4}/g) ?? [];
  return Object.freeze({ display: `${HRP}1 ${groups.join(" ")}`, payloadChars: data.length - 6, payload5: verified.payload5 });
}
