// Encodings used by ADG: base58btc (multibase 'z'), base64url (no padding), RFC 8785 JCS, did:key multikey.
const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Encode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (const b of bytes) {
    let carry = b;
    for (let i = 0; i < digits.length; i++) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  return "1".repeat(zeros) + digits.reverse().map((d) => B58[d]).join("");
}

export function base58Decode(s: string): Uint8Array {
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  const bytes: number[] = [];
  for (const ch of s) {
    let carry = B58.indexOf(ch);
    if (carry < 0) throw new Error(`invalid base58 character '${ch}'`);
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
  }
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes.reverse()]);
}

export const b64u = {
  encode: (bytes: Uint8Array | string): string =>
    Buffer.from(bytes as any).toString("base64url"),
  decode: (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "base64url")),
};

/** RFC 8785 JSON Canonicalization Scheme. JSON.stringify already serialises numbers and strings per ES; keys are sorted by UTF-16 code units. */
export function jcs(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(jcs).join(",") + "]";
  const keys = Object.keys(value as object).filter((k) => (value as any)[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + jcs((value as any)[k])).join(",") + "}";
}

// did:key / multikey: multicodec ed25519-pub (0xed, varint 0xed01) + 32 raw bytes, base58btc, multibase prefix 'z'.
const ED25519_PUB_PREFIX = [0xed, 0x01];

export function multikeyEncode(raw32: Uint8Array): string {
  if (raw32.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return "z" + base58Encode(new Uint8Array([...ED25519_PUB_PREFIX, ...raw32]));
}

export function multikeyDecode(mk: string): Uint8Array {
  if (!mk.startsWith("z")) throw new Error("publicKey must be multibase base58btc (prefix 'z')");
  const bytes = base58Decode(mk.slice(1));
  if (bytes.length !== 34 || bytes[0] !== 0xed || bytes[1] !== 0x01) throw new Error("publicKey is not an Ed25519 multikey (z6Mk...)");
  return bytes.slice(2);
}
