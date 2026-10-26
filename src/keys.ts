import { createPrivateKey, createPublicKey, generateKeyPairSync, sign as nodeSign, verify as nodeVerify, randomBytes, type KeyObject } from "node:crypto";
import { b64u, multikeyDecode, multikeyEncode } from "./codec.ts";

/** A keypair as stored on disk. The public side is the multikey used in grants and did:key; the private side is the 32-byte seed. */
export interface Keypair {
  publicKeyMultibase: string;  // z6Mk...
  did: string;                 // did:key:z6Mk...
  privateKeyBase64url: string; // 32 raw Ed25519 seed bytes
}

// PKCS#8 and SPKI DER prefixes for Ed25519 (RFC 8410); the raw key follows.
const PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");
const SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const privateKeyObject = (seed: string): KeyObject =>
  createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(b64u.decode(seed))]), format: "der", type: "pkcs8" });
const publicKeyObject = (mk: string): KeyObject =>
  createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(multikeyDecode(mk))]), format: "der", type: "spki" });
const rawPublic = (pub: KeyObject): Uint8Array => new Uint8Array(pub.export({ format: "der", type: "spki" }).subarray(-32));

export function generateKeypair(): Keypair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const seed = privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const mk = multikeyEncode(rawPublic(publicKey));
  return { publicKeyMultibase: mk, did: `did:key:${mk}`, privateKeyBase64url: b64u.encode(new Uint8Array(seed)) };
}

export function publicKeyFromPrivate(privateKeyBase64url: string): string {
  if (b64u.decode(privateKeyBase64url).length !== 32) throw new Error("private key must be a 32-byte base64url seed");
  return multikeyEncode(rawPublic(createPublicKey(privateKeyObject(privateKeyBase64url))));
}

export function sign(data: Uint8Array | string, privateKeyBase64url: string): string {
  return b64u.encode(new Uint8Array(nodeSign(null, Buffer.from(data as any), privateKeyObject(privateKeyBase64url))));
}

export function verify(data: Uint8Array | string, publicKeyMultibase: string, signatureBase64url: string): boolean {
  try { return nodeVerify(null, Buffer.from(data as any), publicKeyObject(publicKeyMultibase), Buffer.from(b64u.decode(signatureBase64url))); }
  catch { return false; }
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/** ULID: 10 chars of time (ms), 16 chars of randomness. */
export function ulid(now = Date.now()): string {
  let t = "";
  for (let i = 0, n = now; i < 10; i++) { t = CROCKFORD[n % 32] + t; n = Math.floor(n / 32); }
  const r = randomBytes(16);
  let s = "";
  for (let i = 0; i < 16; i++) s += CROCKFORD[r[i] % 32];
  return t + s;
}
