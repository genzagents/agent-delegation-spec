// Section 7: revocation via a signed bitstring status list (one bit per grant index; 1 = revoked).
import { gunzipSync, gzipSync } from "node:zlib";
import { b64u, jcs } from "./codec.ts";
import { sign, verify } from "./keys.ts";

export interface StatusList {
  version: "0.1";
  id: string;            // the stable URL the grants point at
  issuer: string;        // DID of the issuer
  issuerKey: string;     // multikey, so an RP that cached the list can verify it offline
  issuedAt: string;
  validUntil: string;    // RPs MUST refetch after this; spec says refresh at least every 5 minutes
  size: number;          // number of bits
  encodedList: string;   // base64url(gzip(bitstring))
  signature?: string;    // base64url Ed25519 over JCS(list minus signature)
}

export function newStatusList(id: string, issuerDid: string, issuerKey: string, size = 131072, now = new Date(), validForSeconds = 300): StatusList {
  return {
    version: "0.1", id, issuer: issuerDid, issuerKey, issuedAt: now.toISOString(),
    validUntil: new Date(now.getTime() + validForSeconds * 1000).toISOString(), size,
    encodedList: b64u.encode(gzipSync(new Uint8Array(Math.ceil(size / 8)))),
  };
}

function bits(list: StatusList): Uint8Array { return new Uint8Array(gunzipSync(b64u.decode(list.encodedList))); }

export function isRevoked(list: StatusList, index: number): boolean {
  if (index < 0 || index >= list.size) throw new Error(`index ${index} outside status list of size ${list.size}`);
  return (bits(list)[index >> 3] & (0x80 >> (index & 7))) !== 0;
}

/** Revocation cannot be undone (section 7): there is deliberately no `unrevoke`. Returns a fresh, re-signed list. */
export function revoke(list: StatusList, index: number, issuerPrivateKey: string, now = new Date(), validForSeconds = 300): StatusList {
  if (index < 0 || index >= list.size) throw new Error(`index ${index} outside status list of size ${list.size}`);
  const b = bits(list);
  b[index >> 3] |= 0x80 >> (index & 7);
  return signStatusList({ ...list, encodedList: b64u.encode(gzipSync(b)), issuedAt: now.toISOString(), validUntil: new Date(now.getTime() + validForSeconds * 1000).toISOString() }, issuerPrivateKey);
}

export function signStatusList(list: StatusList, issuerPrivateKey: string): StatusList {
  const { signature: _drop, ...body } = list;
  return { ...body, signature: sign(jcs(body), issuerPrivateKey) };
}

export function verifyStatusList(list: StatusList, now = new Date()): { ok: boolean; reason?: string } {
  const { signature, ...body } = list;
  if (!signature) return { ok: false, reason: "status list is unsigned" };
  if (!verify(jcs(body), list.issuerKey, signature)) return { ok: false, reason: "status list signature invalid" };
  if (new Date(list.validUntil) < now) return { ok: false, reason: `status list stale (validUntil ${list.validUntil}); refetch it` };
  return { ok: true };
}
