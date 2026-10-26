// Section 7: revocation via a signed bitstring status list (one bit per grant index; 1 = revoked).
import { gunzipSync, gzipSync } from "node:zlib";
import { b64u, jcs } from "./codec.js";
import { sign, verify } from "./keys.js";

                             
                 
                                                              
                                             
                                                                                         
                   
                                                                                                   
                                          
                                                      
                                                                            
 

export function newStatusList(id        , issuerDid        , issuerKey        , size = 131072, now = new Date(), validForSeconds = 300)             {
  return {
    version: "0.1", id, issuer: issuerDid, issuerKey, issuedAt: now.toISOString(),
    validUntil: new Date(now.getTime() + validForSeconds * 1000).toISOString(), size,
    encodedList: b64u.encode(gzipSync(new Uint8Array(Math.ceil(size / 8)))),
  };
}

function bits(list            )             { return new Uint8Array(gunzipSync(b64u.decode(list.encodedList))); }

export function isRevoked(list            , index        )          {
  if (index < 0 || index >= list.size) throw new Error(`index ${index} outside status list of size ${list.size}`);
  return (bits(list)[index >> 3] & (0x80 >> (index & 7))) !== 0;
}

/** Revocation cannot be undone (section 7): there is deliberately no `unrevoke`. Returns a fresh, re-signed list. */
export function revoke(list            , index        , issuerPrivateKey        , now = new Date(), validForSeconds = 300)             {
  if (index < 0 || index >= list.size) throw new Error(`index ${index} outside status list of size ${list.size}`);
  const b = bits(list);
  b[index >> 3] |= 0x80 >> (index & 7);
  return signStatusList({ ...list, encodedList: b64u.encode(gzipSync(b)), issuedAt: now.toISOString(), validUntil: new Date(now.getTime() + validForSeconds * 1000).toISOString() }, issuerPrivateKey);
}

export function signStatusList(list            , issuerPrivateKey        )             {
  const { signature: _drop, ...body } = list;
  return { ...body, signature: sign(jcs(body), issuerPrivateKey) };
}

export function verifyStatusList(list            , now = new Date())                                   {
  const { signature, ...body } = list;
  if (!signature) return { ok: false, reason: "status list is unsigned" };
  if (!verify(jcs(body), list.issuerKey, signature)) return { ok: false, reason: "status list signature invalid" };
  if (new Date(list.validUntil) < now) return { ok: false, reason: `status list stale (validUntil ${list.validUntil}); refetch it` };
  return { ok: true };
}
