// Key discovery (section 5): did:key resolves offline; did:web fetches the DID document.
import { multikeyDecode } from "./codec.ts";

export async function resolveDid(did: string, fetchImpl: typeof fetch = fetch): Promise<string> {
  if (did.startsWith("did:key:")) { const mk = did.slice(8); multikeyDecode(mk); return mk; }
  if (did.startsWith("did:web:")) {
    const parts = did.slice(8).split(":").map(decodeURIComponent);
    const url = parts.length === 1 ? `https://${parts[0]}/.well-known/did.json` : `https://${parts[0]}/${parts.slice(1).join("/")}/did.json`;
    const res = await fetchImpl(url);
    if (!res.ok) throw new Error(`DID document fetch failed: ${res.status} ${url}`);
    const doc: any = await res.json();
    const vm = (doc.verificationMethod ?? []).find((m: any) => m.publicKeyMultibase?.startsWith("z6Mk"));
    if (!vm) throw new Error(`no Ed25519 publicKeyMultibase in ${url}`);
    return vm.publicKeyMultibase;
  }
  throw new Error(`unsupported DID method: ${did}`);
}
