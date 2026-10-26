// Section 6: presentation. The grant travels in `Agent-Delegation`; each request carries an RFC 9421 HTTP Message
// Signature over @method, @target-uri, content-digest and created, signed with the delegate key named in the grant.
import { createHash, randomBytes } from "node:crypto";
import { decodeGrant, encodeGrant, verifyGrant, type Grant, type VerifyOptions, type Verdict } from "./grant.ts";
import { sign, verify } from "./keys.ts";

export interface HttpRequest { method: string; url: string; body?: string | Uint8Array; headers?: Record<string, string> }
const LABEL = "adg";

export function contentDigest(body: string | Uint8Array): string {
  return `sha-256=:${createHash("sha256").update(Buffer.from(body as any)).digest("base64")}:`;
}

function signatureBase(req: HttpRequest, params: string, digest?: string): { base: string; components: string[] } {
  const components = ['"@method"', '"@target-uri"'];
  const lines = [`"@method": ${req.method.toUpperCase()}`, `"@target-uri": ${req.url}`];
  if (digest) { components.push('"content-digest"'); lines.push(`"content-digest": ${digest}`); }
  const paramsLine = `(${components.join(" ")})${params}`;
  lines.push(`"@signature-params": ${paramsLine}`);
  return { base: lines.join("\n"), components };
}

/** Delegate side: returns the headers to attach. `ref` sends `Agent-Delegation-Ref` (grant id) instead of the whole grant. */
export function present(grant: Grant, delegatePrivateKey: string, req: HttpRequest, opts: { ref?: boolean; created?: number; nonce?: string } = {}): Record<string, string> {
  const created = opts.created ?? Math.floor(Date.now() / 1000);
  const nonce = opts.nonce ?? randomBytes(12).toString("base64url");
  const digest = req.body !== undefined ? contentDigest(req.body) : undefined;
  const params = `;created=${created};nonce="${nonce}";keyid="${grant.delegate.id}";alg="ed25519"`;
  const { base, components } = signatureBase(req, params, digest);
  const headers: Record<string, string> = {
    ...(opts.ref ? { "Agent-Delegation-Ref": grant.id } : { "Agent-Delegation": encodeGrant(grant) }),
    "Signature-Input": `${LABEL}=(${components.join(" ")})${params}`,
    "Signature": `${LABEL}=:${Buffer.from(sign(base, delegatePrivateKey), "base64url").toString("base64")}:`,
  };
  if (digest) headers["Content-Digest"] = digest;
  return headers;
}

export interface PresentationOptions extends VerifyOptions {
  maxSkewSeconds?: number;                 // default 300
  lookupGrant?: (id: string) => Grant | undefined | Promise<Grant | undefined>; // for Agent-Delegation-Ref
  seenNonce?: (nonce: string, keyid: string) => boolean | Promise<boolean>;       // RP replay cache; return true if already seen
}

/** Relying-party side: section 6 checks on the grant, then the per-request proof. */
export async function verifyPresentation(req: HttpRequest, opts: PresentationOptions = {}): Promise<Verdict & { grant?: Grant }> {
  const h: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers ?? {})) h[k.toLowerCase()] = v;
  const fail = (reason: string, checks: Verdict["checks"] = []): Verdict => ({ ok: false, checks: [...checks, { check: "presentation", ok: false, reason }], reason: `presentation: ${reason}` });

  let grant: Grant | undefined;
  if (h["agent-delegation"]) { try { grant = decodeGrant(h["agent-delegation"]); } catch { return fail("Agent-Delegation header is not a base64url grant"); } }
  else if (h["agent-delegation-ref"]) grant = await opts.lookupGrant?.(h["agent-delegation-ref"]);
  if (!grant) return fail("no grant: send Agent-Delegation or a cached Agent-Delegation-Ref");

  const verdict = await verifyGrant(grant, opts);
  if (!verdict.ok) return { ...verdict, grant };

  const input = h["signature-input"], sigHeader = h["signature"];
  const m = input?.match(new RegExp(`(?:^|,)\\s*${LABEL}=\\(([^)]*)\\)(.*)$`));
  const sm = sigHeader?.match(new RegExp(`(?:^|,)\\s*${LABEL}=:([A-Za-z0-9+/=]+):`));
  if (!m || !sm) return fail(`Signature-Input and Signature headers with label '${LABEL}' required`, verdict.checks);
  const [, componentList, params] = m;
  const p = Object.fromEntries([...params.matchAll(/;([a-z]+)=("?)([^;"]*)\2/g)].map((x) => [x[1], x[3]]));
  if (p.alg !== "ed25519") return fail(`alg must be ed25519, got '${p.alg}'`, verdict.checks);
  if (p.keyid !== grant.delegate.id && p.keyid !== grant.delegate.publicKey) return fail(`keyid '${p.keyid}' is not the grant's delegate`, verdict.checks);
  const created = Number(p.created), now = Math.floor((opts.now ?? new Date()).getTime() / 1000);
  if (!Number.isFinite(created) || Math.abs(now - created) > (opts.maxSkewSeconds ?? 300)) return fail(`created=${p.created} outside the allowed ${opts.maxSkewSeconds ?? 300}s window`, verdict.checks);
  if (!p.nonce) return fail("nonce required", verdict.checks);
  if (opts.seenNonce && (await opts.seenNonce(p.nonce, p.keyid))) return fail("nonce already seen (replay)", verdict.checks);

  const wantsDigest = componentList.includes('"content-digest"');
  let digest: string | undefined;
  if (wantsDigest) {
    if (req.body === undefined || !h["content-digest"]) return fail("content-digest covered but body or Content-Digest header missing", verdict.checks);
    digest = contentDigest(req.body);
    if (digest !== h["content-digest"]) return fail("Content-Digest does not match the body", verdict.checks);
  } else if (req.body !== undefined && req.body.length) return fail("request has a body but content-digest is not covered by the signature", verdict.checks);
  const expected = signatureBase(req, params, digest);
  if (`(${expected.components.join(" ")})` !== `(${componentList})`) return fail(`covered components must be ${expected.components.join(" ")}`, verdict.checks);
  const sig = Buffer.from(sm[1], "base64").toString("base64url");
  if (!verify(expected.base, grant.delegate.publicKey, sig)) return fail("request signature does not verify against the delegate key", verdict.checks);
  return { ...verdict, checks: [...verdict.checks, { check: "presentation", ok: true }], grant };
}
