// Section 3, 5, 6: the grant document, issuing, countersigning and the relying-party verification order.
import { b64u, jcs, multikeyDecode } from "./codec.ts";
import { publicKeyFromPrivate, sign, ulid, verify } from "./keys.ts";
import { actionClass, checkScope, CLASS_DEFAULTS, type Request, type ScopeDecision, type ScopeEntry } from "./scope.ts";
import { isRevoked, verifyStatusList, type StatusList } from "./status.ts";

export type Level = "none" | "light" | "kyc";
export interface Party { type: "human" | "agent" | "service" | "org"; id: string; publicKey?: string }
export interface Grant {
  version: "0.1";
  id: string;
  issuedAt: string;
  notBefore?: string;
  expiresAt: string;
  principal: Party & { type: "human" | "org"; publicKey: string; verification?: { level: Level; provider?: string; verifiedAt?: string } };
  delegate: Party & { type: "agent"; publicKey: string; operator?: Party & { publicKey: string }; runtime?: { model?: string; harness?: string; attestation?: unknown } };
  accountable: { type: string; id: string };
  audience?: string[];
  scope: ScopeEntry[];
  revocation: { method: "status-list" | "endpoint"; url: string; index?: number };
  pacts?: { id: string; claim: string; slashable: boolean; evaluationTrigger?: string }[];
  extensions?: Record<string, unknown>;
  signatures: { principal?: string; delegate?: string; operator?: string | null; issuer?: string | null };
}
export type Role = "principal" | "delegate" | "operator" | "issuer";
export type Draft = Omit<Grant, "version" | "id" | "issuedAt" | "signatures" | "accountable"> & { id?: string; issuedAt?: string; accountable?: Grant["accountable"] };

export const signingBytes = (g: Grant): string => { const { signatures: _s, ...body } = g; return jcs(body); };
const LEVELS: Record<Level, number> = { none: 0, light: 1, kyc: 2 };
const DAY = 86_400_000;

/** Structural rules from section 3 and 4 that need no keys or clock. Returns the list of violations (empty = well-formed). */
export function validateShape(g: Grant): string[] {
  const errs: string[] = [];
  for (const f of ["version", "id", "issuedAt", "expiresAt", "principal", "delegate", "accountable", "scope", "revocation"] as const)
    if ((g as any)[f] === undefined) errs.push(`missing required field '${f}'`);
  if (errs.length) return errs;
  if (g.version !== "0.1") errs.push(`unsupported version '${g.version}'`);
  if (!/^adg_[0-9A-HJKMNP-TV-Z]{26}$/.test(g.id)) errs.push("id must be 'adg_' + ULID");
  for (const p of ["principal", "delegate"] as const) {
    try { multikeyDecode(g[p].publicKey); } catch (e) { errs.push(`${p}.publicKey: ${(e as Error).message}`); }
    if (typeof g[p].id !== "string" || !g[p].id.startsWith("did:")) errs.push(`${p}.id must be a DID`);
  }
  const issued = Date.parse(g.issuedAt), expires = Date.parse(g.expiresAt);
  if (Number.isNaN(issued) || Number.isNaN(expires)) errs.push("issuedAt/expiresAt must be ISO 8601");
  else if (expires - issued > 365 * DAY) errs.push("validity exceeds 365 days");
  else if (expires <= issued) errs.push("expiresAt must be after issuedAt");
  if (!Array.isArray(g.scope) || g.scope.length === 0) errs.push("scope must be a non-empty list");
  else for (const e of g.scope) {
    const cls = actionClass(e.action);
    if (!cls) errs.push(`unknown action '${e.action}'`);
    else if (cls === "forbidden") errs.push(`action '${e.action}' is never delegable`);
    if (typeof e.resource !== "string" || /\*.+|.\*[^$]/.test(e.resource) || (e.resource.includes("*") && !e.resource.endsWith(":*")))
      errs.push(`resource '${e.resource}': '*' is allowed only as the whole last segment`);
  }
  if (!g.audience?.length && g.scope.some((e) => actionClass(e.action) !== "read")) errs.push("a grant with no audience is valid only for read-class actions");
  if (g.accountable.id !== g.principal.id) {
    if (!g.signatures?.operator) errs.push("accountable differs from principal but signatures.operator is absent");
    else if (g.accountable.id !== g.delegate.operator?.id) errs.push("accountable may only move to the operator named in delegate.operator");
  }
  if (!["status-list", "endpoint"].includes(g.revocation.method)) errs.push(`unknown revocation method '${g.revocation.method}'`);
  if (g.revocation.method === "status-list" && typeof g.revocation.index !== "number") errs.push("status-list revocation needs an index");
  return errs;
}

/** The principal creates and signs the grant. The returned grant is not yet valid: the delegate must countersign. */
export function issue(draft: Draft, principalPrivateKey: string, now = new Date()): Grant {
  const principalKey = publicKeyFromPrivate(principalPrivateKey);
  if (draft.principal.publicKey && draft.principal.publicKey !== principalKey) throw new Error("principal.publicKey does not match the signing key");
  const g: Grant = {
    version: "0.1", id: draft.id ?? `adg_${ulid(now.getTime())}`, issuedAt: draft.issuedAt ?? now.toISOString(),
    ...draft, principal: { ...draft.principal, publicKey: principalKey },
    accountable: draft.accountable ?? { type: draft.principal.type, id: draft.principal.id }, signatures: {},
  };
  const errs = validateShape(g);
  if (errs.length) throw new Error("grant is malformed: " + errs.join("; "));
  g.signatures.principal = sign(signingBytes(g), principalPrivateKey);
  return g;
}

/** delegate, operator or issuer adds its signature. Order (section 5): principal, delegate, operator, issuer. */
export function countersign(g: Grant, role: Exclude<Role, "principal">, privateKey: string): Grant {
  if (!g.signatures.principal) throw new Error("principal must sign first");
  const key = publicKeyFromPrivate(privateKey);
  if (role === "delegate" && key !== g.delegate.publicKey) throw new Error("delegate key does not match delegate.publicKey");
  if (role === "operator") {
    if (!g.delegate.operator?.publicKey) throw new Error("grant names no operator");
    if (key !== g.delegate.operator.publicKey) throw new Error("operator key does not match delegate.operator.publicKey");
    if (!g.signatures.delegate) throw new Error("delegate must countersign before the operator");
  }
  return { ...g, signatures: { ...g.signatures, [role]: sign(signingBytes(g), privateKey) } };
}

export interface VerifyOptions {
  audience?: string;               // who the RP is (DID or URL); required unless the RP accepts unaudienced read grants
  now?: Date;
  statusList?: StatusList;         // the cached list the grant points at
  revocationLookup?: (g: Grant) => { revoked: boolean } | Promise<{ revoked: boolean }>; // for method 'endpoint'
  issuerKey?: string;              // multikey; when given, signatures.issuer must verify against it
  request?: Request;               // the action the RP is about to perform
  verificationPolicy?: Partial<Record<"read" | "move" | "admin", Level>>; // RP's minimum level per class; defaults from 4.3
  enforceClassValidity?: boolean;  // RP enforces the 4.3 default maxima (read 365 / move 90 / admin 30 days)
}
export interface Check { check: string; ok: boolean; reason?: string }
export interface Verdict { ok: boolean; checks: Check[]; reason?: string; scope?: ScopeDecision }

/** Section 6 order: signatures, time, audience, revocation, scope and limits. Stops at the first failure with its reason. */
export async function verifyGrant(g: Grant, opts: VerifyOptions = {}): Promise<Verdict> {
  const checks: Check[] = [];
  const fail = (check: string, reason: string): Verdict => { checks.push({ check, ok: false, reason }); return { ok: false, checks, reason: `${check}: ${reason}` }; };
  const pass = (check: string) => checks.push({ check, ok: true });
  const now = opts.now ?? new Date();

  const shape = validateShape(g);
  if (shape.length) return fail("shape", shape.join("; "));
  pass("shape");

  const bytes = signingBytes(g);
  if (!g.signatures.principal || !verify(bytes, g.principal.publicKey, g.signatures.principal)) return fail("signature.principal", "missing or invalid");
  if (!g.signatures.delegate || !verify(bytes, g.delegate.publicKey, g.signatures.delegate)) return fail("signature.delegate", "missing or invalid (the delegate has not countersigned)");
  if (g.signatures.operator && (!g.delegate.operator?.publicKey || !verify(bytes, g.delegate.operator.publicKey, g.signatures.operator))) return fail("signature.operator", "invalid");
  if (opts.issuerKey) { if (!g.signatures.issuer || !verify(bytes, opts.issuerKey, g.signatures.issuer)) return fail("signature.issuer", "missing or invalid against the supplied issuer key"); }
  pass("signatures");

  if (g.notBefore && new Date(g.notBefore) > now) return fail("time", `not valid before ${g.notBefore}`);
  if (new Date(g.expiresAt) <= now) return fail("time", `expired at ${g.expiresAt}`);
  if (opts.enforceClassValidity) {
    const days = (Date.parse(g.expiresAt) - Date.parse(g.issuedAt)) / DAY;
    for (const e of g.scope) { const cls = actionClass(e.action)!; if (days > CLASS_DEFAULTS[cls].maxValidityDays) return fail("time", `${cls}-class scope '${e.action}' allows at most ${CLASS_DEFAULTS[cls].maxValidityDays} days validity, grant has ${Math.ceil(days)}`); }
  }
  pass("time");

  if (opts.audience) { if (!g.audience?.includes(opts.audience)) return fail("audience", `grant audience ${JSON.stringify(g.audience ?? [])} does not include ${opts.audience}`); }
  else if (g.audience?.length) return fail("audience", "grant names an audience; the relying party must identify itself");
  pass("audience");

  const level = g.principal.verification?.level ?? "none";
  for (const e of g.scope) {
    const cls = actionClass(e.action) as "read" | "move" | "admin";
    const need = opts.verificationPolicy?.[cls] ?? CLASS_DEFAULTS[cls].verification;
    if (LEVELS[level] < LEVELS[need]) return fail("verification", `${cls}-class scope '${e.action}' needs principal verification '${need}', grant has '${level}'`);
  }
  pass("verification");

  if (g.revocation.method === "status-list") {
    const list = opts.statusList;
    if (!list) return fail("revocation", `no status list supplied; fetch ${g.revocation.url}`);
    if (list.id !== g.revocation.url) return fail("revocation", `status list id ${list.id} is not the grant's ${g.revocation.url}`);
    const sl = verifyStatusList(list, now);
    if (!sl.ok) return fail("revocation", sl.reason!);
    if (isRevoked(list, g.revocation.index!)) return fail("revocation", `grant ${g.id} is revoked (index ${g.revocation.index})`);
  } else {
    if (!opts.revocationLookup) return fail("revocation", `no endpoint lookup supplied for ${g.revocation.url}`);
    if ((await opts.revocationLookup(g)).revoked) return fail("revocation", `grant ${g.id} is revoked`);
  }
  pass("revocation");

  if (opts.request) {
    const d = checkScope(g.scope, opts.request);
    if (!d.allowed) { const v = fail("scope", d.reason!); v.scope = d; return v; }
    pass("scope");
    return { ok: true, checks, scope: d };
  }
  return { ok: true, checks };
}

export const encodeGrant = (g: Grant): string => b64u.encode(jcs(g));
export const decodeGrant = (s: string): Grant => JSON.parse(Buffer.from(b64u.decode(s)).toString("utf8"));
