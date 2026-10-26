#!/usr/bin/env node
// adg: issue, countersign, present, verify and revoke Agent Delegation Grants from the command line.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { countersign, decodeGrant, issue, verifyGrant, type Grant, type Draft, type Role } from "./grant.ts";
import { generateKeypair, type Keypair } from "./keys.ts";
import { present, verifyPresentation, type HttpRequest } from "./present.ts";
import { isRevoked, newStatusList, revoke, signStatusList, type StatusList } from "./status.ts";
import { resolveDid } from "./did.ts";
import { jcs } from "./codec.ts";

const USAGE = `adg <command> [options]

  keygen [--out keys.json]                                   new Ed25519 keypair (did:key)
  issue --draft draft.json --key principal.json [--out g.json]  principal signs a grant draft
  countersign grant.json --role delegate|operator|issuer --key k.json [--out g.json]
  verify grant.json [--audience RP] [--status-list file|url] [--issuer-key z6Mk...] [--strict] [--now ISO]
         [--action payment.initiate --resource acct:... --amount 100 --currency GBP
          --payee-hash sha256:... --spent 0 --step-up]      relying-party check, section 6 order
  present grant.json --key delegate.json --method POST --url URL [--body file] [--ref]
                                                             headers for one request (RFC 9421)
  verify-request request.json [verify options]              request.json = {method,url,body?,headers}
  status new --url URL --key issuer.json [--size 131072] --out list.json
  status revoke list.json --index N --key issuer.json [--out list.json]
  status check list.json --index N
  did <did>                                                  resolve a did:key or did:web to its key
  example [dir]                                              write a complete worked example (default ./examples)
`;

const args = process.argv.slice(2);
const opts: Record<string, string | boolean> = {};
const positional: string[] = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a.startsWith("--")) { const next = args[i + 1]; if (next === undefined || next.startsWith("--")) opts[a.slice(2)] = true; else { opts[a.slice(2)] = next; i++; } }
  else positional.push(a);
}
const str = (k: string): string | undefined => (typeof opts[k] === "string" ? (opts[k] as string) : undefined);
const readJson = <T,>(p: string): T => JSON.parse(readFileSync(p, "utf8"));
const out = (p: string | undefined, value: unknown) => { const text = JSON.stringify(value, null, 2) + "\n"; if (p) { writeFileSync(p, text); console.error(`wrote ${p}`); } else process.stdout.write(text); };
const die = (msg: string): never => { console.error(`error: ${msg}`); process.exit(2); };
const keyFile = (k = "key"): Keypair => { const p = str(k) ?? die(`--${k} <keys.json> required`); return readJson<Keypair>(p); };

async function loadStatusList(src: string | undefined): Promise<StatusList | undefined> {
  if (!src) return undefined;
  if (/^https?:\/\//.test(src)) { const r = await fetch(src); if (!r.ok) die(`status list fetch ${r.status}`); return (await r.json()) as StatusList; }
  return readJson<StatusList>(src);
}
async function verifyOptions() {
  const amount = str("amount"), currency = str("currency") ?? "GBP";
  const request = str("action") ? {
    action: str("action")!, resource: str("resource") ?? die("--resource required with --action"),
    amount: amount !== undefined ? { amount: Number(amount), currency } : undefined,
    payeeHash: str("payee-hash"), spentInPeriod: str("spent") !== undefined ? { amount: Number(str("spent")), currency } : undefined,
    stepUpSatisfied: opts["step-up"] === true,
  } : undefined;
  const now = str("now") ? new Date(str("now")!) : undefined;
  return { audience: str("audience"), statusList: await loadStatusList(str("status-list")), issuerKey: str("issuer-key"), enforceClassValidity: opts.strict === true, request, now };
}
function report(v: { ok: boolean; checks: { check: string; ok: boolean; reason?: string }[]; reason?: string; scope?: any }) {
  for (const c of v.checks) console.log(`${c.ok ? "ok  " : "FAIL"} ${c.check}${c.reason ? ": " + c.reason : ""}`);
  if (v.scope?.stepUpRequired && v.ok) console.log("note step-up was required and satisfied");
  console.log(v.ok ? "VALID" : `REFUSED (${v.reason})`);
  process.exit(v.ok ? 0 : 1);
}

async function main() {
  const [cmd, ...rest] = positional;
  switch (cmd) {
    case "keygen": { const k = generateKeypair(); out(str("out"), k); console.error(k.did); return; }
    case "issue": {
      const draft = readJson<Draft>(str("draft") ?? die("--draft required"));
      return out(str("out"), issue(draft, keyFile().privateKeyBase64url));
    }
    case "countersign": {
      const g = readJson<Grant>(rest[0] ?? die("grant file required"));
      const role = (str("role") ?? die("--role required")) as Exclude<Role, "principal">;
      return out(str("out") ?? rest[0], countersign(g, role, keyFile().privateKeyBase64url));
    }
    case "verify": {
      const g = readJson<Grant>(rest[0] ?? die("grant file required"));
      return report(await verifyGrant(g, await verifyOptions()));
    }
    case "present": {
      const g = readJson<Grant>(rest[0] ?? die("grant file required"));
      const req: HttpRequest = { method: str("method") ?? "GET", url: str("url") ?? die("--url required"), body: str("body") ? readFileSync(str("body")!, "utf8") : undefined };
      return out(str("out"), present(g, keyFile().privateKeyBase64url, req, { ref: opts.ref === true }));
    }
    case "verify-request": {
      const req = readJson<HttpRequest>(rest[0] ?? die("request file required"));
      return report(await verifyPresentation(req, await verifyOptions()));
    }
    case "status": {
      const sub = rest[0];
      if (sub === "new") { const k = keyFile(); return out(str("out"), signStatusList(newStatusList(str("url") ?? die("--url required"), k.did, k.publicKeyMultibase, Number(str("size") ?? 131072)), k.privateKeyBase64url)); }
      const list = readJson<StatusList>(rest[1] ?? die("list file required"));
      const index = Number(str("index") ?? die("--index required"));
      if (sub === "revoke") return out(str("out") ?? rest[1], revoke(list, index, keyFile().privateKeyBase64url));
      if (sub === "check") { console.log(isRevoked(list, index) ? "revoked" : "active"); return; }
      return die(`unknown status subcommand '${sub}'`);
    }
    case "did": { console.log(await resolveDid(rest[0] ?? die("did required"))); return; }
    case "decode": { out(undefined, decodeGrant(rest[0] ?? die("base64url grant required"))); return; }
    case "example": return writeExample(rest[0] ?? "examples");
    default: console.log(USAGE); process.exit(cmd ? 2 : 0);
  }
}

/** A complete worked flow: four keypairs, a grant, countersignatures, a status list, a presented request. */
function writeExample(dir: string) {
  mkdirSync(dir, { recursive: true });
  const keys = { principal: generateKeypair(), delegate: generateKeypair(), operator: generateKeypair(), issuer: generateKeypair() };
  for (const [role, k] of Object.entries(keys)) writeFileSync(join(dir, `${role}.keys.json`), JSON.stringify(k, null, 2) + "\n");
  const now = new Date();
  const year = 365 * 86_400_000; // the committed example must keep verifying; real grants are short and real lists refresh every 5 minutes
  const statusUrl = "https://example.org/.well-known/adg-status/2026-10.json";
  const draft: Draft = {
    issuedAt: now.toISOString(), expiresAt: new Date(now.getTime() + year - 86_400_000).toISOString(),
    principal: { type: "human", id: keys.principal.did, publicKey: keys.principal.publicKeyMultibase, verification: { level: "kyc", provider: "example-kyc", verifiedAt: "2026-06-02T10:11:00Z" } },
    delegate: { type: "agent", id: keys.delegate.did, publicKey: keys.delegate.publicKeyMultibase,
      operator: { type: "service", id: keys.operator.did, publicKey: keys.operator.publicKeyMultibase }, runtime: { model: "claude-opus-5-5", harness: "example/1.0", attestation: null } },
    audience: ["did:web:bank.example", "https://api.bank.example"],
    scope: [
      { action: "account.read", resource: "acct:*" },
      { action: "payment.initiate", resource: "acct:gb29nwbk60161331926819",
        limits: { perTxn: { amount: 500, currency: "GBP" }, perPeriod: { amount: 2000, currency: "GBP", period: "P1M" } },
        constraints: { payeeAllowlist: ["sha256:7e2d4f3bbd4fa2a0c0c5a7d1e3b8f7a6d5c4b3a2918273645564738291a0b1c2"], requireStepUp: { above: { amount: 250, currency: "GBP" } } } },
    ],
    revocation: { method: "status-list", url: statusUrl, index: 42 },
    pacts: [{ id: "pact_noCredentialStorage", claim: "Delegate never stores or forwards principal credentials", slashable: true }],
  };
  writeFileSync(join(dir, "draft.json"), JSON.stringify(draft, null, 2) + "\n");
  let grant = issue(draft, keys.principal.privateKeyBase64url, now);
  grant = countersign(grant, "delegate", keys.delegate.privateKeyBase64url);
  grant = countersign(grant, "operator", keys.operator.privateKeyBase64url);
  grant = countersign(grant, "issuer", keys.issuer.privateKeyBase64url);
  writeFileSync(join(dir, "grant.json"), JSON.stringify(grant, null, 2) + "\n");
  const list = signStatusList(newStatusList(statusUrl, keys.issuer.did, keys.issuer.publicKeyMultibase, 1024, now, year / 1000), keys.issuer.privateKeyBase64url);
  writeFileSync(join(dir, "status-list.json"), JSON.stringify(list, null, 2) + "\n");
  writeFileSync(join(dir, "status-list.revoked.json"), JSON.stringify(revoke(list, 42, keys.issuer.privateKeyBase64url, now, year / 1000), null, 2) + "\n");
  const body = jcs({ amount: { amount: 120, currency: "GBP" }, to: "acct:gb94barc10201530093459", reference: "October rent" });
  const req: HttpRequest = { method: "POST", url: "https://api.bank.example/payments", body };
  const headers = present(grant, keys.delegate.privateKeyBase64url, req, { created: Math.floor(now.getTime() / 1000) });
  writeFileSync(join(dir, "request.json"), JSON.stringify({ ...req, headers, verifyWith: { now: now.toISOString(), note: "the request signature carries created=<this time>; pass --now to verify-request after the 300s window" } }, null, 2) + "\n");
  console.error(`wrote ${dir}/: principal, delegate, operator and issuer keys; draft.json; grant.json (4 signatures); status-list.json (+ .revoked.json with index 42 set); request.json (signed POST)`);
  console.error(`try: adg verify ${dir}/grant.json --audience did:web:bank.example --status-list ${dir}/status-list.json --action payment.initiate --resource acct:gb29nwbk60161331926819 --amount 120 --currency GBP --payee-hash sha256:7e2d4f3bbd4fa2a0c0c5a7d1e3b8f7a6d5c4b3a2918273645564738291a0b1c2`);
}

main().catch((e) => die(e.message));
