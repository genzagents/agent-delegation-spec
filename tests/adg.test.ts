import { test } from "node:test";
import assert from "node:assert/strict";
import {
  base58Decode, base58Encode, jcs, multikeyDecode, multikeyEncode, generateKeypair, sign, verify, issue, countersign, verifyGrant,
  validateShape, newStatusList, signStatusList, revoke, isRevoked, verifyStatusList, checkScope, resourceMatches, present, verifyPresentation,
  encodeGrant, decodeGrant, resolveDid, type Draft, type Grant,
} from "../src/index.ts";

const P = generateKeypair(), D = generateKeypair(), O = generateKeypair(), I = generateKeypair();
const URL = "https://example.org/status.json";
const now = new Date("2026-10-26T12:00:00Z");
const PAYEE = "sha256:" + "ab".repeat(32);
function draft(over: Partial<Draft> = {}): Draft {
  return {
    issuedAt: now.toISOString(), expiresAt: "2026-11-25T12:00:00Z",
    principal: { type: "human", id: P.did, publicKey: P.publicKeyMultibase, verification: { level: "kyc" } },
    delegate: { type: "agent", id: D.did, publicKey: D.publicKeyMultibase, operator: { type: "service", id: O.did, publicKey: O.publicKeyMultibase } },
    audience: ["did:web:bank.example"],
    scope: [{ action: "account.read", resource: "acct:*" }, { action: "payment.initiate", resource: "acct:gb29", limits: { perTxn: { amount: 500, currency: "GBP" }, perPeriod: { amount: 2000, currency: "GBP", period: "P1M" } }, constraints: { payeeAllowlist: [PAYEE], requireStepUp: { above: { amount: 250, currency: "GBP" } } } }],
    revocation: { method: "status-list", url: URL, index: 7 }, ...over,
  };
}
const list = signStatusList(newStatusList(URL, I.did, I.publicKeyMultibase, 64, now), I.privateKeyBase64url);
const full = () => countersign(issue(draft(), P.privateKeyBase64url, now), "delegate", D.privateKeyBase64url);
const base = { audience: "did:web:bank.example", statusList: list, now };

test("codec: base58 and multikey round-trip, JCS sorts keys and drops undefined", () => {
  const bytes = new Uint8Array([0, 0, 255, 1, 2, 3]);
  assert.deepEqual(base58Decode(base58Encode(bytes)), bytes);
  assert.equal(multikeyEncode(multikeyDecode(P.publicKeyMultibase)), P.publicKeyMultibase);
  assert.ok(P.publicKeyMultibase.startsWith("z6Mk"));
  assert.equal(jcs({ b: [1, "x", null], a: { z: 1, y: undefined } }), '{"a":{"z":1},"b":[1,"x",null]}');
  assert.equal(jcs({ "€": 1, "e": 2 }), '{"e":2,"€":1}');
});

test("keys: sign/verify and tamper", () => {
  const s = sign("hello", P.privateKeyBase64url);
  assert.ok(verify("hello", P.publicKeyMultibase, s));
  assert.ok(!verify("hellp", P.publicKeyMultibase, s));
  assert.ok(!verify("hello", D.publicKeyMultibase, s));
});

test("issue + countersign produce a grant that verifies in section 6 order", async () => {
  const g = full();
  const v = await verifyGrant(g, base);
  assert.ok(v.ok, v.reason);
  assert.deepEqual(v.checks.map((c) => c.check), ["shape", "signatures", "time", "audience", "verification", "revocation"]);
});

test("principal-only grant is not valid; tampered scope fails signatures", async () => {
  const g0 = issue(draft(), P.privateKeyBase64url, now);
  assert.match((await verifyGrant(g0, base)).reason!, /signature.delegate/);
  const g = full();
  const tampered: Grant = { ...g, scope: [...g.scope, { action: "payee.add", resource: "acct:*" }] };
  assert.match((await verifyGrant(tampered, base)).reason!, /signature.principal/);
  const wrongKey = countersign(issue(draft(), P.privateKeyBase64url, now), "delegate", D.privateKeyBase64url);
  assert.ok((await verifyGrant({ ...wrongKey, signatures: { ...wrongKey.signatures, delegate: wrongKey.signatures.principal } }, base)).reason!.includes("signature.delegate"));
});

test("shape rules: validity cap, forbidden actions, wildcard placement, audience rule, accountable rule, id format", () => {
  assert.throws(() => issue(draft({ expiresAt: "2027-12-01T00:00:00Z" }), P.privateKeyBase64url, now), /365 days/);
  assert.throws(() => issue(draft({ scope: [{ action: "credential.reset", resource: "acct:*" }] }), P.privateKeyBase64url, now), /never delegable/);
  assert.throws(() => issue(draft({ scope: [{ action: "account.read", resource: "acct:gb*" }] }), P.privateKeyBase64url, now), /last segment/);
  assert.throws(() => issue(draft({ scope: [{ action: "account.read", resource: "acct:*:x" }] }), P.privateKeyBase64url, now), /last segment/);
  assert.throws(() => issue(draft({ audience: undefined }), P.privateKeyBase64url, now), /read-class/);
  assert.ok(issue(draft({ audience: undefined, scope: [{ action: "account.read", resource: "acct:*" }] }), P.privateKeyBase64url, now));
  assert.throws(() => issue(draft({ accountable: { type: "service", id: O.did } }), P.privateKeyBase64url, now), /signatures.operator/);
  const g = full();
  assert.deepEqual(validateShape({ ...g, id: "adg_short" }), ["id must be 'adg_' + ULID"]);
});

test("liability moves to the operator only with the operator's countersignature", async () => {
  // Build with accountable=operator by signing a draft that will fail shape until the operator signs: issue requires shape, so sign manually.
  const g = full();
  const moved: Grant = { ...g, accountable: { type: "service", id: O.did }, signatures: {} };
  moved.signatures.principal = sign(jcs(stripSig(moved)), P.privateKeyBase64url);
  let m = countersign(moved, "delegate", D.privateKeyBase64url);
  assert.match((await verifyGrant(m, base)).reason!, /signatures.operator is absent/);
  m = countersign(m, "operator", O.privateKeyBase64url);
  assert.ok((await verifyGrant(m, base)).ok);
  assert.throws(() => countersign(m, "operator", D.privateKeyBase64url), /operator key does not match/);
});
function stripSig(g: Grant) { const { signatures, ...b } = g; return b; }

test("time, audience and verification-level checks", async () => {
  const g = full();
  assert.match((await verifyGrant(g, { ...base, now: new Date("2026-12-01T00:00:00Z") })).reason!, /expired/);
  assert.match((await verifyGrant({ ...g }, { ...base, audience: "did:web:other" })).reason!, /audience/);
  assert.match((await verifyGrant(g, { ...base, audience: undefined })).reason!, /must identify itself/);
  const light = countersign(issue(draft({ principal: { ...draft().principal, verification: { level: "light" } } }), P.privateKeyBase64url, now), "delegate", D.privateKeyBase64url);
  assert.match((await verifyGrant(light, base)).reason!, /needs principal verification 'kyc'/);
  assert.ok((await verifyGrant(light, { ...base, verificationPolicy: { move: "light" } })).ok);
  assert.ok((await verifyGrant(g, { ...base, enforceClassValidity: true })).ok);
  const admin = countersign(issue(draft({ expiresAt: "2026-12-25T12:00:00Z", scope: [{ action: "card.freeze", resource: "card:*" }] }), P.privateKeyBase64url, now), "delegate", D.privateKeyBase64url);
  assert.ok((await verifyGrant(admin, base)).ok);
  assert.match((await verifyGrant(admin, { ...base, enforceClassValidity: true })).reason!, /admin-class scope 'card.freeze' allows at most 30 days/);
});

test("revocation: status list signature, staleness, revoke is one-way", async () => {
  const g = full();
  assert.match((await verifyGrant(g, { ...base, statusList: undefined })).reason!, /fetch/);
  const revoked = revoke(list, 7, I.privateKeyBase64url, now);
  assert.ok(isRevoked(revoked, 7) && !isRevoked(revoked, 8) && !isRevoked(list, 7));
  assert.match((await verifyGrant(g, { ...base, statusList: revoked })).reason!, /revoked/);
  assert.equal(verifyStatusList({ ...revoked, encodedList: list.encodedList }).ok, false);
  assert.match(verifyStatusList(list, new Date("2030-01-01")).reason!, /stale/);
  const ep = countersign(issue(draft({ revocation: { method: "endpoint", url: "https://x/r" } }), P.privateKeyBase64url, now), "delegate", D.privateKeyBase64url);
  assert.ok((await verifyGrant(ep, { ...base, revocationLookup: async () => ({ revoked: false }) })).ok);
  assert.match((await verifyGrant(ep, { ...base, revocationLookup: () => ({ revoked: true }) })).reason!, /revoked/);
});

test("scope: resources, limits, running totals, allowlist, step-up, unknown and forbidden actions", () => {
  assert.ok(resourceMatches("acct:*", "acct:gb29") && !resourceMatches("acct:*", "acct:gb29:sub") && !resourceMatches("acct:gb", "acct:gb29"));
  const s = draft().scope;
  assert.ok(checkScope(s, { action: "account.read", resource: "acct:anything" }).allowed);
  const pay = (amount: number, extra = {}) => checkScope(s, { action: "payment.initiate", resource: "acct:gb29", amount: { amount, currency: "GBP" }, payeeHash: PAYEE, ...extra });
  assert.ok(pay(100).allowed);
  assert.match(pay(600).reason!, /perTxn/);
  assert.match(pay(100, { spentInPeriod: { amount: 1950, currency: "GBP" } }).reason!, /perPeriod/);
  assert.match(pay(100, { payeeHash: "sha256:00" }).reason!, /payeeAllowlist/);
  assert.match(pay(300).reason!, /step-up/);
  assert.ok(pay(300, { stepUpSatisfied: true }).allowed);
  assert.match(checkScope(s, { action: "payment.initiate", resource: "acct:other", amount: { amount: 1, currency: "GBP" } }).reason!, /no scope entry/);
  assert.match(checkScope(s, { action: "card.freeze", resource: "card:1" }).reason!, /no scope entry/);
  assert.match(checkScope(s, { action: "credential.reset", resource: "x" }).reason!, /never delegable/);
  assert.match(checkScope(s, { action: "foo.bar", resource: "x" }).reason!, /unknown action/);
  assert.match(checkScope([{ action: "payee.add", resource: "acct:*" }], { action: "payee.add", resource: "acct:1" }).reason!, /step-up/);
});

test("presentation: RFC 9421 headers verify; body tamper, replay, skew, ref lookup and wrong key refuse", async () => {
  const g = full();
  const req = { method: "POST", url: "https://api.bank.example/payments", body: '{"amount":120}' };
  const headers = present(g, D.privateKeyBase64url, req, { created: Math.floor(now.getTime() / 1000) });
  assert.match(headers["Signature-Input"], /^adg=\("@method" "@target-uri" "content-digest"\);created=\d+;nonce="[^"]+";keyid="did:key:/);
  const ok = await verifyPresentation({ ...req, headers }, { ...base, request: { action: "payment.initiate", resource: "acct:gb29", amount: { amount: 120, currency: "GBP" }, payeeHash: PAYEE } });
  assert.ok(ok.ok, ok.reason);
  assert.equal(ok.checks.at(-1)!.check, "presentation");
  assert.match((await verifyPresentation({ ...req, body: '{"amount":121}', headers }, base)).reason!, /Content-Digest/);
  assert.match((await verifyPresentation({ ...req, url: "https://api.bank.example/payees", headers }, base)).reason!, /signature does not verify/);
  const old = present(g, D.privateKeyBase64url, req, { created: Math.floor(now.getTime() / 1000) - 1000 });
  assert.match((await verifyPresentation({ ...req, headers: old }, base)).reason!, /window/);
  const seen = new Set<string>();
  const seenNonce = (n: string) => { const was = seen.has(n); seen.add(n); return was; };
  assert.ok((await verifyPresentation({ ...req, headers }, { ...base, seenNonce })).ok);
  assert.match((await verifyPresentation({ ...req, headers }, { ...base, seenNonce })).reason!, /replay/);
  const other = present(g, O.privateKeyBase64url, req, { created: Math.floor(now.getTime() / 1000) });
  assert.match((await verifyPresentation({ ...req, headers: other }, base)).reason!, /does not verify/);
  const ref = present(g, D.privateKeyBase64url, { method: "GET", url: "https://api.bank.example/accounts" }, { ref: true, created: Math.floor(now.getTime() / 1000) });
  assert.equal(ref["Agent-Delegation-Ref"], g.id);
  assert.match((await verifyPresentation({ method: "GET", url: "https://api.bank.example/accounts", headers: ref }, base)).reason!, /no grant/);
  assert.ok((await verifyPresentation({ method: "GET", url: "https://api.bank.example/accounts", headers: ref }, { ...base, lookupGrant: (id) => (id === g.id ? g : undefined), request: { action: "account.read", resource: "acct:1" } })).ok);
  assert.deepEqual(decodeGrant(encodeGrant(g)), JSON.parse(jcs(g)));
});

test("did:key resolves offline; did:web fetches the document", async () => {
  assert.equal(await resolveDid(D.did), D.publicKeyMultibase);
  const fakeFetch = (async (url: string) => ({ ok: true, status: 200, json: async () => ({ verificationMethod: [{ publicKeyMultibase: P.publicKeyMultibase }], url }) })) as unknown as typeof fetch;
  assert.equal(await resolveDid("did:web:example.com", fakeFetch), P.publicKeyMultibase);
  await assert.rejects(resolveDid("did:ion:abc"), /unsupported/);
});
