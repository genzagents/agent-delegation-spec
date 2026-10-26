# Agent Delegation Grant (ADG) v0.1 — Draft Specification

Status: draft for public comment. Author: Manraj Singh Dhillon. Licence: CC BY-SA 4.0 (spec), Apache-2.0 (reference code). Builds on the Receipt Format v0.1 conventions published at github.com/genzagents/work-receipt-spec.

## 1. Abstract

Banks and other relying parties are discovering AI agents acting inside customer accounts and cannot distinguish three cases: the human, an agent the human authorised acting within what was allowed, and an agent acting outside it. Today the agent logs in with the human's own credentials, so the relying party sees a human session and has no artefact to check. The result is blanket blocking.

An **Agent Delegation Grant** is a small, signed, machine-verifiable document in which a verified human (the **principal**) grants a specific agent (the **delegate**) a specific **scope** for a specific **period**, with a **revocation** mechanism and a named **accountable party**. The agent presents it on every request it makes on the principal's behalf. The relying party verifies the signature, the scope and the revocation status in milliseconds, without contacting the issuer in the hot path.

Know Your Customer answered "who is this person." The grant answers "who is acting for this person, under what authority, and who is liable."

The grant is deliberately not an identity for the agent. Agents are created and destroyed by the hundred. The durable facts are the human, the authority they gave, and the keys that prove it. The grant binds those three.

## 2. Definitions

- **Principal.** The human (or legal entity acting through a human) who holds the account or right being delegated. Identified by a DID (`did:web`, `did:key` or a registry DID) and a public key.
- **Delegate.** The agent receiving authority. Identified by a public key and an optional registry DID. A delegate's identity may be short-lived; the grant is what persists.
- **Accountable party.** The human or legal entity liable for the delegate's actions under the grant. Defaults to the principal. May be the agent operator when the operator has accepted liability by countersigning.
- **Relying party (RP).** The system the delegate acts upon: a bank, a broker, a merchant, an API.
- **Scope.** A list of allowed actions with limits. Expressed in a small declarative grammar (section 4).
- **Grant.** The signed document defined in section 3.
- **Presentation.** The act of attaching a grant, plus a per-request proof of key possession, to a request to the RP (section 6).
- **Revocation.** The principal withdrawing the grant before expiry (section 7).

## 3. Grant schema

JSON Schema 2020-12. `$id: https://spec.genzagents.io/delegation/v0.1.json`

```json
{
  "version": "0.1",
  "id": "adg_01J9ZK3Q7E4N6WVRB8M2P5X0TC",
  "issuedAt": "2026-10-25T14:00:00Z",
  "notBefore": "2026-10-25T14:00:00Z",
  "expiresAt": "2026-11-25T14:00:00Z",

  "principal": {
    "type": "human",
    "id": "did:web:genzagents.com:h:7f3a",
    "publicKey": "z6Mk...base58",
    "verification": { "level": "kyc", "provider": "persona", "verifiedAt": "2026-06-02T10:11:00Z" }
  },

  "delegate": {
    "type": "agent",
    "id": "did:web:genzagents.com:a:91bc",
    "publicKey": "z6Mk...base58",
    "operator": { "type": "service", "id": "did:web:example-assistant.com", "publicKey": "z6Mk...base58" },
    "runtime": { "model": "claude-opus-5-5", "harness": "openclaw/1.4", "attestation": null }
  },

  "accountable": { "type": "human", "id": "did:web:genzagents.com:h:7f3a" },

  "audience": ["did:web:bank.example", "https://api.bank.example"],

  "scope": [
    { "action": "account.read",     "resource": "acct:*" },
    { "action": "payment.initiate", "resource": "acct:gb29nwbk60161331926819",
      "limits": { "perTxn": {"amount": 500, "currency": "GBP"}, "perPeriod": {"amount": 2000, "currency": "GBP", "period": "P1M"} },
      "constraints": { "payeeAllowlist": ["sha256:..."], "requireStepUp": {"above": {"amount": 250, "currency": "GBP"}} } }
  ],

  "revocation": {
    "method": "status-list",
    "url": "https://genzagents.com/.well-known/adg-status/2026-10.json",
    "index": 48213
  },

  "pacts": [
    { "id": "pact_noCredentialStorage", "claim": "Delegate never stores or forwards principal credentials", "slashable": true }
  ],

  "extensions": {},

  "signatures": {
    "principal": "base64url(Ed25519 over JCS(grant minus signatures))",
    "delegate":  "base64url(...)",
    "operator":  "base64url(...) | null",
    "issuer":    "base64url(...) | null"
  }
}
```

Required: `version`, `id`, `issuedAt`, `expiresAt`, `principal`, `delegate`, `accountable`, `scope`, `revocation`, `signatures.principal`, `signatures.delegate`.

Rules:

- `id` is a ULID prefixed `adg_`. Signing covers the id, so grants cannot be replayed under a new id.
- `expiresAt` minus `issuedAt` MUST NOT exceed 365 days. RPs MAY enforce shorter maxima by scope class (section 4.3).
- `audience` is a list of RP identifiers. A grant with no `audience` is valid only for read-class actions (section 4.3). RPs MUST reject grants whose `audience` does not include them.
- `principal.verification.level` is one of `none`, `light`, `kyc`. RPs decide what level each scope class needs. A bank will require `kyc`.
- `delegate.runtime.attestation` is reserved for platform attestations (for example, a signed statement from the agent harness vendor). Null is valid in v0.1.
- `accountable` MUST equal `principal` unless `signatures.operator` is present, in which case it MAY name the operator. This is the only way liability moves off the human: the operator signs for it.
- `pacts` reuse the Receipt Format v0.5 Pact shape (`id`, `claim`, `slashable`, optional `evaluationTrigger`). They are behavioural commitments by the delegate and operator, usable as evidence in dispute.

## 4. Scope grammar

### 4.1 Shape

Each scope entry is `{ action, resource, limits?, constraints? }`.

- `action` is a dotted string from a published vocabulary per RP class. v0.1 ships one vocabulary, `fin` (section 4.2). Unknown actions MUST be rejected.
- `resource` is a URI-like string with `*` wildcards allowed only in the last segment. `acct:*` is "any account of the principal at this RP."
- `limits` are numeric caps, each with a currency or unit, and a `period` in ISO 8601 duration for rolling windows.
- `constraints` are RP-interpreted guards. v0.1 defines `payeeAllowlist` (SHA-256 of payee identifiers), `requireStepUp` (RP must obtain fresh human confirmation above a threshold), `timeWindow` (allowed hours in principal's time zone), `geo` (country list).

### 4.2 The `fin` vocabulary (v0.1)

| Action | Class | Meaning |
|---|---|---|
| `account.read` | read | balances, transactions, statements |
| `account.export` | read | bulk download |
| `payment.initiate` | move | create a payment within limits |
| `payment.cancel` | move | cancel a pending payment |
| `payee.add` | admin | add a payee (RPs SHOULD require step-up) |
| `card.freeze` | admin | freeze or unfreeze a card |
| `profile.read` | read | contact details, KYC status |
| `profile.write` | admin | change contact details |
| `credential.*` | forbidden | never delegable: passwords, recovery, 2FA settings |

### 4.3 Scope classes and defaults

| Class | Default max validity | Default verification level | Step-up |
|---|---|---|---|
| read | 365 days | light | no |
| move | 90 days | kyc | above RP threshold |
| admin | 30 days | kyc | always |
| forbidden | not delegable | | |

## 5. Signing

- Canonicalisation: RFC 8785 (JCS) over the grant with `signatures` removed.
- Algorithm: Ed25519. Signatures are base64url without padding. Keys are base58 (multibase `z`) as in Receipt Format v0.1.
- Order: principal signs first, delegate countersigns, operator optionally countersigns, issuer (a registry) optionally co-signs to indicate it indexed the grant and verified the principal at `verification.level`.
- Key discovery: the principal's and delegate's keys resolve from their DID documents. A registry DID (`did:web:genzagents.com:h:...`) resolves to a DID document the registry publishes.
- No grant is valid without both principal and delegate signatures. The delegate's countersignature proves the agent holds the key it will later use in presentations.

## 6. Presentation

The delegate attaches the grant to each request on the principal's behalf.

- HTTP: header `Agent-Delegation: <base64url(grant)>` or `Agent-Delegation-Ref: <grant id>` when the RP has cached the grant, plus a per-request proof using HTTP Message Signatures (RFC 9421) over `@method`, `@target-uri`, `content-digest`, `created`, signed with the delegate key. This proves the request came from the key named in the grant, and is replay-protected by `created` and a nonce.
- Non-HTTP channels (MCP, native APIs) carry the same two fields: the grant and a signed challenge.
- RPs MUST verify, in order: signature validity of the grant, `notBefore` and `expiresAt`, `audience` includes the RP, revocation status (section 7), the request falls within `scope` and `limits` (with the RP keeping the running totals for `perPeriod` limits), and the per-request proof. Any failure is a refusal with a machine-readable reason.
- An RP that receives a request with the principal's own session credentials AND a grant SHOULD treat the grant as authoritative and record the session as agent-driven. An RP that receives agent-like traffic with no grant MAY block it, which is the current state of the world and the thing this spec replaces.

## 7. Revocation

- Method `status-list`: the issuer publishes a bitstring status list (one bit per grant index) at a stable URL, signed, refreshed at least every 5 minutes. RPs fetch and cache it. This is the same shape as W3C Bitstring Status List and avoids a call to the issuer per request.
- Method `endpoint`: `revocation.url` returns `{revoked: boolean, at: timestamp}` for a given grant id. For RPs that prefer online checks.
- The principal revokes with a signed revocation message to the issuer, or directly to the RP where the RP supports it. Revocation is immediate on publish and cannot be undone; a new grant must be issued.
- Expiry is the default revocation. Short validity plus easy re-grant beats long validity plus manual revocation.

## 8. Liability and dispute

- The `accountable` party is liable for actions within scope. Actions outside scope are the RP's failure to enforce, and the RP SHOULD have refused them.
- Pacts attached to the grant are evidence in dispute. Dispute handling is out of scope for v0.1; Receipt Format v0.1 section 7 describes one model (structured LLM judge, human reviewer, arbitrator panel) that applies unchanged.
- Nothing in this spec creates a legal relationship by itself. It produces the evidence a legal relationship needs: who, what, when, with whose authority, signed.

## 9. Privacy

- A grant reveals that a principal delegated something to a delegate. It does not reveal account contents, balances or task content.
- `payeeAllowlist` carries hashes, not payee details.
- Grants default to being shared only with the named `audience`. A registry MAY index grant metadata (ids, parties, expiry, revocation) without storing scope detail. Zero-knowledge presentation of scope is a v0.2 item.

## 10. What this is not

- Not an agent identity system. The agent may die tomorrow; the grant and the human's key survive.
- Not a payments rail. It sits above Open Banking, card network agent tokens and payment protocols and tells them who authorised the request.
- Not a replacement for the RP's own authentication. The principal still holds their account. The grant removes the need to hand the agent the principal's password.

## 11. Relationship to existing work

- OAuth 2.0 and OpenID Connect: ADG is closest to a signed, offline-verifiable, principal-issued OAuth grant with structured scopes and a liability field. It can be carried inside an OAuth flow as a Rich Authorization Request or presented standalone.
- W3C Verifiable Credentials: a grant is a VC-shaped object. v0.1 uses plain JSON plus JCS and Ed25519 for implementer simplicity; a VC Data Model 2.0 mapping is straightforward and is a v0.2 item.
- HTTP Message Signatures (RFC 9421) and signed-bot proposals (for example Cloudflare's Web Bot Auth): ADG reuses them for per-request proof and adds the human authority layer they lack.
- Card network agentic commerce tokens and agent payment protocols: complementary. They move money. ADG proves who said the money could move.
- Receipt Format v0.1: a grant is the "before" artefact; a receipt is the "after" artefact. A receipt MAY reference the grant id under which the work was done.
- IETF individual drafts in the same space (checked 26 October 2026, none adopted by a working group):
  - draft-nelson-agent-delegation-receipts (Authproof, -12 of 10 October 2026, Informational): a signed JSON record of what a human authorised an agent to do, JWS (ES256 required, EdDSA optional) over JCS, structured `scopeSchema` with attenuating sub-receipts, append-only revocation registry with cascade. It defines no wire format for presenting the receipt on a request and does not address liability. ADG differs by being offline-verifiable at the relying party with a per-request RFC 9421 proof, by naming an accountable party that can only move to the operator by countersignature, and by a finance vocabulary with limits and step-up. A mapping from an ADG grant to a Nelson receipt is mechanical and is a candidate for v0.2.
  - draft-mishra-oauth-agent-grants, "Delegated Agent Authorization Protocol" (Grantex, Informational): an OAuth 2.0 style flow with an authorisation server, RS256 JWTs, `resource:action:constraint` scopes, server-held spending budgets, cascade revocation and a hash-chained audit trail. It needs the server in the hot path for budgets and high-stakes revocation; ADG keeps the relying party's check offline (signature, status list, scope) and leaves running totals with the relying party. DAAP's authorisation-code flow is one reasonable way for a principal to issue an ADG grant.
  - draft-liu-agent-operation-authorization (Alibaba and Cisco, -02 of March 2026, expired, Standards Track intended): a two-phase flow in which the agent proposes an operation as a Rego policy in a PAR-JWT and receives a JWT carrying user-confirmation evidence and a policy reference; bearer presentation per RFC 6750, no revocation, no liability allocation. Its user-confirmation evidence is close to ADG's `requireStepUp`; its policy-by-reference scope is a heavier alternative to ADG's declarative scope list.
- AAIP (AI Agent Identity Protocol, a PyPI package): Ed25519-signed, time-bounded, constrained permissions in JSON. Closest in shape to ADG's grant; no status list, audience or liability field seen.

## 12. Conformance

An implementation conforms as an **issuer** if it produces grants that validate against the schema, with correct canonicalisation and signatures, and publishes a status list. As a **delegate** if it countersigns grants and produces valid per-request proofs. As a **relying party** if it performs every check in section 6 in order and refuses on any failure with a machine-readable reason.

## 13. Open questions for v0.2

1. Should `delegate.runtime.attestation` become mandatory for `move` and `admin` classes once harness vendors ship attestations?
2. Sub-delegation: may a delegate grant a narrower scope to a sub-agent? Proposal: yes, with the chain carried in `extensions.chain` and every link verifiable, total validity capped by the root.
3. Scope vocabularies beyond `fin`: `health`, `gov`, `commerce`, `dev`.
4. Zero-knowledge scope presentation.
5. Governance: donate to a neutral body once two independent implementations exist.

## 14. Reference implementation

A TypeScript reference implementation lives in this repository (`src/`, CLI `adg`): keypairs (did:key), issue, countersign, status list (create, revoke, verify), presentation (RFC 9421 HTTP Message Signatures) and the full section 6 verification order with machine-readable refusal reasons. It has no runtime dependencies: Ed25519 and SHA-256 come from Node's `node:crypto`, JCS and base58 are implemented in `src/codec.ts`. `examples/` holds a complete worked flow produced by `adg example`. See README.md for the one-minute run.

Interoperability note for second implementations: a grant's signing input is the RFC 8785 canonical form of the grant with the `signatures` member removed; keys are multikey `z6Mk...` (multicodec `ed25519-pub`, base58btc); signatures are base64url without padding; the status list is one bit per index, most significant bit first, gzip-compressed and base64url-encoded, with the issuer's signature over the JCS form of the list minus `signature`; the per-request signature base follows RFC 9421 with components `@method`, `@target-uri` and (when there is a body) `content-digest`, parameters `created`, `nonce`, `keyid` (the delegate DID) and `alg="ed25519"`, under the label `adg`.
