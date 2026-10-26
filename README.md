# Agent Delegation Grant (ADG)

A small, signed, offline-verifiable document in which a verified human grants a specific AI agent a specific scope for a specific period, with revocation and a named accountable party.

Banks and other relying parties are blocking AI agents because an agent logging in with a customer's password looks exactly like the customer. "Know Your Customer" answered who the person is. The grant answers who is acting for the person, under what authority, and who is liable.

- Spec: [SPEC.md](SPEC.md) (v0.1 draft, open for comment)
- Scope vocabulary for finance, scope classes, presentation via HTTP Message Signatures (RFC 9421), revocation via a signed status list
- Reference implementation in this repo: TypeScript, zero runtime dependencies (Node's own Ed25519), 11 tests
- Reuses the conventions of the [Receipt Format v0.1](https://github.com/genzagents/work-receipt-spec): Ed25519, JCS canonicalisation, did:key / did:web, Pacts

## Try it in one minute

Needs Node 22.18 or newer. No install step.

```bash
npx github:genzagents/agent-delegation-spec verify examples/grant.json \
  --audience did:web:bank.example --status-list examples/status-list.json \
  --action payment.initiate --resource acct:gb29nwbk60161331926819 --amount 120 --currency GBP \
  --payee-hash sha256:7e2d4f3bbd4fa2a0c0c5a7d1e3b8f7a6d5c4b3a2918273645564738291a0b1c2
```

Output, in the order section 6 requires a relying party to check:

```
ok   shape
ok   signatures
ok   time
ok   audience
ok   verification
ok   revocation
ok   scope
VALID
```

Point it at the revoked copy of the status list and the same grant is refused with a machine-readable reason:

```bash
npx github:genzagents/agent-delegation-spec verify examples/grant.json \
  --audience did:web:bank.example --status-list examples/status-list.revoked.json
# FAIL revocation: grant adg_01M5VZ1CFX997PBTKA4A8AY483 is revoked (index 42)
# REFUSED (revocation: grant adg_01M5VZ1CFX997PBTKA4A8AY483 is revoked (index 42))
```

Ask for more than the grant allows (perTxn limit is 500 GBP) and the scope check refuses; ask for 300 GBP and it refuses until the relying party has obtained a step-up, because the grant says `requireStepUp` above 250:

```bash
npx github:genzagents/agent-delegation-spec verify examples/grant.json --audience did:web:bank.example \
  --status-list examples/status-list.json --action payment.initiate --resource acct:gb29nwbk60161331926819 \
  --amount 300 --payee-hash sha256:7e2d4f3bbd4fa2a0c0c5a7d1e3b8f7a6d5c4b3a2918273645564738291a0b1c2
# FAIL scope: step-up (fresh human confirmation) required and not satisfied
# ... add --step-up once the human has confirmed, and it is VALID
```

The example also contains a signed HTTP request (`examples/request.json`): the grant in the `Agent-Delegation` header plus an RFC 9421 signature over `@method`, `@target-uri` and `content-digest` made with the delegate key. Signatures are only accepted within 300 seconds of `created`, so pass the time the example was generated:

```bash
npx github:genzagents/agent-delegation-spec verify-request examples/request.json \
  --audience https://api.bank.example --status-list examples/status-list.json \
  --now $(node -p "require('./examples/request.json').verifyWith.now") \
  --action payment.initiate --resource acct:gb29nwbk60161331926819 --amount 120 \
  --payee-hash sha256:7e2d4f3bbd4fa2a0c0c5a7d1e3b8f7a6d5c4b3a2918273645564738291a0b1c2
# ok   presentation
# VALID
```

## The whole flow from the command line

```bash
adg keygen --out principal.json        # the human
adg keygen --out delegate.json         # the agent
adg keygen --out issuer.json           # whoever publishes the status list (can be the principal)
adg status new --url https://you.example/adg-status.json --key issuer.json --out status-list.json
# write draft.json (see examples/draft.json): principal, delegate, audience, scope, revocation {url, index}
adg issue --draft draft.json --key principal.json --out grant.json
adg countersign grant.json --role delegate --key delegate.json        # now the grant is valid
adg present grant.json --key delegate.json --method POST --url https://api.bank.example/payments --body payment.json
adg verify grant.json --audience did:web:bank.example --status-list status-list.json --action account.read --resource acct:1
adg status revoke status-list.json --index 48213 --key issuer.json  # one-way; publish the new file at the URL
```

`adg example ./dir` writes all of the above for you (four keypairs, draft, four-signature grant, status list before and after revocation, a signed request). That is how `examples/` was made.

## Library

```ts
import { issue, countersign, verifyGrant, present, verifyPresentation, newStatusList, revoke, generateKeypair } from "@genzagents/adg";

const grant = countersign(issue(draft, principal.privateKeyBase64url), "delegate", delegate.privateKeyBase64url);
const headers = present(grant, delegate.privateKeyBase64url, { method: "POST", url, body });   // delegate side
const verdict = await verifyPresentation({ method: "POST", url, body, headers }, {               // relying-party side
  audience: "did:web:bank.example", statusList, seenNonce, request: { action: "payment.initiate", resource, amount, payeeHash, spentInPeriod },
});
if (!verdict.ok) refuse(verdict.reason);   // e.g. "scope: amount 600 GBP exceeds perTxn limit 500 GBP"
```

`verifyGrant` runs the section 6 checks in order and stops at the first failure: shape (section 3 and 4 rules), the principal and delegate signatures (operator and issuer when present), `notBefore`/`expiresAt`, `audience`, the principal's verification level against the scope class (section 4.3 defaults, overridable with `verificationPolicy`), revocation (status list or endpoint), then the requested action against `scope`, `limits` (the relying party supplies its running total for `perPeriod`), `payeeAllowlist` and `requireStepUp`. Unknown actions and `credential.*` are always refused. Liability (`accountable`) can only move to the operator when the operator has countersigned.

Source: [src/](src/) (about 550 lines across codec, keys, scope, status, grant, present, did). Tests: `npm test`. Build to plain JS: `npm run build` (uses Node's own type stripping; no TypeScript install).

## Status

Draft v0.1, October 2026. One implementation (this one). The bar for taking the spec to a neutral body is two independent implementations (section 13.5): if you write one in another language, open an issue and we will cross-test against `examples/`.

## Contributing

Open an issue or a pull request. Disagreement from people who sit on the relying-party side (banks, brokers, payment providers) is especially welcome. See the open questions in section 13 of the spec.

## Licence

Spec text: CC BY-SA 4.0 ([LICENSE-SPEC](LICENSE-SPEC)). Code: Apache-2.0 ([LICENSE-CODE](LICENSE-CODE)).

Author: Manraj Singh Dhillon.
