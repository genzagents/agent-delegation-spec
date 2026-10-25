# Agent Delegation Grant (ADG)

A small, signed, offline-verifiable document in which a verified human grants a specific AI agent a specific scope for a specific period, with revocation and a named accountable party.

Banks and other relying parties are blocking AI agents because an agent logging in with a customer's password looks exactly like the customer. "Know Your Customer" answered who the person is. The grant answers who is acting for the person, under what authority, and who is liable.

- Spec: [SPEC.md](SPEC.md) (v0.1 draft, open for comment)
- Scope vocabulary for finance, scope classes, presentation via HTTP Message Signatures, revocation via status list
- Reuses the conventions of the [Receipt Format v0.1](https://github.com/genzagents/genzagents): Ed25519, JCS canonicalisation, did:web, Pacts

## Status

Draft v0.1, October 2026. No implementation yet. Reference TypeScript implementation (issue, countersign, present, verify, status list) is the next milestone.

## Contributing

Open an issue or a pull request. Disagreement from people who sit on the relying-party side (banks, brokers, payment providers) is especially welcome. See the open questions in section 13 of the spec.

## Licence

Spec text: CC BY-SA 4.0 ([LICENSE-SPEC](LICENSE-SPEC)). Code: Apache-2.0 ([LICENSE-CODE](LICENSE-CODE)).

Author: Manraj Singh Dhillon.
