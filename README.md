# Biscuit for MoonBit

Experimental MoonBit implementation of the [Eclipse Biscuit](https://www.biscuitsec.org/) authorization-token format.

**Not an authorization library yet. Do not use it to grant access or in production.** The current API verifies a supported token's cryptographic signature chain and final proof only. It does not parse or evaluate Datalog, checks, policies, scopes, expiration, revocation, or any other authorization conditions. A valid signature does not mean a request is permitted. This code and its Ed25519 dependency are unaudited; the dependency is not constant-time.

## Current support

- Parse the outer protobuf token with a 1 MiB input cap and at most 128 appended blocks.
- Verify Ed25519 authority and appended blocks with v0 or v1 signature payloads and verify unsealed or sealed final proofs.
- Fail closed on unsupported algorithms, third-party signatures, unknown fields and versions, duplicate fields, malformed structures, invalid signatures and proof failures. This strict parser may reject otherwise valid tokens with unknown protobuf fields.
- The caller supplies the root public key; a token's optional root key ID is only a hint and is not used for key selection. Choose the trusted root independently.
- Experimental `issue_raw` and `append_raw` construct signed tokens from already serialized blocks. They do not validate Datalog or guarantee that an appended block restricts access. The caller must supply independent, fresh, cryptographically random 32-byte seeds. `issue_raw` exposes the next seed as part of the token by design. Full token rule parsing and authorization are not implemented.
- A separate Datalog subset can parse ground facts, simple positive rules, and predicate queries; derive a least fixed point with caller-set fact and iteration caps; and evaluate query-only checks and ordered policies over caller-supplied facts. It supports strings, signed 64-bit integers, booleans, null, and variables. It does not parse or evaluate expressions, dates, bytes, sets, arrays, maps, scopes, token symbol tables, or serialized block contents. It is not connected to token verification, and is not yet a Biscuit authorizer.

## Build, test and example

Tested with `moon 0.1.20261023` and `moonc 0.10.17` (2026-10-23):

```sh
moon check
moon build
moon test
moon run examples/verify
moon run examples/issue
```

The example uses a public upstream test token and prints whether its signature chain is valid. It does not make an authorization decision. Tests include official Rust sample tokens for v0 and v1, a sealed token, invalid signatures, reordered blocks, and explicit unsupported cases. They are not a complete conformance suite. For a reverse interoperability check, install `biscuit-python==0.4.0` separately and run `python tools/interop.py`; it parses and verifies the MoonBit-generated two-block token. The issue example uses public fixed test seeds and must never be used to issue real tokens.

## Sources and licensing

- Project license: Apache-2.0, see [LICENSE](LICENSE).
- Protocol and test fixtures: [Eclipse Biscuit specification](https://doc.biscuitsec.org/reference/specifications) and [biscuit-rust](https://github.com/eclipse-biscuit/biscuit-rust), Apache-2.0. The sample byte strings in `interop_test.mbt` and `examples/verify` come from commit `21e650f31a8521af575f968925acbb56486172f9`. Their published test key is public and must never protect real resources.
- Cryptography: [hustcer/ed25519 0.6.1](https://mooncakes.io/docs/hustcer/ed25519@0.6.1), Apache-2.0, with its own transitive dependency `moonbitlang/x`. Review their licenses and security properties before use. Its maintainer states it is unaudited and not constant-time.

The [implementation plan](docs/plans/2026-11-05-biscuit.md) records remaining work and release gates.

