# Biscuit for MoonBit

Experimental MoonBit implementation of the [Eclipse Biscuit](https://www.biscuitsec.org/) authorization-token format.

**Experimental; do not use in production.** `authorize_token` is an end-to-end, deny-by-default authorizer for a deliberately narrow subset: v3 blocks, positive authority rules, checks with predicates and simple binary comparisons, caller-supplied ambient facts/rules, and ordered caller-supplied policies. Appended blocks may add checks but may not add facts or rules. The API rejects explicit scopes, unsupported expression bytecode, crypto algorithms, third-party signatures, and appended rights. It is not yet a complete Biscuit implementation; valid signatures alone never grant access. This code and its Ed25519 dependency are unaudited; the dependency is not constant-time.

## Current support

- Parse the outer protobuf token with a 1 MiB input cap and at most 128 appended blocks.
- Verify Ed25519 authority and appended blocks with v0 or v1 signature payloads and verify unsealed or sealed final proofs.
- Decode v3 ground facts from every block after signature verification, preserving block indexes and signatures and using one ordered symbol table. Inspection supports strings, integers, dates, byte arrays, booleans, null, arrays, sets, and maps with integer or string keys; variable terms are rejected.
- Decode positive rules and checks, including one binary comparison per serialized expression. `verify_block_programs` reports unsupported-expression and explicit-scope flags; `authorize_token` fails closed when either is present and applies the documented restrictions on appended blocks.
- `authorize_token` derives bounded facts from authority rules and caller ambient rules, evaluates token checks, then applies the caller's first-match allow/deny policies. Missing matching policy denies access. This initial path does not handle compound/unary expression bytecode, explicit scopes, rules/facts in appended blocks, authorizer-defined checks, revocation, or third-party blocks.
- Fail closed on unsupported algorithms, third-party signatures, unknown outer-token fields and versions, duplicate signed-block fields, malformed structures, invalid signatures and proof failures. This strict token parser may reject otherwise valid tokens with unknown protobuf fields.
- The caller supplies the root public key; a token's optional root key ID is only a hint and is not used for key selection. Choose the trusted root independently.
- `encode_block` serializes structured facts, positive rules, checks, and the supported binary comparisons. `issue` signs that block. `attenuate` verifies an unsealed token and appends checks only while continuing the shared symbol table; it rejects an empty restriction. These APIs still require caller-supplied, independent, fresh, cryptographically random 32-byte seeds. The next seed is intentionally included in an unsealed token for its holder to attenuate it.
- `token_to_base64url` and `token_from_base64url` provide canonical unpadded URL-safe transport with character, encoded-size, decoded-size and canonical-form validation. Decoding is not signature verification; call a verification or authorization API before trusting the token.
- Low-level `issue_raw` and `append_raw` accept pre-serialized block bytes and do not validate their Datalog semantics. In particular, `append_raw` can append facts or rules and is not a safe authorization policy by itself. Use `attenuate` for the constrained check-only operation.
- The Datalog subset also parses safe positive rules, conjunctive predicate queries, and simple comparison conditions; derives a least fixed point with caller-set fact and iteration caps; and evaluates any/all/reject checks plus first-match policies over caller-supplied facts. Order comparisons cover integers and dates. Compound/unary serialized expression bytecode and scope annotations remain unsupported.

## Build, test and example

Tested with `moon 0.1.20261023` and `moonc 0.10.17` (2026-10-23):

```sh
moon check
moon build
moon test
moon run examples/verify
moon run examples/issue
moon run examples/inspect
moon run examples/authorize
```

`examples/verify` checks the signature chain of a public upstream token. `examples/inspect` issues a disposable test token and demonstrates verified fact inspection. `examples/authorize` exercises the supported authorization subset and shows a token check denying a write request. `examples/issue` issues and check-only attenuates a structured token for interoperability. Tests include official Rust sample tokens for v0 and v1, a sealed token, invalid signatures, reordered blocks, authority and appended facts, nested values, structured value round trips, token checks, policy ordering, canonical Base64URL, and explicit unsupported cases. They are not a complete conformance suite. For a reverse interoperability check, install `biscuit-python==0.4.0` separately and run `python tools/interop.py`; it parses the authority rule, serialized comparison and appended check emitted by MoonBit. The issue, inspect and authorize examples use public fixed test seeds and must never be used to issue real tokens.

## Sources and licensing

- Project license: Apache-2.0, see [LICENSE](LICENSE).
- Protocol and test fixtures: [Eclipse Biscuit specification](https://doc.biscuitsec.org/reference/specifications) and [biscuit-rust](https://github.com/eclipse-biscuit/biscuit-rust), Apache-2.0. The sample byte strings in `interop_test.mbt` and `examples/verify` come from commit `21e650f31a8521af575f968925acbb56486172f9`. Their published test key is public and must never protect real resources.
- Cryptography: [hustcer/ed25519 0.6.1](https://mooncakes.io/docs/hustcer/ed25519@0.6.1), Apache-2.0, with its own transitive dependency `moonbitlang/x`. Review their licenses and security properties before use. Its maintainer states it is unaudited and not constant-time.

The [implementation plan](docs/plans/2026-11-05-biscuit.md) records remaining work and release gates.

