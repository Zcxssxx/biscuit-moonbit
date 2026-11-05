# Third-party notices

This file records third-party components and source material used by this
repository. The project itself is licensed under Apache-2.0; see [LICENSE](LICENSE).

## Protocol and test fixtures

- The implementation follows the [Eclipse Biscuit specification](https://doc.biscuitsec.org/reference/specifications).
- `interop_test.mbt` and `examples/verify/main.mbt` contain Biscuit token test
  vectors and a published test key from
  [eclipse-biscuit/biscuit-rust](https://github.com/eclipse-biscuit/biscuit-rust),
  pinned in the source fixture comment to commit
  `21e650f31a8521af575f968925acbb56486172f9`. The upstream project is licensed
  under Apache-2.0. These public vectors are for testing only; the test key
  must not protect real resources.

## Runtime dependencies

| Component | Version | Relationship | License | Notes |
| --- | --- | --- | --- | --- |
| [hustcer/ed25519](https://github.com/hustcer/mbt-ed25519) | 0.6.1 | Direct | Apache-2.0 | Maintainer states the implementation is unaudited and not constant-time. |
| [moonbitlang/x](https://github.com/moonbitlang/x) | 0.5.5 | Transitive, via `hustcer/ed25519` | Apache-2.0 | Experimental MoonBit packages. |
| [moonbitlang/core](https://github.com/moonbitlang/core) | MoonBit toolchain | Standard library | Apache-2.0 | Imported for core collections, strings, encoding and test support. |

The versions above match `moon.mod` and the dependency metadata for
`hustcer/ed25519` in the inspected Mooncakes cache. Recheck dependency metadata
when updating packages or the toolchain.
