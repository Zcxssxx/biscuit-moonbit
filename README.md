# Biscuit for MoonBit — early prototype

This is an early experiment based on the Eclipse Biscuit specification. **It cannot issue, verify, attenuate, or authorize tokens and must not be used for access control.** It currently constructs one version 1 Ed25519 authority-block signature payload; it is not a conforming Biscuit implementation.

## Build and test

Tested with moon 0.1.20261023 and moonc 0.10.17 (2026-10-23):

```sh
moon check
moon build
moon test
```

## Sources and dependencies

- [Eclipse Biscuit specification](https://doc.biscuitsec.org/reference/specifications) and [upstream repository](https://github.com/eclipse-biscuit/biscuit), Apache-2.0. This prototype refers to the specification; it does not claim upstream endorsement.
- `hustcer/ed25519` 0.6.1, Apache-2.0, is an intended dependency, not yet used. Its author states it is unaudited and not constant-time. See its [documentation](https://mooncakes.io/docs/hustcer/ed25519@0.6.1); review transitive dependencies before release.

See [implementation plan](docs/plans/2026-11-05-biscuit.md) for open work and release gates. Licensed under Apache-2.0; see LICENSE.
