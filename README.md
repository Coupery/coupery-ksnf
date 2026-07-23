# coupery-ksnf

`coupery-ksnf` implements the plain-Schnorr, Shamir, depth-two construction
from *Key-Stable Nested FROST*.

The crate is under active development. Its first stable surface will include
canonical encodings, nested signing, one-use leaf state, same-key
redistribution, atomic activation, and test vectors.

It excludes DKG, transport, storage, application policy, BIP-340, Taproot, and
recursive depth.

[`PROFILE.md`](PROFILE.md) fixes the v1 group, encoding, and hash rules.

```sh
cargo test --all-targets
```

MIT licensed.
