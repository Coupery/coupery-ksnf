# Taproot adapter vectors

These vectors exercise the key-path adapter in
[`src/taproot/`](../../src/taproot/). Each file has
`format = "coupery-ksnf-taproot-v1"`.

| File | Check |
|---|---|
| `taproot-keypath-2of2` | No script tree; outer and inner 2-of-2 |
| `taproot-keypath-with-tree-2of2` | Key-path spend for an output that commits to a script tree |
| `taproot-keypath-mixed-inner` | Inner 3-of-3 and 1-of-1 groups |

`canonical.plain_root_package` is the inner v1 package.
`canonical.taproot_package` also binds the script-tree root.
`canonical.taproot_reservations` gives one private reservation envelope per
outer slot. The shared session identifier and expiry are under `reservation`.
`canonical.signature` verifies under `canonical.output_key` with `sighash`.
The response arrays use their canonical wire encodings. `public` records the
three parity signs, tweak, challenge, and x-only nonce. `test_only_secret`
publishes fixture secrets to reproduce the bytes. Never use them as live keys
or nonces.

[`tests/tweaked_signing.rs`](../../tests/tweaked_signing.rs) also checks output
derivation against the Bitcoin BIP-341 wallet vectors and verifies signatures
with `k256`'s independent BIP-340 implementation.

Check the files with:

```sh
cargo test --test vector_conformance_tr
```

Regenerate them with `UPDATE_VECTORS=1 cargo test --test vector_conformance_tr`.
A byte change requires a new profile version unless it fixes an unpublished draft.
