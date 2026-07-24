# Test vectors

Hex strings are lowercase, have no `0x` prefix, and contain the exact encoded
bytes.

- [`v1/`](v1/) fixes the secp256k1 profile in
  [`PROFILE.md`](../PROFILE.md).
- [`v1-ed25519/`](v1-ed25519/) fixes the profile in
  [`ED25519.md`](../ED25519.md).
- [`v1-tr/`](v1-tr/) fixes the Taproot adapter in
  [`TAPROOT.md`](../TAPROOT.md).

| File | Check |
|---|---|
| `sign-outer-2of3-inner-2of3` | Full depth-two signature and Schnorr equation |
| `sign-alternate-supports` | Same key and message through other valid supports |
| `receiver-interleaving` | Per-receiver schedule and distinct local aggregates |
| `leaf-replay-and-close` | Replay, refusal, abort, timeout, and attempt closure |
| `inner-veto-retry-activate` | Vetoed prefix, retry, bundle, and stable keys |
| `outer-reshare` | Stable identity and vault keys with a changed member point |
| `dealing-invalid` | Eight validation and activation failures |
| `multi-vault-identity-reuse` | One identity key across two private vault memberships |

Every plain file has `format = "coupery-ksnf-v1"` and a matching `case`.
Structured fields explain the fixture; fields named `canonical`, `command`,
`candidate_view`, `member_body`, `member_opening`, `member_record`,
`reservation`, `response`, or `signature` hold protocol bytes.
`test_only_secret` publishes fixture secrets. Never use them as keys or nonces.

Check the files with:

```sh
cargo test --test vector_conformance
cargo test --no-default-features --features ed25519 --test vector_conformance_ed25519
cargo test --features taproot --test vector_conformance_tr
cargo test --test vector_integrity
```

Maintainers regenerate one profile at a time:

```sh
UPDATE_VECTORS=1 cargo test --test vector_conformance
UPDATE_VECTORS=1 cargo test --no-default-features --features ed25519 --test vector_conformance_ed25519
UPDATE_VECTORS=1 cargo test --features taproot --test vector_conformance_tr
```

Review the diff after regeneration. A byte change requires a new profile
version unless it fixes an unpublished draft.
