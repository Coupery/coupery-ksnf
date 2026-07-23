# Test vectors

Version 1 uses the byte rules in [`PROFILE.md`](../PROFILE.md). Hex strings are
lowercase, have no `0x` prefix, and contain the exact encoded bytes.

| File | Check |
|---|---|
| `sign-outer-2of3-inner-2of3` | Full depth-two signature and Schnorr equation |
| `sign-alternate-supports` | Same key and message through other valid supports |
| `receiver-interleaving` | Per-receiver schedule and distinct local aggregates |
| `leaf-replay-and-close` | Replay, refusal, abort, timeout, and tombstones |
| `inner-veto-retry-activate` | Vetoed prefix, retry, bundle, and stable keys |
| `outer-reshare` | Stable identity and vault keys with a changed member point |
| `dealing-invalid` | Eight validation and activation failures |
| `multi-vault-identity-reuse` | One identity key across two private vault memberships |

Every file has `format = "coupery-ksnf-v1"` and a matching `case`. Structured
fields explain the fixture; fields named `canonical`, `command`, `candidate_view`,
`member_body`, `member_opening`, `member_record`, `reservation`, `response`, or
`signature` hold protocol bytes. `test_only_secret` publishes fixture secrets.
Never use them as keys or nonces.

Check the files with:

```sh
cargo test --test vector_conformance
```

Maintainers can regenerate them with:

```sh
UPDATE_VECTORS=1 cargo test --test vector_conformance
```

Review the diff after regeneration. A byte change requires a new profile
version unless it fixes an unpublished draft.
