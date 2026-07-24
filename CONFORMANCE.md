# Conformance

The vectors test bytes, equations, and refusal paths for the fixed profiles in
[`PROFILE.md`](PROFILE.md), [`ED25519.md`](ED25519.md), and
[`TAPROOT.md`](TAPROOT.md). JSON is a test container, not protocol syntax.

## Common form

Every vector is one JSON object.

| Field | Form | Meaning |
|---|---|---|
| `format` | string | Profile discriminator: `coupery-ksnf-v1`, `coupery-ksnf-ed25519-v1`, or `coupery-ksnf-taproot-v1` |
| `case` | string | Stable case name matching the file stem |
| `profile` | string | Human-readable group or adapter profile, when present |
| `test_only_secret` | object | Published fixture secrets used to reproduce the case |

Byte strings are lowercase hexadecimal without a `0x` prefix. Their decoded
bytes are exact. JSON integers explain fixture values; they do not replace the
canonical integer encodings in the profile. Array order is significant unless
the case says it presents deliberately unsorted input.

`test_only_secret` values are test data. Never use them for live keys or
nonces.

## Plain vectors

Files under [`test-vectors/v1`](test-vectors/v1/) use
`format = "coupery-ksnf-v1"`.

| Case family | Fields | Required check |
|---|---|---|
| `sign-*` | `vault_id`, `vault_key`, `message`, `selected_people`, `public_skeleton`, `members`, `derived`, `canonical` | Rebuild both supports and transcripts; reproduce every canonical package, response, and signature; verify each partial and the final signature |
| `receiver-interleaving` | `reservation`, `leaf_attempts`, `schedule`, `commitment_views`, `opening_views`, `local_aggregates`, `corrupt_receiver_specific` | Follow the listed receiver-local order; reproduce each view and local aggregate; keep receiver-specific corrupt openings separate |
| `leaf-replay-and-close` | `leaf_attempt`, `retry_attempt`, `reservation`, `commitment`, `nonce_pair`, `response`, `trace`, `terminal_cases` | Reproduce exact replays, altered-replay closure, refusal, and the next attempt |
| `inner-veto-retry-activate` | `vault_id`, `person_id`, `keys`, `rejected`, `retry` | Retain the rejected prefix; retry from the same predecessor; activate once; preserve the named keys |
| `outer-reshare` | `command`, `candidate_view`, `activation_handle`, `installed`, `new_root_prepackage`, `new_session_reservation`, `old_attempt_closed`, `keys` | Install only after activation; close old attempts; preserve identity and vault keys while allowing the member point to change |
| `dealing-invalid` | `checks` | Reject every listed malformed or out-of-phase action with the stated error |
| `multi-vault-identity-reuse` | `identity_key`, `vaults`, `visible_to_outer`, `not_in_root` | Reuse one identity key; keep vault state separate; omit private roster data from root packages |

Within a `canonical` object, each value named `root_package`, `root_prepackage`,
`member_body`, `member_record`, `member_opening`, `reservation`, `command`,
`candidate_view`, `response`, or `signature` is a complete canonical encoding.
Response arrays preserve their stated slot or device association.

## Taproot vectors

Files under [`test-vectors/v1-tr`](test-vectors/v1-tr/) use
`format = "coupery-ksnf-taproot-v1"`.

| Field | Meaning |
|---|---|
| `vault_key` | Compressed plain KSNF vault key |
| `sighash` | Caller-supplied 32-byte BIP-341 signature hash |
| `reservation` | Shared session identifier and expiry |
| `public` | Internal key, optional Merkle root, tweak, parity signs, challenge, and x-only nonce |
| `canonical.plain_root_package` | Embedded v1 root package |
| `canonical.taproot_package` | Adapter package binding the plain root and optional Merkle root |
| `canonical.taproot_reservations` | Slot-tagged private reservation envelopes |
| `canonical.device_responses` | Device response encodings in fixture order |
| `canonical.member_responses` | Member response encodings in fixture order |
| `canonical.output_key` | BIP-341 x-only output key |
| `canonical.signature` | BIP-340 `r || s` signature |

A Taproot implementation must also derive the same output key from the plain
vault key and Merkle root, apply all three parity signs in
[`TAPROOT.md`](TAPROOT.md), and verify the final signature with an independent
BIP-340 verifier.

## Ed25519 vectors

Files under [`test-vectors/v1-ed25519`](test-vectors/v1-ed25519/) use
`format = "coupery-ksnf-ed25519-v1"`.

| Case | Required check |
|---|---|
| `nested-webauthn` | Rebuild both tiers, reproduce every partial and canonical byte string, and verify the 64-byte result with an independent Ed25519 verifier |
| `mixed-supports` | Recompute coefficients for the listed device subsets and reproduce the final signature |
| `refresh` | Run the complete candidate and activation path on the same roster; preserve the anchored constant |
| `reshare` | Move the sharing to the listed devices; preserve the anchored constant and activate once |

Internal decoders must also reject malformed, noncanonical, identity, torsion,
non-prime-subgroup, and cross-profile inputs. Final public keys and signatures
remain untagged RFC 8032 objects.

## Claiming conformance

A plain-v1 implementation conforms when it:

1. reproduces every plain canonical byte string;
2. accepts every valid state transition and refuses every negative case;
3. reproduces every device partial, member partial, and final signature;
4. verifies final signatures under the published vault keys; and
5. rejects alternate encodings, unknown versions, duplicate identifiers,
   invalid supports, and trailing bytes as required by the profile.

Ed25519-v1 conformance requires all `v1-ed25519` cases and an independent RFC
8032 verification check. Taproot-v1 conformance requires secp256k1-v1
conformance plus all `v1-tr` cases and the independent BIP-340 check.

Run the Rust reference checks with:

```sh
cargo test --test vector_conformance
cargo test --no-default-features --features ed25519 --test vector_conformance_ed25519
cargo test --features taproot --test vector_conformance_tr
cargo test --test vector_integrity
```

## Versioning

Released vector files are immutable. Their SHA-256 digests are pinned in
`tests/vector_integrity.rs`. A new case may be added to an existing directory
only when it follows that directory's byte profile and leaves every released
file unchanged; its digest joins the pinned list. Any change to algebra, hash
domains, canonical encodings, protocol equations, or existing expected bytes
requires a new profile and vector directory.

Vector generators are maintainer tools. Their output does not define the
protocol; the profile and released files do.
