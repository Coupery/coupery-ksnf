# secp256k1 profile

This document fixes `coupery-ksnf/v1`, the original secp256k1 byte profile.
[`ED25519.md`](ED25519.md) fixes the independent Ed25519 profile.

## Group

- Curve: secp256k1.
- Scalar: canonical 32-byte big-endian integer below the group order.
- Point: 33-byte compressed SEC1 encoding. The identity is invalid.
- Element: one tag byte followed by 33 bytes. `00 || 0^33` is the identity.
  `01 || point` is a nonidentity point.

Coefficient commitments and device share points use `Element`; either may be
zero. Keys and nonce points use `Point`.

## Fields

| Field | Encoding |
|---|---|
| Version | `u8`, value `1` |
| Identifier or activation handle | 32 fixed bytes |
| Leaf attempt | `device_id || u64(sequence)` |
| Slot or collection count | big-endian `u16` |
| Byte string | big-endian `u32` length, then bytes |
| Epoch or expiry | big-endian `u64` |
| Scalar | 32 bytes |
| Point | 33 bytes |
| Element | 34 bytes |

Structured protocol objects start with version `1`. The plain Schnorr
signature is the exception: `R_compressed || z`, 65 bytes, with no version
byte. A device response is `1 || device_id || sequence || z`, 73 bytes. A
member response is `1 || slot || z`, 35 bytes.

Maps and sets sort by their encoded keys and reject duplicates. Decoders reject
unknown versions, unknown tags, noncanonical scalars, alternate identity
encodings, truncated input, and trailing bytes. Numeric epochs label state;
activation handles identify it.

Root packages bind the protocol identifier `coupery-ksnf/v1`.

## Objects

This grammar is normative. `bytes(x)` is the `u32` length of `x` followed by
`x`. `point`, `element`, and `scalar` use the forms above. `v` is the version
byte. `*` repeats the prior term by the preceding count.

```text
key_epoch =
    u64(outer_epoch) || u64(inner_epoch) || vault_id || person_id
    || identity_handle || member_handle

leaf_attempt = device_id || u64(sequence)

device_row =
    device_id || scalar(node) || element(share) || scalar(inner_coefficient)

member_body =
    v || point(identity_key) || point(member_point) || key_epoch
    || u16(device_count) || device_row*
    || person_id || u16(slot) || scalar(outer_coefficient)

record = u16(slot) || point(member_point) || scalar(commitment)
member_record = v || record

root_prefix =
    v || point(vault_key) || bytes(message) || bytes("coupery-ksnf/v1")
    || vault_id || u64(outer_epoch) || ceremony_id

root_prepackage = root_prefix || u16(record_count) || record*

root_entry =
    u16(slot) || point(member_point) || point(hiding_nonce)
    || point(binding_nonce)

root_package =
    root_prefix || u16(entry_count) || root_entry*
    || u16(record_count) || record*

member_opening = v || scalar(salt) || bytes(member_body)

member_reservation =
    v || bytes(root_prepackage) || u16(slot) || bytes(member_opening)
    || session_id || u64(expiry)

device_response = v || leaf_attempt || scalar(response)
member_response = v || u16(slot) || scalar(response)
signature = point(aggregate_nonce) || scalar(response)
```

`root_package` requires equal entry and record counts. Rows use ascending
device identifiers. Records and entries use ascending slots. The outer row in
`member_body` must match the accepted outer support. All support coefficients
are encoded and then recomputed by the decoder.

### Redistribution

```text
target_id =
    00 || device_id
  | 01 || person_id || device_id

single_shape =
    u16(threshold) || u16(device_count)
    || (device_id || scalar(node))*

target_shape =
    00 || single_shape
  | 01 || u16(outer_threshold) || u16(person_count)
       || (person_id || scalar(outer_node) || single_shape)*

role_id =
    00 || source_device_id
  | 01 || refresher_device_id

role_row =
    role_id || element(required_constant) || element(source_share)
    || scalar(source_weight)

command =
    v || scope_id || command_id || predecessor_handle || point(anchor)
    || target_shape || u16(role_count) || role_row*

point_vector = u16(point_count) || element(coefficient)*

contribution_points =
    v || 00 || point_vector
  | v || 01 || point_vector || u16(member_count)
      || (person_id || point_vector)*

opening = v || role_id || bytes(contribution_points) || scalar(salt)

candidate_view =
    v || bytes(command) || u16(commitment_count)
    || (role_id || scalar(commitment))*
    || u16(opening_count) || bytes(opening)*

target_receipt = v || command_id || target_id || bytes(candidate_view)
```

For a refresher, `source_share` is the identity element and `source_weight` is
zero. Source rows carry the accepted share point and its support-derived
weight. Outer people, devices, and roles are sorted by identifier. Outer
member point vectors use the same person order as the target shape.

### Receiver-local views

These bytes support replay checks. The authenticated transport must also bind
the message kind.

```text
view_prefix =
    v || receiver_leaf_attempt || session_id || bytes(member_reservation)
    || u16(sender_count)

commitment_view =
    view_prefix || (sender_leaf_attempt || scalar(commitment))*

opening_view =
    view_prefix || (sender_leaf_attempt || point(hiding_nonce)
    || point(binding_nonce))*
```

Senders use ascending device identifiers. Each receiver may hold a different
valid view. The authenticated delivery binds both leaf attempts, the session,
the reservation, and the message kind.

Each device issues leaf attempts in ascending sequence order. It durably
advances the sequence and marks the attempt live before creating a nonce. A
closed attempt never becomes live again. A later try for the same ceremony
uses a new attempt. `SessionId` names the ceremony; `LeafAttempt` is the
device-local one-use slot that refines the paper's leaf tombstone.

## Hashes

Hashes use RFC 9380 `hash_to_field` with SHA-256 `ExpandMsgXmd`, one
secp256k1 scalar output, and one fixed domain string:

```text
KSNF/v1/deal
KSNF/v1/member
KSNF/v1/nonce
KSNF/v1/bind
KSNF/v1/challenge
```

Commitments, binding factors, and challenges use the scalar's canonical
32-byte encoding. The unit test in [`src/hash.rs`](src/hash.rs) fixes one output
for every domain.

Their preimages are:

```text
deal =
    v || bytes("deal") || bytes(command) || role_id
    || bytes(contribution_points) || scalar(salt)

member = v || bytes("member") || scalar(salt) || bytes(member_body)

nonce =
    v || bytes("nonce") || leaf_attempt || bytes(member_reservation)
    || point(hiding_nonce) || point(binding_nonce)

bind = v || bytes(root_package) || u16(zero_based_entry_index)

challenge =
    v || point(aggregate_nonce) || point(vault_key) || bytes(message)
```

## Boundary

Version 1 uses plain Schnorr. It does not apply x-only encoding, even-Y key or
nonce normalization, nonce negation, or a Taproot tweak. Such a transform
needs its own proof and vector version. [`TAPROOT.md`](TAPROOT.md) specifies the
separate key-path adapter.

The JSON files under [`test-vectors/`](test-vectors/) annotate canonical
bytes. JSON itself is not protocol syntax.

`LeafMaterial` and `LeafJournal` use separate versioned storage encodings.
They are not signed protocol messages and do not change the v1 byte profile.
See [`STORAGE.md`](STORAGE.md).

## Profile checklist

Every proposed profile must fix the items below before code lands.

| Item | Required decision |
|---|---|
| Group | Prime-order group, scalar field, generator, and security assumptions |
| Hash suite | Hash-to-field construction and every domain string |
| Scalars | Canonical width, byte order, range checks, and zero rules |
| Points | Canonical encoding, identity handling, and subgroup checks |
| Elements | Encoding for identity-capable commitment and share values |
| Nodes | Node derivation, nonzero rule, uniqueness rule, and canonical support order |
| Objects | Version byte, protocol identifier, field grammar, map order, and duplicate policy |
| Signing | Nonce binding, challenge preimage, response equations, and signature encoding |
| Adapters | Key and nonce normalization, tweaks, extra messages, and separate proof status |
| Vectors | New directory, positive paths, refusal paths, partials, final signatures, and immutable digests |
| Review | Proof mapping and an independent implementation or verifier |

A curve change is a reviewed upstream profile, not a downstream fork that
silently replaces the algebra. The Ed25519 profile follows this process and
has its own proof mapping and vectors. Adapter coverage is stated separately
from each plain theorem.

See [`CONFORMANCE.md`](CONFORMANCE.md) for the release rule and certification
checks.
