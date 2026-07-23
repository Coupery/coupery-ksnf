# KSNF v1 profile

The paper is group-generic. This crate fixes one byte profile.

## Group

- Curve: secp256k1.
- Scalar: canonical 32-byte big-endian integer below the group order.
- Point: 33-byte compressed SEC1 encoding. The identity is invalid.
- Element: one tag byte followed by 33 bytes. `00 || 0^33` is the identity.
  `01 || point` is a nonidentity point.

The tagged element form is used where the protocol permits zero coefficient
commitments. Keys, share points, and nonces use `Point`.

## Fields

Integers are big-endian. Variable byte strings have a big-endian `u32` length.
Maps and sets sort by their encoded keys and reject duplicates. Decoders reject
unknown tags, noncanonical scalars, trailing bytes, and alternate identity
encodings.

## Hashes

Each hash uses SHA-256 XMD hash-to-field with one domain:

```text
KSNF/v1/deal
KSNF/v1/member
KSNF/v1/nonce
KSNF/v1/bind
KSNF/v1/challenge
```

Commitments, binding factors, and challenges are canonical scalar encodings.
This profile does not apply x-only normalization, nonce negation, or a Taproot
tweak.
