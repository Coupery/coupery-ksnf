# Taproot key-path profile

This adapter turns one plain KSNF session into a BIP-340 key-path signature.
The caller supplies the 32-byte BIP-341 signature hash.

## Keys

Let `Q` be the stable plain vault key. The adapter computes:

```text
P = even(Q) = aQ
t = int(tagged_hash("TapTweak", x(P) || merkle_root))
T = P + tG
X = even(T) = bT
```

`a` and `b` are `+1` or `-1`. An absent Merkle root is omitted from the tweak
preimage. The adapter rejects `t >= n` and the identity `T`. `X` is the wallet's
x-only output key.

Each device stores `X` outside the signing transcript. It passes that key to
`LeafRegistry::reserve_taproot`. A different output key is rejected before
nonce creation. If it alters a live reservation, that attempt closes.

## Signing

Binding factors hash the full canonical Taproot package. If the raw aggregate
nonce is odd, `r = -1`; otherwise, `r = 1`. Devices respond with:

```text
z[j,i] = r(d[j,i] + rho[j]e[j,i])
       + c beta[j,i] alpha[j] b(a x[j,i] + t)
```

The inner coefficients `beta[j,i]` sum to one for each member. The outer
coefficients `alpha[j]` also sum to one. The tweak therefore enters the final
response once. Inner aggregation verifies every device partial. Outer
aggregation verifies every member partial and the final signature.

## Bytes

The envelope protocol identifier is `coupery-ksnf/taproot/v1`.

```text
envelope =
    1 || bytes(protocol_id) || kind || bytes(plain_payload)
    || merkle_root_flag || merkle_root?

reservation = envelope(kind = 1, plain member reservation)
package     = envelope(kind = 2, plain root package)

device_response = 1 || 1 || device_id || u64(sequence) || scalar(response)
member_response = 1 || 2 || slot || scalar(response)
signature       = nonce_x || scalar(response)
```

The plain payload carries the vault key. That key and the optional Merkle root
determine the output key, so the envelope does not repeat it.

The root package message must be exactly 32 bytes. It is the BIP-341 signature
hash, not an arbitrary application message. The wallet appends a non-default
sighash-type byte to the 64-byte signature when required.

The adapter supports key-path signing for outputs with or without a script
tree. It does not construct transactions, tapleaves, control blocks, or
signature hashes. The plain-Schnorr theorem does not prove this adapter.

Canonical examples live in [`test-vectors/v1-tr/`](test-vectors/v1-tr/).
Output derivation is checked against the
[BIP-341 wallet vectors](https://github.com/bitcoin/bips/blob/master/bip-0341/wallet-test-vectors.json).
