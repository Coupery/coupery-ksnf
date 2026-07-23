# coupery-ksnf

`coupery-ksnf` is the Rust reference implementation for *Key-Stable Nested
FROST*. It implements plain Schnorr over secp256k1, with a FROST group of
people whose members are FROST groups of devices.

This crate is new and unaudited. Do not protect funds with it yet.

## What it does

- Produces one Schnorr signature under a stable vault key.
- Keeps each person's public identity stable across device changes.
- Hides each person's device roster, threshold, and participating subset from
  the outer group.
- Refreshes inner and outer Shamir sharings without changing their named key.
- Binds every nonce to one canonical session and one live device slot.
- Shares that live slot across every vault on the device.
- Records vetoed redistribution prefixes and audits the paper's exposure rule.

The three public key scopes are different:

| Key | Meaning | Stability |
|---|---|---|
| `Y_j` | Person identity key | Stable across rosters and vaults |
| `V_j` | Person's member point in one vault | Stable across inner changes; may change after an outer reshare |
| `Q` | Vault verification key | Stable across valid changes |

```text
device shares ── inner FROST ── member response ── outer FROST ── (R, z)
                     V_j                              Q
```

The outer group sees one member record, nonce pair, response, and result for
each person. It does not see that person's device roster, threshold, chosen
devices, or inner epoch.

## Start here

```sh
cargo test --all-targets
```

- [`PROFILE.md`](PROFILE.md) fixes the group, bytes, and hash domains.
- [`IMPLEMENTING.md`](IMPLEMENTING.md) lists the integration rules.
- [`test-vectors/`](test-vectors/) contains eight deterministic vector sets.
- [`tests/nested_signing.rs`](tests/nested_signing.rs) shows one full
  depth-two signature.
- [`tests/activation.rs`](tests/activation.rs) shows bundled activation and
  epoch closure.

## Crate map

| Module | Purpose |
|---|---|
| `algebra`, `shamir` | Group values, secret scalars, polynomials, interpolation |
| `keys`, `genesis` | Key scopes and validated initial shares |
| `support` | Accepted supports and derived Lagrange coefficients |
| `transcript` | Canonical root, member, reservation, and signing contexts |
| `signing` | Device responses, member aggregation, plain Schnorr signatures |
| `auth`, `leaf` | Receiver-local delivery and the device-global one-live machine |
| `dealing`, `log_act` | Same-key redistribution, inner bundles, and atomic activation |
| `exposure` | Audit ledger for the paper's joint corruption rule |

The core owns no network, storage, clock, policy, or consensus code. An
application supplies those services and passes authenticated values into the
typed API. `MemoryLog` is a deterministic test implementation of the
append-only activation boundary. It is not a broadcast or consensus system.

## Setup boundary

Production code imports public polynomial commitments and one device's local
shares through `ValidatedPublicGenesis` and `DeviceGenesis`. The crate checks
their equations. `LeafRegistry::from_vaults` also checks that reused identity
states have the same roster, threshold, sharing, epoch, and handle. It keeps
one identity share and one anchor per vault. The crate does not create an
initial sharing or prove a DKG.

The crate also excludes BIP-340, Taproot tweaks, Birkhoff access structures,
recursive nesting, persistent crash recovery, and application policy.

Published by Coupery Cryptography Corp. MIT licensed.
