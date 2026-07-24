# coupery-ksnf

[![CI](https://github.com/Coupery/coupery-ksnf/actions/workflows/ci.yml/badge.svg)](https://github.com/Coupery/coupery-ksnf/actions/workflows/ci.yml)

`coupery-ksnf` is the Rust reference implementation of *Key-Stable Nested
FROST*. A FROST group of people contains FROST groups of devices. Device
rosters can change without changing the public key.

The crate has two fixed profiles:

- plain Schnorr over secp256k1;
- RFC 8032-compatible Ed25519 public keys and signatures.

An optional secp256k1 adapter emits BIP-340 Taproot key-path signatures over a
caller-supplied BIP-341 signature hash.

This crate is new and unaudited. Do not protect funds with it yet.

## What it does

- Produces one signature under a stable vault key.
- Keeps each person's public identity stable across device changes.
- Hides each person's device roster, threshold, participating devices, and
  inner epoch from the outer group.
- Refreshes inner and outer Shamir sharings without changing the vault key.
- Enforces one live signing attempt across every vault on a device.
- Retains rejected redistribution prefixes for exposure checks.
- Emits ordinary Ed25519 credentials for passkeys and other applications.
- Adapts a secp256k1 vault key to a fixed Taproot output.

The public keys have distinct jobs:

| Key | Meaning | Stability |
|---|---|---|
| `Y_j` | Person identity key | Stable across rosters and vaults |
| `V_j` | Person's member point in one vault | Stable across inner changes; may change after an outer reshare |
| `Q` | Vault verification key | Stable across valid changes |

```text
device shares ── inner FROST ── member response ── outer FROST ── signature
                     V_j                              Q
```

The outer group sees one member record, nonce pair, response, and result for
each person. It does not see that person's device roster, threshold,
participating devices, or inner epoch.

## Install

The first release is `v0.1.0`. Pick the profile in `Cargo.toml`:

```toml
[dependencies]
coupery-ksnf = { git = "https://github.com/Coupery/coupery-ksnf", tag = "v0.1.0" }
```

Plain secp256k1 is the default. Select Ed25519 alone with:

```toml
[dependencies.coupery-ksnf]
git = "https://github.com/Coupery/coupery-ksnf"
tag = "v0.1.0"
default-features = false
features = ["ed25519"]
```

| Feature | Result | Default |
|---|---|---|
| `secp256k1` | Plain 65-byte Schnorr signatures | Yes |
| `ed25519` | Ordinary 32-byte public keys and 64-byte Ed25519 signatures | No |
| `taproot` | BIP-340 adapter; enables `secp256k1` | No |

Use the profile namespace at the application boundary. The default profile
looks like this:

```rust
# #[cfg(feature = "secp256k1")]
# mod profile_example {
use coupery_ksnf::secp256k1::{Signature, VaultKey};
use coupery_ksnf::Result;

pub fn verify(signature: &[u8; 65], key: &[u8; 33], message: &[u8]) -> Result<()> {
    Signature::from_bytes(signature)?.verify(VaultKey::from_bytes(key)?, message)
}
# }
```

The Ed25519 surface differs only in canonical lengths:

```rust
# #[cfg(feature = "ed25519")]
# mod profile_example {
use coupery_ksnf::ed25519::{Signature, VaultKey};
use coupery_ksnf::Result;

pub fn verify(signature: &[u8; 64], key: &[u8; 32], message: &[u8]) -> Result<()> {
    Signature::from_bytes(signature)?.verify(VaultKey::from_bytes(key)?, message)
}
# }
```

Run complete flows from a checkout:

```sh
cargo run --example nested_signing
cargo run --example reshare_during_signing
cargo run --no-default-features --features ed25519 --example ed25519_webauthn
cargo run --features taproot --example taproot_keypath
```

Each example ends with verification assertions. `reshare_during_signing`
overlaps signing with a vetoed redistribution, retry, and atomic activation.
`ed25519_webauthn` signs exact `WebAuthn` assertion bytes and verifies the result
with an independent Ed25519 implementation.

## API map

Concrete driver types live under `secp256k1` and `ed25519`. Generic protocol
types remain available through their modules.

| Type | Role | Module |
|---|---|---|
| `ValidatedPublicGenesis`, `DeviceGenesis` | Validate public setup and attach one device's shares | Profile namespace, `genesis` |
| `LeafRegistry`, `PersistentLeaf`, `MemoryLeafStore` | Enforce the device-wide lock and one-use attempts | Profile namespace, `leaf` |
| `LeafStore<P>` | Supply durable device storage | `leaf` |
| `SigningContext`, `DeviceResponse`, `MemberResponse`, `Signature` | Verify and assemble signatures | Profile namespace, `transcript`, `signing` |
| `Candidate`, `InnerBundle`, `ReleasedContribution`, `LogAct` | Run redistribution and atomic activation | Profile namespace, `dealing`, crate root |
| `IdentityKey`, `MemberPoint`, `VaultKey` | Name the three public key scopes | Profile namespace, `keys` |
| `ExposureLedger`, `ExposureViolation` | Check the paper's joint exposure rule | Crate root, `exposure` |
| `Error`, `Result` | Handle protocol failures | Crate root |

Taproot stays module-qualified because its signature and response types differ
from the plain secp256k1 profile.

## Integration boundary

This crate does not choose a transport, storage engine, authorization policy,
consensus system, clock, or async runtime. It owns protocol validation and leaf
state transitions. Applications provide authenticated confidential delivery,
a `LeafStore` with durable linearizable compare-and-set, and a `LogAct`
implementation with ordered atomic activation.

`PersistentLeaf` routes immutable secret material and the device-local journal
through separate store calls. Material may live in a syncable keychain. The
journal needs one non-replicated authority for the physical device, shared by
every vault in that profile. Nonces stay in memory. `MemoryLeafStore` and
`MemoryLog` are test implementations.

The application passes its current time to `reserve`. The leaf rejects expired
reservations and authenticates both selected support tiers against its active
public polynomials before it allocates an attempt.

Production setup imports public polynomial commitments and local shares through
`ValidatedPublicGenesis`. The crate checks their equations. It does not create
the initial sharing or prove a DKG.

For `WebAuthn`, the caller owns CBOR, credential IDs, relying-party metadata,
counters, user-presence policy, and the exact assertion input. For Taproot, the
caller builds transactions and BIP-341 signature hashes. The KSNF theorem does
not cover either application layer or the Taproot adapter.

The crate also excludes Birkhoff access structures, recursive nesting,
storage-engine correctness, and application policy.

## Stability

- The MSRV is Rust 1.85.
- The default build enables only `secp256k1`. Ed25519 and Taproot are explicit
  features.
- Released `test-vectors/v1`, `test-vectors/v1-ed25519`, and
  `test-vectors/v1-tr` bytes never change. A byte change requires a new profile
  directory.
- The concrete profile namespaces are the path toward 1.0. Generic expert APIs
  may change before then.

## Read next

- [`IMPLEMENTING.md`](IMPLEMENTING.md) lists proof-critical integration rules.
- [`STORAGE.md`](STORAGE.md) defines the crash-safe leaf-store contract.
- [`PROFILE.md`](PROFILE.md) fixes the secp256k1 profile.
- [`ED25519.md`](ED25519.md) fixes the Ed25519 profile and `WebAuthn` boundary.
- [`CONFORMANCE.md`](CONFORMANCE.md) defines vector compatibility.
- [`TAPROOT.md`](TAPROOT.md) specifies the key-path adapter.
- [`examples/`](examples/) contains runnable protocol flows.

Published by Coupery Cryptography Corp. MIT licensed.
