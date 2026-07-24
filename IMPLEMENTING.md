# Implementing with coupery-ksnf

The crate supplies protocol math and state transitions. The application owns
transport, storage, authorization, and the activation ledger.

Choose one compile-time profile. The default build enables secp256k1.
Ed25519-only applications use `default-features = false, features =
["ed25519"]`. Concrete driver types live under `secp256k1` and `ed25519`;
the protocol modules expose the generic machinery beneath them.

## Data flow

```text
validated vault states + local shares
                  │
                  ▼
       DeviceGenesis[] ──► PersistentLeaf ──► device response
                                │
                                ▼
                            LeafStore

Command ──► Candidate ──► PendingShare ──► terminal activation
Commands ──► InnerBundle ────────────────► one terminal activation
                                                  │
                                                  ▼
                                           InstalledShare
```

Install a share only after its exact candidate receives an activated terminal
handle. Install both blocks from an inner change under the same handle.
`reserve` returns a `LeafAttempt`; carry it unchanged through every delivery
and response for that device.

## Required rules

| Rule | API | Failure if omitted |
|---|---|---|
| Use one fixed reviewed profile | `PROFILE.md` or `ED25519.md`, conformance vectors | The result may fall outside the proof |
| Validate initial public data and each local share | `ValidatedPublicGenesis`, `attach_share` | A device may sign under a false key map |
| Reduce an authorized set to its first threshold-sized subset | `outer_support`, `inner_support` | The transcript would use a support outside the proof |
| Derive coefficients from the chosen support | `InnerSupport`, `OuterSupport` | A coordinator may change the signing equation |
| Pass the exact active outer support to each leaf | `reserve`, `reserve_taproot` | The leaf cannot authenticate both support tiers |
| Supply the current time in the reservation's clock domain | `reserve`, `reserve_taproot`, `close_expired` | An expired ceremony may create a nonce |
| Sample each member-record salt | `MemberOpening::sample` | A guessed salt may expose the private member body |
| Reserve before creating a nonce | `PersistentLeaf::reserve`, then `commit` | A nonce may bind to incomplete state |
| Persist one increasing attempt counter and one live attempt per device | `PersistentLeaf`, `LeafStore` | A restart may permit a second response |
| Keep nonce state volatile and one-use | `Nonce`, `PersistentLeaf` | Reuse may reveal a signing share |
| Authenticate sender and receiver attempts, session, reservation, and message kind | `AuthenticatedCommitment`, `AuthenticatedOpening`, `AuthenticatedAbort` | A delivery may move between attempts or views |
| Fix each receiver's commitment vector before its reveal | `reveal` | A sender may choose after seeing an honest opening |
| Pass the exact root bytes at response time | `respond` | A response may move to another transcript |
| Treat local close as local | `receive_abort`, `close` | The protocol would assume agreement it does not have |
| Close every affected old live slot after activation | `activate_inner`, `activate_outer` | Old and new epochs may overlap on one device |
| Run every inner component through one target shape and phase schedule | `InnerBundle` | A later block may adapt after an earlier opening |
| Refresh one identity block with every active vault member block | `activate_inner_bundle` | Vaults may install different identity states |
| Compare command bytes with locally derived parameters | `Command::verify_bytes` | A peer may choose another source row or target shape |
| Post each local opening through `open_contribution` | `Candidate`, `InnerBundle` | A stale candidate may release an opening or private shares |
| Keep every rejected dealing prefix | `LogAct` | The exposure audit would erase leaked rows |
| Reject a stale predecessor on each fresh post and phase close | `LogAct::post`, `close_phase` | A losing candidate may release more data |
| Use one predecessor compare-and-set for each activation | `LogAct::activate`, `activate_bundle` | Two successors may both install |
| Assign each activated transcript or canonical bundle a permanent injective handle | `LogAct::activate`, `activate_bundle` | Distinct histories may share one anchor |
| Record source exposure and corrupt-recipient rows | `ExposureLedger` | A deployment may leave the theorem's corruption bound |
| Pool each person's identity revelations across vaults | Application ledger | Cross-vault exposure may leave the theorem's bound |

## Taproot

Build `taproot::Key` from the stable vault key and the exact optional
script-tree root. Store its output key with the wallet. A device must pass that
stored key to `PersistentLeaf::reserve_taproot`; do not copy it from the incoming
reservation.

Use the 32-byte BIP-341 signature hash as the root-package message. Wrap member
reservations in `taproot::Reservation` and the finalized root in
`taproot::Package`. Pass the canonical package bytes to
`PersistentLeaf::respond_taproot`. Aggregate devices with
`taproot::SigningContext::aggregate_member`, then aggregate members with
`aggregate_signature`. Both calls verify every partial and require the exact
support.

The persistent path does not use `taproot::hazmat`. That module is only for an
implementation that replaces the complete leaf machine and proves the same
attempt-counter, lock, nonce, and closure rules itself.

The application owns transaction construction, sighash computation, script
execution, and the optional sighash-type byte. [`TAPROOT.md`](TAPROOT.md) fixes
the adapter bytes and equations.

Use one `PersistentLeaf` per physical device. Build its initial `LeafRegistry`
with `from_vaults`; this merges a person's vault states under one identity share
and one live lock. `activate_inner` is the single-vault form; use
`activate_inner_bundle` once the registry has more than one vault.

`LeafStore` has separate calls for immutable secret material and the device
journal. An adapter may put material in a syncable keychain or encrypted backup.
The journal must use one linearizable, non-replicated authority for the device.
Nonces stay in memory and never enter either record. `PersistentLeaf::load`
closes an attempt left live by a stopped process. After `PersistError::Store`
or `PersistError::Conflict`, call `reconcile` before any other transition.
[`STORAGE.md`](STORAGE.md) gives the full contract.

`LogAct` is also a boundary. `MemoryLog` gives deterministic tests, ordered
phases, retained prefixes, and compare-and-set activation. Replace it with an
application ledger that supplies the same semantics. Each fresh post and phase
close must atomically confirm the command's predecessor. Reconcile an
ambiguous backend result inside that adapter before returning from a `LogAct`
method. Retain the exact canonical transcript behind every activation handle.
Equal handles must mean equal bytes, including bundle membership and contents. A
counter or digest may index this map, but is not the map.

## Ed25519 and WebAuthn

Use `ed25519::VaultKey::to_bytes` for the 32-byte credential public key and
`ed25519::Signature::to_bytes` for the 64-byte Ed25519 signature. Pass the
exact assertion bytes, `authenticatorData || SHA256(clientDataJSON)`, as the
root-package message. Do not prehash them again inside KSNF.

The application encodes the COSE key with `alg = -8` and `crv = 6`. It also
owns CBOR, credential IDs, relying-party metadata, user handles, counters,
presence and authorization policy, and initial provisioning. KSNF never
reconstructs the credential secret.

The profile uses fresh random threshold nonces. Never derive them from an
Ed25519 seed, and never use the KSNF vault key with a separate Ed25519 signer.
See [`ED25519.md`](ED25519.md) for the normative profile and proof boundary.

## Errors

Match `Error` variants in Rust. Use `Error::code()` at a language or process
boundary. Codes are stable and contain no secret data.

Persistent operations return `PersistError<E>`, where `E` is the store's own
error. This keeps database or keychain detail intact. A store error may report
an unknown write outcome; the leaf blocks further use until reconciliation.

An exact reservation replay returns its live attempt. Later exact calls return
the cached value for that attempt. An altered replay closes it. Another session
gets `busy` without disturbing it. A closed attempt stays closed; retrying the
ceremony allocates a new attempt. `SessionId` names the ceremony;
`LeafAttempt` is its device-local one-use slot.

`reserve` authenticates the selected inner and outer supports against the
leaf's active public polynomials before it allocates an attempt. It also
rejects `expiry <= now`. The application supplies `now`; the crate does not
read a clock.

## Vectors

Run:

```sh
cargo test --test vector_conformance
cargo test --no-default-features --features ed25519 --test vector_conformance_ed25519
cargo test --features taproot --test vector_conformance_tr
```

Each vector publishes its fixture secrets under `test_only_secret`. They exist
to reproduce bytes, not to seed live keys or nonces.
