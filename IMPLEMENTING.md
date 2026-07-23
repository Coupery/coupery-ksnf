# Implementing with coupery-ksnf

The crate supplies protocol math and state transitions. The application owns
transport, storage, authorization, and the activation ledger.

## Data flow

```text
validated vault states + local shares
                  │
                  ▼
       DeviceGenesis[] ──► LeafRegistry ──► device response

Command ──► Candidate ──► PendingShare ──► terminal activation
Commands ──► InnerBundle ────────────────► one terminal activation
                                                  │
                                                  ▼
                                           InstalledShare
```

Install a share only after its exact candidate receives an activated terminal
handle. Install both blocks from an inner change under the same handle.

## Required rules

| Rule | API | Failure if omitted |
|---|---|---|
| Use the v1 plain-Schnorr profile | `algebra`, `hash`, `signing` | The result may fall outside the proof |
| Validate initial public data and each local share | `ValidatedPublicGenesis`, `attach_share` | A device may sign under a false key map |
| Reduce an authorized set to its first threshold-sized subset | `outer_support`, `inner_support` | The transcript would use a support outside the proof |
| Derive coefficients from the chosen support | `InnerSupport`, `OuterSupport` | A coordinator may change the signing equation |
| Sample each member-record salt | `MemberOpening::sample` | A guessed salt may expose the private member body |
| Reserve before creating a nonce | `LeafRegistry::reserve`, then `commit` | A nonce may bind to incomplete state |
| Persist one live slot and all tombstones per device | `LeafRegistry` | A restart may permit a second response |
| Keep nonce state volatile and one-use | `Nonce`, `LeafRegistry` | Reuse may reveal a signing share |
| Authenticate sender, receiver, session, reservation, and message kind | `AuthenticatedCommitment`, `AuthenticatedOpening`, `AuthenticatedAbort` | A delivery may move between views |
| Fix each receiver's commitment vector before its reveal | `reveal` | A sender may choose after seeing an honest opening |
| Pass the exact root bytes at response time | `respond` | A response may move to another transcript |
| Treat local close as local | `receive_abort`, `close` | The protocol would assume agreement it does not have |
| Close every affected old live slot after activation | `activate_inner`, `activate_outer` | Old and new epochs may overlap on one device |
| Run every inner component through one target shape and phase schedule | `InnerBundle` | A later block may adapt after an earlier opening |
| Refresh one identity block with every active vault member block | `activate_inner_bundle` | Vaults may install different identity states |
| Compare command bytes with locally derived parameters | `Command::verify_bytes` | A peer may choose another source row or target shape |
| Keep every rejected dealing prefix | `LogAct` | The exposure audit would erase leaked rows |
| Use one predecessor compare-and-set for each activation | `LogAct::activate`, `activate_bundle` | Two successors may both install |
| Record source exposure and corrupt-recipient rows | `ExposureLedger` | A deployment may leave the theorem's corruption bound |
| Pool each person's identity revelations across vaults | Application ledger | Cross-vault exposure may leave the theorem's bound |

Use one `LeafRegistry` per physical device. `from_vaults` merges a person's
vault states under one identity share and one live lock. `activate_inner` is
the single-vault form; use `activate_inner_bundle` once the registry has more
than one vault.

`LeafRegistry` is process memory in this release. A production store must make
the live lock, nonce destruction, response publication, and tombstone one
crash-safe transition. The crate does not supply that store.

`LogAct` is also a boundary. `MemoryLog` gives deterministic tests, ordered
phases, retained prefixes, and compare-and-set activation. Replace it with an
application ledger that supplies the same semantics.

## Errors

Match `Error` variants in Rust. Use `Error::code()` at a language or process
boundary. Codes are stable and contain no secret data.

An exact replay returns the cached result while its slot remains live. An
altered replay closes that slot. A new session gets `busy` without disturbing
the current one. A tombstoned session stays closed.

## Vectors

Run:

```sh
cargo test --test vector_conformance
```

Each vector publishes its fixture secrets under `test_only_secret`. They exist
to reproduce bytes, not to seed live keys or nonces.
