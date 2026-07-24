# Leaf storage

KSNF leaf state has four storage classes. Combining them into one serialized
signer makes crash safety harder and prevents an application from choosing the
right protection for each class.

| State | Contents | Required storage |
|---|---|---|
| Material | Identity share, vault anchors, public key maps, epochs | Secret, immutable, integrity checked |
| Journal | Active material, next attempt, one live attempt | One linearizable authority per device |
| Nonce | One live signing nonce and receiver-local views | Memory only |
| Public records | Genesis commitments, activation log, exposure ledger | Application owned |

Material and journal records carry a profile-specific header. Store
secp256k1 and Ed25519 records in separate namespaces; never infer a profile
from record length or reinterpret one profile's bytes as another's. Each
profile has distinct signing shares and its own journal authority.

Material may live in a syncable keychain or an encrypted recovery store. The
journal must not use eventual cloud sync. Replicas could each accept the same
old revision and release two responses. Syncing material also does not activate
a second signer. Recovery under the same `DeviceId` transfers the journal and
its authority. Recovery under a new `DeviceId` retires the old device and
reconfigures the sharing. Every party that can decrypt copied material counts
as holding that device share under the application's corruption policy.

`LeafMaterial` is plaintext key material. Its content hash detects a mismatched
record; it does not encrypt, authenticate, or prevent rollback. The adapter must
provide those properties or store the bytes in a keychain that does.

`LeafStore` exposes separate material and journal operations so one adapter can
route them to different systems. `PersistentLeaf` owns every state transition.
An adapter stores bytes and supplies compare-and-set; it never decides whether
a session may reserve, respond, close, or activate.

```rust,ignore
let registry = LeafRegistry::from_vaults(installed)?;
let mut leaf = PersistentLeaf::create(&mut store, registry)?;
let attempt = leaf.reserve(&mut store, session, now, reservation, outer_support)?;
let commitment = leaf.commit(&mut store, attempt, reservation, rng)?;
let pair = leaf.reveal(&mut store, attempt, commitments)?;
leaf.fix(&mut store, attempt, openings)?;
let response = leaf.respond(&mut store, attempt, root_package)?;
```

## Required store behavior

- Material records are immutable and addressed by their hash. Repeating the
  same write is harmless. A different value cannot replace the same hash.
- A journal write compares one device's exact revision and replaces the whole
  fixed-size record atomically. Success means the write is durable.
- Journal revisions and attempt counters never decrease or wrap.
- Old and failed-staging material is collected under a fixed retention limit.
  Archives sit outside the live signer store.
- One physical device has one journal authority across all vaults and process
  instances that share an identity in one profile.
- A store error may have an unknown outcome. The caller discards the leaf and
  reloads it instead of retrying a transition in place.
- Neither material nor journal storage contains a signing nonce.

If `create` returns a store error, call `load` before trying to create the same
device again. The first journal write may already be durable.

Material alone cannot restore a signer. If the journal is lost, do not create
the same `DeviceId` again. Retire it and add a new device through
reconfiguration.

On reserve, `PersistentLeaf` advances the counter and records the live attempt
before it returns. On response, it destroys the nonce and clears the live
attempt before releasing the response. Load closes an attempt left live by a
stopped process. Any earlier attempt stays closed because its sequence is below
the durable counter.

The journal has a fixed byte size. A repeated ceremony may allocate a new
attempt, but it cannot reopen an old one.

The caller supplies `now` from the same clock domain used to encode the
reservation expiry. Reserve rejects an expired ceremony before it records an
attempt or creates a nonce. `close_expired` closes a live attempt when time
advances.

Activation writes new immutable material first, then changes the journal's
active material hash. A stop before the journal change leaves the old state
active. A stop after it leaves the new state active. Unreferenced material is
safe to collect. `MemoryLeafStore` collects it on the journal write.

## Other boundaries

Genesis remains import plus validation. `ValidatedPublicGenesis::attach_share`
checks local shares against public commitments; the crate does not accept a DKG
driver trait. Authenticated confidential delivery remains application owned.
The crate checks typed, origin-bound messages after delivery. `LogAct` remains
the semantic activation-log boundary; an implementation must obtain its
ordering and terminal decision from the application's consensus system. It
must reject a stale predecessor on every fresh post, phase close, and
activation. It must reconcile uncertain backend writes before returning a
semantic result. Each activated canonical transcript or canonical bundle needs a
permanent, injective handle. Equal handles mean equal retained bytes. A bare
epoch, resettable counter, or digest without retained collision resolution is
not enough.
The signer need not load that history. A production log must set a quota and
fail closed, or stream sealed segments to application-owned storage. It must
not discard rejected prefixes. `ExposureLedger` is a bounded audit batch, not
a permanent signer database; export each result and drop the batch.

## Rejected designs

- Serializing `LeafRegistry`, including its signing nonce, makes replay after
  rollback possible.
- Giving applications a trait for `reserve` or `respond` moves proof-critical
  decisions out of the crate.
- Keeping one live lock per vault permits concurrent use of one device share.
- Tracking closed sessions in a set makes signer state grow with use.
- Treating a cloud-synced keychain as the journal permits divergent writers.
- Retrying after an ambiguous store error may repeat a completed transition.
- A `Dkg` or channel trait would imply protocol coverage the crate does not
  provide.

## Prior art

RFC 9591 requires FROST nonces to be stored between rounds, deleted after use,
and never reused, but leaves crash recovery to implementations. Zcash
Foundation's `frost` keeps setup and DKG separate and leaves nonce lifecycle to
the caller. Validating Lightning Signer places durable writes behind a
transactional persistence boundary. BDK's persisted wallet keeps state changes
inside a wrapper until its persister accepts them. ChillDKG uses opaque round
states and a separate final setup result instead of a general DKG backend.

Sources were checked at these revisions:

- [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html)
- [Zcash Foundation frost, `0966bd1`](https://github.com/ZcashFoundation/frost/tree/0966bd1529aa)
- [Validating Lightning Signer, `9bae33b`](https://gitlab.com/lightning-signer/validating-lightning-signer/-/tree/9bae33b26ec3)
- [BDK WalletPersister](https://docs.rs/bdk_wallet/latest/bdk_wallet/trait.WalletPersister.html)
- [Blockstream ChillDKG, `0091fec`](https://github.com/BlockstreamResearch/bip-frost-dkg/tree/0091fec4663f)
- [Apple synchronizable keychain items](https://developer.apple.com/documentation/security/ksecattrsynchronizable)
