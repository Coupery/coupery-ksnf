# Changelog

## 0.1.0 - 2026-07-24

Initial release.

### Added

- Depth-two Key-Stable Nested FROST signing and redistribution.
- Fixed secp256k1 and Ed25519 profiles with compile-time namespaced APIs.
- Ordinary RFC 8032 Ed25519 public keys and signatures for passkeys and other
  applications.
- A secp256k1 Taproot key-path adapter.
- Genesis import and validation without a DKG claim.
- A device-global leaf state machine with caller-owned durable storage.
- Pre-nonce expiry, signing-mode, and two-tier support authentication.
- An activation-log boundary with exact handle and bundle replay semantics.
- Predecessor-safe opening release and private share delivery.
- Exposure-ledger checks for the paper's joint corruption rule.
- Immutable plain, Ed25519, and Taproot vectors with independent final-signature
  verification.
- Runnable nested signing, concurrent redistribution, WebAuthn, and Taproot
  examples.
- MSRV, feature-matrix, Clippy, rustdoc, package, vector, and public-API gates.
