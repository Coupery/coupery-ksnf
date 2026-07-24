#![forbid(unsafe_code)]
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
macro_rules! profile_api {
    ($profile:ty) => {
        /// The identifier bound into root signing packages.
        pub const PROFILE_ID: &[u8] = <$profile as crate::profile::Profile>::PROTOCOL_ID;
        /// The leading byte on structured protocol objects.
        pub const WIRE_ID: u8 = <$profile as crate::profile::Profile>::WIRE_ID;
        /// The profile marker used by generic protocol APIs.
        pub type Profile = $profile;
        /// A scalar in this profile.
        pub type Scalar = crate::algebra::ScalarFor<$profile>;
        /// A group element, including the identity.
        pub type Element = crate::algebra::Element<$profile>;
        /// A nonidentity prime-order point.
        pub type Point = crate::algebra::Point<$profile>;
        /// A secret scalar cleared on drop.
        pub type SecretScalar = crate::algebra::SecretScalar<$profile>;
        /// Validated public setup data.
        pub type ValidatedPublicGenesis = crate::genesis::ValidatedPublicGenesis<$profile>;
        /// One device's validated setup data.
        pub type DeviceGenesis = crate::genesis::DeviceGenesis<$profile>;
        /// A stable person identity key.
        pub type IdentityKey = crate::keys::IdentityKey<$profile>;
        /// A person's vault-local member point.
        pub type MemberPoint = crate::keys::MemberPoint<$profile>;
        /// A public device share.
        pub type SharePoint = crate::keys::SharePoint<$profile>;
        /// A stable vault key.
        pub type VaultKey = crate::keys::VaultKey<$profile>;
        /// An in-memory leaf state machine.
        pub type LeafRegistry = crate::leaf::LeafRegistry<$profile>;
        /// A leaf backed by caller-owned storage.
        pub type PersistentLeaf = crate::leaf::PersistentLeaf<$profile>;
        /// An in-memory store for tests and examples.
        pub type MemoryLeafStore = crate::leaf::MemoryLeafStore<$profile>;
        /// One device response.
        pub type DeviceResponse = crate::signing::DeviceResponse<$profile>;
        /// One member response.
        pub type MemberResponse = crate::signing::MemberResponse<$profile>;
        /// A final signature.
        pub type Signature = crate::signing::Signature<$profile>;
        /// Hashes derived from one root package.
        pub type SigningContext<'a> = crate::transcript::SigningContext<'a, $profile>;
        /// A verified redistribution candidate.
        pub type Candidate = crate::dealing::Candidate<$profile>;
        /// One atomic inner-redistribution bundle.
        pub type InnerBundle = crate::dealing::InnerBundle<$profile>;
    };
}

#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
pub mod algebra;
#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
pub mod auth;
#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
pub mod dealing;
#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
mod encoding;
pub mod error;
pub mod exposure;
#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
pub mod genesis;
#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
mod hash;
#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
pub mod keys;
#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
pub mod leaf;
pub mod log_act;
pub mod profile;
#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
pub mod shamir;
#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
pub mod signing;
#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
pub mod support;
#[cfg(feature = "taproot")]
pub mod taproot;
#[cfg(any(feature = "secp256k1", feature = "ed25519"))]
pub mod transcript;
pub mod types;

/// Plain Schnorr over secp256k1.
#[cfg(feature = "secp256k1")]
pub mod secp256k1 {
    profile_api!(crate::profile::Secp256k1);
}

/// RFC 8032-compatible Ed25519 signatures.
#[cfg(feature = "ed25519")]
pub mod ed25519 {
    profile_api!(crate::profile::Ed25519);
}

pub use error::{Error, Result};
pub use exposure::{ExposureLedger, ExposureViolation, MemberBlockSpec, TargetGroup};
pub use log_act::LogAct;
