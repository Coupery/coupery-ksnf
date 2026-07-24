//! Taproot key-path signing for the plain KSNF core.
//!
//! A [`Key`] fixes the internal key, script-tree root, and output key.
//! [`Reservation`] and [`Package`] bind it to canonical session bytes. The device,
//! member, and outer aggregators verify every partial before returning a
//! BIP-340 [`Signature`].
//!
//! The response equation is the public affine transform
//! `r·(d + ρe) + c·γ·b·(a·x + t)`. The Shamir coefficients reconstruct the
//! secret and sum to one, so the tweak enters once. This module implements that
//! transform; the crate's plain-Schnorr theorem does not prove it.

mod key;
mod package;
mod sign;
mod state;

pub mod hazmat;

pub use key::{Key, Sighash, XOnlyKey};
pub use package::{Package, Reservation};
pub use sign::{DeviceResponse, MemberResponse, Signature, SigningContext};
