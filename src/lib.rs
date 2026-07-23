//! Plain-Schnorr primitives for Key-Stable Nested FROST.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod algebra;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod shamir;

pub use error::{Error, Result};
