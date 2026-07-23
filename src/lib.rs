//! Plain-Schnorr primitives for Key-Stable Nested FROST.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod algebra;
pub mod encoding;
pub mod error;
pub mod genesis;
pub mod hash;
pub mod keys;
pub mod shamir;
pub mod signing;
pub mod support;
pub mod transcript;
pub mod types;

pub use error::{Error, Result};
