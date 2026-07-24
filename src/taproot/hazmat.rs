//! Raw response generation for custom nonce stores.
//!
//! [`crate::leaf::LeafRegistry::respond_taproot`] is the in-memory safe path.
//! Code in this module does not enforce the device-global attempt counter or
//! lock. Product code should use [`crate::leaf::PersistentLeaf`].
//!
//! # Security
//!
//! A replacement leaf must enforce the same lock, counter, nonce, replay, and
//! closure rules before it publishes a response.

use crate::Result;
use crate::algebra::SecretScalar;
use crate::signing::{DeviceNonceSet, Nonce};
use crate::transcript::MemberTranscript;
use crate::types::DeviceId;

use super::{DeviceResponse, SigningContext};

/// Consumes one nonce and returns a Taproot device response.
///
/// The caller must fix the reservation and nonce set before nonce creation,
/// persist a monotonic attempt, permit one live attempt across the device, and
/// close that attempt durably before publishing the response.
///
/// # Errors
///
/// Returns an error when the transcript, support, nonce, or share differs from
/// its public value.
pub fn respond_device(
    signing: &SigningContext<'_>,
    nonce: Nonce,
    transcript: &MemberTranscript,
    nonces: &DeviceNonceSet,
    device: DeviceId,
    share: &SecretScalar,
) -> Result<DeviceResponse> {
    signing.respond_device(nonce, transcript, nonces, device, share)
}
