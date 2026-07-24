//! Raw response generation for custom leaf machines.
//!
//! [`crate::leaf::LeafRegistry`] and [`crate::leaf::PersistentLeaf`] enforce
//! the device-wide lock, attempt counter, transcript fixation, and durable
//! closure. Code in this module does not.
//!
//! # Security
//!
//! Product code should use [`crate::leaf::PersistentLeaf`]. A replacement must
//! enforce the same lock, counter, nonce, replay, and closure rules.

use crate::Result;
use crate::algebra::SecretScalar;
use crate::profile::Profile;
use crate::transcript::{MemberTranscript, SigningContext};
use crate::types::DeviceId;

use super::{DeviceNonceSet, DeviceResponse, Nonce};

/// Consumes one nonce and returns a device response.
///
/// The caller must implement the complete leaf state machine before publishing
/// the result.
///
/// # Errors
///
/// Returns an error when the transcript, nonce set, share, or nonce differs
/// from its public value.
pub fn respond_device<P: Profile>(
    nonce: Nonce<P>,
    transcript: &MemberTranscript<P>,
    signing: &SigningContext<'_, P>,
    nonces: &DeviceNonceSet<P>,
    device: DeviceId,
    share: &SecretScalar<P>,
) -> Result<DeviceResponse<P>> {
    super::respond_device(nonce, transcript, signing, nonces, device, share)
}
