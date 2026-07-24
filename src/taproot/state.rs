use crate::leaf::{LeafRegistry, ResponseBinding, ResponseInputs, ResponseMode};
use crate::support::OuterSupport;
use crate::transcript::MemberTranscript;
use crate::types::{LeafAttempt, SessionId};
use crate::{Error, Result};

use super::package::reservation_key;
use super::{DeviceResponse, Package, Reservation, XOnlyKey};

impl LeafRegistry {
    /// Reserves a Taproot session under the locally expected output key.
    ///
    /// `now` must use the same clock domain as the encoded expiry.
    ///
    /// # Errors
    ///
    /// Returns an error for a busy device, altered replay, expired or invalid
    /// reservation, untrusted support, or unexpected output key.
    pub fn reserve_taproot(
        &mut self,
        session: SessionId,
        now: u64,
        bytes: &[u8],
        expected: XOnlyKey,
        outer: &OuterSupport,
    ) -> Result<LeafAttempt> {
        self.reserve_with(
            session,
            now,
            bytes,
            ResponseBinding::taproot(expected.to_bytes()),
            outer,
            || {
                let (reservation, parsed_session, expiry) = Reservation::from_bytes(bytes, outer)?;
                if reservation.key().output_key() != expected {
                    return Err(Error::OutputKeyMismatch);
                }
                Ok((reservation.into_member(), parsed_session, expiry))
            },
        )
    }

    /// Emits one Taproot device response and closes the attempt.
    ///
    /// # Errors
    ///
    /// Returns an error for a changed profile, invalid package, nonce set, or
    /// stage. Every same-attempt return closes the attempt.
    pub fn respond_taproot(
        &mut self,
        attempt: LeafAttempt,
        package_bytes: &[u8],
    ) -> Result<DeviceResponse> {
        self.respond_with(
            attempt,
            ResponseMode::Taproot,
            |input, reservation_bytes| {
                let reserved = reserved_key(reservation_bytes, &input)?;
                let package = Package::from_bytes(package_bytes)?;
                if package.key() != reserved {
                    return Err(Error::InvalidTranscript);
                }
                let transcript =
                    MemberTranscript::finalize(package.root().clone(), input.reservation)?;
                package.signing()?.respond_device(
                    input.nonce,
                    &transcript,
                    &input.nonces,
                    input.device,
                    &input.share,
                )
            },
        )
    }
}

fn reserved_key(bytes: &[u8], input: &ResponseInputs) -> Result<super::Key> {
    reservation_key(bytes, &input.reservation, input.session, input.expiry)
}
