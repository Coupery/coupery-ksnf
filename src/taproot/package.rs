use zeroize::Zeroizing;

use crate::encoding::{Decoder, Encoder};
use crate::keys::VaultKey;
use crate::support::OuterSupport;
use crate::transcript::{MemberReservation, RootPackage};
use crate::types::SessionId;
use crate::{Error, Result};

use super::{Key, Sighash};

const VERSION: u8 = 1;
const RESERVATION_KIND: u8 = 1;
const PACKAGE_KIND: u8 = 2;
const PROTOCOL_ID: &[u8] = b"coupery-ksnf/taproot/v1";

/// A private member reservation bound to one Taproot key.
pub struct Reservation {
    member: MemberReservation,
    key: Key,
}

impl Reservation {
    /// Binds a verified member reservation to a Taproot key.
    ///
    /// # Errors
    ///
    /// Returns an error when the reservation names another vault key or its
    /// message is not a 32-byte BIP-341 signature hash.
    pub fn new(member: MemberReservation, key: Key) -> Result<Self> {
        validate_profile(
            member.prepackage().key(),
            member.prepackage().message(),
            &key,
        )?;
        Ok(Self { member, key })
    }

    /// Decodes canonical reservation bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed bytes, a bad member reservation, or
    /// invalid key derivation.
    pub fn from_bytes(bytes: &[u8], outer: &OuterSupport) -> Result<(Self, SessionId, u64)> {
        let envelope = decode_envelope(bytes, RESERVATION_KIND)?;
        let (member, session, expiry) = MemberReservation::from_bytes(envelope.payload, outer)?;
        let key = Key::new(member.prepackage().key(), envelope.merkle_root)?;
        let reservation = Self::new(member, key)?;
        if reservation.to_bytes(session, expiry)?.as_slice() != bytes {
            return Err(Error::InvalidTranscript);
        }
        Ok((reservation, session, expiry))
    }

    /// Returns canonical private bytes in zeroizing memory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for an oversized member reservation.
    pub fn to_bytes(&self, session: SessionId, expiry: u64) -> Result<Zeroizing<Vec<u8>>> {
        let member = self.member.to_bytes(session, expiry)?;
        Ok(Zeroizing::new(encode_envelope(
            RESERVATION_KIND,
            &member,
            &self.key,
        )?))
    }

    /// Returns the bound Taproot key.
    #[must_use]
    pub const fn key(&self) -> Key {
        self.key
    }

    pub(super) fn into_member(self) -> MemberReservation {
        self.member
    }
}

/// A canonical public Taproot signing package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Package {
    pub(super) root: RootPackage,
    pub(super) key: Key,
}

impl Package {
    /// Binds a finalized root package to one Taproot key.
    ///
    /// # Errors
    ///
    /// Returns an error when the package names another vault key or its message
    /// is not a 32-byte BIP-341 signature hash.
    pub fn new(root: RootPackage, key: Key) -> Result<Self> {
        validate_profile(root.key(), root.message(), &key)?;
        Ok(Self { root, key })
    }

    /// Decodes canonical package bytes.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed bytes or invalid key derivation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let envelope = decode_envelope(bytes, PACKAGE_KIND)?;
        let root = RootPackage::from_bytes(envelope.payload)?;
        let key = Key::new(root.key(), envelope.merkle_root)?;
        let package = Self::new(root, key)?;
        if package.to_bytes()?.as_slice() != bytes {
            return Err(Error::InvalidTranscript);
        }
        Ok(package)
    }

    /// Returns the canonical package bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::LengthOverflow`] for an oversized root package.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        encode_envelope(PACKAGE_KIND, &self.root.to_bytes()?, &self.key)
    }

    /// Returns the plain root package.
    #[must_use]
    pub const fn root(&self) -> &RootPackage {
        &self.root
    }

    /// Returns the bound Taproot key.
    #[must_use]
    pub const fn key(&self) -> Key {
        self.key
    }

    /// Returns the BIP-341 signature hash.
    #[must_use]
    pub fn sighash(&self) -> Sighash {
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(self.root.message());
        Sighash::from(bytes)
    }

    /// Derives the signing hashes and aggregate nonce.
    ///
    /// # Errors
    ///
    /// Returns an error for an oversized package or identity nonce sum.
    pub fn signing(&self) -> Result<super::SigningContext<'_>> {
        super::SigningContext::new(self)
    }
}

pub(super) fn reservation_key(
    bytes: &[u8],
    member: &MemberReservation,
    session: SessionId,
    expiry: u64,
) -> Result<Key> {
    let envelope = decode_envelope(bytes, RESERVATION_KIND)?;
    let encoded = member.to_bytes(session, expiry)?;
    if envelope.payload != encoded.as_slice() {
        return Err(Error::InvalidTranscript);
    }
    let key = Key::new(member.prepackage().key(), envelope.merkle_root)?;
    validate_profile(
        member.prepackage().key(),
        member.prepackage().message(),
        &key,
    )?;
    Ok(key)
}

fn validate_profile(vault: VaultKey, message: &[u8], key: &Key) -> Result<()> {
    if vault.point().to_bytes() != key.vault {
        return Err(Error::InvalidTranscript);
    }
    if message.len() != 32 {
        return Err(Error::InvalidSighash);
    }
    Ok(())
}

struct Envelope<'a> {
    payload: &'a [u8],
    merkle_root: Option<[u8; 32]>,
}

fn encode_envelope(kind: u8, payload: &[u8], key: &Key) -> Result<Vec<u8>> {
    let mut encoder = Encoder::new();
    encoder.put_u8(VERSION);
    encoder.put_bytes(PROTOCOL_ID)?;
    encoder.put_u8(kind);
    encoder.put_bytes(payload)?;
    match key.merkle_root {
        None => encoder.put_u8(0),
        Some(root) => {
            encoder.put_u8(1);
            encoder.put_fixed(&root);
        }
    }
    Ok(encoder.finish())
}

fn decode_envelope(bytes: &[u8], expected_kind: u8) -> Result<Envelope<'_>> {
    let mut decoder = Decoder::new(bytes);
    if decoder.get_u8()? != VERSION {
        return Err(Error::UnsupportedVersion);
    }
    if decoder.get_bytes()? != PROTOCOL_ID || decoder.get_u8()? != expected_kind {
        return Err(Error::ProtocolMismatch);
    }
    let payload = decoder.get_bytes()?;
    let merkle_root = match decoder.get_u8()? {
        0 => None,
        1 => Some(decoder.get_fixed()?),
        _ => return Err(Error::InvalidTranscript),
    };
    decoder.finish()?;
    Ok(Envelope {
        payload,
        merkle_root,
    })
}
