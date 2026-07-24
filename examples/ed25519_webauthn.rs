//! Signs `WebAuthn` assertion bytes with a nested Ed25519 quorum.
//!
//! Fixture shares and nonces are public test values.

mod support;

use ed25519_dalek::{Signature as DalekSignature, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha256};

use coupery_ksnf::profile::Ed25519;
use coupery_ksnf::{Error, Result};

fn main() -> Result<()> {
    let authenticator_data = [0xa5; 37];
    let client_data_hash = Sha256::digest(
        br#"{"type":"webauthn.get","challenge":"c","origin":"https://coupery.com"}"#,
    );
    let mut message = Vec::with_capacity(authenticator_data.len() + client_data_hash.len());
    message.extend_from_slice(&authenticator_data);
    message.extend_from_slice(&client_data_hash);

    let credential = support::two_of_three::<Ed25519>(message)?;
    let signature = support::sign_plain(&credential)?;
    let public_key = credential.vault_key.to_bytes();
    let signature_bytes = signature.to_bytes();

    let verifier = VerifyingKey::from_bytes(&public_key).map_err(|_| Error::InvalidPoint)?;
    verifier
        .verify(
            &credential.message,
            &DalekSignature::from_bytes(&signature_bytes),
        )
        .map_err(|_| Error::InvalidSignature)?;

    assert_eq!(public_key.len(), 32);
    assert_eq!(signature_bytes.len(), 64);
    Ok(())
}
