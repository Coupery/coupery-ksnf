#![allow(missing_docs)]

use k256::ProjectivePoint;

use coupery_ksnf::algebra::{Point, Scalar, SecretScalar};
use coupery_ksnf::keys::{AnchorId, IdentityKey, KeyEpoch, MemberPoint, SharePoint, VaultKey};
use coupery_ksnf::shamir::Node;
use coupery_ksnf::signing::{
    self, DeviceNonce, DeviceNonceSet, Nonce, aggregate_member, aggregate_signature, respond_device,
};
use coupery_ksnf::support::{DeviceParticipant, InnerSupport, OuterSupport, PersonParticipant};
use coupery_ksnf::transcript::{
    MemberBody, MemberOpening, MemberRecord, MemberTranscript, RootContext, RootEntry, RootPackage,
    SigningContext,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, OuterEpoch, PersonId, Slot, VaultId,
};
use coupery_ksnf::{Error, Result};

#[test]
#[allow(clippy::too_many_lines)]
fn depth_two_signature_hides_inner_state_and_verifies() -> Result<()> {
    let vault = VaultId::new([0x55; 32]);
    let outer_epoch = OuterEpoch::new(7);
    let person_1 = PersonId::new([0xa1; 32]);
    let person_2 = PersonId::new([0xa2; 32]);
    let device_11 = DeviceId::new([0x11; 32]);
    let device_12 = DeviceId::new([0x12; 32]);
    let device_21 = DeviceId::new([0x21; 32]);
    let device_22 = DeviceId::new([0x22; 32]);

    let vault_secret = Scalar::from(101_u64);
    let member_1_secret = Scalar::from(118_u64);
    let member_2_secret = Scalar::from(135_u64);
    let member_1 = MemberPoint::new(Point::from_scalar(member_1_secret)?);
    let member_2 = MemberPoint::new(Point::from_scalar(member_2_secret)?);
    let key = VaultKey::new(Point::from_scalar(vault_secret)?);
    let outer = OuterSupport::new(vec![
        PersonParticipant::new(person_2, Slot::new(2), Node::from_u64(2)?, member_2),
        PersonParticipant::new(person_1, Slot::new(1), Node::from_u64(1)?, member_1),
    ])?;

    let share_11 = Scalar::from(127_u64);
    let share_12 = Scalar::from(136_u64);
    let share_21 = Scalar::from(146_u64);
    let share_22 = Scalar::from(157_u64);
    let inner_1 = inner_support(device_11, share_11, device_12, share_12)?;
    let inner_2 = inner_support(device_21, share_21, device_22, share_22)?;

    let identity_1 = IdentityKey::new(Point::from_scalar(Scalar::from(31_u64))?);
    let identity_2 = IdentityKey::new(Point::from_scalar(Scalar::from(37_u64))?);
    let body_1 = MemberBody::new(
        identity_1,
        member_1,
        key_epoch(vault, person_1, outer_epoch, 3, 0x81, 0x91),
        inner_1.clone(),
        outer.coefficient(person_1)?,
    )?;
    let body_2 = MemberBody::new(
        identity_2,
        member_2,
        key_epoch(vault, person_2, outer_epoch, 4, 0x82, 0x92),
        inner_2.clone(),
        outer.coefficient(person_2)?,
    )?;

    let salt_1 = SecretScalar::new(Scalar::from(71_u64));
    let salt_2 = SecretScalar::new(Scalar::from(73_u64));
    let record_1 = MemberRecord::commit(&body_1, &salt_1)?;
    let record_2 = MemberRecord::commit(&body_2, &salt_2)?;

    let nonce_11 = Nonce::new(Scalar::from(5_u64), Scalar::from(7_u64))?;
    let nonce_12 = Nonce::new(Scalar::from(11_u64), Scalar::from(13_u64))?;
    let nonce_21 = Nonce::new(Scalar::from(17_u64), Scalar::from(19_u64))?;
    let nonce_22 = Nonce::new(Scalar::from(23_u64), Scalar::from(29_u64))?;
    let nonces_1 = DeviceNonceSet::new(
        &inner_1,
        vec![
            DeviceNonce::new(device_12, nonce_12.commitments()?),
            DeviceNonce::new(device_11, nonce_11.commitments()?),
        ],
    )?;
    let nonces_2 = DeviceNonceSet::new(
        &inner_2,
        vec![
            DeviceNonce::new(device_22, nonce_22.commitments()?),
            DeviceNonce::new(device_21, nonce_21.commitments()?),
        ],
    )?;

    let root = RootPackage::new(
        key,
        b"approve transfer 42".to_vec(),
        RootContext::new(vault, outer_epoch, CommandId::new([0x66; 32])),
        &outer,
        vec![
            RootEntry::new(record_2, nonces_2.aggregate()),
            RootEntry::new(record_1, nonces_1.aggregate()),
        ],
    )?;
    let root_bytes = root.to_bytes()?;
    assert_eq!(RootPackage::from_bytes(&root_bytes)?, root);
    assert!(!contains(&root_bytes, device_11.as_bytes()));
    assert!(!contains(&root_bytes, &identity_1.point().to_bytes()));

    let opening_1 = MemberOpening::new(salt_1, body_1);
    let opening_2 = MemberOpening::new(salt_2, body_2);
    let opening_1_bytes = opening_1.to_bytes()?;
    let opening_2_bytes = opening_2.to_bytes()?;
    let transcript_1 = MemberTranscript::new(
        root.clone(),
        MemberOpening::from_bytes(&opening_1_bytes, &outer)?,
        &outer,
    )?;
    let transcript_2 = MemberTranscript::new(
        root.clone(),
        MemberOpening::from_bytes(&opening_2_bytes, &outer)?,
        &outer,
    )?;
    let signing = SigningContext::new(&root)?;

    let response_11 = respond_device(
        nonce_11,
        &transcript_1,
        &signing,
        &nonces_1,
        device_11,
        &SecretScalar::new(share_11),
    )?;
    let response_12 = respond_device(
        nonce_12,
        &transcript_1,
        &signing,
        &nonces_1,
        device_12,
        &SecretScalar::new(share_12),
    )?;
    let response_21 = respond_device(
        nonce_21,
        &transcript_2,
        &signing,
        &nonces_2,
        device_21,
        &SecretScalar::new(share_21),
    )?;
    let response_22 = respond_device(
        nonce_22,
        &transcript_2,
        &signing,
        &nonces_2,
        device_22,
        &SecretScalar::new(share_22),
    )?;
    let member_response_1 = aggregate_member(
        &transcript_1,
        &signing,
        &nonces_1,
        &[response_12, response_11],
    )?;
    let member_response_2 = aggregate_member(
        &transcript_2,
        &signing,
        &nonces_2,
        &[response_22, response_21],
    )?;
    assert_eq!(
        signing::DeviceResponse::from_bytes(&response_11.to_bytes())?,
        response_11
    );
    assert_eq!(
        signing::MemberResponse::from_bytes(&member_response_1.to_bytes())?,
        member_response_1
    );
    let signature = aggregate_signature(&signing, &outer, &[member_response_2, member_response_1])?;

    signature.verify(key, root.message())?;
    assert_eq!(
        signing::Signature::from_bytes(&signature.to_bytes())?,
        signature
    );
    let left = ProjectivePoint::GENERATOR * signature.response();
    let right = *signature.nonce().as_projective()
        + *key.point().as_projective()
            * signing::challenge(signature.nonce(), key, root.message())?;
    assert_eq!(left, right);

    let mut altered_opening = opening_1_bytes;
    altered_opening[32] ^= 1;
    assert_eq!(
        MemberTranscript::new(
            root,
            MemberOpening::from_bytes(&altered_opening, &outer)?,
            &outer,
        )
        .err(),
        Some(Error::CommitmentMismatch)
    );
    Ok(())
}

fn inner_support(
    device_1: DeviceId,
    share_1: Scalar,
    device_2: DeviceId,
    share_2: Scalar,
) -> Result<InnerSupport> {
    InnerSupport::new(vec![
        DeviceParticipant::new(
            device_2,
            Node::from_u64(2)?,
            SharePoint::new(Point::from_scalar(share_2)?),
        ),
        DeviceParticipant::new(
            device_1,
            Node::from_u64(1)?,
            SharePoint::new(Point::from_scalar(share_1)?),
        ),
    ])
}

const fn key_epoch(
    vault: VaultId,
    person: PersonId,
    outer: OuterEpoch,
    inner: u64,
    identity_handle: u8,
    member_handle: u8,
) -> KeyEpoch {
    KeyEpoch::new(
        outer,
        InnerEpoch::new(inner),
        AnchorId::new(
            vault,
            person,
            ActivationHandle::new([identity_handle; 32]),
            ActivationHandle::new([member_handle; 32]),
        ),
    )
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
