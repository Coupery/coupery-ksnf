//! Depth-two signing tests.

#![cfg(feature = "secp256k1")]

use k256::ProjectivePoint;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use coupery_ksnf::algebra::{Element, Scalar, SecretScalar};
use coupery_ksnf::auth::{AuthenticatedCommitment, AuthenticatedOpening};
use coupery_ksnf::genesis::{PublicDevice, PublicPerson, PublicPolynomial, ValidatedPublicGenesis};
use coupery_ksnf::keys::{AnchorId, KeyEpoch, SharePoint};
use coupery_ksnf::leaf::LeafRegistry;
use coupery_ksnf::shamir::Node;
use coupery_ksnf::signing::{
    self, DeviceNonce, DeviceNonceSet, NoncePair, aggregate_member, aggregate_signature,
};
use coupery_ksnf::support::{InnerSupport, OuterSupport};
use coupery_ksnf::transcript::{
    MemberBody, MemberNonce, MemberOpening, MemberRecord, MemberReservation, MemberTranscript,
    RootContext, RootPackage, RootPrepackage, SigningContext,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, LeafAttempt, OuterEpoch, PersonId,
    SessionId, Slot, VaultId,
};
use coupery_ksnf::{Error, Result};

const NOW: u64 = 50;
const EXPIRY: u64 = 100;

#[test]
#[expect(clippy::too_many_lines, reason = "Keeps one protocol path together.")]
fn depth_two_signature_hides_inner_state_and_verifies() -> Result<()> {
    let vault = VaultId::new([0x55; 32]);
    let outer_epoch = OuterEpoch::new(7);
    let person_1 = PersonId::new([0xa1; 32]);
    let person_2 = PersonId::new([0xa2; 32]);
    let device_11 = DeviceId::new([0x11; 32]);
    let device_12 = DeviceId::new([0x12; 32]);
    let device_21 = DeviceId::new([0x21; 32]);
    let device_22 = DeviceId::new([0x22; 32]);

    let member_1_secret = Scalar::from(118_u64);
    let member_2_secret = Scalar::from(135_u64);
    let share_11 = Scalar::ZERO;
    let share_12 = -member_1_secret;
    let share_21 = Scalar::from(146_u64);
    let share_22 = Scalar::from(157_u64);
    let genesis = ValidatedPublicGenesis::validate(
        vault,
        polynomial(&[Scalar::from(101_u64), Scalar::from(17_u64)])?,
        vec![
            public_person(
                person_1,
                1,
                [Scalar::from(31_u64), Scalar::from(3_u64)],
                [member_1_secret, -member_1_secret],
                [
                    (device_11, 1, Scalar::from(34_u64), share_11),
                    (device_12, 2, Scalar::from(37_u64), share_12),
                ],
            )?,
            public_person(
                person_2,
                2,
                [Scalar::from(37_u64), Scalar::from(5_u64)],
                [member_2_secret, Scalar::from(11_u64)],
                [
                    (device_21, 1, Scalar::from(42_u64), share_21),
                    (device_22, 2, Scalar::from(47_u64), share_22),
                ],
            )?,
        ],
    )?;
    let key = genesis.vault_key();
    let outer = genesis.outer_support(&[person_2, person_1])?;
    let inner_1 = genesis.inner_support(person_1, &[device_12, device_11])?;
    let inner_2 = genesis.inner_support(person_2, &[device_22, device_21])?;
    let epoch_1 = key_epoch(vault, person_1, outer_epoch, 3, 0x81, 0x91);
    let epoch_2 = key_epoch(vault, person_2, outer_epoch, 4, 0x82, 0x92);

    let mut leaves_1 = [
        LeafRegistry::new(
            genesis.attach_share(
                person_1,
                device_11,
                SecretScalar::new(Scalar::from(34_u64)),
                SecretScalar::new(share_11),
            )?,
            epoch_1,
        )?,
        LeafRegistry::new(
            genesis.attach_share(
                person_1,
                device_12,
                SecretScalar::new(Scalar::from(37_u64)),
                SecretScalar::new(share_12),
            )?,
            epoch_1,
        )?,
    ];
    let mut leaves_2 = [
        LeafRegistry::new(
            genesis.attach_share(
                person_2,
                device_21,
                SecretScalar::new(Scalar::from(42_u64)),
                SecretScalar::new(share_21),
            )?,
            epoch_2,
        )?,
        LeafRegistry::new(
            genesis.attach_share(
                person_2,
                device_22,
                SecretScalar::new(Scalar::from(47_u64)),
                SecretScalar::new(share_22),
            )?,
            epoch_2,
        )?,
    ];

    let identity_1 = genesis.person(person_1)?.identity_key();
    let identity_2 = genesis.person(person_2)?.identity_key();
    let body_1 = MemberBody::new(
        identity_1,
        genesis.person(person_1)?.member_point(),
        epoch_1,
        inner_1.clone(),
        outer.coefficient(person_1)?,
    )?;
    let body_2 = MemberBody::new(
        identity_2,
        genesis.person(person_2)?.member_point(),
        epoch_2,
        inner_2.clone(),
        outer.coefficient(person_2)?,
    )?;

    let salt_1 = SecretScalar::new(Scalar::from(71_u64));
    let salt_2 = SecretScalar::new(Scalar::from(73_u64));
    let record_1 = MemberRecord::commit(&body_1, &salt_1)?;
    let record_2 = MemberRecord::commit(&body_2, &salt_2)?;
    let opening_1 = MemberOpening::new(salt_1, body_1);
    let opening_2 = MemberOpening::new(salt_2, body_2);
    let opening_1_bytes = opening_1.to_bytes()?;
    let prepackage = RootPrepackage::new(
        key,
        b"approve transfer 42".to_vec(),
        RootContext::new(vault, outer_epoch, CommandId::new([0x66; 32])),
        &outer,
        vec![record_2, record_1],
    )?;
    let session = SessionId::new([0x76; 32]);
    let reservation_1 = MemberReservation::new(prepackage.clone(), opening_1, &outer)?;
    let reservation_2 = MemberReservation::new(prepackage.clone(), opening_2, &outer)?;
    let reservation_1_bytes = reservation_1.to_bytes(session, EXPIRY)?;
    let reservation_2_bytes = reservation_2.to_bytes(session, EXPIRY)?;
    let prepared_1 = prepare_member(
        &mut leaves_1,
        session,
        &reservation_1_bytes,
        &inner_1,
        &outer,
        [[0x11; 32], [0x12; 32]],
    )?;
    let prepared_2 = prepare_member(
        &mut leaves_2,
        session,
        &reservation_2_bytes,
        &inner_2,
        &outer,
        [[0x21; 32], [0x22; 32]],
    )?;
    let root = RootPackage::finalize(
        prepackage,
        &outer,
        vec![
            MemberNonce::new(Slot::new(2), prepared_2.nonces.aggregate()),
            MemberNonce::new(Slot::new(1), prepared_1.nonces.aggregate()),
        ],
    )?;
    let root_bytes = root.to_bytes()?;
    assert_eq!(RootPackage::from_bytes(&root_bytes)?, root);
    assert!(!contains(&root_bytes, device_11.as_bytes()));
    assert!(!contains(&root_bytes, &identity_1.point().to_bytes()));

    let transcript_1 = MemberTranscript::finalize(root.clone(), reservation_1)?;
    let transcript_2 = MemberTranscript::finalize(root.clone(), reservation_2)?;
    let signing = SigningContext::new(&root)?;
    let response_11 = leaves_1[0].respond(prepared_1.attempts[0], &root_bytes)?;
    let response_12 = leaves_1[1].respond(prepared_1.attempts[1], &root_bytes)?;
    let response_21 = leaves_2[0].respond(prepared_2.attempts[0], &root_bytes)?;
    let response_22 = leaves_2[1].respond(prepared_2.attempts[1], &root_bytes)?;
    assert!(
        leaves_1[0].is_closed(prepared_1.attempts[0])
            && leaves_1[1].is_closed(prepared_1.attempts[1])
            && leaves_2[0].is_closed(prepared_2.attempts[0])
            && leaves_2[1].is_closed(prepared_2.attempts[1])
    );
    let member_response_1 = aggregate_member(
        &transcript_1,
        &signing,
        &prepared_1.nonces,
        &[response_12, response_11],
    )?;
    let member_response_2 = aggregate_member(
        &transcript_2,
        &signing,
        &prepared_2.nonces,
        &[response_22, response_21],
    )?;
    let wrong_attempt =
        signing::DeviceResponse::new(LeafAttempt::new(device_11, 1), response_11.scalar());
    assert_eq!(
        aggregate_member(
            &transcript_1,
            &signing,
            &prepared_1.nonces,
            &[response_12, wrong_attempt],
        ),
        Err(Error::AttemptMismatch)
    );
    let response_bytes: [u8; 73] = response_11.into();
    assert_eq!(
        signing::DeviceResponse::try_from(response_bytes.as_slice())?,
        response_11
    );
    let member_bytes: [u8; 35] = member_response_1.into();
    assert_eq!(
        signing::MemberResponse::try_from(member_bytes.as_slice())?,
        member_response_1
    );
    let signature = aggregate_signature(&signing, &outer, &[member_response_2, member_response_1])?;

    signature.verify(key, root.message())?;
    let signature_bytes: [u8; 65] = signature.into();
    assert_eq!(
        signing::Signature::try_from(signature_bytes.as_slice())?,
        signature
    );
    let left = ProjectivePoint::GENERATOR * signature.response();
    let right = *signature.nonce().as_raw()
        + *key.point().as_raw() * signing::challenge(signature.nonce(), key, root.message())?;
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

struct PreparedMember {
    attempts: [LeafAttempt; 2],
    nonces: DeviceNonceSet,
}

fn prepare_member(
    leaves: &mut [LeafRegistry; 2],
    session: SessionId,
    reservation: &[u8],
    inner: &InnerSupport,
    outer: &OuterSupport,
    seeds: [[u8; 32]; 2],
) -> Result<PreparedMember> {
    let attempts = [
        leaves[0].reserve(session, NOW, reservation, outer)?,
        leaves[1].reserve(session, NOW, reservation, outer)?,
    ];
    let commitments = [
        leaves[0].commit(
            attempts[0],
            reservation,
            &mut ChaCha20Rng::from_seed(seeds[0]),
        )?,
        leaves[1].commit(
            attempts[1],
            reservation,
            &mut ChaCha20Rng::from_seed(seeds[1]),
        )?,
    ];
    let pairs = [
        leaves[0].reveal(
            attempts[0],
            commitment_deliveries(attempts, attempts[0], session, reservation, commitments),
        )?,
        leaves[1].reveal(
            attempts[1],
            commitment_deliveries(attempts, attempts[1], session, reservation, commitments),
        )?,
    ];
    let aggregate_1 = leaves[0].fix(
        attempts[0],
        opening_deliveries(attempts, attempts[0], session, reservation, &pairs),
    )?;
    let aggregate_2 = leaves[1].fix(
        attempts[1],
        opening_deliveries(attempts, attempts[1], session, reservation, &pairs),
    )?;
    let nonces = DeviceNonceSet::new(
        inner,
        vec![
            DeviceNonce::new(attempts[1], pairs[1]),
            DeviceNonce::new(attempts[0], pairs[0]),
        ],
    )?;
    assert_eq!(aggregate_1, nonces.aggregate());
    assert_eq!(aggregate_2, nonces.aggregate());
    Ok(PreparedMember { attempts, nonces })
}

fn commitment_deliveries(
    attempts: [LeafAttempt; 2],
    receiver: LeafAttempt,
    session: SessionId,
    reservation: &[u8],
    commitments: [Scalar; 2],
) -> Vec<AuthenticatedCommitment> {
    attempts
        .into_iter()
        .zip(commitments)
        .map(|(sender, commitment)| {
            AuthenticatedCommitment::new(sender, receiver, session, reservation, commitment)
        })
        .collect()
}

fn opening_deliveries(
    attempts: [LeafAttempt; 2],
    receiver: LeafAttempt,
    session: SessionId,
    reservation: &[u8],
    pairs: &[NoncePair; 2],
) -> Vec<AuthenticatedOpening> {
    attempts
        .into_iter()
        .zip(pairs.iter().copied())
        .map(|(sender, pair)| {
            AuthenticatedOpening::new(sender, receiver, session, reservation, pair)
        })
        .collect()
}

fn public_person(
    person: PersonId,
    outer_node: u64,
    identity: [Scalar; 2],
    member: [Scalar; 2],
    devices: [(DeviceId, u64, Scalar, Scalar); 2],
) -> Result<PublicPerson> {
    PublicPerson::new(
        person,
        Node::from_u64(outer_node)?,
        polynomial(&identity)?,
        polynomial(&member)?,
        devices
            .into_iter()
            .map(|(device, node, identity_share, member_share)| {
                Ok(PublicDevice::new(
                    device,
                    Node::from_u64(node)?,
                    SharePoint::new(Element::from_scalar(identity_share)),
                    SharePoint::new(Element::from_scalar(member_share)),
                ))
            })
            .collect::<Result<Vec<_>>>()?,
    )
}

fn polynomial(coefficients: &[Scalar]) -> Result<PublicPolynomial> {
    PublicPolynomial::new(
        coefficients
            .iter()
            .copied()
            .map(Element::from_scalar)
            .collect(),
    )
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
