#![allow(missing_docs)]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::dealing::{
    Candidate, Command, Contribution, InstalledShare, PendingShare, RoleSpec, SingleShape,
    TargetAccumulator, TargetDevice, TargetId, TargetShape, activate_bundle,
};
use coupery_ksnf::genesis::{PublicDevice, PublicPerson, PublicPolynomial, ValidatedPublicGenesis};
use coupery_ksnf::keys::{AnchorId, KeyEpoch, SharePoint};
use coupery_ksnf::leaf::{LeafRegistry, LeafStage};
use coupery_ksnf::log_act::{MemoryLog, Terminal};
use coupery_ksnf::shamir::Node;
use coupery_ksnf::support::{DeviceParticipant, InnerSupport};
use coupery_ksnf::transcript::{
    MemberBody, MemberOpening, MemberRecord, MemberReservation, RootContext, RootPrepackage,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, OuterEpoch, PersonId, ScopeId, SessionId,
    VaultId,
};
use coupery_ksnf::{Error, Result};

#[test]
#[allow(clippy::too_many_lines)]
fn bundled_inner_activation_closes_old_leaf_state() -> Result<()> {
    let vault = VaultId::new([0x11; 32]);
    let person = PersonId::new([0x21; 32]);
    let device_1 = DeviceId::new([0x31; 32]);
    let device_2 = DeviceId::new([0x32; 32]);
    let identity_handle = ActivationHandle::new([0x41; 32]);
    let member_handle = ActivationHandle::new([0x42; 32]);
    let epoch = KeyEpoch::new(
        OuterEpoch::new(5),
        InnerEpoch::new(7),
        AnchorId::new(vault, person, identity_handle, member_handle),
    );
    let public_person = PublicPerson::new(
        person,
        Node::from_u64(1)?,
        constant_polynomial(31)?,
        constant_polynomial(101)?,
        vec![PublicDevice::new(
            device_1,
            Node::from_u64(1)?,
            share_point(31)?,
            share_point(101)?,
        )],
    )?;
    let genesis =
        ValidatedPublicGenesis::from_parts(vault, constant_polynomial(101)?, vec![public_person])?;
    let outer = genesis.outer_support(&[person])?;
    let old_inner = genesis.inner_support(person, &[device_1])?;
    let device_state = genesis.attach_share(
        person,
        device_1,
        SecretScalar::new(Scalar::from(31_u64)),
        SecretScalar::new(Scalar::from(101_u64)),
    )?;
    let mut leaf = LeafRegistry::new(device_state, epoch)?;
    let old_session = SessionId::new([0x51; 32]);
    let old_reservation =
        reservation_bytes(&genesis, &outer, old_inner.clone(), epoch, old_session, 1)?;
    leaf.reserve(old_session, &old_reservation, &outer)?;
    leaf.commit(
        old_session,
        &old_reservation,
        &mut ChaCha20Rng::from_seed([1; 32]),
    )?;
    assert_eq!(leaf.stage(), Some(LeafStage::Committed));

    let target_shape = TargetShape::Single(SingleShape::new(
        2,
        vec![
            TargetDevice::new(device_1, Node::from_u64(1)?),
            TargetDevice::new(device_2, Node::from_u64(2)?),
        ],
    )?);
    let identity_source = InnerSupport::new(vec![DeviceParticipant::new(
        device_1,
        Node::from_u64(1)?,
        share_point(31)?,
    )])?;
    let identity_roles = roles(&identity_source, device_1, device_2, 31)?;
    let member_roles = roles(&old_inner, device_1, device_2, 101)?;
    let identity_scope = ScopeId::new([0x61; 32]);
    let member_scope = ScopeId::new([0x62; 32]);
    let identity_command = Command::new(
        identity_scope,
        CommandId::new([0x71; 32]),
        identity_handle,
        Point::from_scalar(Scalar::from(31_u64))?,
        target_shape.clone(),
        identity_roles,
    )?;
    let member_command = Command::new(
        member_scope,
        CommandId::new([0x72; 32]),
        member_handle,
        Point::from_scalar(Scalar::from(101_u64))?,
        target_shape,
        member_roles,
    )?;
    let mut log = MemoryLog::default();
    log.install_genesis(identity_scope, identity_handle)?;
    log.install_genesis(member_scope, member_handle)?;
    let mut rng = ChaCha20Rng::from_seed([2; 32]);
    let identity_contributions =
        contributions(&identity_command, device_1, device_2, 31, &mut rng)?;
    let member_contributions = contributions(&member_command, device_1, device_2, 101, &mut rng)?;
    let (mut identity_candidate, identity_pending) =
        prepare(&identity_command, &identity_contributions, &mut log)?;
    let (mut member_candidate, member_pending) =
        prepare(&member_command, &member_contributions, &mut log)?;
    let terminal = activate_bundle(
        &mut [&mut identity_candidate, &mut member_candidate],
        &mut log,
    )?;
    let Terminal::Activated(handle) = terminal else {
        return Err(Error::InvalidTranscript);
    };
    let mut identity_installed = resolve(identity_pending, terminal)?;
    let mut member_installed = resolve(member_pending, terminal)?;
    let identity_1 = take(&mut identity_installed, TargetId::Single(device_1))?;
    let member_1_public = Point::try_from(
        member_installed
            .iter()
            .find(|share| share.target() == TargetId::Single(device_1))
            .ok_or(Error::ParticipantNotFound)?
            .public(),
    )?;
    let member_2_public = Point::try_from(
        member_installed
            .iter()
            .find(|share| share.target() == TargetId::Single(device_2))
            .ok_or(Error::ParticipantNotFound)?
            .public(),
    )?;
    let member_1 = take(&mut member_installed, TargetId::Single(device_1))?;
    let new_epoch = KeyEpoch::new(
        epoch.outer(),
        InnerEpoch::new(epoch.inner().get() + 1),
        AnchorId::new(vault, person, handle, handle),
    );
    leaf.activate_inner(new_epoch, identity_1, member_1)?;
    assert_eq!(leaf.epoch(), new_epoch);
    assert_eq!(leaf.stage(), None);
    assert!(leaf.is_tombstoned(old_session));

    let new_inner = InnerSupport::new(vec![
        DeviceParticipant::new(
            device_1,
            Node::from_u64(1)?,
            SharePoint::new(member_1_public),
        ),
        DeviceParticipant::new(
            device_2,
            Node::from_u64(2)?,
            SharePoint::new(member_2_public),
        ),
    ])?;
    let new_session = SessionId::new([0x52; 32]);
    let new_reservation =
        reservation_bytes(&genesis, &outer, new_inner, new_epoch, new_session, 2)?;
    leaf.reserve(new_session, &new_reservation, &outer)?;
    assert_eq!(leaf.stage(), Some(LeafStage::Reserved));
    assert_eq!(
        leaf.commit(
            old_session,
            &old_reservation,
            &mut ChaCha20Rng::from_seed([3; 32]),
        ),
        Err(Error::Tombstoned)
    );
    Ok(())
}

#[test]
fn bundle_failure_aborts_every_candidate() -> Result<()> {
    let source = DeviceId::new([0x33; 32]);
    let target = DeviceId::new([0x34; 32]);
    let support = InnerSupport::new(vec![DeviceParticipant::new(
        source,
        Node::from_u64(1)?,
        share_point(31)?,
    )])?;
    let shape = TargetShape::Single(SingleShape::new(
        2,
        vec![
            TargetDevice::new(source, Node::from_u64(1)?),
            TargetDevice::new(target, Node::from_u64(2)?),
        ],
    )?);
    let scope_1 = ScopeId::new([0x63; 32]);
    let scope_2 = ScopeId::new([0x64; 32]);
    let predecessor_1 = ActivationHandle::new([0x43; 32]);
    let predecessor_2 = ActivationHandle::new([0x44; 32]);
    let command_1 = Command::new(
        scope_1,
        CommandId::new([0x73; 32]),
        predecessor_1,
        Point::from_scalar(Scalar::from(31_u64))?,
        shape.clone(),
        roles(&support, source, target, 31)?,
    )?;
    let command_2 = Command::new(
        scope_2,
        CommandId::new([0x74; 32]),
        predecessor_2,
        Point::from_scalar(Scalar::from(31_u64))?,
        shape,
        roles(&support, source, target, 31)?,
    )?;
    let mut log = MemoryLog::default();
    log.install_genesis(scope_1, predecessor_1)?;
    log.install_genesis(scope_2, predecessor_2)?;
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let contributions_1 = contributions(&command_1, source, target, 31, &mut rng)?;
    let contributions_2 = contributions(&command_2, source, target, 31, &mut rng)?;
    let (mut ready, _) = prepare(&command_1, &contributions_1, &mut log)?;
    let mut incomplete = Candidate::new(command_2.clone(), &mut log)?;
    for contribution in &contributions_2 {
        incomplete.commit(contribution.role(), contribution.commitment(), &mut log)?;
    }
    incomplete.close_commitments(&mut log)?;
    for contribution in &contributions_2 {
        incomplete.open(contribution.opening(), &mut log)?;
    }
    incomplete.close_openings(&mut log)?;
    assert_eq!(
        activate_bundle(&mut [&mut ready, &mut incomplete], &mut log),
        Err(Error::SupportMismatch)
    );
    assert_eq!(
        log.transcript(command_1.id())
            .and_then(coupery_ksnf::log_act::LogTranscript::terminal),
        Some(Terminal::Aborted)
    );
    assert_eq!(
        log.transcript(command_2.id())
            .and_then(coupery_ksnf::log_act::LogTranscript::terminal),
        Some(Terminal::Aborted)
    );
    Ok(())
}

fn prepare(
    command: &Command,
    contributions: &[Contribution],
    log: &mut MemoryLog,
) -> Result<(Candidate, Vec<PendingShare>)> {
    let mut candidate = Candidate::new(command.clone(), log)?;
    for contribution in contributions {
        candidate.commit(contribution.role(), contribution.commitment(), log)?;
    }
    candidate.close_commitments(log)?;
    for contribution in contributions {
        candidate.open(contribution.opening(), log)?;
    }
    let view = candidate.close_openings(log)?;
    let mut pending = Vec::new();
    for target in command.shape().targets() {
        let mut accumulator = TargetAccumulator::new(view.clone(), target)?;
        for contribution in contributions {
            accumulator.receive(contribution.share(command, target)?)?;
        }
        let (receipt, share) = accumulator.finish()?.into_parts();
        candidate.receipt(receipt, log)?;
        pending.push(share);
    }
    Ok((candidate, pending))
}

fn contributions(
    command: &Command,
    device_1: DeviceId,
    device_2: DeviceId,
    source: u64,
    rng: &mut ChaCha20Rng,
) -> Result<Vec<Contribution>> {
    Ok(vec![
        Contribution::source(
            command,
            device_1,
            &SecretScalar::new(Scalar::from(source)),
            rng,
        )?,
        Contribution::refresher(command, device_1, rng)?,
        Contribution::refresher(command, device_2, rng)?,
    ])
}

fn roles(
    support: &InnerSupport,
    device_1: DeviceId,
    device_2: DeviceId,
    share: u64,
) -> Result<Vec<RoleSpec>> {
    Ok(vec![
        RoleSpec::source(
            device_1,
            share_point(share)?,
            support.source_weight(device_1)?,
        )?,
        RoleSpec::refresher(device_1),
        RoleSpec::refresher(device_2),
    ])
}

fn resolve(pending: Vec<PendingShare>, terminal: Terminal) -> Result<Vec<InstalledShare>> {
    pending
        .into_iter()
        .map(|share| share.resolve(terminal)?.ok_or(Error::AlreadyTerminal))
        .collect()
}

fn take(shares: &mut Vec<InstalledShare>, target: TargetId) -> Result<InstalledShare> {
    let index = shares
        .iter()
        .position(|share| share.target() == target)
        .ok_or(Error::ParticipantNotFound)?;
    Ok(shares.swap_remove(index))
}

fn reservation_bytes(
    genesis: &ValidatedPublicGenesis,
    outer: &coupery_ksnf::support::OuterSupport,
    inner: InnerSupport,
    epoch: KeyEpoch,
    session: SessionId,
    marker: u8,
) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    let person = epoch.anchor().person();
    let body = MemberBody::new(
        genesis.person(person)?.identity_key(),
        genesis.person(person)?.member_point(),
        epoch,
        inner,
        outer.coefficient(person)?,
    )?;
    let salt = SecretScalar::new(Scalar::from(u64::from(marker) + 40));
    let record = MemberRecord::commit(&body, &salt)?;
    let prepackage = RootPrepackage::new(
        genesis.vault_key(),
        b"activation overlap".to_vec(),
        RootContext::new(genesis.vault(), epoch.outer(), CommandId::new([marker; 32])),
        outer,
        vec![record],
    )?;
    MemberReservation::new(prepackage, MemberOpening::new(salt, body), outer)?
        .to_bytes(session, 100)
}

fn constant_polynomial(value: u64) -> Result<PublicPolynomial> {
    PublicPolynomial::new(vec![Element::from_scalar(Scalar::from(value))])
}

fn share_point(value: u64) -> Result<SharePoint> {
    Ok(SharePoint::new(Point::from_scalar(Scalar::from(value))?))
}
