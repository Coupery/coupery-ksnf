#![allow(missing_docs)]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::dealing::{
    Command, Contribution, InnerBundle, InstalledShare, PendingShare, RoleSpec, SingleShape,
    TargetAccumulator, TargetDevice, TargetId, TargetShape,
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
    let (mut bundle, pending) = prepare_inner_bundle(
        &[
            (&identity_command, &identity_contributions),
            (&member_command, &member_contributions),
        ],
        &mut log,
    )?;
    let mut pending = pending.into_iter();
    let identity_pending = pending.next().ok_or(Error::EmptyInput)?;
    let member_pending = pending.next().ok_or(Error::EmptyInput)?;
    let terminal = bundle.activate(&mut log)?;
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
    assert_eq!(leaf.epoch(vault)?, new_epoch);
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
#[allow(clippy::too_many_lines)]
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
    let mismatched = Command::new(
        scope_2,
        CommandId::new([0x75; 32]),
        predecessor_2,
        Point::from_scalar(Scalar::from(31_u64))?,
        TargetShape::Single(SingleShape::new(
            2,
            vec![
                TargetDevice::new(source, Node::from_u64(1)?),
                TargetDevice::new(target, Node::from_u64(3)?),
            ],
        )?),
        roles(&support, source, target, 31)?,
    )?;
    assert!(matches!(
        InnerBundle::new(
            vec![command_1.clone(), mismatched],
            &mut MemoryLog::default(),
        ),
        Err(Error::SupportMismatch)
    ));
    let mut log = MemoryLog::default();
    log.install_genesis(scope_1, predecessor_1)?;
    log.install_genesis(scope_2, predecessor_2)?;
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let contributions_1 = contributions(&command_1, source, target, 31, &mut rng)?;
    let contributions_2 = contributions(&command_2, source, target, 31, &mut rng)?;
    let mut bundle = InnerBundle::new(vec![command_1.clone(), command_2.clone()], &mut log)?;
    for (command, contributions) in [
        (&command_1, &contributions_1),
        (&command_2, &contributions_2),
    ] {
        for contribution in contributions {
            bundle.commit(
                command.id(),
                contribution.role(),
                contribution.commitment(),
                &mut log,
            )?;
        }
    }
    bundle.close_commitments(&mut log)?;
    for (command, contributions) in [
        (&command_1, &contributions_1),
        (&command_2, &contributions_2),
    ] {
        for contribution in contributions {
            bundle.open(command.id(), contribution.opening(), &mut log)?;
        }
    }
    let views = bundle.close_openings(&mut log)?;
    let view = views
        .into_iter()
        .find_map(|(command, view)| (command == command_1.id()).then_some(view))
        .ok_or(Error::ParticipantNotFound)?;
    for target in command_1.shape().targets() {
        let mut accumulator = TargetAccumulator::new(view.clone(), target)?;
        for contribution in &contributions_1 {
            accumulator.receive(contribution.share(&command_1, target)?)?;
        }
        let (receipt, _) = accumulator.finish()?.into_parts();
        bundle.receipt(receipt, &mut log)?;
    }
    assert_eq!(bundle.activate(&mut log), Err(Error::SupportMismatch));
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

#[test]
#[allow(clippy::too_many_lines)]
fn multi_vault_registry_shares_one_lock_and_inner_epoch() -> Result<()> {
    let vault_1 = VaultId::new([0x14; 32]);
    let vault_2 = VaultId::new([0x15; 32]);
    let person = PersonId::new([0x24; 32]);
    let device_1 = DeviceId::new([0x34; 32]);
    let device_2 = DeviceId::new([0x35; 32]);
    let identity_handle = ActivationHandle::new([0x44; 32]);
    let member_handle_1 = ActivationHandle::new([0x45; 32]);
    let member_handle_2 = ActivationHandle::new([0x46; 32]);
    let epoch_1 = KeyEpoch::new(
        OuterEpoch::new(3),
        InnerEpoch::new(5),
        AnchorId::new(vault_1, person, identity_handle, member_handle_1),
    );
    let epoch_2 = KeyEpoch::new(
        OuterEpoch::new(7),
        InnerEpoch::new(5),
        AnchorId::new(vault_2, person, identity_handle, member_handle_2),
    );
    let genesis_1 = one_device_genesis(vault_1, person, device_1, 31, 101)?;
    let genesis_2 = one_device_genesis(vault_2, person, device_1, 31, 151)?;
    let outer_1 = genesis_1.outer_support(&[person])?;
    let outer_2 = genesis_2.outer_support(&[person])?;
    let old_inner_1 = genesis_1.inner_support(person, &[device_1])?;
    let old_inner_2 = genesis_2.inner_support(person, &[device_1])?;
    let other_vault = VaultId::new([0x16; 32]);
    let other_epoch = KeyEpoch::new(
        OuterEpoch::new(9),
        epoch_1.inner(),
        AnchorId::new(
            other_vault,
            person,
            identity_handle,
            ActivationHandle::new([0x47; 32]),
        ),
    );
    let other_genesis = two_device_genesis(other_vault, person, device_1, device_2, 31, 201)?;
    let duplicate_state = genesis_1.attach_share(
        person,
        device_1,
        SecretScalar::new(Scalar::from(31_u64)),
        SecretScalar::new(Scalar::from(101_u64)),
    )?;
    let other_state = other_genesis.attach_share(
        person,
        device_1,
        SecretScalar::new(Scalar::from(31_u64)),
        SecretScalar::new(Scalar::from(201_u64)),
    )?;
    assert!(matches!(
        LeafRegistry::from_vaults(vec![(duplicate_state, epoch_1), (other_state, other_epoch),]),
        Err(Error::EpochMismatch)
    ));
    let state_1 = genesis_1.attach_share(
        person,
        device_1,
        SecretScalar::new(Scalar::from(31_u64)),
        SecretScalar::new(Scalar::from(101_u64)),
    )?;
    let state_2 = genesis_2.attach_share(
        person,
        device_1,
        SecretScalar::new(Scalar::from(31_u64)),
        SecretScalar::new(Scalar::from(151_u64)),
    )?;
    let mut leaf = LeafRegistry::from_vaults(vec![(state_2, epoch_2), (state_1, epoch_1)])?;
    assert_eq!(leaf.vaults().collect::<Vec<_>>(), vec![vault_1, vault_2]);

    let session_1 = SessionId::new([0x54; 32]);
    let session_2 = SessionId::new([0x55; 32]);
    let reservation_1 = reservation_bytes(
        &genesis_1,
        &outer_1,
        old_inner_1.clone(),
        epoch_1,
        session_1,
        1,
    )?;
    let reservation_2 = reservation_bytes(
        &genesis_2,
        &outer_2,
        old_inner_2.clone(),
        epoch_2,
        session_2,
        2,
    )?;
    leaf.reserve(session_1, &reservation_1, &outer_1)?;
    assert_eq!(
        leaf.reserve(session_2, &reservation_2, &outer_2),
        Err(Error::Busy)
    );
    leaf.close(session_1)?;
    leaf.reserve(session_2, &reservation_2, &outer_2)?;
    leaf.close(session_2)?;

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
    let identity_scope = ScopeId::new([0x64; 32]);
    let member_scope_1 = ScopeId::new([0x65; 32]);
    let member_scope_2 = ScopeId::new([0x66; 32]);
    let identity_command = Command::new(
        identity_scope,
        CommandId::new([0x74; 32]),
        identity_handle,
        Point::from_scalar(Scalar::from(31_u64))?,
        target_shape.clone(),
        roles(&identity_source, device_1, device_2, 31)?,
    )?;
    let member_command_1 = Command::new(
        member_scope_1,
        CommandId::new([0x75; 32]),
        member_handle_1,
        Point::from_scalar(Scalar::from(101_u64))?,
        target_shape.clone(),
        roles(&old_inner_1, device_1, device_2, 101)?,
    )?;
    let member_command_2 = Command::new(
        member_scope_2,
        CommandId::new([0x76; 32]),
        member_handle_2,
        Point::from_scalar(Scalar::from(151_u64))?,
        target_shape,
        roles(&old_inner_2, device_1, device_2, 151)?,
    )?;
    let mut log = MemoryLog::default();
    log.install_genesis(identity_scope, identity_handle)?;
    log.install_genesis(member_scope_1, member_handle_1)?;
    log.install_genesis(member_scope_2, member_handle_2)?;
    let mut rng = ChaCha20Rng::from_seed([8; 32]);
    let identity_contributions =
        contributions(&identity_command, device_1, device_2, 31, &mut rng)?;
    let member_contributions_1 =
        contributions(&member_command_1, device_1, device_2, 101, &mut rng)?;
    let member_contributions_2 =
        contributions(&member_command_2, device_1, device_2, 151, &mut rng)?;
    let (mut bundle, pending) = prepare_inner_bundle(
        &[
            (&identity_command, &identity_contributions),
            (&member_command_1, &member_contributions_1),
            (&member_command_2, &member_contributions_2),
        ],
        &mut log,
    )?;
    let mut pending = pending.into_iter();
    let identity_pending = pending.next().ok_or(Error::EmptyInput)?;
    let member_pending_1 = pending.next().ok_or(Error::EmptyInput)?;
    let member_pending_2 = pending.next().ok_or(Error::EmptyInput)?;
    let terminal = bundle.activate(&mut log)?;
    let Terminal::Activated(handle) = terminal else {
        return Err(Error::InvalidTranscript);
    };
    let mut identity_installed = resolve(identity_pending, terminal)?;
    let mut member_installed_1 = resolve(member_pending_1, terminal)?;
    let mut member_installed_2 = resolve(member_pending_2, terminal)?;
    let next_inner_1 = installed_support(&member_installed_1, device_1, device_2)?;
    let next_inner_2 = installed_support(&member_installed_2, device_1, device_2)?;
    let identity = take(&mut identity_installed, TargetId::Single(device_1))?;
    let member_1 = take(&mut member_installed_1, TargetId::Single(device_1))?;
    let member_2 = take(&mut member_installed_2, TargetId::Single(device_1))?;
    let next_epoch_1 = KeyEpoch::new(
        epoch_1.outer(),
        InnerEpoch::new(6),
        AnchorId::new(vault_1, person, handle, handle),
    );
    let next_epoch_2 = KeyEpoch::new(
        epoch_2.outer(),
        InnerEpoch::new(6),
        AnchorId::new(vault_2, person, handle, handle),
    );
    leaf.activate_inner_bundle(
        identity,
        vec![(next_epoch_2, member_2), (next_epoch_1, member_1)],
    )?;
    assert_eq!(leaf.epoch(vault_1)?, next_epoch_1);
    assert_eq!(leaf.epoch(vault_2)?, next_epoch_2);

    let next_session = SessionId::new([0x56; 32]);
    let next_reservation = reservation_bytes(
        &genesis_1,
        &outer_1,
        next_inner_1,
        next_epoch_1,
        next_session,
        3,
    )?;
    leaf.reserve(next_session, &next_reservation, &outer_1)?;
    leaf.close(next_session)?;
    let next_session = SessionId::new([0x57; 32]);
    let next_reservation = reservation_bytes(
        &genesis_2,
        &outer_2,
        next_inner_2,
        next_epoch_2,
        next_session,
        4,
    )?;
    leaf.reserve(next_session, &next_reservation, &outer_2)?;
    Ok(())
}

fn prepare_inner_bundle(
    components: &[(&Command, &[Contribution])],
    log: &mut MemoryLog,
) -> Result<(InnerBundle, Vec<Vec<PendingShare>>)> {
    let mut bundle = InnerBundle::new(
        components
            .iter()
            .map(|(command, _)| (*command).clone())
            .collect(),
        log,
    )?;
    for (command, contributions) in components {
        for contribution in *contributions {
            bundle.commit(
                command.id(),
                contribution.role(),
                contribution.commitment(),
                log,
            )?;
        }
    }
    bundle.close_commitments(log)?;
    for (command, contributions) in components {
        for contribution in *contributions {
            bundle.open(command.id(), contribution.opening(), log)?;
        }
    }
    let views = bundle.close_openings(log)?;
    let mut all_pending = Vec::with_capacity(components.len());
    for (command, contributions) in components {
        let view = views
            .iter()
            .find_map(|(id, view)| (*id == command.id()).then_some(view))
            .ok_or(Error::ParticipantNotFound)?;
        let mut pending = Vec::new();
        for target in command.shape().targets() {
            let mut accumulator = TargetAccumulator::new(view.clone(), target)?;
            for contribution in *contributions {
                accumulator.receive(contribution.share(command, target)?)?;
            }
            let (receipt, share) = accumulator.finish()?.into_parts();
            bundle.receipt(receipt, log)?;
            pending.push(share);
        }
        all_pending.push(pending);
    }
    Ok((bundle, all_pending))
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

fn installed_support(
    shares: &[InstalledShare],
    device_1: DeviceId,
    device_2: DeviceId,
) -> Result<InnerSupport> {
    InnerSupport::new(vec![
        installed_participant(shares, device_1, 1)?,
        installed_participant(shares, device_2, 2)?,
    ])
}

fn installed_participant(
    shares: &[InstalledShare],
    device: DeviceId,
    node: u64,
) -> Result<DeviceParticipant> {
    let share = shares
        .iter()
        .find(|share| share.target() == TargetId::Single(device))
        .ok_or(Error::ParticipantNotFound)?;
    Ok(DeviceParticipant::new(
        device,
        Node::from_u64(node)?,
        SharePoint::new(share.public()),
    ))
}

fn one_device_genesis(
    vault: VaultId,
    person: PersonId,
    device: DeviceId,
    identity: u64,
    member: u64,
) -> Result<ValidatedPublicGenesis> {
    let person = PublicPerson::new(
        person,
        Node::from_u64(1)?,
        constant_polynomial(identity)?,
        constant_polynomial(member)?,
        vec![PublicDevice::new(
            device,
            Node::from_u64(1)?,
            share_point(identity)?,
            share_point(member)?,
        )],
    )?;
    ValidatedPublicGenesis::from_parts(vault, constant_polynomial(member)?, vec![person])
}

fn two_device_genesis(
    vault: VaultId,
    person: PersonId,
    device_1: DeviceId,
    device_2: DeviceId,
    identity: u64,
    member: u64,
) -> Result<ValidatedPublicGenesis> {
    let identity = Scalar::from(identity);
    let member = Scalar::from(member);
    let identity_polynomial =
        PublicPolynomial::new(vec![Element::from_scalar(identity), Element::IDENTITY])?;
    let member_polynomial =
        PublicPolynomial::new(vec![Element::from_scalar(member), Element::IDENTITY])?;
    let person = PublicPerson::new(
        person,
        Node::from_u64(1)?,
        identity_polynomial,
        member_polynomial,
        vec![
            PublicDevice::new(
                device_1,
                Node::from_u64(1)?,
                SharePoint::new(Element::from_scalar(identity)),
                SharePoint::new(Element::from_scalar(member)),
            ),
            PublicDevice::new(
                device_2,
                Node::from_u64(2)?,
                SharePoint::new(Element::from_scalar(identity)),
                SharePoint::new(Element::from_scalar(member)),
            ),
        ],
    )?;
    ValidatedPublicGenesis::from_parts(
        vault,
        PublicPolynomial::new(vec![Element::from_scalar(member)])?,
        vec![person],
    )
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
