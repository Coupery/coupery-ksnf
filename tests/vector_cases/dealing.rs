use coupery_ksnf::Result as KResult;
use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::dealing::{
    Candidate, CandidateView, Command, Contribution, ContributionPoints, InnerBundle,
    InstalledShare, Opening, OuterShape, OuterTarget, PendingShare, PrivateShare, RoleSpec,
    SingleShape, TargetAccumulator, TargetDevice, TargetId, TargetShape,
};
use coupery_ksnf::genesis::{PublicDevice, PublicPerson, PublicPolynomial, ValidatedPublicGenesis};
use coupery_ksnf::keys::{AnchorId, IdentityKey, KeyEpoch, MemberPoint, SharePoint, VaultKey};
use coupery_ksnf::leaf::{LeafRegistry, LeafStage};
use coupery_ksnf::log_act::{LogAct, MemoryLog, Terminal};
use coupery_ksnf::shamir::Node;
use coupery_ksnf::support::{DeviceParticipant, InnerSupport, OuterSupport, PersonParticipant};
use coupery_ksnf::transcript::{
    MemberBody, MemberOpening, MemberRecord, MemberReservation, RootContext, RootPrepackage,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, OuterEpoch, PersonId, ScopeId, SessionId,
    Slot, VaultId,
};
use coupery_ksnf::{Error, Result};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;
use serde_json::{Value, json};

use super::{VectorCase, hex, vector};

type AnyResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type PreparedComponent = (Vec<PendingShare>, CandidateView);

#[allow(clippy::too_many_lines)]
pub fn inner() -> AnyResult<VectorCase> {
    let vault = VaultId::new([0x51; 32]);
    let person = PersonId::new([0x61; 32]);
    let source = DeviceId::new([0x71; 32]);
    let target = DeviceId::new([0x72; 32]);
    let identity_predecessor = ActivationHandle::new([0x81; 32]);
    let member_predecessor = ActivationHandle::new([0x91; 32]);
    let identity_scope = ScopeId::new([0xa1; 32]);
    let member_scope = ScopeId::new([0xa2; 32]);
    let shape = single_shape(source, target)?;
    let identity_support = one_device_support(source, 31)?;
    let member_support = one_device_support(source, 101)?;
    let identity_roles = roles(&identity_support, source, target, 31)?;
    let member_roles = roles(&member_support, source, target, 101)?;
    let mut log = MemoryLog::default();
    log.install_genesis(identity_scope, identity_predecessor)?;
    log.install_genesis(member_scope, member_predecessor)?;
    let mut rng = ChaCha20Rng::from_seed([11; 32]);

    let rejected_command = command(
        identity_scope,
        0xb1,
        identity_predecessor,
        31,
        shape.clone(),
        identity_roles.clone(),
    )?;
    let rejected_contributions = contributions(&rejected_command, source, target, 31, &mut rng)?;
    let (mut rejected, _, rejected_view) =
        prepare(&rejected_command, &rejected_contributions, &mut log)?;
    assert_eq!(rejected.abort(&mut log)?, Terminal::Aborted);
    assert_eq!(log.current(identity_scope), Some(identity_predecessor));

    let identity_command = command(
        identity_scope,
        0xb2,
        identity_predecessor,
        31,
        shape.clone(),
        identity_roles,
    )?;
    let member_command = command(
        member_scope,
        0xb3,
        member_predecessor,
        101,
        shape,
        member_roles,
    )?;
    let identity_contributions = contributions(&identity_command, source, target, 31, &mut rng)?;
    let member_contributions = contributions(&member_command, source, target, 101, &mut rng)?;
    let (mut bundle, components) = prepare_inner_bundle(
        &[
            (&identity_command, &identity_contributions),
            (&member_command, &member_contributions),
        ],
        &mut log,
    )?;
    let mut components = components.into_iter();
    let (identity_pending, identity_view) = components.next().ok_or(Error::EmptyInput)?;
    let (member_pending, member_view) = components.next().ok_or(Error::EmptyInput)?;
    let terminal = bundle.activate(&mut log)?;
    let identity_installed = resolve(identity_pending, terminal)?;
    let member_installed = resolve(member_pending, terminal)?;
    let Terminal::Activated(handle) = terminal else {
        return Err(Error::InvalidTranscript.into());
    };
    assert_eq!(
        identity_view.aggregate().constant()?,
        Element::from_scalar(Scalar::from(31_u64))
    );
    assert_eq!(
        member_view.aggregate().constant()?,
        Element::from_scalar(Scalar::from(101_u64))
    );
    assert_eq!(log.current(identity_scope), Some(handle));
    assert_eq!(log.current(member_scope), Some(handle));

    Ok(vector(
        "inner-veto-retry-activate",
        json!({
            "case": "inner-veto-retry-activate",
            "format": "coupery-ksnf-v1",
            "keys": {
                "identity_after": point_hex(Point::from_scalar(Scalar::from(31_u64))?),
                "identity_before": point_hex(Point::from_scalar(Scalar::from(31_u64))?),
                "member_after": point_hex(Point::from_scalar(Scalar::from(101_u64))?),
                "member_before": point_hex(Point::from_scalar(Scalar::from(101_u64))?),
                "vault_after": point_hex(Point::from_scalar(Scalar::from(101_u64))?),
                "vault_before": point_hex(Point::from_scalar(Scalar::from(101_u64))?)
            },
            "rejected": {
                "candidate_view": hex(rejected_view.as_bytes()),
                "command": hex(rejected_command.to_bytes()?),
                "terminal": "aborted"
            },
            "retry": {
                "activation_handle": id_hex(handle.as_bytes()),
                "identity": candidate_json(&identity_command, &identity_view, &identity_installed)?,
                "member": candidate_json(&member_command, &member_view, &member_installed)?,
                "terminal": "activated"
            },
            "test_only_secret": {
                "rng_seed": hex([11_u8; 32]),
                "source_identity_share": scalar_hex(Scalar::from(31_u64)),
                "source_member_share": scalar_hex(Scalar::from(101_u64))
            },
            "vault_id": id_hex(vault.as_bytes()),
            "person_id": id_hex(person.as_bytes())
        }),
    ))
}

#[allow(clippy::too_many_lines)]
pub fn outer() -> AnyResult<VectorCase> {
    let vault = VaultId::new([0x52; 32]);
    let person_1 = PersonId::new([0x61; 32]);
    let person_2 = PersonId::new([0x62; 32]);
    let device_1 = DeviceId::new([0x71; 32]);
    let device_2 = DeviceId::new([0x72; 32]);
    let identity_handle = ActivationHandle::new([0x82; 32]);
    let member_predecessor = ActivationHandle::new([0x92; 32]);
    let mut old = old_leaf(
        vault,
        person_1,
        device_1,
        identity_handle,
        member_predecessor,
    )?;
    let old_session = SessionId::new([0xc1; 32]);
    let old_reservation = reservation(
        &old.genesis,
        &old.outer,
        old.inner.clone(),
        old.epoch,
        old_session,
        0xc2,
    )?;
    old.leaf
        .reserve(old_session, &old_reservation, &old.outer)?;
    old.leaf.commit(
        old_session,
        &old_reservation,
        &mut ChaCha20Rng::from_seed([12; 32]),
    )?;
    assert_eq!(old.leaf.stage(), Some(LeafStage::Committed));

    let shape = TargetShape::Outer(OuterShape::new(
        2,
        vec![
            OuterTarget::new(
                person_1,
                Node::from_u64(1)?,
                SingleShape::new(1, vec![TargetDevice::new(device_1, Node::from_u64(1)?)])?,
            ),
            OuterTarget::new(
                person_2,
                Node::from_u64(2)?,
                SingleShape::new(1, vec![TargetDevice::new(device_2, Node::from_u64(1)?)])?,
            ),
        ],
    )?);
    let roles = vec![
        RoleSpec::source(
            device_1,
            share_point(101),
            old.outer.source_weight(person_1, &old.inner, device_1)?,
        )?,
        RoleSpec::refresher(device_1),
        RoleSpec::refresher(device_2),
    ];
    let scope = ScopeId::new([0xa3; 32]);
    let command = command(scope, 0xb4, member_predecessor, 101, shape, roles)?;
    let mut log = MemoryLog::default();
    log.install_genesis(scope, member_predecessor)?;
    let mut rng = ChaCha20Rng::from_seed([13; 32]);
    let contributions = vec![
        Contribution::source(
            &command,
            device_1,
            &SecretScalar::new(Scalar::from(101_u64)),
            &mut rng,
        )?,
        Contribution::refresher(&command, device_1, &mut rng)?,
        Contribution::refresher(&command, device_2, &mut rng)?,
    ];
    let (mut candidate, pending, view) = prepare(&command, &contributions, &mut log)?;
    let terminal = candidate.activate(&mut log)?;
    let Terminal::Activated(handle) = terminal else {
        return Err(Error::InvalidTranscript.into());
    };
    let mut installed = resolve(pending, terminal)?;
    let new_member_1 = Point::try_from(view.aggregate().member_constant(person_1)?)?;
    let new_member_2 = Point::try_from(view.aggregate().member_constant(person_2)?)?;
    assert_ne!(
        new_member_1,
        old.genesis.person(person_1)?.member_point().point()
    );
    let public_1 = installed
        .iter()
        .find(|share| {
            share.target()
                == TargetId::Outer {
                    person: person_1,
                    device: device_1,
                }
        })
        .ok_or(Error::ParticipantNotFound)?
        .public();
    let public_2 = installed
        .iter()
        .find(|share| {
            share.target()
                == TargetId::Outer {
                    person: person_2,
                    device: device_2,
                }
        })
        .ok_or(Error::ParticipantNotFound)?
        .public();
    let installed_json = installed_values(&installed);
    let member_1_share = take(
        &mut installed,
        TargetId::Outer {
            person: person_1,
            device: device_1,
        },
    )?;
    let new_epoch = KeyEpoch::new(
        OuterEpoch::new(old.epoch.outer().get() + 1),
        old.epoch.inner(),
        AnchorId::new(vault, person_1, identity_handle, handle),
    );
    old.leaf.activate_outer(new_epoch, member_1_share)?;
    assert!(old.leaf.is_tombstoned(old_session));

    let new_outer = OuterSupport::new(vec![
        PersonParticipant::new(
            person_1,
            Slot::new(1),
            Node::from_u64(1)?,
            MemberPoint::new(new_member_1),
        ),
        PersonParticipant::new(
            person_2,
            Slot::new(2),
            Node::from_u64(2)?,
            MemberPoint::new(new_member_2),
        ),
    ])?;
    let inner_1 = InnerSupport::new(vec![DeviceParticipant::new(
        device_1,
        Node::from_u64(1)?,
        SharePoint::new(public_1),
    )])?;
    let inner_2 = InnerSupport::new(vec![DeviceParticipant::new(
        device_2,
        Node::from_u64(1)?,
        SharePoint::new(public_2),
    )])?;
    let body_1 = MemberBody::new(
        old.genesis.person(person_1)?.identity_key(),
        MemberPoint::new(new_member_1),
        new_epoch,
        inner_1,
        new_outer.coefficient(person_1)?,
    )?;
    let body_2 = MemberBody::new(
        IdentityKey::new(Point::from_scalar(Scalar::from(37_u64))?),
        MemberPoint::new(new_member_2),
        KeyEpoch::new(
            new_epoch.outer(),
            InnerEpoch::new(1),
            AnchorId::new(vault, person_2, ActivationHandle::new([0x83; 32]), handle),
        ),
        inner_2,
        new_outer.coefficient(person_2)?,
    )?;
    let salt_1 = SecretScalar::new(Scalar::from(71_u64));
    let salt_2 = SecretScalar::new(Scalar::from(73_u64));
    let record_1 = MemberRecord::commit(&body_1, &salt_1)?;
    let record_2 = MemberRecord::commit(&body_2, &salt_2)?;
    let prepackage = RootPrepackage::new(
        VaultKey::new(Point::from_scalar(Scalar::from(101_u64))?),
        b"new outer epoch".to_vec(),
        RootContext::new(vault, new_epoch.outer(), CommandId::new([0xc3; 32])),
        &new_outer,
        vec![record_2, record_1],
    )?;
    let new_session = SessionId::new([0xc4; 32]);
    let new_reservation = MemberReservation::new(
        prepackage.clone(),
        MemberOpening::new(salt_1, body_1),
        &new_outer,
    )?
    .to_bytes(new_session, 200)?;
    old.leaf
        .reserve(new_session, &new_reservation, &new_outer)?;
    assert_eq!(old.leaf.stage(), Some(LeafStage::Reserved));

    Ok(vector(
        "outer-reshare",
        json!({
            "activation_handle": id_hex(handle.as_bytes()),
            "candidate_view": hex(view.as_bytes()),
            "case": "outer-reshare",
            "command": hex(command.to_bytes()?),
            "format": "coupery-ksnf-v1",
            "installed": installed_json,
            "keys": {
                "identity_after": point_hex(old.genesis.person(person_1)?.identity_key().point()),
                "identity_before": point_hex(old.genesis.person(person_1)?.identity_key().point()),
                "member_after": point_hex(new_member_1),
                "member_before": point_hex(old.genesis.person(person_1)?.member_point().point()),
                "vault_after": point_hex(old.genesis.vault_key().point()),
                "vault_before": point_hex(old.genesis.vault_key().point())
            },
            "new_root_prepackage": hex(prepackage.to_bytes()?),
            "new_session_reservation": hex(new_reservation.as_slice()),
            "old_live_session_tombstoned": old.leaf.is_tombstoned(old_session),
            "test_only_secret": {
                "candidate_rng_seed": hex([13_u8; 32]),
                "old_commit_rng_seed": hex([12_u8; 32]),
                "old_member_share": scalar_hex(Scalar::from(101_u64))
            }
        }),
    ))
}

#[allow(clippy::too_many_lines)]
pub fn invalid() -> AnyResult<VectorCase> {
    let source = DeviceId::new([0x74; 32]);
    let target = DeviceId::new([0x75; 32]);
    let scope = ScopeId::new([0xa4; 32]);
    let predecessor = ActivationHandle::new([0x94; 32]);
    let shape = TargetShape::Single(SingleShape::new(
        1,
        vec![TargetDevice::new(target, Node::from_u64(1)?)],
    )?);
    let support = one_device_support(source, 35)?;
    let roles = vec![
        RoleSpec::source(source, share_point(35), support.source_weight(source)?)?,
        RoleSpec::refresher(target),
    ];
    let mut rng = ChaCha20Rng::from_seed([14; 32]);

    let altered_command = command(scope, 0xb5, predecessor, 35, shape.clone(), roles.clone())?;
    let altered_contributions =
        one_target_contributions(&altered_command, source, target, 35, &mut rng)?;
    let mut altered_log = MemoryLog::default();
    altered_log.install_genesis(scope, predecessor)?;
    let mut altered = Candidate::new(altered_command.clone(), &mut altered_log)?;
    for contribution in &altered_contributions {
        altered.commit(
            contribution.role(),
            contribution.commitment(),
            &mut altered_log,
        )?;
    }
    altered.close_commitments(&mut altered_log)?;
    let opening = altered_contributions[0].opening();
    let altered_opening = Opening::new(
        opening.role(),
        opening.points().clone(),
        opening.salt() + Scalar::ONE,
    );
    let altered_opening_bytes = altered_opening.to_bytes()?;
    let altered_error = expect_error(&altered.open(altered_opening, &mut altered_log))?;
    altered.close_commitments(&mut altered_log)?;

    let wrong_constant = expect_error(
        &ContributionPoints::Single(vec![Element::from_scalar(Scalar::from(36_u64))])
            .validate(&shape, Element::from_scalar(Scalar::from(35_u64))),
    )?;
    let wrong_degree = expect_error(
        &ContributionPoints::Single(vec![
            Element::from_scalar(Scalar::from(35_u64)),
            Element::GENERATOR,
        ])
        .validate(&shape, Element::from_scalar(Scalar::from(35_u64))),
    )?;
    let linked_person = PersonId::new([0x64; 32]);
    let linked_shape = TargetShape::Outer(OuterShape::new(
        1,
        vec![OuterTarget::new(
            linked_person,
            Node::from_u64(1)?,
            SingleShape::new(1, vec![TargetDevice::new(target, Node::from_u64(1)?)])?,
        )],
    )?);
    let wrong_linkage = expect_error(
        &ContributionPoints::Outer {
            outer: vec![Element::from_scalar(Scalar::from(35_u64))],
            members: vec![(
                linked_person,
                vec![Element::from_scalar(Scalar::from(36_u64))],
            )],
        }
        .validate(&linked_shape, Element::from_scalar(Scalar::from(35_u64))),
    )?;

    let missing_command = command(scope, 0xb6, predecessor, 35, shape.clone(), roles.clone())?;
    let missing_contributions =
        one_target_contributions(&missing_command, source, target, 35, &mut rng)?;
    let mut missing_log = MemoryLog::default();
    missing_log.install_genesis(scope, predecessor)?;
    let mut missing = Candidate::new(missing_command.clone(), &mut missing_log)?;
    for contribution in &missing_contributions {
        missing.commit(
            contribution.role(),
            contribution.commitment(),
            &mut missing_log,
        )?;
    }
    missing.close_commitments(&mut missing_log)?;
    for contribution in &missing_contributions {
        missing.open(contribution.opening(), &mut missing_log)?;
    }
    let missing_view = missing.close_openings(&mut missing_log)?;
    let mut accumulator = TargetAccumulator::new(missing_view, TargetId::Single(target))?;
    let private_error = expect_error(&accumulator.receive(PrivateShare::new(
        missing_command.id(),
        missing_contributions[0].role(),
        TargetId::Single(target),
        SecretScalar::new(Scalar::from(36_u64)),
    )))?;
    let missing_receipt = expect_error(&missing.activate(&mut missing_log))?;

    let veto_command = command(scope, 0xb7, predecessor, 35, shape.clone(), roles.clone())?;
    let veto_contributions = one_target_contributions(&veto_command, source, target, 35, &mut rng)?;
    let mut veto_log = MemoryLog::default();
    veto_log.install_genesis(scope, predecessor)?;
    let (mut veto, _, veto_view) = prepare(&veto_command, &veto_contributions, &mut veto_log)?;
    assert_eq!(veto.abort(&mut veto_log)?, Terminal::Aborted);

    let mut stale_log = MemoryLog::default();
    stale_log.install_genesis(scope, predecessor)?;
    let active_command = command(scope, 0xb8, predecessor, 35, shape.clone(), roles.clone())?;
    let active_contributions =
        one_target_contributions(&active_command, source, target, 35, &mut rng)?;
    let (mut active, _, _) = prepare(&active_command, &active_contributions, &mut stale_log)?;
    active.activate(&mut stale_log)?;
    let stale_command = command(scope, 0xb9, predecessor, 35, shape, roles)?;
    let stale = expect_error(&Candidate::new(stale_command.clone(), &mut stale_log))?;

    Ok(vector(
        "dealing-invalid",
        json!({
            "case": "dealing-invalid",
            "checks": [
                {"input": hex(altered_opening_bytes), "name": "altered opening", "result": altered_error},
                {"name": "wrong anchored constant", "result": wrong_constant},
                {"name": "wrong degree", "result": wrong_degree},
                {"name": "wrong outer linkage", "result": wrong_linkage},
                {"name": "invalid private evaluation", "result": private_error},
                {"name": "missing receipt", "result": missing_receipt},
                {"input": hex(stale_command.to_bytes()?), "name": "stale predecessor", "result": stale},
                {"candidate_view": hex(veto_view.as_bytes()), "name": "post-open veto", "result": "aborted"}
            ],
            "format": "coupery-ksnf-v1",
            "test_only_secret": {"rng_seed": hex([14_u8; 32])}
        }),
    ))
}

struct OldLeaf {
    genesis: ValidatedPublicGenesis,
    outer: OuterSupport,
    inner: InnerSupport,
    epoch: KeyEpoch,
    leaf: LeafRegistry,
}

fn old_leaf(
    vault: VaultId,
    person: PersonId,
    device: DeviceId,
    identity_handle: ActivationHandle,
    member_handle: ActivationHandle,
) -> KResult<OldLeaf> {
    let public_person = PublicPerson::new(
        person,
        Node::from_u64(1)?,
        constant_polynomial(31)?,
        constant_polynomial(101)?,
        vec![PublicDevice::new(
            device,
            Node::from_u64(1)?,
            share_point(31),
            share_point(101),
        )],
    )?;
    let genesis =
        ValidatedPublicGenesis::from_parts(vault, constant_polynomial(101)?, vec![public_person])?;
    let outer = genesis.outer_support(&[person])?;
    let inner = genesis.inner_support(person, &[device])?;
    let epoch = KeyEpoch::new(
        OuterEpoch::new(5),
        InnerEpoch::new(7),
        AnchorId::new(vault, person, identity_handle, member_handle),
    );
    let state = genesis.attach_share(
        person,
        device,
        SecretScalar::new(Scalar::from(31_u64)),
        SecretScalar::new(Scalar::from(101_u64)),
    )?;
    Ok(OldLeaf {
        genesis,
        outer,
        inner,
        epoch,
        leaf: LeafRegistry::new(state, epoch)?,
    })
}

fn reservation(
    genesis: &ValidatedPublicGenesis,
    outer: &OuterSupport,
    inner: InnerSupport,
    epoch: KeyEpoch,
    session: SessionId,
    marker: u8,
) -> KResult<zeroize::Zeroizing<Vec<u8>>> {
    let person = epoch.anchor().person();
    let body = MemberBody::new(
        genesis.person(person)?.identity_key(),
        genesis.person(person)?.member_point(),
        epoch,
        inner,
        outer.coefficient(person)?,
    )?;
    let salt = SecretScalar::new(Scalar::from(41_u64));
    let record = MemberRecord::commit(&body, &salt)?;
    let prepackage = RootPrepackage::new(
        genesis.vault_key(),
        b"old outer epoch".to_vec(),
        RootContext::new(genesis.vault(), epoch.outer(), CommandId::new([marker; 32])),
        outer,
        vec![record],
    )?;
    MemberReservation::new(prepackage, MemberOpening::new(salt, body), outer)?
        .to_bytes(session, 100)
}

fn prepare(
    command: &Command,
    contributions: &[Contribution],
    log: &mut MemoryLog,
) -> KResult<(Candidate, Vec<PendingShare>, CandidateView)> {
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
    Ok((candidate, pending, view))
}

fn prepare_inner_bundle(
    components: &[(&Command, &[Contribution])],
    log: &mut MemoryLog,
) -> KResult<(InnerBundle, Vec<PreparedComponent>)> {
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
    let mut prepared = Vec::with_capacity(components.len());
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
        prepared.push((pending, view.clone()));
    }
    Ok((bundle, prepared))
}

fn resolve(pending: Vec<PendingShare>, terminal: Terminal) -> KResult<Vec<InstalledShare>> {
    pending
        .into_iter()
        .map(|share| share.resolve(terminal)?.ok_or(Error::AlreadyTerminal))
        .collect()
}

fn take(shares: &mut Vec<InstalledShare>, target: TargetId) -> KResult<InstalledShare> {
    let index = shares
        .iter()
        .position(|share| share.target() == target)
        .ok_or(Error::ParticipantNotFound)?;
    Ok(shares.swap_remove(index))
}

fn command(
    scope: ScopeId,
    marker: u8,
    predecessor: ActivationHandle,
    anchor: u64,
    shape: TargetShape,
    roles: Vec<RoleSpec>,
) -> KResult<Command> {
    Command::new(
        scope,
        CommandId::new([marker; 32]),
        predecessor,
        Point::from_scalar(Scalar::from(anchor))?,
        shape,
        roles,
    )
}

fn single_shape(first: DeviceId, second: DeviceId) -> KResult<TargetShape> {
    Ok(TargetShape::Single(SingleShape::new(
        2,
        vec![
            TargetDevice::new(first, Node::from_u64(1)?),
            TargetDevice::new(second, Node::from_u64(2)?),
        ],
    )?))
}

fn one_device_support(device: DeviceId, share: u64) -> KResult<InnerSupport> {
    InnerSupport::new(vec![DeviceParticipant::new(
        device,
        Node::from_u64(1)?,
        share_point(share),
    )])
}

fn roles(
    support: &InnerSupport,
    source: DeviceId,
    target: DeviceId,
    share: u64,
) -> KResult<Vec<RoleSpec>> {
    Ok(vec![
        RoleSpec::source(source, share_point(share), support.source_weight(source)?)?,
        RoleSpec::refresher(source),
        RoleSpec::refresher(target),
    ])
}

fn contributions(
    command: &Command,
    source: DeviceId,
    target: DeviceId,
    share: u64,
    rng: &mut ChaCha20Rng,
) -> KResult<Vec<Contribution>> {
    Ok(vec![
        Contribution::source(
            command,
            source,
            &SecretScalar::new(Scalar::from(share)),
            rng,
        )?,
        Contribution::refresher(command, source, rng)?,
        Contribution::refresher(command, target, rng)?,
    ])
}

fn one_target_contributions(
    command: &Command,
    source: DeviceId,
    target: DeviceId,
    share: u64,
    rng: &mut ChaCha20Rng,
) -> KResult<Vec<Contribution>> {
    Ok(vec![
        Contribution::source(
            command,
            source,
            &SecretScalar::new(Scalar::from(share)),
            rng,
        )?,
        Contribution::refresher(command, target, rng)?,
    ])
}

fn candidate_json(
    command: &Command,
    view: &CandidateView,
    installed: &[InstalledShare],
) -> KResult<Value> {
    Ok(json!({
        "aggregate_points": hex(view.aggregate().to_bytes()?),
        "candidate_view": hex(view.as_bytes()),
        "command": hex(command.to_bytes()?),
        "installed": installed_values(installed)
    }))
}

fn installed_values(installed: &[InstalledShare]) -> Vec<Value> {
    installed
        .iter()
        .map(|share| {
            json!({
                "public": element_hex(share.public()),
                "target": target_name(share.target()),
                "test_only_secret": scalar_hex(share.expose(|value| *value))
            })
        })
        .collect()
}

fn target_name(target: TargetId) -> Value {
    match target {
        TargetId::Single(device) => json!({"device": id_hex(device.as_bytes()), "kind": "single"}),
        TargetId::Outer { person, device } => json!({
            "device": id_hex(device.as_bytes()),
            "kind": "outer",
            "person": id_hex(person.as_bytes())
        }),
    }
}

const fn expect_error<T>(result: &Result<T>) -> KResult<&'static str> {
    match result {
        Ok(_) => Err(Error::InvalidTranscript),
        Err(error) => Ok(error.code()),
    }
}

fn constant_polynomial(constant: u64) -> KResult<PublicPolynomial> {
    PublicPolynomial::new(vec![Element::from_scalar(Scalar::from(constant))])
}

fn share_point(value: u64) -> SharePoint {
    SharePoint::new(Element::from_scalar(Scalar::from(value)))
}

fn scalar_hex(scalar: Scalar) -> String {
    hex(<[u8; 32]>::from(scalar.to_bytes()))
}

fn point_hex(point: Point) -> String {
    hex(point.to_bytes())
}

fn element_hex(element: Element) -> String {
    hex(element.to_bytes())
}

fn id_hex(bytes: &[u8; 32]) -> String {
    hex(bytes)
}
