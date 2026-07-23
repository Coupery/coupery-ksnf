#![allow(missing_docs)]

use std::collections::BTreeMap;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::dealing::{
    Candidate, CandidateView, Command, Contribution, InstalledShare, Opening, OuterShape,
    OuterTarget, PrivateShare, RoleSpec, SingleShape, TargetAccumulator, TargetDevice, TargetId,
    TargetShape,
};
use coupery_ksnf::keys::{MemberPoint, SharePoint};
use coupery_ksnf::log_act::{LogAct, MemoryLog, Terminal};
use coupery_ksnf::shamir::{Node, interpolate_constant};
use coupery_ksnf::support::{DeviceParticipant, InnerSupport, OuterSupport, PersonParticipant};
use coupery_ksnf::types::{ActivationHandle, CommandId, DeviceId, PersonId, ScopeId, Slot};
use coupery_ksnf::{Error, Result};

#[test]
fn rejected_single_candidate_retries_under_the_same_key() -> Result<()> {
    let source_1 = DeviceId::new([0x11; 32]);
    let source_2 = DeviceId::new([0x12; 32]);
    let target_1 = DeviceId::new([0x21; 32]);
    let target_2 = DeviceId::new([0x22; 32]);
    let target_3 = DeviceId::new([0x23; 32]);
    let support = InnerSupport::new(vec![
        device_participant(source_1, 1, 41)?,
        device_participant(source_2, 2, 47)?,
    ])?;
    let shape = TargetShape::Single(SingleShape::new(
        2,
        vec![
            TargetDevice::new(target_1, Node::from_u64(1)?),
            TargetDevice::new(target_2, Node::from_u64(2)?),
            TargetDevice::new(target_3, Node::from_u64(3)?),
        ],
    )?);
    let roles = vec![
        RoleSpec::source(source_1, share_point(41)?, support.source_weight(source_1)?)?,
        RoleSpec::source(source_2, share_point(47)?, support.source_weight(source_2)?)?,
        RoleSpec::refresher(target_1),
        RoleSpec::refresher(target_2),
        RoleSpec::refresher(target_3),
    ];
    let scope = ScopeId::new([0x31; 32]);
    let predecessor = ActivationHandle::new([0x41; 32]);
    let mut log = MemoryLog::default();
    log.install_genesis(scope, predecessor)?;

    let rejected_command = command(scope, 1, predecessor, 35, shape.clone(), roles.clone())?;
    let mut rng = ChaCha20Rng::from_seed([1; 32]);
    let exposed = Contribution::source(
        &rejected_command,
        source_1,
        &SecretScalar::new(Scalar::from(41_u64)),
        &mut rng,
    )?;
    let mut rejected = Candidate::new(rejected_command, &mut log)?;
    rejected.commit(exposed.role(), exposed.commitment(), &mut log)?;
    assert_eq!(
        rejected.close_commitments(&mut log),
        Err(Error::SupportMismatch)
    );
    assert_eq!(log.current(scope), Some(predecessor));
    assert_eq!(
        log.transcript(CommandId::new([1; 32]))
            .and_then(coupery_ksnf::log_act::LogTranscript::terminal),
        Some(Terminal::Aborted)
    );

    let retry_command = command(scope, 2, predecessor, 35, shape, roles)?;
    let contributions = vec![
        Contribution::source(
            &retry_command,
            source_1,
            &SecretScalar::new(Scalar::from(41_u64)),
            &mut rng,
        )?,
        Contribution::source(
            &retry_command,
            source_2,
            &SecretScalar::new(Scalar::from(47_u64)),
            &mut rng,
        )?,
        Contribution::refresher(&retry_command, target_1, &mut rng)?,
        Contribution::refresher(&retry_command, target_2, &mut rng)?,
        Contribution::refresher(&retry_command, target_3, &mut rng)?,
    ];
    let (terminal, installed, _) = execute(&retry_command, &contributions, &mut log)?;
    let Terminal::Activated(handle) = terminal else {
        return Err(Error::InvalidTranscript);
    };
    assert_eq!(log.current(scope), Some(handle));
    let values = installed
        .iter()
        .take(2)
        .map(|share| share.expose(|value| *value))
        .collect::<Vec<_>>();
    assert_eq!(
        interpolate_constant(&[Node::from_u64(1)?, Node::from_u64(2)?], &values)?,
        Scalar::from(35_u64)
    );
    assert!(installed.iter().all(|share| share.handle() == handle));
    Ok(())
}

#[test]
#[allow(clippy::too_many_lines)]
fn outer_candidate_links_each_inner_constant() -> Result<()> {
    let source = DeviceId::new([0x11; 32]);
    let source_person = PersonId::new([0x10; 32]);
    let source_point = share_point(50)?;
    let inner_source = InnerSupport::new(vec![DeviceParticipant::new(
        source,
        Node::from_u64(1)?,
        source_point,
    )])?;
    let outer_source = OuterSupport::new(vec![PersonParticipant::new(
        source_person,
        Slot::new(1),
        Node::from_u64(1)?,
        MemberPoint::new(Point::try_from(source_point.element())?),
    )])?;
    let person_1 = PersonId::new([0x61; 32]);
    let person_2 = PersonId::new([0x62; 32]);
    let device_11 = DeviceId::new([0x71; 32]);
    let device_12 = DeviceId::new([0x72; 32]);
    let device_21 = DeviceId::new([0x73; 32]);
    let device_22 = DeviceId::new([0x74; 32]);
    let inner_1 = SingleShape::new(
        2,
        vec![target_device(device_11, 1)?, target_device(device_12, 2)?],
    )?;
    let inner_2 = SingleShape::new(
        2,
        vec![target_device(device_21, 1)?, target_device(device_22, 2)?],
    )?;
    let shape = TargetShape::Outer(OuterShape::new(
        2,
        vec![
            OuterTarget::new(person_1, Node::from_u64(1)?, inner_1),
            OuterTarget::new(person_2, Node::from_u64(2)?, inner_2),
        ],
    )?);
    let roles = vec![
        RoleSpec::source(
            source,
            source_point,
            outer_source.source_weight(source_person, &inner_source, source)?,
        )?,
        RoleSpec::refresher(device_11),
        RoleSpec::refresher(device_12),
        RoleSpec::refresher(device_21),
        RoleSpec::refresher(device_22),
    ];
    let scope = ScopeId::new([0x32; 32]);
    let predecessor = ActivationHandle::new([0x42; 32]);
    let command = command(scope, 3, predecessor, 50, shape, roles)?;
    let mut log = MemoryLog::default();
    log.install_genesis(scope, predecessor)?;
    let mut rng = ChaCha20Rng::from_seed([2; 32]);
    let contributions = vec![
        Contribution::source(
            &command,
            source,
            &SecretScalar::new(Scalar::from(50_u64)),
            &mut rng,
        )?,
        Contribution::refresher(&command, device_11, &mut rng)?,
        Contribution::refresher(&command, device_12, &mut rng)?,
        Contribution::refresher(&command, device_21, &mut rng)?,
        Contribution::refresher(&command, device_22, &mut rng)?,
    ];
    let (_, installed, view) = execute(&command, &contributions, &mut log)?;
    let coupery_ksnf::dealing::ContributionPoints::Outer { outer, members } = view.aggregate()
    else {
        return Err(Error::SupportMismatch);
    };
    assert_eq!(outer[0], Element::from_scalar(Scalar::from(50_u64)));
    assert_eq!(members.len(), 2);

    let values = installed
        .iter()
        .map(|share| (share.target(), share.expose(|value| *value)))
        .collect::<BTreeMap<_, _>>();
    let member_1 = interpolate_constant(
        &[Node::from_u64(1)?, Node::from_u64(2)?],
        &[
            values[&TargetId::Outer {
                person: person_1,
                device: device_11,
            }],
            values[&TargetId::Outer {
                person: person_1,
                device: device_12,
            }],
        ],
    )?;
    let member_2 = interpolate_constant(
        &[Node::from_u64(1)?, Node::from_u64(2)?],
        &[
            values[&TargetId::Outer {
                person: person_2,
                device: device_21,
            }],
            values[&TargetId::Outer {
                person: person_2,
                device: device_22,
            }],
        ],
    )?;
    assert_eq!(
        interpolate_constant(
            &[Node::from_u64(1)?, Node::from_u64(2)?],
            &[member_1, member_2],
        )?,
        Scalar::from(50_u64)
    );
    Ok(())
}

#[test]
fn invalid_opening_and_private_share_never_install() -> Result<()> {
    let source = DeviceId::new([0x14; 32]);
    let target = DeviceId::new([0x24; 32]);
    let scope = ScopeId::new([0x34; 32]);
    let predecessor = ActivationHandle::new([0x44; 32]);
    let shape = TargetShape::Single(SingleShape::new(
        1,
        vec![TargetDevice::new(target, Node::from_u64(1)?)],
    )?);
    let roles = vec![
        RoleSpec::source(
            source,
            share_point(35)?,
            InnerSupport::new(vec![device_participant(source, 1, 35)?])?.source_weight(source)?,
        )?,
        RoleSpec::refresher(target),
    ];
    let bad_command = command(scope, 4, predecessor, 35, shape.clone(), roles.clone())?;
    let mut log = MemoryLog::default();
    log.install_genesis(scope, predecessor)?;
    let mut rng = ChaCha20Rng::from_seed([4; 32]);
    let contribution = Contribution::source(
        &bad_command,
        source,
        &SecretScalar::new(Scalar::from(35_u64)),
        &mut rng,
    )?;
    let refresher = Contribution::refresher(&bad_command, target, &mut rng)?;
    let mut bad = Candidate::new(bad_command.clone(), &mut log)?;
    bad.commit(contribution.role(), contribution.commitment(), &mut log)?;
    bad.commit(refresher.role(), refresher.commitment(), &mut log)?;
    bad.close_commitments(&mut log)?;
    let opening = contribution.opening();
    assert_eq!(
        bad.open(
            Opening::new(
                opening.role(),
                opening.points().clone(),
                opening.salt() + Scalar::ONE,
            ),
            &mut log,
        ),
        Err(Error::CommitmentMismatch)
    );
    assert_eq!(bad.close_commitments(&mut log), Ok(()));

    let command = command(scope, 5, predecessor, 35, shape, roles)?;
    let contribution = Contribution::source(
        &command,
        source,
        &SecretScalar::new(Scalar::from(35_u64)),
        &mut rng,
    )?;
    let refresher = Contribution::refresher(&command, target, &mut rng)?;
    let mut candidate = Candidate::new(command.clone(), &mut log)?;
    candidate.commit(contribution.role(), contribution.commitment(), &mut log)?;
    candidate.commit(refresher.role(), refresher.commitment(), &mut log)?;
    candidate.close_commitments(&mut log)?;
    candidate.open(contribution.opening(), &mut log)?;
    candidate.open(refresher.opening(), &mut log)?;
    let view = candidate.close_openings(&mut log)?;
    let mut accumulator = TargetAccumulator::new(view, TargetId::Single(target))?;
    assert_eq!(
        accumulator.receive(PrivateShare::new(
            command.id(),
            contribution.role(),
            TargetId::Single(target),
            SecretScalar::new(Scalar::from(36_u64)),
        )),
        Err(Error::ShareMismatch)
    );
    assert_eq!(candidate.abort(&mut log)?, Terminal::Aborted);
    assert_eq!(log.current(scope), Some(predecessor));
    Ok(())
}

fn execute(
    command: &Command,
    contributions: &[Contribution],
    log: &mut MemoryLog,
) -> Result<(Terminal, Vec<InstalledShare>, CandidateView)> {
    let mut candidate = Candidate::new(command.clone(), log)?;
    for contribution in contributions {
        candidate.commit(contribution.role(), contribution.commitment(), log)?;
    }
    candidate.close_commitments(log)?;
    for contribution in contributions {
        candidate.open(contribution.opening(), log)?;
    }
    let view = candidate.close_openings(log)?;
    candidate.commit(contributions[0].role(), contributions[0].commitment(), log)?;
    candidate.open(contributions[0].opening(), log)?;

    let mut pending = Vec::new();
    for target in command.shape().targets() {
        let mut accumulator = TargetAccumulator::new(view.clone(), target)?;
        for contribution in contributions {
            accumulator.receive(contribution.share(command, target)?)?;
        }
        let (receipt, share) = accumulator.finish()?.into_parts();
        candidate.receipt(receipt.clone(), log)?;
        candidate.receipt(receipt, log)?;
        pending.push(share);
    }
    let terminal = candidate.activate(log)?;
    assert_eq!(candidate.activate(log)?, terminal);
    let installed = pending
        .into_iter()
        .map(|share| share.resolve(terminal))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .flatten()
        .collect();
    Ok((terminal, installed, view))
}

fn command(
    scope: ScopeId,
    marker: u8,
    predecessor: ActivationHandle,
    anchor: u64,
    shape: TargetShape,
    roles: Vec<RoleSpec>,
) -> Result<Command> {
    Command::new(
        scope,
        CommandId::new([marker; 32]),
        predecessor,
        Point::from_scalar(Scalar::from(anchor))?,
        shape,
        roles,
    )
}

fn device_participant(device: DeviceId, node: u64, share: u64) -> Result<DeviceParticipant> {
    Ok(DeviceParticipant::new(
        device,
        Node::from_u64(node)?,
        share_point(share)?,
    ))
}

fn target_device(device: DeviceId, node: u64) -> Result<TargetDevice> {
    Ok(TargetDevice::new(device, Node::from_u64(node)?))
}

fn share_point(value: u64) -> Result<SharePoint> {
    Ok(SharePoint::new(Point::from_scalar(Scalar::from(value))?))
}
