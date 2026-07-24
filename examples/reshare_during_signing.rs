//! Overlaps signing with a vetoed redistribution, then activates its retry.

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::auth::{AuthenticatedCommitment, AuthenticatedOpening};
use coupery_ksnf::dealing::{
    Command, Contribution, InstalledShare, PendingShare, RoleSpec, SingleShape, TargetAccumulator,
    TargetDevice, TargetId, TargetShape,
};
use coupery_ksnf::genesis::{PublicDevice, PublicPerson, PublicPolynomial};
use coupery_ksnf::keys::{AnchorId, KeyEpoch, SharePoint};
use coupery_ksnf::leaf::LeafStage;
use coupery_ksnf::log_act::{MemoryLog, Terminal};
use coupery_ksnf::secp256k1::{InnerBundle, LeafRegistry, ValidatedPublicGenesis};
use coupery_ksnf::shamir::Node;
use coupery_ksnf::signing::{
    DeviceNonce, DeviceNonceSet, Signature, aggregate_member, aggregate_signature,
};
use coupery_ksnf::support::{DeviceParticipant, InnerSupport, OuterSupport};
use coupery_ksnf::transcript::{
    MemberBody, MemberNonce, MemberOpening, MemberRecord, MemberReservation, MemberTranscript,
    RootContext, RootPackage, RootPrepackage, SigningContext,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, LeafAttempt, OuterEpoch, PersonId, ScopeId,
    SessionId, VaultId,
};
use coupery_ksnf::{Error, Result};

const NOW: u64 = 50;
const EXPIRY: u64 = 100;

struct Setup {
    genesis: ValidatedPublicGenesis,
    outer: OuterSupport,
    inner: InnerSupport,
    leaf: LeafRegistry,
    epoch: KeyEpoch,
    vault: VaultId,
    person: PersonId,
    device: DeviceId,
}

struct OpenSigning {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    prepackage: RootPrepackage,
    inner: InnerSupport,
    attempt: LeafAttempt,
    session: SessionId,
    commitment: Scalar,
}

fn setup() -> Result<Setup> {
    let vault = VaultId::new([0x11; 32]);
    let person = PersonId::new([0x21; 32]);
    let device = DeviceId::new([0x31; 32]);
    let node = Node::from_u64(1)?;
    let identity = Scalar::from(31_u64);
    let member = Scalar::from(101_u64);
    let identity_handle = ActivationHandle::new([0x41; 32]);
    let member_handle = ActivationHandle::new([0x42; 32]);
    let epoch = KeyEpoch::new(
        OuterEpoch::new(5),
        InnerEpoch::new(7),
        AnchorId::new(vault, person, identity_handle, member_handle),
    );
    let genesis = ValidatedPublicGenesis::validate(
        vault,
        polynomial(member)?,
        vec![PublicPerson::new(
            person,
            node,
            polynomial(identity)?,
            polynomial(member)?,
            vec![PublicDevice::new(
                device,
                node,
                SharePoint::new(Element::from_scalar(identity)),
                SharePoint::new(Element::from_scalar(member)),
            )],
        )?],
    )?;
    let outer = genesis.outer_support(&[person])?;
    let inner = genesis.inner_support(person, &[device])?;
    let state = genesis.attach_share(
        person,
        device,
        SecretScalar::new(identity),
        SecretScalar::new(member),
    )?;
    let leaf = LeafRegistry::new(state, epoch)?;
    Ok(Setup {
        genesis,
        outer,
        inner,
        leaf,
        epoch,
        vault,
        person,
        device,
    })
}

fn main() -> Result<()> {
    let mut setup = setup()?;
    let identity_key = setup.genesis.person(setup.person)?.identity_key();
    let vault_key = setup.genesis.vault_key();
    let open_signature = open_signing(
        &mut setup.leaf,
        &setup.genesis,
        &setup.outer,
        &setup.inner,
        setup.epoch,
        1,
    )?;

    let mut log = MemoryLog::default();
    let identity_scope = ScopeId::new([0x61; 32]);
    let member_scope = ScopeId::new([0x62; 32]);
    log.install_genesis(identity_scope, setup.epoch.anchor().identity())?;
    log.install_genesis(member_scope, setup.epoch.anchor().member())?;
    let first = commands(&setup, identity_scope, member_scope, [0x71, 0x72])?;
    let first_contributions = contributions(&first, setup.device, [2; 32])?;
    let (mut vetoed, _) = prepare(&first, &first_contributions, &mut log)?;
    assert_eq!(vetoed.abort(&mut log)?, Terminal::Aborted);
    let old_signature = finish_signing(&mut setup.leaf, &setup.outer, open_signature)?;
    old_signature.verify(vault_key, &[1; 32])?;

    let stale = open_signing(
        &mut setup.leaf,
        &setup.genesis,
        &setup.outer,
        &setup.inner,
        setup.epoch,
        2,
    )?;
    let stale_attempt = stale.attempt;
    assert_eq!(setup.leaf.stage(), Some(LeafStage::Committed));

    let retry = commands(&setup, identity_scope, member_scope, [0x73, 0x74])?;
    let retry_contributions = contributions(&retry, setup.device, [4; 32])?;
    let (mut bundle, pending) = prepare(&retry, &retry_contributions, &mut log)?;
    let terminal = bundle.activate(&mut log)?;
    let Terminal::Activated(handle) = terminal else {
        return Err(Error::InvalidTranscript);
    };
    let mut pending = pending.into_iter();
    let mut identity = resolve(pending.next().ok_or(Error::EmptyInput)?, terminal)?;
    let mut member = resolve(pending.next().ok_or(Error::EmptyInput)?, terminal)?;
    let next_inner = installed_support(&member, setup.device)?;
    let next_epoch = KeyEpoch::new(
        setup.epoch.outer(),
        InnerEpoch::new(setup.epoch.inner().get() + 1),
        AnchorId::new(setup.vault, setup.person, handle, handle),
    );
    setup.leaf.activate_inner(
        next_epoch,
        take(&mut identity, setup.device)?,
        take(&mut member, setup.device)?,
    )?;

    assert_eq!(setup.leaf.stage(), None);
    assert!(setup.leaf.is_closed(stale_attempt));
    assert_eq!(setup.leaf.epoch(setup.vault)?, next_epoch);
    assert_eq!(
        setup.genesis.person(setup.person)?.identity_key(),
        identity_key
    );
    assert_eq!(setup.genesis.vault_key(), vault_key);

    let new_signature = sign(
        &mut setup.leaf,
        &setup.genesis,
        &setup.outer,
        &next_inner,
        next_epoch,
        5,
    )?;
    new_signature.verify(vault_key, &[5; 32])?;
    assert_ne!(old_signature.to_bytes(), new_signature.to_bytes());
    Ok(())
}

fn commands(
    setup: &Setup,
    identity_scope: ScopeId,
    member_scope: ScopeId,
    ids: [u8; 2],
) -> Result<[Command; 2]> {
    let shape = TargetShape::Single(SingleShape::new(
        1,
        vec![TargetDevice::new(setup.device, Node::from_u64(1)?)],
    )?);
    let identity = InnerSupport::new(vec![DeviceParticipant::new(
        setup.device,
        Node::from_u64(1)?,
        share_point(31),
    )])?;
    Ok([
        Command::new(
            identity_scope,
            CommandId::new([ids[0]; 32]),
            setup.epoch.anchor().identity(),
            Point::from_scalar(Scalar::from(31_u64))?,
            shape.clone(),
            roles(&identity, setup.device, 31)?,
        )?,
        Command::new(
            member_scope,
            CommandId::new([ids[1]; 32]),
            setup.epoch.anchor().member(),
            Point::from_scalar(Scalar::from(101_u64))?,
            shape,
            roles(&setup.inner, setup.device, 101)?,
        )?,
    ])
}

fn contributions(
    commands: &[Command; 2],
    device: DeviceId,
    seed: [u8; 32],
) -> Result<[Vec<Contribution>; 2]> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    Ok([
        vec![
            Contribution::source(
                &commands[0],
                device,
                &SecretScalar::new(Scalar::from(31_u64)),
                &mut rng,
            )?,
            Contribution::refresher(&commands[0], device, &mut rng)?,
        ],
        vec![
            Contribution::source(
                &commands[1],
                device,
                &SecretScalar::new(Scalar::from(101_u64)),
                &mut rng,
            )?,
            Contribution::refresher(&commands[1], device, &mut rng)?,
        ],
    ])
}

fn prepare(
    commands: &[Command; 2],
    contributions: &[Vec<Contribution>; 2],
    log: &mut MemoryLog,
) -> Result<(InnerBundle, Vec<Vec<PendingShare>>)> {
    let mut bundle = InnerBundle::new(commands.to_vec(), log)?;
    for (command, shares) in commands.iter().zip(contributions) {
        for share in shares {
            bundle.commit(command.id(), share.role(), share.commitment(), log)?;
        }
    }
    bundle.close_commitments(log)?;
    let mut released = Vec::with_capacity(contributions.len());
    for (command, shares) in commands.iter().zip(contributions) {
        let mut component = Vec::with_capacity(shares.len());
        for share in shares {
            component.push(bundle.open_contribution(command.id(), share, log)?);
        }
        released.push(component);
    }
    let views = bundle.close_openings(log)?;
    let mut pending = Vec::new();
    for (component, command) in released.iter().zip(commands) {
        let view = views
            .iter()
            .find_map(|(id, view)| (*id == command.id()).then_some(view))
            .ok_or(Error::ParticipantNotFound)?;
        let target = command
            .shape()
            .targets()
            .first()
            .copied()
            .ok_or(Error::EmptyInput)?;
        let mut accumulator = TargetAccumulator::new(view.clone(), target)?;
        for share in component {
            accumulator.receive(share.share(command, target)?)?;
        }
        let (receipt, share) = accumulator.finish()?.into_parts();
        bundle.receipt(receipt, log)?;
        pending.push(vec![share]);
    }
    Ok((bundle, pending))
}

fn sign(
    leaf: &mut LeafRegistry,
    genesis: &ValidatedPublicGenesis,
    outer: &OuterSupport,
    inner: &InnerSupport,
    epoch: KeyEpoch,
    marker: u8,
) -> Result<Signature> {
    let open = open_signing(leaf, genesis, outer, inner, epoch, marker)?;
    finish_signing(leaf, outer, open)
}

fn open_signing(
    leaf: &mut LeafRegistry,
    genesis: &ValidatedPublicGenesis,
    outer: &OuterSupport,
    inner: &InnerSupport,
    epoch: KeyEpoch,
    marker: u8,
) -> Result<OpenSigning> {
    let (bytes, prepackage) = reservation(genesis, outer, inner.clone(), epoch, marker)?;
    let session = SessionId::new([marker; 32]);
    let attempt = leaf.reserve(session, NOW, &bytes, outer)?;
    let commitment = leaf.commit(attempt, &bytes, &mut ChaCha20Rng::from_seed([marker; 32]))?;
    Ok(OpenSigning {
        bytes,
        prepackage,
        inner: inner.clone(),
        attempt,
        session,
        commitment,
    })
}

fn finish_signing(
    leaf: &mut LeafRegistry,
    outer: &OuterSupport,
    open: OpenSigning,
) -> Result<Signature> {
    let pair = leaf.reveal(
        open.attempt,
        vec![AuthenticatedCommitment::new(
            open.attempt,
            open.attempt,
            open.session,
            &open.bytes,
            open.commitment,
        )],
    )?;
    leaf.fix(
        open.attempt,
        vec![AuthenticatedOpening::new(
            open.attempt,
            open.attempt,
            open.session,
            &open.bytes,
            pair,
        )],
    )?;
    let root = RootPackage::finalize(
        open.prepackage,
        outer,
        vec![MemberNonce::new(outer.participants()[0].slot(), pair)],
    )?;
    let signing = SigningContext::new(&root)?;
    let response = leaf.respond(open.attempt, &root.to_bytes()?)?;
    let (member, _, _) = MemberReservation::from_bytes(&open.bytes, outer)?;
    let transcript = MemberTranscript::finalize(root.clone(), member)?;
    let nonces = DeviceNonceSet::new(
        &open.inner,
        vec![DeviceNonce::new(
            LeafAttempt::new(response.device(), open.attempt.sequence()),
            pair,
        )],
    )?;
    let member = aggregate_member(&transcript, &signing, &nonces, &[response])?;
    aggregate_signature(&signing, outer, &[member])
}

fn reservation(
    genesis: &ValidatedPublicGenesis,
    outer: &OuterSupport,
    inner: InnerSupport,
    epoch: KeyEpoch,
    marker: u8,
) -> Result<(zeroize::Zeroizing<Vec<u8>>, RootPrepackage)> {
    let person = epoch.anchor().person();
    let body = MemberBody::new(
        genesis.person(person)?.identity_key(),
        genesis.person(person)?.member_point(),
        epoch,
        inner,
        outer.coefficient(person)?,
    )?;
    let salt = Scalar::from(40_u64 + u64::from(marker));
    let record = MemberRecord::commit(&body, &SecretScalar::new(salt))?;
    let prepackage = RootPrepackage::new(
        genesis.vault_key(),
        vec![marker; 32],
        RootContext::new(genesis.vault(), epoch.outer(), CommandId::new([marker; 32])),
        outer,
        vec![record],
    )?;
    let reservation = MemberReservation::new(
        prepackage.clone(),
        MemberOpening::new(SecretScalar::new(salt), body),
        outer,
    )?;
    Ok((
        reservation.to_bytes(SessionId::new([marker; 32]), EXPIRY)?,
        prepackage,
    ))
}

fn roles(support: &InnerSupport, device: DeviceId, share: u64) -> Result<Vec<RoleSpec>> {
    Ok(vec![
        RoleSpec::source(device, share_point(share), support.source_weight(device)?)?,
        RoleSpec::refresher(device),
    ])
}

fn resolve(pending: Vec<PendingShare>, terminal: Terminal) -> Result<Vec<InstalledShare>> {
    pending
        .into_iter()
        .map(|share| share.resolve(terminal)?.ok_or(Error::AlreadyTerminal))
        .collect()
}

fn take(shares: &mut Vec<InstalledShare>, device: DeviceId) -> Result<InstalledShare> {
    let target = TargetId::Single(device);
    let index = shares
        .iter()
        .position(|share| share.target() == target)
        .ok_or(Error::ParticipantNotFound)?;
    Ok(shares.swap_remove(index))
}

fn installed_support(shares: &[InstalledShare], device: DeviceId) -> Result<InnerSupport> {
    let share = shares
        .iter()
        .find(|share| share.target() == TargetId::Single(device))
        .ok_or(Error::ParticipantNotFound)?;
    InnerSupport::new(vec![DeviceParticipant::new(
        device,
        Node::from_u64(1)?,
        SharePoint::new(share.public()),
    )])
}

fn polynomial(constant: Scalar) -> Result<PublicPolynomial> {
    PublicPolynomial::new(vec![Element::from_scalar(constant)])
}

fn share_point(value: u64) -> SharePoint {
    SharePoint::new(Element::from_scalar(Scalar::from(value)))
}
