//! Shared Taproot test fixture.
#![expect(
    dead_code,
    reason = "Each integration test uses part of the shared fixture."
)]

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;

use coupery_ksnf::Result;
use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::dealing::{
    Candidate, Command, Contribution, RoleSpec, SingleShape, TargetAccumulator, TargetDevice,
    TargetId, TargetShape,
};
use coupery_ksnf::keys::{AnchorId, IdentityKey, KeyEpoch, MemberPoint, SharePoint, VaultKey};
use coupery_ksnf::log_act::{MemoryLog, Terminal};
use coupery_ksnf::shamir::Node;
use coupery_ksnf::signing::{DeviceNonce, DeviceNonceSet, Nonce, NoncePair};
use coupery_ksnf::support::{DeviceParticipant, InnerSupport, OuterSupport, PersonParticipant};
use coupery_ksnf::taproot::{
    DeviceResponse, Key, MemberResponse, Package, Reservation, Signature, hazmat,
};
use coupery_ksnf::transcript::{
    MemberBody, MemberOpening, MemberRecord, MemberReservation, MemberTranscript, RootContext,
    RootEntry, RootPackage,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, LeafAttempt, OuterEpoch, PersonId, ScopeId,
    SessionId, Slot, VaultId,
};

/// One device in a plan, keyed by a marker byte.
///
/// `share_override` supplies a share directly (used for shares that come from a
/// redistribution); when `None` the share is generated from the inner
/// polynomial.
pub struct DevicePlan {
    pub marker: u8,
    pub node: u64,
    pub hiding: u64,
    pub binding: u64,
    pub share_override: Option<Scalar>,
}

/// One outer member in a plan.
pub struct PersonPlan {
    pub marker: u8,
    pub slot: u16,
    pub outer_node: u64,
    pub identity: u64,
    pub inner_extra: Vec<u64>,
    pub devices: Vec<DevicePlan>,
}

/// A full depth-two session plan.
pub struct Scenario {
    pub vault_secret: u64,
    pub outer_extra: Vec<u64>,
    pub message: [u8; 32],
    pub command: u8,
    pub people: Vec<PersonPlan>,
}

/// One built device with its secrets retained for signing.
pub struct BuiltDevice {
    pub id: DeviceId,
    pub node: u64,
    pub share: Scalar,
    pub hiding: Scalar,
    pub binding: Scalar,
}

/// One built member with its transcript and device nonce set.
pub struct BuiltPerson {
    pub person: PersonId,
    pub slot: Slot,
    pub member_secret: Scalar,
    pub transcript: MemberTranscript,
    pub nonces: DeviceNonceSet,
    pub devices: Vec<BuiltDevice>,
}

/// A built session ready to sign.
pub struct Session {
    pub vault_secret: Scalar,
    pub vault_key: VaultKey,
    pub outer: OuterSupport,
    pub root: RootPackage,
    pub message: [u8; 32],
    pub people: Vec<BuiltPerson>,
}

/// One complete Taproot signing path.
pub struct SignedSession {
    pub package: Package,
    pub devices: Vec<DeviceResponse>,
    pub members: Vec<MemberResponse>,
    pub signature: Signature,
}

const VAULT: VaultId = VaultId::new([0x55; 32]);
const OUTER_EPOCH: OuterEpoch = OuterEpoch::new(7);

/// Evaluates a constant-first polynomial at `node`.
fn eval(coefficients: &[Scalar], node: u64) -> Scalar {
    let point = Scalar::from(node);
    coefficients
        .iter()
        .rev()
        .fold(Scalar::ZERO, |acc, coefficient| acc * point + coefficient)
}

const fn person_id(marker: u8) -> PersonId {
    PersonId::new([marker; 32])
}

const fn device_id(marker: u8) -> DeviceId {
    DeviceId::new([marker; 32])
}

/// Builds a full session from a plan.
///
/// Member secrets lie on the outer polynomial through `vault_secret`; device
/// shares lie on each member's inner polynomial. The participating supports are
/// exactly the planned people and devices.
pub fn build(scenario: &Scenario) -> Result<Session> {
    let vault_secret = Scalar::from(scenario.vault_secret);
    let vault_key = VaultKey::new(Point::from_scalar(vault_secret)?);

    let mut outer_coefficients = vec![vault_secret];
    outer_coefficients.extend(
        scenario
            .outer_extra
            .iter()
            .map(|value| Scalar::from(*value)),
    );

    let mut participants = Vec::new();
    let mut member_secrets = Vec::new();
    for plan in &scenario.people {
        let secret = eval(&outer_coefficients, plan.outer_node);
        member_secrets.push(secret);
        participants.push(PersonParticipant::new(
            person_id(plan.marker),
            Slot::new(plan.slot),
            Node::from_u64(plan.outer_node)?,
            MemberPoint::new(Point::from_scalar(secret)?),
        ));
    }
    let outer = OuterSupport::new(participants)?;

    let mut assembled = Vec::new();
    let mut entries = Vec::new();
    for (plan, member_secret) in scenario.people.iter().zip(&member_secrets) {
        let assembly = assemble_person(plan, *member_secret, &outer)?;
        entries.push(RootEntry::new(assembly.record, assembly.nonces.aggregate()));
        assembled.push(assembly);
    }

    let root = RootPackage::new(
        vault_key,
        scenario.message.to_vec(),
        RootContext::new(VAULT, OUTER_EPOCH, CommandId::new([scenario.command; 32])),
        &outer,
        entries,
    )?;

    let mut people = Vec::new();
    for assembly in assembled {
        let transcript = MemberTranscript::new(
            root.clone(),
            MemberOpening::new(assembly.salt, assembly.body),
            &outer,
        )?;
        people.push(BuiltPerson {
            person: assembly.person,
            slot: assembly.slot,
            member_secret: assembly.member_secret,
            transcript,
            nonces: assembly.nonces,
            devices: assembly.devices,
        });
    }

    Ok(Session {
        vault_secret,
        vault_key,
        outer,
        root,
        message: scenario.message,
        people,
    })
}

struct PersonAssembly {
    person: PersonId,
    slot: Slot,
    member_secret: Scalar,
    body: MemberBody,
    salt: SecretScalar,
    record: MemberRecord,
    nonces: DeviceNonceSet,
    devices: Vec<BuiltDevice>,
}

fn assemble_person(
    plan: &PersonPlan,
    member_secret: Scalar,
    outer: &OuterSupport,
) -> Result<PersonAssembly> {
    let person = person_id(plan.marker);
    let mut inner_coefficients = vec![member_secret];
    inner_coefficients.extend(plan.inner_extra.iter().map(|value| Scalar::from(*value)));

    let mut devices = Vec::new();
    let mut participants = Vec::new();
    let mut device_nonces = Vec::new();
    for device in &plan.devices {
        let id = device_id(device.marker);
        let share = device
            .share_override
            .unwrap_or_else(|| eval(&inner_coefficients, device.node));
        let hiding = Scalar::from(device.hiding);
        let binding = Scalar::from(device.binding);
        participants.push(DeviceParticipant::new(
            id,
            Node::from_u64(device.node)?,
            SharePoint::new(Element::from_scalar(share)),
        ));
        device_nonces.push(DeviceNonce::new(
            LeafAttempt::new(id, device.node),
            NoncePair::new(Point::from_scalar(hiding)?, Point::from_scalar(binding)?),
        ));
        devices.push(BuiltDevice {
            id,
            node: device.node,
            share,
            hiding,
            binding,
        });
    }
    let inner = InnerSupport::new(participants)?;
    let nonces = DeviceNonceSet::new(&inner, device_nonces)?;

    let body = MemberBody::new(
        IdentityKey::new(Point::from_scalar(Scalar::from(plan.identity))?),
        MemberPoint::new(Point::from_scalar(member_secret)?),
        KeyEpoch::new(
            OUTER_EPOCH,
            InnerEpoch::new(u64::from(plan.marker)),
            AnchorId::new(
                VAULT,
                person,
                ActivationHandle::new([plan.marker; 32]),
                ActivationHandle::new([plan.marker.wrapping_add(0x80); 32]),
            ),
        ),
        inner,
        outer.coefficient(person)?,
    )?;
    let salt = SecretScalar::new(Scalar::from(70_u64 + u64::from(plan.slot)));
    let record = MemberRecord::commit(&body, &salt)?;

    Ok(PersonAssembly {
        person,
        slot: Slot::new(plan.slot),
        member_secret,
        body,
        salt,
        record,
        nonces,
        devices,
    })
}

/// Signs one session through both aggregation tiers.
pub fn sign(session: &Session, merkle_root: Option<[u8; 32]>) -> Result<SignedSession> {
    let key = Key::new(session.vault_key, merkle_root)?;
    let package = Package::new(session.root.clone(), key)?;
    let signing = package.signing()?;
    let mut devices = Vec::new();
    let mut members = Vec::new();
    for person in &session.people {
        let mut responses = Vec::new();
        for device in &person.devices {
            let nonce = Nonce::new(device.hiding, device.binding)?;
            let response = hazmat::respond_device(
                &signing,
                nonce,
                &person.transcript,
                &person.nonces,
                device.id,
                &SecretScalar::new(device.share),
            )?;
            devices.push(response);
            responses.push(response);
        }
        members.push(signing.aggregate_member(&person.transcript, &person.nonces, &responses)?);
    }
    let signature = signing.aggregate_signature(&session.outer, &members)?;
    Ok(SignedSession {
        package,
        devices,
        members,
        signature,
    })
}

/// Encodes one Taproot reservation per outer member.
pub fn reservations(
    session: &Session,
    key: Key,
    signing_session: SessionId,
    expiry: u64,
) -> Result<Vec<(Slot, zeroize::Zeroizing<Vec<u8>>)>> {
    session
        .people
        .iter()
        .map(|person| {
            let salt = SecretScalar::new(Scalar::from(70_u64 + u64::from(person.slot.get())));
            let member = MemberReservation::new(
                session.root.prepackage(),
                MemberOpening::new(salt, person.transcript.body().clone()),
                &session.outer,
            )?;
            let bytes = Reservation::new(member, key)?.to_bytes(signing_session, expiry)?;
            Ok((person.slot, bytes))
        })
        .collect()
}

/// Verifies raw signature bytes with `k256`'s independent BIP-340 code.
#[must_use]
pub fn verifies_bytes_under_k256(
    signature: &[u8; 64],
    output_key: &[u8; 32],
    sighash: &[u8; 32],
) -> bool {
    let Ok(key) = k256::schnorr::VerifyingKey::from_bytes(output_key) else {
        return false;
    };
    let Ok(parsed) = k256::schnorr::Signature::try_from(signature.as_slice()) else {
        return false;
    };
    key.verify_raw(sighash, &parsed).is_ok()
}

/// Verifies a signature with `k256`'s independent BIP-340 implementation.
#[must_use]
pub fn verifies_under_k256(signed: &SignedSession, sighash: &[u8; 32]) -> bool {
    verifies_bytes_under_k256(
        &signed.signature.to_bytes(),
        &signed.package.key().output_key().to_bytes(),
        sighash,
    )
}

/// Redistributes one inner group to a new device set under a stable constant.
///
/// Mirrors the crate's dealing happy path. Returns the new devices with the
/// installed share scalars, which interpolate to `member_secret`.
pub fn redistribute_inner(
    member_secret: Scalar,
    old: &[(DeviceId, u64, Scalar)],
    new: &[(DeviceId, u64)],
    threshold: u16,
    scope_marker: u8,
    seed: [u8; 32],
) -> Result<Vec<(DeviceId, u64, Scalar)>> {
    let support = InnerSupport::new(
        old.iter()
            .map(|(id, node, share)| {
                Ok(DeviceParticipant::new(
                    *id,
                    Node::from_u64(*node)?,
                    SharePoint::new(Point::from_scalar(*share)?),
                ))
            })
            .collect::<Result<Vec<_>>>()?,
    )?;
    let shape = TargetShape::Single(SingleShape::new(
        threshold,
        new.iter()
            .map(|(id, node)| Ok(TargetDevice::new(*id, Node::from_u64(*node)?)))
            .collect::<Result<Vec<_>>>()?,
    )?);

    let mut roles = Vec::new();
    for (id, _, share) in old {
        roles.push(RoleSpec::source(
            *id,
            SharePoint::new(Point::from_scalar(*share)?),
            support.source_weight(*id)?,
        )?);
    }
    for (id, _) in new {
        roles.push(RoleSpec::refresher(*id));
    }

    let scope = ScopeId::new([scope_marker; 32]);
    let predecessor = ActivationHandle::new([scope_marker.wrapping_add(1); 32]);
    let command = Command::new(
        scope,
        CommandId::new([scope_marker.wrapping_add(2); 32]),
        predecessor,
        Point::from_scalar(member_secret)?,
        shape,
        roles,
    )?;

    let mut log = MemoryLog::default();
    log.install_genesis(scope, predecessor)?;
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut contributions = Vec::new();
    for (id, _, share) in old {
        contributions.push(Contribution::source(
            &command,
            *id,
            &SecretScalar::new(*share),
            &mut rng,
        )?);
    }
    for (id, _) in new {
        contributions.push(Contribution::refresher(&command, *id, &mut rng)?);
    }

    let installed = execute(&command, &contributions, &mut log)?;
    let mut result = Vec::new();
    for (id, node) in new {
        let installed_share = installed
            .iter()
            .find(|entry| entry.0 == TargetId::Single(*id))
            .map(|entry| entry.1)
            .ok_or(coupery_ksnf::Error::ParticipantNotFound)?;
        result.push((*id, *node, installed_share));
    }
    Ok(result)
}

fn execute(
    command: &Command,
    contributions: &[Contribution],
    log: &mut MemoryLog,
) -> Result<Vec<(TargetId, Scalar)>> {
    let mut candidate = Candidate::new(command.clone(), log)?;
    for contribution in contributions {
        candidate.commit(contribution.role(), contribution.commitment(), log)?;
    }
    candidate.close_commitments(log)?;
    let mut released = Vec::with_capacity(contributions.len());
    for contribution in contributions {
        released.push(candidate.open_contribution(contribution, log)?);
    }
    let view = candidate.close_openings(log)?;

    let mut pending = Vec::new();
    for target in command.shape().targets() {
        let mut accumulator = TargetAccumulator::new(view.clone(), target)?;
        for contribution in &released {
            accumulator.receive(contribution.share(command, target)?)?;
        }
        let (receipt, share) = accumulator.finish()?.into_parts();
        candidate.receipt(receipt, log)?;
        pending.push(share);
    }
    let Terminal::Activated(handle) = candidate.activate(log)? else {
        return Err(coupery_ksnf::Error::InvalidTranscript);
    };

    let mut installed = Vec::new();
    for share in pending {
        if let Some(entry) = share.resolve(Terminal::Activated(handle))? {
            installed.push((entry.target(), entry.expose(|value| *value)));
        }
    }
    Ok(installed)
}
