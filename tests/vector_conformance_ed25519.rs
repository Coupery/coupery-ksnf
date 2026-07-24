//! Ed25519 vector conformance tests.

#![cfg(feature = "ed25519")]

use std::fs;
use std::path::Path;

use ed25519_dalek::{Signature as DalekSignature, Verifier as _, VerifyingKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;
use serde_json::{Value, json};

use coupery_ksnf::algebra::{Element, Point, ScalarFor, SecretScalar};
use coupery_ksnf::dealing::{
    Candidate, Command, Contribution, InstalledShare, RoleSpec, SingleShape, TargetAccumulator,
    TargetDevice, TargetShape,
};
use coupery_ksnf::keys::{AnchorId, IdentityKey, KeyEpoch, MemberPoint, SharePoint, VaultKey};
use coupery_ksnf::log_act::{MemoryLog, Terminal};
use coupery_ksnf::profile::{Ed25519, Profile as _};
use coupery_ksnf::shamir::{Node, interpolate_constant};
use coupery_ksnf::signing::hazmat::respond_device;
use coupery_ksnf::signing::{
    DeviceNonce, DeviceNonceSet, Nonce, aggregate_member, aggregate_signature,
};
use coupery_ksnf::support::{DeviceParticipant, InnerSupport, OuterSupport, PersonParticipant};
use coupery_ksnf::transcript::{
    MemberBody, MemberOpening, MemberRecord, MemberTranscript, RootContext, RootEntry, RootPackage,
    SigningContext,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, LeafAttempt, OuterEpoch, PersonId, ScopeId,
    Slot, VaultId,
};
use coupery_ksnf::{Error, Result};

type Scalar = ScalarFor<Ed25519>;
type AnyResult<T> = core::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn published_ed25519_vectors_match() -> AnyResult<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors/v1-ed25519");
    let update = std::env::var_os("UPDATE_VECTORS").is_some();
    let cases = [
        signing_case(
            "nested-webauthn",
            [[1, 2], [1, 2]],
            [[127, 136], [146, 157]],
            10,
        )?,
        signing_case(
            "mixed-supports",
            [[1, 3], [2, 3]],
            [[127, 145], [157, 168]],
            40,
        )?,
        redistribution_case("refresh", false)?,
        redistribution_case("reshare", true)?,
    ];
    for (name, value) in cases {
        let path = root.join(format!("{name}.json"));
        let rendered = format!("{}\n", serde_json::to_string_pretty(&value)?);
        if update {
            fs::write(&path, rendered)?;
        }
        let published: Value = serde_json::from_str(&fs::read_to_string(path)?)?;
        assert_eq!(published, value, "{name}");
    }
    Ok(())
}

fn signing_case(
    name: &'static str,
    nodes: [[u64; 2]; 2],
    shares: [[u64; 2]; 2],
    nonce_base: u64,
) -> AnyResult<(&'static str, Value)> {
    let vault = VaultId::new([0x55; 32]);
    let people = [PersonId::new([0xa1; 32]), PersonId::new([0xa2; 32])];
    let member_scalars = [scalar(118), scalar(135)];
    let members = [
        MemberPoint::new(Point::from_scalar(member_scalars[0])?),
        MemberPoint::new(Point::from_scalar(member_scalars[1])?),
    ];
    let key = VaultKey::new(Point::from_scalar(scalar(101))?);
    let outer = OuterSupport::new(vec![
        PersonParticipant::new(people[0], Slot::new(1), Node::from_u64(1)?, members[0]),
        PersonParticipant::new(people[1], Slot::new(2), Node::from_u64(2)?, members[1]),
    ])?;
    let mut work = Vec::new();
    for index in 0..2 {
        work.push(person_work(
            index,
            vault,
            people[index],
            members[index],
            &outer,
            nodes[index],
            shares[index],
            nonce_base,
        )?);
    }
    let message = webauthn_message();
    let root = RootPackage::new(
        key,
        message.clone(),
        RootContext::new(vault, OuterEpoch::new(7), CommandId::new([0x66; 32])),
        &outer,
        work.iter()
            .map(|person| RootEntry::new(person.record, person.nonces.aggregate()))
            .collect(),
    )?;
    let signing = SigningContext::new(&root)?;
    let mut responses = Vec::new();
    let mut member_values = Vec::new();
    for person in work {
        let opening = MemberOpening::new(person.salt, person.body);
        let transcript = MemberTranscript::new(root.clone(), opening, &outer)?;
        let mut device_responses = Vec::new();
        for device in person.devices {
            device_responses.push(respond_device(
                Nonce::new(device.hiding, device.binding)?,
                &transcript,
                &signing,
                &person.nonces,
                device.id,
                &SecretScalar::new(device.share),
            )?);
        }
        let response = aggregate_member(&transcript, &signing, &person.nonces, &device_responses)?;
        member_values.push(json!({
            "body": hex(transcript.body().to_bytes()?),
            "device_responses": device_responses.iter().map(|value| hex(value.to_bytes())).collect::<Vec<_>>(),
            "member_response": hex(response.to_bytes()),
            "slot": response.slot().get()
        }));
        responses.push(response);
    }
    let signature = aggregate_signature(&signing, &outer, &responses)?;
    signature.verify(key, &message)?;
    verify_ed25519(key, &message, signature.to_bytes())?;
    Ok((
        name,
        json!({
            "canonical": {
                "root_package": hex(root.to_bytes()?),
                "signature": hex(signature.to_bytes())
            },
            "case": name,
            "format": "coupery-ksnf-ed25519-v1",
            "members": member_values,
            "message": hex(&message),
            "profile": "coupery-ksnf/ed25519/v1",
            "selected_nodes": nodes,
            "test_only_secret": {
                "member_shares": shares,
                "nonce_base": nonce_base,
                "vault_secret": 101
            },
            "vault_key": hex(key.to_bytes())
        }),
    ))
}

struct PersonWork {
    body: MemberBody<Ed25519>,
    salt: SecretScalar<Ed25519>,
    record: MemberRecord<Ed25519>,
    nonces: DeviceNonceSet<Ed25519>,
    devices: Vec<DeviceWork>,
}

struct DeviceWork {
    id: DeviceId,
    share: Scalar,
    hiding: Scalar,
    binding: Scalar,
}

#[expect(
    clippy::too_many_arguments,
    reason = "The vector names every fixture input."
)]
fn person_work(
    index: usize,
    vault: VaultId,
    person: PersonId,
    member: MemberPoint<Ed25519>,
    outer: &OuterSupport<Ed25519>,
    nodes: [u64; 2],
    shares: [u64; 2],
    nonce_base: u64,
) -> Result<PersonWork> {
    let index_u8 = u8::try_from(index).map_err(|_| Error::LengthOverflow)?;
    let index_u64 = u64::try_from(index).map_err(|_| Error::LengthOverflow)?;
    let mut devices = Vec::new();
    let mut participants = Vec::new();
    let mut public_nonces = Vec::new();
    for position in 0..2 {
        let position_u64 = u64::try_from(position).map_err(|_| Error::LengthOverflow)?;
        let node_marker = u8::try_from(nodes[position]).map_err(|_| Error::LengthOverflow)?;
        let id = DeviceId::new([0x10 * (index_u8 + 1) + node_marker; 32]);
        let share = scalar(shares[position]);
        let hiding = scalar(nonce_base + 20 * u64::from(index_u8) + 4 * position_u64 + 1);
        let binding = scalar(nonce_base + 20 * u64::from(index_u8) + 4 * position_u64 + 2);
        let nonce = Nonce::new(hiding, binding)?;
        participants.push(DeviceParticipant::new(
            id,
            Node::from_u64(nodes[position])?,
            SharePoint::new(Element::from_scalar(share)),
        ));
        public_nonces.push(DeviceNonce::new(
            LeafAttempt::new(id, nodes[position]),
            nonce.commitments()?,
        ));
        devices.push(DeviceWork {
            id,
            share,
            hiding,
            binding,
        });
    }
    let inner = InnerSupport::new(participants)?;
    let nonces = DeviceNonceSet::new(&inner, public_nonces)?;
    let body = MemberBody::new(
        IdentityKey::new(Point::from_scalar(scalar(31 + 6 * index_u64))?),
        member,
        KeyEpoch::new(
            OuterEpoch::new(7),
            InnerEpoch::new(3 + u64::from(index_u8)),
            AnchorId::new(
                vault,
                person,
                ActivationHandle::new([0x81 + index_u8; 32]),
                ActivationHandle::new([0x91 + index_u8; 32]),
            ),
        ),
        inner,
        outer.coefficient(person)?,
    )?;
    let salt = SecretScalar::new(scalar(71 + u64::from(index_u8)));
    let record = MemberRecord::commit(&body, &salt)?;
    Ok(PersonWork {
        body,
        salt,
        record,
        nonces,
        devices,
    })
}

fn redistribution_case(name: &'static str, new_devices: bool) -> AnyResult<(&'static str, Value)> {
    let source_devices = [DeviceId::new([0x11; 32]), DeviceId::new([0x12; 32])];
    let target_devices = if new_devices {
        [DeviceId::new([0x21; 32]), DeviceId::new([0x22; 32])]
    } else {
        source_devices
    };
    let source_shares = [scalar(127), scalar(136)];
    let source = InnerSupport::new(vec![
        participant(source_devices[0], 1, source_shares[0])?,
        participant(source_devices[1], 2, source_shares[1])?,
    ])?;
    let shape = TargetShape::Single(SingleShape::new(
        2,
        vec![
            TargetDevice::new(target_devices[0], Node::from_u64(1)?),
            TargetDevice::new(target_devices[1], Node::from_u64(2)?),
        ],
    )?);
    let roles = vec![
        RoleSpec::source(
            source_devices[0],
            SharePoint::new(Element::from_scalar(source_shares[0])),
            source.source_weight(source_devices[0])?,
        )?,
        RoleSpec::source(
            source_devices[1],
            SharePoint::new(Element::from_scalar(source_shares[1])),
            source.source_weight(source_devices[1])?,
        )?,
        RoleSpec::refresher(target_devices[0]),
        RoleSpec::refresher(target_devices[1]),
    ];
    let scope = ScopeId::new([0x31; 32]);
    let predecessor = ActivationHandle::new([0x32; 32]);
    let command = Command::new(
        scope,
        CommandId::new([if new_devices { 0x34 } else { 0x33 }; 32]),
        predecessor,
        Point::from_scalar(scalar(118))?,
        shape,
        roles,
    )?;
    let mut rng = ChaCha20Rng::from_seed([if new_devices { 0x44 } else { 0x43 }; 32]);
    let contributions = vec![
        Contribution::source(
            &command,
            source_devices[0],
            &SecretScalar::new(source_shares[0]),
            &mut rng,
        )?,
        Contribution::source(
            &command,
            source_devices[1],
            &SecretScalar::new(source_shares[1]),
            &mut rng,
        )?,
        Contribution::refresher(&command, target_devices[0], &mut rng)?,
        Contribution::refresher(&command, target_devices[1], &mut rng)?,
    ];
    let mut log = MemoryLog::default();
    log.install_genesis(scope, predecessor)?;
    let (terminal, installed, view) = execute(&command, &contributions, &mut log)?;
    let Terminal::Activated(handle) = terminal else {
        return Err(Error::InvalidTranscript.into());
    };
    let values = installed
        .iter()
        .map(|share| share.expose(|value| *value))
        .collect::<Vec<_>>();
    assert_eq!(
        interpolate_constant::<Ed25519>(&[Node::from_u64(1)?, Node::from_u64(2)?], &values,)?,
        scalar(118)
    );
    Ok((
        name,
        json!({
            "activation_handle": hex(handle.as_bytes()),
            "anchor": hex(Point::<Ed25519>::from_scalar(scalar(118))?.to_bytes()),
            "canonical": {
                "candidate_view": hex(view.as_bytes()),
                "command": hex(command.to_bytes()?)
            },
            "case": name,
            "format": "coupery-ksnf-ed25519-v1",
            "installed": installed.iter().map(|share| json!({
                "device": hex(share.target().device().as_bytes()),
                "public": hex(share.public().to_bytes()),
                "share": scalar_hex(share.expose(|value| *value))
            })).collect::<Vec<_>>(),
            "profile": "coupery-ksnf/ed25519/v1",
            "source_devices": source_devices.map(|device| hex(device.as_bytes())),
            "target_devices": target_devices.map(|device| hex(device.as_bytes())),
            "test_only_secret": {
                "source_shares": source_shares.map(scalar_hex)
            }
        }),
    ))
}

fn execute(
    command: &Command<Ed25519>,
    contributions: &[Contribution<Ed25519>],
    log: &mut MemoryLog,
) -> Result<(
    Terminal,
    Vec<InstalledShare<Ed25519>>,
    coupery_ksnf::dealing::CandidateView<Ed25519>,
)> {
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
    let terminal = candidate.activate(log)?;
    let installed = pending
        .into_iter()
        .map(|share| share.resolve(terminal)?.ok_or(Error::InvalidTranscript))
        .collect::<Result<Vec<_>>>()?;
    Ok((terminal, installed, view))
}

fn participant(device: DeviceId, node: u64, share: Scalar) -> Result<DeviceParticipant<Ed25519>> {
    Ok(DeviceParticipant::new(
        device,
        Node::from_u64(node)?,
        SharePoint::new(Element::from_scalar(share)),
    ))
}

fn verify_ed25519(key: VaultKey<Ed25519>, message: &[u8], signature: [u8; 64]) -> AnyResult<()> {
    let key = VerifyingKey::from_bytes(&key.to_bytes())?;
    key.verify(message, &DalekSignature::from_bytes(&signature))?;
    Ok(())
}

fn webauthn_message() -> Vec<u8> {
    use sha2::{Digest as _, Sha256};

    let mut message = vec![0xa5; 37];
    message.extend_from_slice(&Sha256::digest(
        br#"{"type":"webauthn.get","challenge":"c","origin":"https://coupery.com"}"#,
    ));
    message
}

fn scalar(value: u64) -> Scalar {
    Ed25519::scalar_from_u64(value)
}

fn scalar_hex(value: Scalar) -> String {
    hex(value.to_bytes())
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let bytes = bytes.as_ref();
    let mut value = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        value.push(char::from(DIGITS[usize::from(byte >> 4)]));
        value.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    value
}
