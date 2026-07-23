use coupery_ksnf::Result as KResult;
use coupery_ksnf::algebra::{Element, Point, Scalar, SecretScalar};
use coupery_ksnf::keys::{AnchorId, IdentityKey, KeyEpoch, MemberPoint, SharePoint, VaultKey};
use coupery_ksnf::shamir::Node;
use coupery_ksnf::signing::{
    DeviceNonce, DeviceNonceSet, MemberResponse, Nonce, aggregate_member, aggregate_signature,
    respond_device,
};
use coupery_ksnf::support::{DeviceParticipant, InnerSupport, OuterSupport, PersonParticipant};
use coupery_ksnf::transcript::{
    MemberBody, MemberOpening, MemberRecord, MemberTranscript, RootContext, RootEntry, RootPackage,
    SigningContext,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, OuterEpoch, PersonId, Slot, VaultId,
};
use serde_json::{Value, json};

use super::{VectorCase, hex, vector};

const MESSAGE: &[u8] = b"approve transfer 42";
type AnyResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn primary() -> AnyResult<VectorCase> {
    signing_vector(
        "sign-outer-2of3-inner-2of3",
        [1, 3],
        [[1, 3], [2, 3]],
        0x66,
        10,
    )
}

pub fn alternate() -> AnyResult<VectorCase> {
    signing_vector(
        "sign-alternate-supports",
        [1, 2],
        [[2, 3], [1, 2]],
        0x67,
        40,
    )
}

pub fn multi_vault() -> AnyResult<VectorCase> {
    let identity = IdentityKey::new(Point::from_scalar(Scalar::from(31_u64))?);
    let first = one_vault(identity, 0x51, 101, 71, 5, 7)?;
    let second = one_vault(identity, 0x52, 203, 73, 11, 13)?;
    assert_ne!(first["vault_key"], second["vault_key"]);
    assert_ne!(first["member_point"], second["member_point"]);
    Ok(vector(
        "multi-vault-identity-reuse",
        json!({
            "case": "multi-vault-identity-reuse",
            "format": "coupery-ksnf-v1",
            "identity_key": point_hex(identity.point()),
            "vaults": [first, second],
            "visible_to_outer": ["member_record", "member_nonce", "member_response"],
            "not_in_root": ["identity_key", "device_id", "inner_threshold", "inner_epoch", "participating_device_subset"]
        }),
    ))
}

fn signing_vector(
    name: &'static str,
    selected_people: [u8; 2],
    selected_nodes: [[u64; 2]; 2],
    command_marker: u8,
    nonce_base: u64,
) -> AnyResult<VectorCase> {
    let vault = VaultId::new([0x55; 32]);
    let outer_epoch = OuterEpoch::new(7);
    let key = VaultKey::new(Point::from_scalar(Scalar::from(101_u64))?);
    let outer = OuterSupport::new(
        selected_people
            .iter()
            .map(|index| person_participant(*index))
            .collect::<KResult<Vec<_>>>()?,
    )?;

    let mut people = Vec::new();
    for (position, index) in selected_people.iter().enumerate() {
        people.push(person_work(
            vault,
            outer_epoch,
            &outer,
            *index,
            selected_nodes[position],
            nonce_base + u64::from(*index) * 10,
        )?);
    }
    let entries = people
        .iter()
        .map(|person| RootEntry::new(person.record, person.nonces.aggregate()))
        .collect();
    let root = RootPackage::new(
        key,
        MESSAGE.to_vec(),
        RootContext::new(vault, outer_epoch, CommandId::new([command_marker; 32])),
        &outer,
        entries,
    )?;
    let root_bytes = root.to_bytes()?;
    for person in &people {
        assert!(!contains(&root_bytes, person.person.as_bytes()));
        for device in &person.devices {
            assert!(!contains(&root_bytes, device.device.as_bytes()));
        }
    }
    let signing = SigningContext::new(&root)?;
    let signed = people
        .into_iter()
        .map(|person| sign_person(person, &root, &outer, &signing))
        .collect::<KResult<Vec<_>>>()?;
    let member_responses = signed
        .iter()
        .map(|person| person.response)
        .collect::<Vec<_>>();
    let member_vectors = signed
        .iter()
        .map(|person| person.value.clone())
        .collect::<Vec<_>>();
    let nonce_secrets = signed
        .into_iter()
        .flat_map(|person| person.nonce_secrets)
        .collect::<Vec<_>>();

    let signature = aggregate_signature(&signing, &outer, &member_responses)?;
    signature.verify(key, MESSAGE)?;
    let left = Element::from_scalar(signature.response());
    let right = Element::from(signature.nonce()) + Element::from(key.point()) * signing.challenge();
    assert_eq!(left, right);

    Ok(vector(
        name,
        json!({
            "case": name,
            "canonical": {
                "root_package": hex(root_bytes),
                "signature": hex(signature.to_bytes())
            },
            "derived": {
                "aggregate_nonce": point_hex(signing.nonce()),
                "challenge": scalar_hex(signing.challenge()),
                "equation_left": element_hex(left),
                "equation_right": element_hex(right),
                "response": scalar_hex(signature.response())
            },
            "format": "coupery-ksnf-v1",
            "members": member_vectors,
            "message": hex(MESSAGE),
            "profile": "secp256k1/plain-schnorr",
            "public_skeleton": public_skeleton()?,
            "selected_people": selected_people,
            "test_only_secret": {
                "nonces": nonce_secrets,
                "outer_polynomial": [scalar_hex(Scalar::from(101_u64)), scalar_hex(Scalar::from(17_u64))]
            },
            "vault_id": id_hex(vault.as_bytes()),
            "vault_key": point_hex(key.point())
        }),
    ))
}

struct SignedPerson {
    response: MemberResponse,
    value: Value,
    nonce_secrets: Vec<Value>,
}

fn sign_person(
    person: PersonWork,
    root: &RootPackage,
    outer: &OuterSupport,
    signing: &SigningContext<'_>,
) -> KResult<SignedPerson> {
    let body_bytes = person.body.to_bytes()?;
    let record_bytes = person.record.to_bytes();
    let salt = Scalar::from(70_u64 + u64::from(person.slot.get()));
    let opening = MemberOpening::new(person.salt, person.body);
    let opening_bytes = opening.to_bytes()?;
    let transcript = MemberTranscript::new(root.clone(), opening, outer)?;
    let mut responses = Vec::new();
    let mut response_values = Vec::new();
    let mut device_values = Vec::new();
    let mut nonce_secrets = Vec::new();
    let mut share_secrets = Vec::new();
    for device in person.devices {
        let response = respond_device(
            device.nonce,
            &transcript,
            signing,
            &person.nonces,
            device.device,
            &SecretScalar::new(device.share),
        )?;
        response_values.push(json!({
            "bytes": hex(response.to_bytes()),
            "device": id_hex(device.device.as_bytes()),
            "inner_coefficient": scalar_hex(person.inner.coefficient(device.device)?.scalar()),
            "scalar": scalar_hex(response.scalar())
        }));
        device_values.push(json!({
            "device": id_hex(device.device.as_bytes()),
            "member_share": element_hex(Element::from_scalar(device.share)),
            "node": device.node,
            "nonce": {
                "binding": point_hex(device.pair.binding()),
                "hiding": point_hex(device.pair.hiding())
            }
        }));
        nonce_secrets.push(json!({
            "binding": scalar_hex(device.binding),
            "device": id_hex(device.device.as_bytes()),
            "hiding": scalar_hex(device.hiding)
        }));
        share_secrets.push(json!({
            "device": id_hex(device.device.as_bytes()),
            "member_share": scalar_hex(device.share)
        }));
        responses.push(response);
    }
    let member = aggregate_member(&transcript, signing, &person.nonces, &responses)?;
    let value = json!({
        "binding_factor": scalar_hex(signing.binding(person.slot)?),
        "device_responses": response_values,
        "devices": device_values,
        "member_body": hex(body_bytes),
        "member_nonce": {
            "binding": point_hex(person.nonces.aggregate().binding()),
            "hiding": point_hex(person.nonces.aggregate().hiding())
        },
        "member_opening": hex(opening_bytes.as_slice()),
        "member_point": point_hex(person.member.point()),
        "member_record": hex(record_bytes),
        "member_response": {
            "bytes": hex(member.to_bytes()),
            "scalar": scalar_hex(member.scalar())
        },
        "outer_coefficient": scalar_hex(outer.coefficient(person.person)?.scalar()),
        "person": id_hex(person.person.as_bytes()),
        "slot": person.slot.get(),
        "test_only_secret": {
            "member_salt": scalar_hex(salt),
            "member_shares": share_secrets
        }
    });
    Ok(SignedPerson {
        response: member,
        value,
        nonce_secrets,
    })
}

struct PersonWork {
    person: PersonId,
    slot: Slot,
    member: MemberPoint,
    body: MemberBody,
    salt: SecretScalar,
    record: MemberRecord,
    inner: InnerSupport,
    devices: Vec<DeviceWork>,
    nonces: DeviceNonceSet,
}

struct DeviceWork {
    device: DeviceId,
    node: u64,
    share: Scalar,
    hiding: Scalar,
    binding: Scalar,
    nonce: Nonce,
    pair: coupery_ksnf::signing::NoncePair,
}

fn person_work(
    vault: VaultId,
    outer_epoch: OuterEpoch,
    outer: &OuterSupport,
    index: u8,
    nodes: [u64; 2],
    nonce_base: u64,
) -> KResult<PersonWork> {
    let person = person_id(index);
    let slot = Slot::new(u16::from(index));
    let member_secret = outer_share(index);
    let member = MemberPoint::new(Point::from_scalar(member_secret)?);
    let devices = nodes
        .iter()
        .enumerate()
        .map(|(position, node)| {
            let position =
                u64::try_from(position).map_err(|_| coupery_ksnf::Error::LengthOverflow)?;
            let hiding = Scalar::from(nonce_base + position * 4 + 1);
            let binding = Scalar::from(nonce_base + position * 4 + 2);
            let nonce = Nonce::new(hiding, binding)?;
            let pair = nonce.commitments()?;
            Ok(DeviceWork {
                device: device_id(
                    index,
                    u8::try_from(*node).map_err(|_| coupery_ksnf::Error::LengthOverflow)?,
                ),
                node: *node,
                share: member_share(index, *node),
                hiding,
                binding,
                nonce,
                pair,
            })
        })
        .collect::<KResult<Vec<_>>>()?;
    let inner = InnerSupport::new(
        devices
            .iter()
            .map(|device| {
                Ok(DeviceParticipant::new(
                    device.device,
                    Node::from_u64(device.node)?,
                    SharePoint::new(Element::from_scalar(device.share)),
                ))
            })
            .collect::<KResult<Vec<_>>>()?,
    )?;
    let body = MemberBody::new(
        IdentityKey::new(Point::from_scalar(identity_constant(index))?),
        member,
        KeyEpoch::new(
            outer_epoch,
            InnerEpoch::new(10 + u64::from(index)),
            AnchorId::new(
                vault,
                person,
                ActivationHandle::new([0x80 + index; 32]),
                ActivationHandle::new([0x90 + index; 32]),
            ),
        ),
        inner.clone(),
        outer.coefficient(person)?,
    )?;
    let salt = SecretScalar::new(Scalar::from(70_u64 + u64::from(index)));
    let record = MemberRecord::commit(&body, &salt)?;
    let nonces = DeviceNonceSet::new(
        &inner,
        devices
            .iter()
            .map(|device| DeviceNonce::new(device.device, device.pair))
            .collect(),
    )?;
    Ok(PersonWork {
        person,
        slot,
        member,
        body,
        salt,
        record,
        inner,
        devices,
        nonces,
    })
}

fn public_skeleton() -> KResult<Value> {
    let mut people = Vec::new();
    for index in 1..=3 {
        let mut devices = Vec::new();
        for node in 1..=3 {
            devices.push(json!({
                "device": id_hex(device_id(index, node).as_bytes()),
                "identity_share": element_hex(Element::from_scalar(identity_share(index, u64::from(node)))),
                "member_share": element_hex(Element::from_scalar(member_share(index, u64::from(node)))),
                "node": node
            }));
        }
        people.push(json!({
            "devices": devices,
            "identity_key": point_hex(Point::from_scalar(identity_constant(index))?),
            "member_point": point_hex(Point::from_scalar(outer_share(index))?),
            "outer_node": index,
            "person": id_hex(person_id(index).as_bytes()),
            "slot": index
        }));
    }
    Ok(json!({
        "outer_threshold": 2,
        "people": people,
        "people_count": 3
    }))
}

fn person_participant(index: u8) -> KResult<PersonParticipant> {
    Ok(PersonParticipant::new(
        person_id(index),
        Slot::new(u16::from(index)),
        Node::from_u64(u64::from(index))?,
        MemberPoint::new(Point::from_scalar(outer_share(index))?),
    ))
}

fn one_vault(
    identity: IdentityKey,
    marker: u8,
    secret: u64,
    salt_value: u64,
    hiding: u64,
    binding: u64,
) -> KResult<Value> {
    let vault = VaultId::new([marker; 32]);
    let person = PersonId::new([0xa1; 32]);
    let device = DeviceId::new([0x11; 32]);
    let member_secret = Scalar::from(secret);
    let member = MemberPoint::new(Point::from_scalar(member_secret)?);
    let key = VaultKey::new(Point::from_scalar(member_secret)?);
    let outer = OuterSupport::new(vec![PersonParticipant::new(
        person,
        Slot::new(1),
        Node::from_u64(1)?,
        member,
    )])?;
    let inner = InnerSupport::new(vec![DeviceParticipant::new(
        device,
        Node::from_u64(1)?,
        SharePoint::new(Element::from_scalar(member_secret)),
    )])?;
    let body = MemberBody::new(
        identity,
        member,
        KeyEpoch::new(
            OuterEpoch::new(1),
            InnerEpoch::new(1),
            AnchorId::new(
                vault,
                person,
                ActivationHandle::new([0x81; 32]),
                ActivationHandle::new([0x91; 32]),
            ),
        ),
        inner.clone(),
        outer.coefficient(person)?,
    )?;
    let salt = SecretScalar::new(Scalar::from(salt_value));
    let record = MemberRecord::commit(&body, &salt)?;
    let nonce = Nonce::new(Scalar::from(hiding), Scalar::from(binding))?;
    let pair = nonce.commitments()?;
    let nonces = DeviceNonceSet::new(&inner, vec![DeviceNonce::new(device, pair)])?;
    let root = RootPackage::new(
        key,
        b"vault-local request".to_vec(),
        RootContext::new(vault, OuterEpoch::new(1), CommandId::new([marker + 1; 32])),
        &outer,
        vec![RootEntry::new(record, pair)],
    )?;
    let root_bytes = root.to_bytes()?;
    assert!(!contains(
        &root_bytes,
        identity.point().to_bytes().as_slice()
    ));
    assert!(!contains(&root_bytes, device.as_bytes()));
    let transcript = MemberTranscript::new(root.clone(), MemberOpening::new(salt, body), &outer)?;
    let signing = SigningContext::new(&root)?;
    let response = respond_device(
        nonce,
        &transcript,
        &signing,
        &nonces,
        device,
        &SecretScalar::new(member_secret),
    )?;
    let member_response = aggregate_member(&transcript, &signing, &nonces, &[response])?;
    let signature = aggregate_signature(&signing, &outer, &[member_response])?;
    signature.verify(key, root.message())?;
    Ok(json!({
        "member_point": point_hex(member.point()),
        "root_package": hex(root_bytes),
        "signature": hex(signature.to_bytes()),
        "test_only_secret": {
            "binding_nonce": scalar_hex(Scalar::from(binding)),
            "hiding_nonce": scalar_hex(Scalar::from(hiding)),
            "member_share": scalar_hex(member_secret)
        },
        "vault_id": id_hex(vault.as_bytes()),
        "vault_key": point_hex(key.point())
    }))
}

fn identity_constant(index: u8) -> Scalar {
    Scalar::from(match index {
        1 => 31_u64,
        2 => 37_u64,
        _ => 41_u64,
    })
}

fn identity_slope(index: u8) -> Scalar {
    Scalar::from(match index {
        1 => 3_u64,
        2 => 5_u64,
        _ => 7_u64,
    })
}

fn member_slope(index: u8) -> Scalar {
    Scalar::from(match index {
        1 => 9_u64,
        2 => 11_u64,
        _ => 13_u64,
    })
}

fn outer_share(index: u8) -> Scalar {
    Scalar::from(101_u64) + Scalar::from(17_u64) * Scalar::from(u64::from(index))
}

fn identity_share(index: u8, node: u64) -> Scalar {
    identity_constant(index) + identity_slope(index) * Scalar::from(node)
}

fn member_share(index: u8, node: u64) -> Scalar {
    outer_share(index) + member_slope(index) * Scalar::from(node)
}

const fn person_id(index: u8) -> PersonId {
    PersonId::new([0xa0 + index; 32])
}

const fn device_id(person: u8, node: u8) -> DeviceId {
    DeviceId::new([person * 0x10 + node; 32])
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}
