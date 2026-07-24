use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

use super::{LeafJournal, MATERIAL_HASH_DOMAIN, MaterialId};
use crate::algebra::{Element, SecretScalar};
use crate::encoding::{Decoder, Encoder};
use crate::genesis::{IdentityMap, MemberMap, OuterMap, evaluate_commitments};
use crate::keys::{IdentityKey, MemberPoint, SharePoint, VaultKey};
use crate::leaf::{LeafRegistry, VaultState};
use crate::profile::Profile;
use crate::shamir::Node;
use crate::types::{
    ActivationHandle, DeviceId, InnerEpoch, LeafAttempt, OuterEpoch, PersonId, VaultId,
};
use crate::{Error, Result};

type IdentityDevice<P> = (DeviceId, Node<P>, SharePoint<P>);
type OuterPerson<P> = (PersonId, Node<P>, MemberPoint<P>);

pub(super) fn hash_material(bytes: &[u8]) -> MaterialId {
    let mut hash = Sha256::new();
    hash.update(MATERIAL_HASH_DOMAIN);
    hash.update(bytes);
    MaterialId::new(hash.finalize().into())
}

pub(super) fn encode_material<P: Profile>(registry: &LeafRegistry<P>) -> Result<Vec<u8>> {
    if registry.live.is_some() {
        return Err(Error::Busy);
    }
    checked_len(registry.identity_map.commitments.len())?;
    checked_len(registry.identity_map.devices.len())?;
    checked_len(registry.vaults.len())?;
    for vault in registry.vaults.values() {
        checked_len(vault.member_map.commitments.len())?;
        checked_len(vault.outer_map.commitments.len())?;
        checked_len(vault.outer_map.people.len())?;
    }
    let mut encoder = Encoder::<P>::for_profile();
    encoder.put_fixed(P::MATERIAL_MAGIC);
    encoder.put_fixed(registry.device.as_bytes());
    encoder.put_fixed(registry.person.as_bytes());
    encoder.put_scalar(&registry.node.scalar());
    put_elements(&mut encoder, &registry.identity_map.commitments)?;
    put_identity_devices(&mut encoder, &registry.identity_map.devices)?;
    encoder.put_point(registry.identity_key.point());
    registry.identity.expose(|value| encoder.put_scalar(value));
    encoder.put_u64(registry.inner_epoch.get());
    encoder.put_fixed(registry.identity_handle.as_bytes());
    put_len(&mut encoder, registry.vaults.len())?;
    for (vault_id, vault) in &registry.vaults {
        encoder.put_fixed(vault_id.as_bytes());
        encoder.put_scalar(&vault.outer_node.scalar());
        encoder.put_u64(vault.outer_epoch.get());
        encoder.put_fixed(vault.member_handle.as_bytes());
        encoder.put_point(vault.member_point.point());
        encoder.put_point(vault.vault_key.point());
        put_elements(&mut encoder, &vault.member_map.commitments)?;
        put_elements(&mut encoder, &vault.outer_map.commitments)?;
        put_outer_people(&mut encoder, &vault.outer_map.people)?;
        vault.anchor.expose(|value| encoder.put_scalar(value));
    }
    Ok(encoder.finish())
}

pub(super) fn decode_material<P: Profile>(bytes: &[u8]) -> Result<LeafRegistry<P>> {
    let mut decoder = Decoder::<P>::for_profile(bytes);
    if decoder.get_fixed::<8>()? != *P::MATERIAL_MAGIC {
        return Err(Error::ProtocolMismatch);
    }
    let device = DeviceId::new(decoder.get_fixed()?);
    let person = PersonId::new(decoder.get_fixed()?);
    let node = Node::new(decoder.get_scalar()?)?;
    let commitments = get_elements(&mut decoder)?;
    let devices = get_identity_devices(&mut decoder)?;
    let identity_key = IdentityKey::new(decoder.get_point()?);
    let identity = SecretScalar::new(decoder.get_scalar()?);
    let inner_epoch = InnerEpoch::new(decoder.get_u64()?);
    let identity_handle = ActivationHandle::new(decoder.get_fixed()?);
    let vault_count = decoder.get_u32()?;
    if vault_count == 0 {
        return Err(Error::EmptyInput);
    }
    let mut vaults = BTreeMap::new();
    let mut previous_vault = None;
    for _ in 0..vault_count {
        let vault_id = VaultId::new(decoder.get_fixed()?);
        if previous_vault.is_some_and(|previous| previous >= vault_id) {
            return Err(Error::DuplicateParticipant);
        }
        previous_vault = Some(vault_id);
        let state = VaultState {
            outer_node: Node::new(decoder.get_scalar()?)?,
            outer_epoch: OuterEpoch::new(decoder.get_u64()?),
            member_handle: ActivationHandle::new(decoder.get_fixed()?),
            member_point: MemberPoint::new(decoder.get_point()?),
            vault_key: VaultKey::new(decoder.get_point()?),
            member_map: MemberMap {
                commitments: get_elements(&mut decoder)?,
            },
            outer_map: OuterMap {
                commitments: get_elements(&mut decoder)?,
                people: get_outer_people(&mut decoder)?,
            },
            anchor: SecretScalar::new(decoder.get_scalar()?),
        };
        if vaults.insert(vault_id, state).is_some() {
            return Err(Error::DuplicateParticipant);
        }
    }
    decoder.finish()?;
    let registry = LeafRegistry {
        device,
        person,
        node,
        identity_map: IdentityMap {
            commitments,
            devices,
        },
        identity_key,
        identity,
        inner_epoch,
        identity_handle,
        vaults,
        live: None,
        next_sequence: 0,
    };
    validate_material(&registry)?;
    Ok(registry)
}

fn validate_material<P: Profile>(registry: &LeafRegistry<P>) -> Result<()> {
    let commitments = &registry.identity_map.commitments;
    if commitments.is_empty() || commitments.len() > registry.identity_map.devices.len() {
        return Err(Error::SupportMismatch);
    }
    if commitments[0] != Element::from(registry.identity_key.point()) {
        return Err(Error::ShareMismatch);
    }
    let mut previous_device = None;
    let mut nodes = Vec::new();
    let mut own_share = None;
    for (device, node, share) in &registry.identity_map.devices {
        if previous_device.is_some_and(|previous| previous >= *device) {
            return Err(Error::DuplicateParticipant);
        }
        if nodes.contains(node) {
            return Err(Error::DuplicateNode);
        }
        nodes.push(*node);
        previous_device = Some(*device);
        if evaluate_commitments(commitments, *node) != share.element() {
            return Err(Error::ShareMismatch);
        }
        if *device == registry.device {
            if *node != registry.node {
                return Err(Error::ParticipantMismatch);
            }
            own_share = Some(*share);
        }
    }
    let own_share = own_share.ok_or(Error::ParticipantNotFound)?;
    if registry
        .identity
        .expose(|value| Element::from_scalar(*value))
        != own_share.element()
    {
        return Err(Error::ShareMismatch);
    }
    for vault in registry.vaults.values() {
        validate_vault(registry, vault)?;
    }
    Ok(())
}

fn validate_vault<P: Profile>(registry: &LeafRegistry<P>, vault: &VaultState<P>) -> Result<()> {
    if vault.member_map.commitments.len() != registry.identity_map.commitments.len()
        || vault.member_map.commitments.first().copied()
            != Some(Element::from(vault.member_point.point()))
        || vault.outer_map.commitments.is_empty()
        || vault.outer_map.commitments.len() > vault.outer_map.people.len()
        || vault.outer_map.commitments.first().copied()
            != Some(Element::from(vault.vault_key.point()))
    {
        return Err(Error::SupportMismatch);
    }
    let signing_public = registry
        .identity
        .expose(|identity| Element::from_scalar(*identity))
        + vault.anchor.expose(|anchor| Element::from_scalar(*anchor));
    if evaluate_commitments(&vault.member_map.commitments, registry.node) != signing_public {
        return Err(Error::ShareMismatch);
    }
    let mut previous_person = None;
    let mut nodes = Vec::new();
    let mut own = None;
    for (person, node, member) in &vault.outer_map.people {
        if previous_person.is_some_and(|previous| previous >= *person) {
            return Err(Error::DuplicateParticipant);
        }
        if nodes.contains(node) {
            return Err(Error::DuplicateNode);
        }
        previous_person = Some(*person);
        nodes.push(*node);
        if evaluate_commitments(&vault.outer_map.commitments, *node)
            != Element::from(member.point())
        {
            return Err(Error::ShareMismatch);
        }
        if *person == registry.person {
            own = Some((*node, *member));
        }
    }
    if own == Some((vault.outer_node, vault.member_point)) {
        Ok(())
    } else {
        Err(Error::ParticipantMismatch)
    }
}

fn put_elements<P: Profile>(encoder: &mut Encoder<P>, elements: &[Element<P>]) -> Result<()> {
    put_len(encoder, elements.len())?;
    for element in elements {
        encoder.put_element(*element);
    }
    Ok(())
}

fn get_elements<P: Profile>(decoder: &mut Decoder<'_, P>) -> Result<Vec<Element<P>>> {
    let count = decoder.get_u32()?;
    let mut elements = Vec::new();
    for _ in 0..count {
        elements.push(decoder.get_element()?);
    }
    Ok(elements)
}

fn put_outer_people<P: Profile>(encoder: &mut Encoder<P>, people: &[OuterPerson<P>]) -> Result<()> {
    put_len(encoder, people.len())?;
    for (person, node, member) in people {
        encoder.put_fixed(person.as_bytes());
        encoder.put_scalar(&node.scalar());
        encoder.put_point(member.point());
    }
    Ok(())
}

fn get_outer_people<P: Profile>(decoder: &mut Decoder<'_, P>) -> Result<Vec<OuterPerson<P>>> {
    let count = decoder.get_u32()?;
    let mut people = Vec::new();
    for _ in 0..count {
        people.push((
            PersonId::new(decoder.get_fixed()?),
            Node::new(decoder.get_scalar()?)?,
            MemberPoint::new(decoder.get_point()?),
        ));
    }
    Ok(people)
}

fn put_identity_devices<P: Profile>(
    encoder: &mut Encoder<P>,
    devices: &[(DeviceId, Node<P>, SharePoint<P>)],
) -> Result<()> {
    put_len(encoder, devices.len())?;
    for (device, node, share) in devices {
        encoder.put_fixed(device.as_bytes());
        encoder.put_scalar(&node.scalar());
        encoder.put_element(share.element());
    }
    Ok(())
}

fn get_identity_devices<P: Profile>(
    decoder: &mut Decoder<'_, P>,
) -> Result<Vec<IdentityDevice<P>>> {
    let count = decoder.get_u32()?;
    let mut devices = Vec::new();
    for _ in 0..count {
        devices.push((
            DeviceId::new(decoder.get_fixed()?),
            Node::new(decoder.get_scalar()?)?,
            SharePoint::new(decoder.get_element()?),
        ));
    }
    Ok(devices)
}

pub(super) fn encode_journal<P: Profile>(journal: &LeafJournal<P>) -> [u8; 89] {
    let mut bytes = [0_u8; 89];
    bytes[..8].copy_from_slice(P::JOURNAL_MAGIC);
    bytes[8..40].copy_from_slice(journal.device.as_bytes());
    bytes[40..72].copy_from_slice(journal.material.as_bytes());
    bytes[72..80].copy_from_slice(&journal.next_sequence.to_be_bytes());
    if let Some(attempt) = journal.live {
        bytes[80] = 1;
        bytes[81..].copy_from_slice(&attempt.sequence().to_be_bytes());
    }
    bytes
}

pub(super) fn decode_journal<P: Profile>(bytes: &[u8]) -> Result<LeafJournal<P>> {
    let mut decoder = Decoder::<P>::for_profile(bytes);
    if decoder.get_fixed::<8>()? != *P::JOURNAL_MAGIC {
        return Err(Error::ProtocolMismatch);
    }
    let device = DeviceId::new(decoder.get_fixed()?);
    let material = MaterialId::new(decoder.get_fixed()?);
    let next_sequence = decoder.get_u64()?;
    let live_tag = decoder.get_u8()?;
    let live_sequence = decoder.get_u64()?;
    let live = if live_tag == 0 && live_sequence == 0 {
        None
    } else if live_tag == 1 {
        Some(LeafAttempt::new(device, live_sequence))
    } else {
        return Err(Error::InvalidTranscript);
    };
    decoder.finish()?;
    LeafJournal::new(device, material, next_sequence, live)
}

fn put_len<P: Profile>(encoder: &mut Encoder<P>, len: usize) -> Result<()> {
    encoder.put_u32(checked_len(len)?);
    Ok(())
}

fn checked_len(len: usize) -> Result<u32> {
    u32::try_from(len).map_err(|_| Error::LengthOverflow)
}
