//! Taproot signing tests.

#![cfg(feature = "taproot")]

mod tweaked_support;

use std::collections::BTreeSet;

use coupery_ksnf::algebra::{Point, Scalar};
use coupery_ksnf::keys::VaultKey;
use coupery_ksnf::profile::Secp256k1;
use coupery_ksnf::shamir::{Node, interpolate_constant};
use coupery_ksnf::taproot::{DeviceResponse, Key, MemberResponse, Signature, XOnlyKey};
use coupery_ksnf::types::DeviceId;
use coupery_ksnf::{Error, Result};

use tweaked_support::{
    DevicePlan, PersonPlan, Scenario, Session, build, redistribute_inner, sign,
    verifies_bytes_under_k256, verifies_under_k256,
};

type AnyResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

const fn dev(marker: u8, node: u64, hiding: u64, binding: u64) -> DevicePlan {
    DevicePlan {
        marker,
        node,
        hiding,
        binding,
        share_override: None,
    }
}

fn shape_two_by_two() -> Scenario {
    Scenario {
        vault_secret: 101,
        outer_extra: vec![17],
        message: [0x42; 32],
        command: 0x66,
        people: vec![
            PersonPlan {
                marker: 0x11,
                slot: 1,
                outer_node: 1,
                identity: 31,
                inner_extra: vec![9],
                devices: vec![dev(0xa1, 1, 5, 7), dev(0xa2, 2, 11, 13)],
            },
            PersonPlan {
                marker: 0x12,
                slot: 2,
                outer_node: 2,
                identity: 37,
                inner_extra: vec![11],
                devices: vec![dev(0xb1, 1, 17, 19), dev(0xb2, 2, 23, 29)],
            },
        ],
    }
}

fn shape_mixed_inner() -> Scenario {
    Scenario {
        vault_secret: 220,
        outer_extra: vec![41],
        message: [0x71; 32],
        command: 0x71,
        people: vec![
            PersonPlan {
                marker: 0x21,
                slot: 1,
                outer_node: 1,
                identity: 53,
                inner_extra: vec![9, 3],
                devices: vec![
                    dev(0xc1, 1, 3, 5),
                    dev(0xc2, 2, 7, 11),
                    dev(0xc3, 3, 13, 17),
                ],
            },
            PersonPlan {
                marker: 0x22,
                slot: 2,
                outer_node: 2,
                identity: 59,
                inner_extra: vec![],
                devices: vec![dev(0xd1, 1, 19, 23)],
            },
        ],
    }
}

fn shape_three_by_two() -> Scenario {
    Scenario {
        vault_secret: 307,
        outer_extra: vec![17, 5],
        message: [0x77; 32],
        command: 0x77,
        people: vec![
            PersonPlan {
                marker: 0x31,
                slot: 1,
                outer_node: 1,
                identity: 61,
                inner_extra: vec![9],
                devices: vec![dev(0xe1, 1, 5, 7), dev(0xe2, 2, 11, 13)],
            },
            PersonPlan {
                marker: 0x32,
                slot: 2,
                outer_node: 2,
                identity: 67,
                inner_extra: vec![11],
                devices: vec![dev(0xf1, 1, 17, 19), dev(0xf2, 2, 23, 29)],
            },
            PersonPlan {
                marker: 0x33,
                slot: 3,
                outer_node: 3,
                identity: 71,
                inner_extra: vec![13],
                devices: vec![dev(0x41, 1, 31, 37), dev(0x42, 2, 41, 43)],
            },
        ],
    }
}

#[test]
fn nested_taproot_signatures_verify_at_both_boundaries() -> Result<()> {
    for scenario in [
        shape_two_by_two(),
        shape_mixed_inner(),
        shape_three_by_two(),
    ] {
        let session = build(&scenario)?;
        for merkle_root in [None, Some([0x5a; 32])] {
            let signed = sign(&session, merkle_root)?;
            let signing = signed.package.signing()?;
            let key = signed.package.key();
            assert_eq!(key.merkle_root(), merkle_root);
            signed
                .signature
                .verify(key.output_key(), signed.package.sighash())?;
            assert!(verifies_under_k256(&signed, &session.message));
            let signature_bytes: [u8; 64] = signed.signature.into();
            assert_eq!(
                Signature::try_from(signature_bytes.as_slice())?,
                signed.signature
            );
            let response_bytes: [u8; 74] = signed.devices[0].into();
            assert_eq!(
                DeviceResponse::try_from(response_bytes.as_slice())?,
                signed.devices[0]
            );
            let member_bytes: [u8; 36] = signed.members[0].into();
            assert_eq!(
                MemberResponse::try_from(member_bytes.as_slice())?,
                signed.members[0]
            );

            let first = &session.people[0];
            assert_eq!(
                signing.aggregate_member(
                    &first.transcript,
                    &first.nonces,
                    &signed.devices[..first.devices.len() - 1],
                ),
                Err(Error::SupportMismatch)
            );
            let mut changed = signed.devices[..first.devices.len()].to_vec();
            changed[0] =
                DeviceResponse::new(changed[0].attempt(), changed[0].scalar() + Scalar::ONE);
            assert_eq!(
                signing.aggregate_member(&first.transcript, &first.nonces, &changed),
                Err(Error::InvalidPartial)
            );
            assert_eq!(
                signing.aggregate_signature(
                    &session.outer,
                    &signed.members[..signed.members.len() - 1],
                ),
                Err(Error::SupportMismatch)
            );

            let mut tampered = signed.signature.to_bytes();
            tampered[40] ^= 1;
            assert!(!verifies_bytes_under_k256(
                &tampered,
                &key.output_key().to_bytes(),
                &session.message,
            ));
        }
    }
    Ok(())
}

#[test]
fn output_key_survives_inner_redistribution() -> Result<()> {
    let session_one = build(&shape_two_by_two())?;
    let signed_one = sign(&session_one, None)?;
    let member_secret = member_one_secret(&session_one);
    let old = old_inner_group(&session_one);
    let new_ids = [
        (DeviceId::new([0x51; 32]), 1_u64),
        (DeviceId::new([0x52; 32]), 2_u64),
        (DeviceId::new([0x53; 32]), 3_u64),
    ];
    let redistributed = redistribute_inner(member_secret, &old, &new_ids, 2, 0x30, [9; 32])?;
    let nodes = redistributed
        .iter()
        .map(|(_, node, _)| Node::from_u64(*node))
        .collect::<Result<Vec<_>>>()?;
    let shares = redistributed
        .iter()
        .map(|(_, _, share)| *share)
        .collect::<Vec<_>>();
    assert_eq!(
        interpolate_constant::<Secp256k1>(&nodes, &shares)?,
        member_secret
    );

    let session_two = build(&second_scenario(&redistributed))?;
    let signed_two = sign(&session_two, None)?;
    assert_eq!(
        signed_one.package.key().output_key(),
        signed_two.package.key().output_key()
    );
    assert!(verifies_under_k256(&signed_one, &session_one.message));
    assert!(verifies_under_k256(&signed_two, &session_two.message));
    Ok(())
}

#[test]
fn all_parity_combinations_verify() -> Result<()> {
    let mut seen = BTreeSet::new();
    for secret in 1..400_u64 {
        let session = build(&single_device(
            secret,
            5,
            7,
            u8::try_from(secret).unwrap_or(0),
        ))?;
        let signed = sign(&session, None)?;
        let key = signed.package.key();
        let signing = signed.package.signing()?;
        seen.insert((key.internal_sign(), key.output_sign(), signing.nonce_sign()));
        assert!(verifies_under_k256(&signed, &session.message));
        if seen.len() == 8 {
            break;
        }
    }
    assert_eq!(seen.len(), 8);
    Ok(())
}

#[test]
fn bip341_output_keys_match_reference_vectors() -> AnyResult<()> {
    for (internal, merkle_root, tweak, output) in [
        (
            "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d",
            None,
            "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70",
            "53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343",
        ),
        (
            "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27",
            Some("5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21"),
            "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001",
            "147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3",
        ),
    ] {
        let internal_x = decode_hex::<32>(internal)?;
        let mut point = [0_u8; 33];
        point[0] = 2;
        point[1..].copy_from_slice(&internal_x);
        let vault = VaultKey::new(Point::from_bytes(&point)?);
        let merkle_root = merkle_root.map(decode_hex::<32>).transpose()?;
        let expected = decode_hex(output)?;
        let key = Key::new(vault, merkle_root)?;
        assert_eq!(<[u8; 32]>::from(key.tweak().to_bytes()), decode_hex(tweak)?);
        assert_eq!(<[u8; 32]>::from(key.output_key()), expected);
        assert_eq!(XOnlyKey::try_from(expected)?, key.output_key());
    }
    Ok(())
}

fn member_one_secret(session: &Session) -> Scalar {
    session.people[0].member_secret
}

fn old_inner_group(session: &Session) -> Vec<(DeviceId, u64, Scalar)> {
    session.people[0]
        .devices
        .iter()
        .map(|device| (device.id, device.node, device.share))
        .collect()
}

fn second_scenario(redistributed: &[(DeviceId, u64, Scalar)]) -> Scenario {
    let devices = redistributed
        .iter()
        .take(2)
        .enumerate()
        .map(|(index, (_, node, share))| DevicePlan {
            marker: 0x61 + u8::try_from(index).unwrap_or(0),
            node: *node,
            hiding: 40 + *node,
            binding: 50 + *node,
            share_override: Some(*share),
        })
        .collect();
    Scenario {
        vault_secret: 101,
        outer_extra: vec![17],
        message: [0x68; 32],
        command: 0x68,
        people: vec![
            PersonPlan {
                marker: 0x11,
                slot: 1,
                outer_node: 1,
                identity: 31,
                inner_extra: vec![9],
                devices,
            },
            PersonPlan {
                marker: 0x12,
                slot: 2,
                outer_node: 2,
                identity: 37,
                inner_extra: vec![11],
                devices: vec![dev(0xb1, 1, 17, 19), dev(0xb2, 2, 23, 29)],
            },
        ],
    }
}

fn single_device(secret: u64, hiding: u64, binding: u64, command: u8) -> Scenario {
    Scenario {
        vault_secret: secret,
        outer_extra: vec![],
        message: [command; 32],
        command,
        people: vec![PersonPlan {
            marker: 0x11,
            slot: 1,
            outer_node: 1,
            identity: 3,
            inner_extra: vec![],
            devices: vec![dev(0xa1, 1, hiding, binding)],
        }],
    }
}

fn decode_hex<const N: usize>(input: &str) -> AnyResult<[u8; N]> {
    if input.len() != N * 2 {
        return Err("wrong hex length".into());
    }
    let mut bytes = Vec::with_capacity(N);
    for index in 0..N {
        bytes.push(u8::from_str_radix(&input[index * 2..index * 2 + 2], 16)?);
    }
    bytes.try_into().map_err(|_| "wrong hex length".into())
}
