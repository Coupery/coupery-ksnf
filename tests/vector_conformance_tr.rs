//! Published Taproot vector conformance.

#![cfg(feature = "taproot")]

mod tweaked_support;

use std::fs;
use std::path::Path;

use serde_json::{Value, json};

use coupery_ksnf::algebra::{Point, Scalar};
use coupery_ksnf::taproot::Reservation;
use coupery_ksnf::types::SessionId;

use tweaked_support::{
    DevicePlan, PersonPlan, Scenario, Session, build, reservations, sign, verifies_under_k256,
};

type AnyResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn published_taproot_vectors_match() -> AnyResult<()> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors/v1-tr");
    let update = std::env::var_os("UPDATE_VECTORS").is_some();
    for (name, value) in all()? {
        let path = root.join(format!("{name}.json"));
        let rendered = format!("{}\n", serde_json::to_string_pretty(&value)?);
        if update {
            fs::write(&path, &rendered)?;
        }
        let published: Value = serde_json::from_str(&fs::read_to_string(&path)?)?;
        assert_eq!(published, value, "{name}");
    }
    Ok(())
}

fn all() -> AnyResult<Vec<(String, Value)>> {
    Ok(vec![
        case("taproot-keypath-2of2", &two_by_two(), None)?,
        case(
            "taproot-keypath-with-tree-2of2",
            &two_by_two(),
            Some([0x5a; 32]),
        )?,
        case("taproot-keypath-mixed-inner", &mixed_inner(), None)?,
    ])
}

fn case(
    name: &str,
    scenario: &Scenario,
    merkle_root: Option<[u8; 32]>,
) -> AnyResult<(String, Value)> {
    let session = build(scenario)?;
    let signed = sign(&session, merkle_root)?;
    assert!(verifies_under_k256(&signed, &session.message));
    let signing = signed.package.signing()?;
    let key = signed.package.key();
    let signing_session = SessionId::new([scenario.command; 32]);
    let expiry = 100_u64;
    let reservations = reservations(&session, key, signing_session, expiry)?;
    for (_, bytes) in &reservations {
        let (decoded, parsed_session, parsed_expiry) =
            Reservation::from_bytes(bytes, &session.outer)?;
        assert_eq!(parsed_session, signing_session);
        assert_eq!(parsed_expiry, expiry);
        assert_eq!(decoded.key(), key);
        assert_eq!(decoded.to_bytes(parsed_session, parsed_expiry)?, *bytes);
    }
    let value = json!({
        "case": name,
        "format": "coupery-ksnf-taproot-v1",
        "profile": "secp256k1/bip340-keypath",
        "sighash": hex(session.message),
        "vault_key": point_hex(session.vault_key.point()),
        "canonical": {
            "plain_root_package": hex(session.root.to_bytes()?),
            "taproot_package": hex(signed.package.to_bytes()?),
            "taproot_reservations": reservations.iter().map(|(slot, bytes)| json!({
                "slot": slot.get(),
                "bytes": hex(bytes)
            })).collect::<Vec<_>>(),
            "signature": hex(signed.signature.to_bytes()),
            "output_key": hex(key.output_key().to_bytes()),
            "device_responses": signed.devices.iter().map(|value| hex(value.to_bytes())).collect::<Vec<_>>(),
            "member_responses": signed.members.iter().map(|value| hex(value.to_bytes())).collect::<Vec<_>>()
        },
        "reservation": {
            "session_id": hex(signing_session.as_bytes()),
            "expiry": expiry
        },
        "public": {
            "internal_key": hex(key.internal_key().to_bytes()),
            "merkle_root": merkle_root.map_or(Value::Null, |root| Value::String(hex(root))),
            "tweak": scalar_hex(key.tweak()),
            "internal_sign": key.internal_sign(),
            "output_sign": key.output_sign(),
            "nonce_sign": signing.nonce_sign(),
            "challenge": scalar_hex(signing.challenge()),
            "nonce_x": hex(signed.signature.nonce_x())
        },
        "test_only_secret": secret_json(&session)
    });
    Ok((name.to_owned(), value))
}

fn secret_json(session: &Session) -> Value {
    let members = session
        .people
        .iter()
        .map(|person| {
            let devices = person
                .devices
                .iter()
                .map(|device| {
                    json!({
                        "device": hex(device.id.as_bytes()),
                        "member_share": scalar_hex(device.share),
                        "hiding_nonce": scalar_hex(device.hiding),
                        "binding_nonce": scalar_hex(device.binding)
                    })
                })
                .collect::<Vec<_>>();
            json!({
                "slot": person.slot.get(),
                "member_secret": scalar_hex(person.member_secret),
                "devices": devices
            })
        })
        .collect::<Vec<_>>();
    json!({
        "vault_secret": scalar_hex(session.vault_secret),
        "members": members
    })
}

fn two_by_two() -> Scenario {
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
                devices: vec![device(0xa1, 1, 5, 7), device(0xa2, 2, 11, 13)],
            },
            PersonPlan {
                marker: 0x12,
                slot: 2,
                outer_node: 2,
                identity: 37,
                inner_extra: vec![11],
                devices: vec![device(0xb1, 1, 17, 19), device(0xb2, 2, 23, 29)],
            },
        ],
    }
}

fn mixed_inner() -> Scenario {
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
                    device(0xc1, 1, 3, 5),
                    device(0xc2, 2, 7, 11),
                    device(0xc3, 3, 13, 17),
                ],
            },
            PersonPlan {
                marker: 0x22,
                slot: 2,
                outer_node: 2,
                identity: 59,
                inner_extra: vec![],
                devices: vec![device(0xd1, 1, 19, 23)],
            },
        ],
    }
}

const fn device(marker: u8, node: u64, hiding: u64, binding: u64) -> DevicePlan {
    DevicePlan {
        marker,
        node,
        hiding,
        binding,
        share_override: None,
    }
}

fn hex(bytes: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn scalar_hex(scalar: Scalar) -> String {
    hex(<[u8; 32]>::from(scalar.to_bytes()))
}

fn point_hex(point: Point) -> String {
    hex(point.to_bytes())
}
