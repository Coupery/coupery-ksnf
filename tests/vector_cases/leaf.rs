use coupery_ksnf::Result as KResult;
use coupery_ksnf::algebra::{Element, Scalar, SecretScalar};
use coupery_ksnf::auth::{
    AuthenticatedAbort, AuthenticatedCommitment, AuthenticatedOpening, CommitmentView, OpeningView,
    nonce_commitment,
};
use coupery_ksnf::genesis::{PublicDevice, PublicPerson, PublicPolynomial, ValidatedPublicGenesis};
use coupery_ksnf::keys::{AnchorId, KeyEpoch, SharePoint};
use coupery_ksnf::leaf::{LeafRegistry, LeafStage};
use coupery_ksnf::shamir::Node;
use coupery_ksnf::signing::{Nonce, NoncePair, Signature};
use coupery_ksnf::support::{InnerSupport, OuterSupport};
use coupery_ksnf::transcript::{
    MemberBody, MemberNonce, MemberOpening, MemberRecord, MemberReservation, RootContext,
    RootPackage, RootPrepackage, SigningContext,
};
use coupery_ksnf::types::{
    ActivationHandle, CommandId, DeviceId, InnerEpoch, LeafAttempt, OuterEpoch, PersonId,
    SessionId, VaultId,
};
use coupery_ksnf::{Error, Result};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng as _;
use serde_json::json;

use super::{VectorCase, hex, vector};

type AnyResult<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn interleaving() -> AnyResult<VectorCase> {
    let fixture = make_fixture(3, 1)?;
    let mut leaf_1 = at("leaf 1", fixture.leaf(1))?;
    let mut leaf_2 = at("leaf 2", fixture.leaf(2))?;
    let attempt_1 = at(
        "reserve 1",
        leaf_1.reserve(fixture.session, 0, &fixture.reservation, &fixture.outer),
    )?;
    let attempt_2 = at(
        "reserve 2",
        leaf_2.reserve(fixture.session, 0, &fixture.reservation, &fixture.outer),
    )?;
    let attempts = [attempt_1, attempt_2, LeafAttempt::new(fixture.device(3), 0)];
    let mut rng_1 = ChaCha20Rng::from_seed([1; 32]);
    let mut rng_2 = ChaCha20Rng::from_seed([2; 32]);
    let commitment_1 = leaf_1.commit(attempt_1, &fixture.reservation, &mut rng_1)?;
    let commitment_2 = leaf_2.commit(attempt_2, &fixture.reservation, &mut rng_2)?;

    let corrupt_a = Nonce::new(Scalar::from(31_u64), Scalar::from(37_u64))?.commitments()?;
    let corrupt_b = Nonce::new(Scalar::from(41_u64), Scalar::from(43_u64))?.commitments()?;
    let corrupt_commitment_a = nonce_commitment(attempts[2], &fixture.reservation, corrupt_a)?;
    let corrupt_commitment_b = nonce_commitment(attempts[2], &fixture.reservation, corrupt_b)?;
    let receiver_1_deliveries = commitments(
        &fixture,
        attempts,
        attempt_1,
        commitment_1,
        commitment_2,
        corrupt_commitment_a,
    );
    let commitment_view_1 = at(
        "commitment view 1",
        CommitmentView::new(&fixture.inner, receiver_1_deliveries.clone()),
    )?;
    let pair_1 = at("reveal 1", leaf_1.reveal(attempt_1, receiver_1_deliveries))?;
    assert_eq!(leaf_1.stage(), Some(LeafStage::Held));
    assert_eq!(leaf_2.stage(), Some(LeafStage::Committed));

    let receiver_2_deliveries = commitments(
        &fixture,
        attempts,
        attempt_2,
        commitment_1,
        commitment_2,
        corrupt_commitment_b,
    );
    let commitment_view_2 = at(
        "commitment view 2",
        CommitmentView::new(&fixture.inner, receiver_2_deliveries.clone()),
    )?;
    let pair_2 = at("reveal 2", leaf_2.reveal(attempt_2, receiver_2_deliveries))?;
    let openings_1 = openings(&fixture, attempts, attempt_1, &pair_1, &pair_2, &corrupt_a);
    let openings_2 = openings(&fixture, attempts, attempt_2, &pair_1, &pair_2, &corrupt_b);
    let opening_view_1 = OpeningView::new(&fixture.inner, openings_1.clone())?;
    let opening_view_2 = OpeningView::new(&fixture.inner, openings_2.clone())?;
    let aggregate_1 = at("fix 1", leaf_1.fix(attempt_1, openings_1))?;
    let aggregate_2 = at("fix 2", leaf_2.fix(attempt_2, openings_2))?;
    assert_ne!(aggregate_1, aggregate_2);

    Ok(vector(
        "receiver-interleaving",
        json!({
            "case": "receiver-interleaving",
            "commitment_views": [
                hex(commitment_view_1.to_bytes()?.as_slice()),
                hex(commitment_view_2.to_bytes()?.as_slice())
            ],
            "corrupt_receiver_specific": [
                scalar_hex(corrupt_commitment_a),
                scalar_hex(corrupt_commitment_b)
            ],
            "format": "coupery-ksnf-v1",
            "leaf_attempts": attempts.map(LeafAttempt::sequence),
            "local_aggregates": [pair_json(&aggregate_1), pair_json(&aggregate_2)],
            "opening_views": [
                hex(opening_view_1.to_bytes()?.as_slice()),
                hex(opening_view_2.to_bytes()?.as_slice())
            ],
            "reservation": hex(fixture.reservation.as_slice()),
            "schedule": [
                "reserve receiver 1",
                "reserve receiver 2",
                "commit receivers 1 and 2",
                "fix receiver 1 commitment vector",
                "reveal receiver 1",
                "fix receiver 2 commitment vector",
                "reveal receiver 2",
                "fix both opening views"
            ],
            "test_only_secret": {
                "corrupt_openings": [pair_json(&corrupt_a), pair_json(&corrupt_b)],
                "receiver_rng_seeds": [hex([1_u8; 32]), hex([2_u8; 32])]
            }
        }),
    ))
}

pub fn lifecycle() -> AnyResult<VectorCase> {
    let fixture = make_fixture(1, 2)?;
    let mut leaf = fixture.leaf(1)?;
    let mut trace = Vec::new();
    let attempt = leaf.reserve(fixture.session, 0, &fixture.reservation, &fixture.outer)?;
    trace.push(step("reserve", "reserved", "ok"));
    assert_eq!(
        leaf.reserve(fixture.session, 0, &fixture.reservation, &fixture.outer)?,
        attempt
    );
    trace.push(step("reserve exact replay", "reserved", "ok"));
    let mut rng = ChaCha20Rng::from_seed([7; 32]);
    let commitment = leaf.commit(attempt, &fixture.reservation, &mut rng)?;
    trace.push(step("commit", "committed", "ok"));
    let mut replay_rng = ChaCha20Rng::from_seed([8; 32]);
    let replay = leaf.commit(attempt, &fixture.reservation, &mut replay_rng)?;
    assert_eq!(commitment, replay);
    trace.push(step("commit exact replay", "committed", "ok"));
    let fresh = SessionId::new([0xfe; 32]);
    let busy = error_code(&leaf.reserve(fresh, 0, &fixture.reservation, &fixture.outer))?;
    trace.push(step("fresh session while live", "committed", busy));
    let delivery = AuthenticatedCommitment::new(
        attempt,
        attempt,
        fixture.session,
        &fixture.reservation,
        commitment,
    );
    let pair = leaf.reveal(attempt, vec![delivery.clone()])?;
    assert_eq!(leaf.reveal(attempt, vec![delivery])?, pair);
    trace.push(step("reveal and exact replay", "held", "ok"));
    let opening = AuthenticatedOpening::new(
        attempt,
        attempt,
        fixture.session,
        &fixture.reservation,
        pair,
    );
    assert_eq!(leaf.fix(attempt, vec![opening.clone()])?, pair);
    assert_eq!(leaf.fix(attempt, vec![opening])?, pair);
    trace.push(step("fix and exact replay", "fixed", "ok"));
    let root = RootPackage::finalize(
        fixture.prepackage.clone(),
        &fixture.outer,
        vec![MemberNonce::new(
            fixture.outer.participants()[0].slot(),
            pair,
        )],
    )?;
    let signing = SigningContext::new(&root)?;
    let response = leaf.respond(attempt, &root.to_bytes()?)?;
    Signature::new(signing.nonce(), response.scalar()).verify(root.key(), root.message())?;
    trace.push(step("respond", "closed", "ok"));
    let closed = error_code(&leaf.commit(attempt, &fixture.reservation, &mut rng))?;
    trace.push(step("post-close call", "closed", closed));
    let retry = leaf.reserve(fixture.session, 0, &fixture.reservation, &fixture.outer)?;
    assert_ne!(retry, attempt);
    trace.push(step("retry same ceremony", "reserved", "ok"));
    leaf.close(retry)?;
    trace.push(step("close retry", "closed", "ok"));

    let before_commit = close_case(&fixture, CloseCase::BeforeCommit)?;
    let after_commit = close_case(&fixture, CloseCase::AfterCommit)?;
    let timeout = close_case(&fixture, CloseCase::Timeout)?;
    let sibling_abort = close_case(&make_fixture(2, 3)?, CloseCase::SiblingAbort)?;
    let altered = close_case(&fixture, CloseCase::AlteredReplay)?;

    Ok(vector(
        "leaf-replay-and-close",
        json!({
            "case": "leaf-replay-and-close",
            "commitment": scalar_hex(commitment),
            "format": "coupery-ksnf-v1",
            "leaf_attempt": attempt.sequence(),
            "nonce_pair": pair_json(&pair),
            "reservation": hex(fixture.reservation.as_slice()),
            "response": hex(response.to_bytes()),
            "retry_attempt": retry.sequence(),
            "terminal_cases": [before_commit, after_commit, timeout, sibling_abort, altered],
            "test_only_secret": {
                "commit_rng_seed": hex([7_u8; 32]),
                "replay_rng_seed_unused": hex([8_u8; 32])
            },
            "trace": trace
        }),
    ))
}

#[derive(Clone, Copy)]
enum CloseCase {
    BeforeCommit,
    AfterCommit,
    Timeout,
    SiblingAbort,
    AlteredReplay,
}

fn close_case(fixture: &Fixture, case: CloseCase) -> KResult<serde_json::Value> {
    let mut leaf = fixture.leaf(1)?;
    let attempt = leaf.reserve(fixture.session, 0, &fixture.reservation, &fixture.outer)?;
    let mut rng = ChaCha20Rng::from_seed([9; 32]);
    let (name, result) = match case {
        CloseCase::BeforeCommit => ("abort before commit", leaf.close(attempt)),
        CloseCase::AfterCommit => {
            leaf.commit(attempt, &fixture.reservation, &mut rng)?;
            ("abort after commit", leaf.close(attempt))
        }
        CloseCase::Timeout => (
            "timeout",
            if leaf.close_expired(101) == Some(attempt) {
                Ok(())
            } else {
                Err(Error::WrongStage)
            },
        ),
        CloseCase::SiblingAbort => (
            "authenticated sibling abort",
            leaf.receive_abort(&AuthenticatedAbort::new(
                LeafAttempt::new(fixture.device(2), 0),
                attempt,
                fixture.session,
                &fixture.reservation,
            )),
        ),
        CloseCase::AlteredReplay => {
            leaf.commit(attempt, &fixture.reservation, &mut rng)?;
            let mut altered = fixture.reservation.to_vec();
            altered[0] ^= 1;
            (
                "altered same-session replay",
                leaf.commit(attempt, &altered, &mut rng).map(|_| ()),
            )
        }
    };
    let result = match result {
        Ok(()) => "ok",
        Err(error) => error.code(),
    };
    Ok(json!({
        "attempt": attempt.sequence(),
        "case": name,
        "closed": leaf.is_closed(attempt),
        "result": result,
    }))
}

struct Fixture {
    genesis: ValidatedPublicGenesis,
    person: PersonId,
    devices: Vec<DeviceId>,
    outer: OuterSupport,
    inner: InnerSupport,
    epoch: KeyEpoch,
    session: SessionId,
    reservation: zeroize::Zeroizing<Vec<u8>>,
    prepackage: RootPrepackage,
}

impl Fixture {
    fn device(&self, index: usize) -> DeviceId {
        self.devices[index - 1]
    }

    fn leaf(&self, index: usize) -> KResult<LeafRegistry> {
        let node = u64::try_from(index).map_err(|_| Error::LengthOverflow)?;
        let state = self.genesis.attach_share(
            self.person,
            self.device(index),
            SecretScalar::new(identity_share(self.devices.len(), node)),
            SecretScalar::new(member_share(self.devices.len(), node)),
        )?;
        LeafRegistry::new(state, self.epoch)
    }
}

fn make_fixture(count: u8, marker: u8) -> AnyResult<Fixture> {
    let vault = VaultId::new([0x50 + marker; 32]);
    let person = PersonId::new([0x61; 32]);
    let devices = (1..=count)
        .map(|index| DeviceId::new([0x70 + index; 32]))
        .collect::<Vec<_>>();
    let public_devices = at(
        "public devices",
        devices
            .iter()
            .enumerate()
            .map(|(index, device)| {
                let node = u64::try_from(index + 1).map_err(|_| Error::LengthOverflow)?;
                let identity = identity_share(usize::from(count), node);
                let member = member_share(usize::from(count), node);
                Ok(PublicDevice::new(
                    *device,
                    Node::from_u64(node)?,
                    SharePoint::new(Element::from_scalar(identity)),
                    SharePoint::new(Element::from_scalar(member)),
                ))
            })
            .collect::<KResult<Vec<_>>>(),
    )?;
    let identity = at("identity polynomial", polynomial(31, 3, 2, count))?;
    let member = at("member polynomial", polynomial(101, 7, 5, count))?;
    let public_person = at(
        "public person",
        PublicPerson::new(person, Node::from_u64(1)?, identity, member, public_devices),
    )?;
    let genesis = at(
        "genesis",
        ValidatedPublicGenesis::validate(
            vault,
            PublicPolynomial::new(vec![Element::from_scalar(Scalar::from(101_u64))])?,
            vec![public_person],
        ),
    )?;
    let outer = at("outer support", genesis.outer_support(&[person]))?;
    let inner = at("inner support", genesis.inner_support(person, &devices))?;
    let epoch = KeyEpoch::new(
        OuterEpoch::new(8),
        InnerEpoch::new(9),
        AnchorId::new(
            vault,
            person,
            ActivationHandle::new([0x81; 32]),
            ActivationHandle::new([0x91; 32]),
        ),
    );
    let body = at(
        "member body",
        MemberBody::new(
            genesis.person(person)?.identity_key(),
            genesis.person(person)?.member_point(),
            epoch,
            inner.clone(),
            outer.coefficient(person)?,
        ),
    )?;
    let salt = SecretScalar::new(Scalar::from(41_u64));
    let record = MemberRecord::commit(&body, &salt)?;
    let prepackage = at(
        "prepackage",
        RootPrepackage::new(
            genesis.vault_key(),
            b"leaf vector".to_vec(),
            RootContext::new(vault, epoch.outer(), CommandId::new([0x90 + marker; 32])),
            &outer,
            vec![record],
        ),
    )?;
    let session = SessionId::new([0xa0 + marker; 32]);
    let reservation = at(
        "reservation",
        MemberReservation::new(prepackage.clone(), MemberOpening::new(salt, body), &outer),
    )?
    .to_bytes(session, 100)?;
    Ok(Fixture {
        genesis,
        person,
        devices,
        outer,
        inner,
        epoch,
        session,
        reservation,
        prepackage,
    })
}

fn commitments(
    fixture: &Fixture,
    attempts: [LeafAttempt; 3],
    receiver: LeafAttempt,
    first: Scalar,
    second: Scalar,
    third: Scalar,
) -> Vec<AuthenticatedCommitment> {
    [first, second, third]
        .into_iter()
        .enumerate()
        .map(|(index, commitment)| {
            AuthenticatedCommitment::new(
                attempts[index],
                receiver,
                fixture.session,
                &fixture.reservation,
                commitment,
            )
        })
        .collect()
}

fn openings(
    fixture: &Fixture,
    attempts: [LeafAttempt; 3],
    receiver: LeafAttempt,
    first: &NoncePair,
    second: &NoncePair,
    third: &NoncePair,
) -> Vec<AuthenticatedOpening> {
    [*first, *second, *third]
        .into_iter()
        .enumerate()
        .map(|(index, nonce)| {
            AuthenticatedOpening::new(
                attempts[index],
                receiver,
                fixture.session,
                &fixture.reservation,
                nonce,
            )
        })
        .collect()
}

fn polynomial(constant: u64, linear: u64, quadratic: u64, count: u8) -> KResult<PublicPolynomial> {
    let mut points = vec![Element::from_scalar(Scalar::from(constant))];
    if count >= 2 {
        points.push(Element::from_scalar(Scalar::from(linear)));
    }
    if count >= 3 {
        points.push(Element::from_scalar(Scalar::from(quadratic)));
    }
    PublicPolynomial::new(points)
}

fn identity_share(count: usize, node: u64) -> Scalar {
    evaluate(31, 3, 2, count, node)
}

fn member_share(count: usize, node: u64) -> Scalar {
    evaluate(101, 7, 5, count, node)
}

fn evaluate(constant: u64, linear: u64, quadratic: u64, count: usize, node: u64) -> Scalar {
    let node = Scalar::from(node);
    let mut value = Scalar::from(constant);
    if count >= 2 {
        value += Scalar::from(linear) * node;
    }
    if count >= 3 {
        value += Scalar::from(quadratic) * node * node;
    }
    value
}

fn step(call: &str, state: &str, result: &str) -> serde_json::Value {
    json!({"call": call, "result": result, "state": state})
}

const fn error_code<T>(result: &Result<T>) -> KResult<&'static str> {
    match result {
        Ok(_) => Err(Error::InvalidTranscript),
        Err(error) => Ok(error.code()),
    }
}

fn pair_json(pair: &NoncePair) -> serde_json::Value {
    json!({
        "binding": hex(pair.binding().to_bytes()),
        "hiding": hex(pair.hiding().to_bytes())
    })
}

fn scalar_hex(scalar: Scalar) -> String {
    hex(<[u8; 32]>::from(scalar.to_bytes()))
}

fn at<T>(name: &str, result: KResult<T>) -> AnyResult<T> {
    result.map_err(|error| std::io::Error::other(format!("{name}: {error}")).into())
}
