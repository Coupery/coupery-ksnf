//! Exposure-ledger tests.

use coupery_ksnf::exposure::{ExposureLedger, ExposureViolation, MemberBlockSpec, TargetGroup};
use coupery_ksnf::types::{BlockId, CommandId, DeviceId, OuterEpoch, PersonId, VaultId};
use coupery_ksnf::{Error, Result};

#[test]
fn audit_uses_control_state_at_first_source_exposure() -> Result<()> {
    let corrupt_1 = DeviceId::new([0x11; 32]);
    let corrupt_2 = DeviceId::new([0x12; 32]);
    let honest_1 = DeviceId::new([0x21; 32]);
    let honest_2 = DeviceId::new([0x22; 32]);
    let person_1 = PersonId::new([0x31; 32]);
    let person_2 = PersonId::new([0x32; 32]);
    let block_1 = BlockId::new([0x41; 32]);
    let block_2 = BlockId::new([0x42; 32]);
    let vault = VaultId::new([0x51; 32]);
    let epoch = OuterEpoch::new(7);
    let member_before = CommandId::new([0x61; 32]);
    let member_after = CommandId::new([0x62; 32]);
    let outer = CommandId::new([0x63; 32]);
    let controlled_target = TargetGroup::new(person_1, 2, vec![corrupt_1, corrupt_2])?;

    let mut ledger = ExposureLedger::new([corrupt_1, corrupt_2]);
    ledger.register_epoch(
        vault,
        epoch,
        2,
        vec![
            MemberBlockSpec::new(block_1, person_1, 2, vec![corrupt_1, honest_1])?,
            MemberBlockSpec::new(block_2, person_2, 2, vec![corrupt_2, honest_2])?,
        ],
    )?;
    ledger.expose_member_candidate(member_before, block_1, &controlled_target)?;
    ledger.reveal(block_1, honest_1)?;
    ledger.expose_member_candidate(member_after, block_1, &controlled_target)?;
    ledger.reveal(block_2, honest_2)?;
    ledger.expose_outer_candidate(
        outer,
        2,
        &[
            controlled_target.clone(),
            TargetGroup::new(person_2, 2, vec![corrupt_1, corrupt_2])?,
        ],
    )?;

    let violations = ledger.audit();
    assert!(violations.contains(&ExposureViolation::MemberCandidate {
        command: member_before,
        person: person_1,
    }));
    assert!(!violations.contains(&ExposureViolation::MemberCandidate {
        command: member_after,
        person: person_1,
    }));
    assert!(violations.contains(&ExposureViolation::ActivatedEpoch {
        vault,
        epoch,
        controlled: 2,
        limit: 1,
    }));
    assert!(violations.contains(&ExposureViolation::OuterCandidate {
        command: outer,
        controlled: 2,
        limit: 1,
    }));
    assert_eq!(
        ledger.expose_outer_candidate(
            CommandId::new([0x64; 32]),
            2,
            &[controlled_target.clone(), controlled_target],
        ),
        Err(Error::DuplicateParticipant)
    );
    Ok(())
}
