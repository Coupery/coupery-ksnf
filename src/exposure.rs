//! Audit data for the paper's joint corruption restriction.

use std::collections::{BTreeMap, BTreeSet};

use crate::types::{BlockId, CommandId, DeviceId, OuterEpoch, PersonId, VaultId};
use crate::{Error, Result};

/// One member block in an activated outer epoch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberBlockSpec {
    block: BlockId,
    person: PersonId,
    threshold: u16,
    devices: BTreeSet<DeviceId>,
}

impl MemberBlockSpec {
    /// Validates one member block.
    ///
    /// # Errors
    ///
    /// Returns an error for zero threshold, too few devices, or duplicates.
    pub fn new(
        block: BlockId,
        person: PersonId,
        threshold: u16,
        devices: Vec<DeviceId>,
    ) -> Result<Self> {
        let count = devices.len();
        let devices = devices.into_iter().collect::<BTreeSet<_>>();
        if devices.len() != count {
            return Err(Error::DuplicateParticipant);
        }
        if threshold == 0 || devices.len() < usize::from(threshold) {
            return Err(Error::SupportMismatch);
        }
        Ok(Self {
            block,
            person,
            threshold,
            devices,
        })
    }

    /// Returns the block identifier.
    #[must_use]
    pub const fn block(&self) -> BlockId {
        self.block
    }

    /// Returns the person identifier.
    #[must_use]
    pub const fn person(&self) -> PersonId {
        self.person
    }
}

/// One target person's proposed device block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TargetGroup {
    person: PersonId,
    threshold: u16,
    devices: BTreeSet<DeviceId>,
}

impl TargetGroup {
    /// Validates one proposed target group.
    ///
    /// # Errors
    ///
    /// Returns an error for zero threshold or too few devices.
    pub fn new(person: PersonId, threshold: u16, devices: Vec<DeviceId>) -> Result<Self> {
        let count = devices.len();
        let devices = devices.into_iter().collect::<BTreeSet<_>>();
        if devices.len() != count {
            return Err(Error::DuplicateParticipant);
        }
        if threshold == 0 || devices.len() < usize::from(threshold) {
            return Err(Error::SupportMismatch);
        }
        Ok(Self {
            person,
            threshold,
            devices,
        })
    }

    /// Returns the person identifier.
    #[must_use]
    pub const fn person(&self) -> PersonId {
        self.person
    }
}

/// A violation of one clause in condition (1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExposureViolation {
    /// Too many member blocks are controlled in one activated outer epoch.
    ActivatedEpoch {
        /// The vault.
        vault: VaultId,
        /// The outer epoch.
        epoch: OuterEpoch,
        /// Number of controlled people.
        controlled: usize,
        /// Maximum permitted number.
        limit: usize,
    },
    /// Too many proposed outer targets are controlled.
    OuterCandidate {
        /// The candidate command.
        command: CommandId,
        /// Number of controlled target people.
        controlled: usize,
        /// Maximum permitted number.
        limit: usize,
    },
    /// An uncontrolled source member exposed to a controlled target group.
    MemberCandidate {
        /// The candidate command.
        command: CommandId,
        /// The source person.
        person: PersonId,
    },
}

/// A deterministic audit ledger for condition (1).
pub struct ExposureLedger {
    corrupt: BTreeSet<DeviceId>,
    blocks: BTreeMap<BlockId, MemberBlock>,
    epochs: BTreeMap<(VaultId, OuterEpoch), EpochRecord>,
    outer_candidates: Vec<OuterCandidate>,
    member_candidates: Vec<MemberCandidate>,
}

impl ExposureLedger {
    /// Creates a ledger with one static corrupt device set.
    #[must_use]
    pub fn new(corrupt: impl IntoIterator<Item = DeviceId>) -> Self {
        Self {
            corrupt: corrupt.into_iter().collect(),
            blocks: BTreeMap::new(),
            epochs: BTreeMap::new(),
            outer_candidates: Vec::new(),
            member_candidates: Vec::new(),
        }
    }

    /// Registers one activated outer epoch and its member blocks.
    ///
    /// # Errors
    ///
    /// Returns an error for zero outer threshold, duplicate records, or too
    /// few people.
    pub fn register_epoch(
        &mut self,
        vault: VaultId,
        epoch: OuterEpoch,
        outer_threshold: u16,
        blocks: Vec<MemberBlockSpec>,
    ) -> Result<()> {
        if outer_threshold == 0 || blocks.len() < usize::from(outer_threshold) {
            return Err(Error::SupportMismatch);
        }
        let key = (vault, epoch);
        if self.epochs.contains_key(&key) {
            return Err(Error::ReplayMismatch);
        }
        let mut people = BTreeMap::new();
        let mut pending = Vec::with_capacity(blocks.len());
        for spec in blocks {
            if people.insert(spec.person, spec.block).is_some()
                || self.blocks.contains_key(&spec.block)
                || pending
                    .iter()
                    .any(|(block, _): &(BlockId, MemberBlock)| *block == spec.block)
            {
                return Err(Error::DuplicateParticipant);
            }
            let revealed = spec.devices.intersection(&self.corrupt).copied().collect();
            pending.push((
                spec.block,
                MemberBlock {
                    person: spec.person,
                    threshold: spec.threshold,
                    devices: spec.devices,
                    revealed,
                },
            ));
        }
        for (block, record) in pending {
            self.blocks.insert(block, record);
        }
        self.epochs.insert(
            key,
            EpochRecord {
                threshold: outer_threshold,
                people,
            },
        );
        Ok(())
    }

    /// Records a retained scalar revelation from one installed block.
    ///
    /// # Errors
    ///
    /// Returns an error when the block or recipient is absent.
    pub fn reveal(&mut self, block: BlockId, recipient: DeviceId) -> Result<()> {
        let block = self
            .blocks
            .get_mut(&block)
            .ok_or(Error::ParticipantNotFound)?;
        if !block.devices.contains(&recipient) {
            return Err(Error::ParticipantNotFound);
        }
        block.revealed.insert(recipient);
        Ok(())
    }

    /// Records an outer candidate at first source exposure.
    ///
    /// # Errors
    ///
    /// Returns an error for zero threshold, too few targets, or duplicate
    /// candidate identifiers.
    pub fn expose_outer_candidate(
        &mut self,
        command: CommandId,
        threshold: u16,
        targets: &[TargetGroup],
    ) -> Result<()> {
        if threshold == 0 || targets.len() < usize::from(threshold) {
            return Err(Error::SupportMismatch);
        }
        if self.candidate_exists(command) {
            return Err(Error::ReplayMismatch);
        }
        let people = targets
            .iter()
            .map(TargetGroup::person)
            .collect::<BTreeSet<_>>();
        if people.len() != targets.len() {
            return Err(Error::DuplicateParticipant);
        }
        let controlled = targets
            .iter()
            .filter(|target| self.corrupt_count(target) >= usize::from(target.threshold))
            .count();
        self.outer_candidates.push(OuterCandidate {
            command,
            threshold,
            controlled,
        });
        Ok(())
    }

    /// Records a member candidate at first source exposure.
    ///
    /// The source-control bit is fixed at this call.
    ///
    /// # Errors
    ///
    /// Returns an error when the source block is absent or the command repeats.
    pub fn expose_member_candidate(
        &mut self,
        command: CommandId,
        source: BlockId,
        target: &TargetGroup,
    ) -> Result<()> {
        if self.candidate_exists(command) {
            return Err(Error::ReplayMismatch);
        }
        let source = self.blocks.get(&source).ok_or(Error::ParticipantNotFound)?;
        if source.person != target.person {
            return Err(Error::ParticipantMismatch);
        }
        let source_controlled = source.controlled();
        let target_controlled = self.corrupt_count(target) >= usize::from(target.threshold);
        self.member_candidates.push(MemberCandidate {
            command,
            person: target.person,
            source_controlled,
            target_controlled,
        });
        Ok(())
    }

    /// Checks all three clauses of condition (1).
    #[must_use]
    pub fn audit(&self) -> Vec<ExposureViolation> {
        let mut violations = Vec::new();
        for ((vault, epoch), record) in &self.epochs {
            let controlled = record
                .people
                .values()
                .filter(|block| self.blocks.get(block).is_some_and(MemberBlock::controlled))
                .count();
            let limit = usize::from(record.threshold) - 1;
            if controlled > limit {
                violations.push(ExposureViolation::ActivatedEpoch {
                    vault: *vault,
                    epoch: *epoch,
                    controlled,
                    limit,
                });
            }
        }
        for candidate in &self.outer_candidates {
            let limit = usize::from(candidate.threshold) - 1;
            if candidate.controlled > limit {
                violations.push(ExposureViolation::OuterCandidate {
                    command: candidate.command,
                    controlled: candidate.controlled,
                    limit,
                });
            }
        }
        for candidate in &self.member_candidates {
            if !candidate.source_controlled && candidate.target_controlled {
                violations.push(ExposureViolation::MemberCandidate {
                    command: candidate.command,
                    person: candidate.person,
                });
            }
        }
        violations
    }

    fn corrupt_count(&self, target: &TargetGroup) -> usize {
        target.devices.intersection(&self.corrupt).count()
    }

    fn candidate_exists(&self, command: CommandId) -> bool {
        self.outer_candidates
            .iter()
            .any(|candidate| candidate.command == command)
            || self
                .member_candidates
                .iter()
                .any(|candidate| candidate.command == command)
    }
}

struct MemberBlock {
    person: PersonId,
    threshold: u16,
    devices: BTreeSet<DeviceId>,
    revealed: BTreeSet<DeviceId>,
}

impl MemberBlock {
    fn controlled(&self) -> bool {
        self.revealed.len() >= usize::from(self.threshold)
    }
}

struct EpochRecord {
    threshold: u16,
    people: BTreeMap<PersonId, BlockId>,
}

struct OuterCandidate {
    command: CommandId,
    threshold: u16,
    controlled: usize,
}

struct MemberCandidate {
    command: CommandId,
    person: PersonId,
    source_controlled: bool,
    target_controlled: bool,
}
