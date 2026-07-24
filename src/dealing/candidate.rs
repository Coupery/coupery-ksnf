use std::collections::{BTreeMap, BTreeSet};

use crate::algebra::{Element, ScalarFor};
use crate::encoding::Encoder;
use crate::log_act::{LogAct, LogPhase, Terminal};
use crate::profile::{DefaultProfile, Profile};
use crate::types::CommandId;
use crate::{Error, Result};

use super::contribution::aggregate_points;
use super::{
    CandidateView, Command, Contribution, Opening, ReleasedContribution, RoleId, TargetId,
    TargetReceipt, TargetShape, count_u16,
};

/// One independent redistribution transcript.
///
/// Inner changes use [`InnerBundle`].
pub struct Candidate<P: Profile = DefaultProfile> {
    command: Command<P>,
    commitments: BTreeMap<RoleId, ScalarFor<P>>,
    commit_closed: bool,
    openings: BTreeMap<RoleId, Opening<P>>,
    receipts: BTreeMap<TargetId, TargetReceipt<P>>,
    view: Option<CandidateView<P>>,
    terminal: Option<Terminal>,
    stage: CandidateStage,
}

impl<P: Profile> Candidate<P> {
    /// Starts one transcript in `log`.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid command replay or stale predecessor.
    pub fn new(command: Command<P>, log: &mut impl LogAct) -> Result<Self> {
        log.begin(
            command.scope,
            command.command,
            command.predecessor,
            &command.to_bytes()?,
        )?;
        Ok(Self {
            command,
            commitments: BTreeMap::new(),
            commit_closed: false,
            openings: BTreeMap::new(),
            receipts: BTreeMap::new(),
            view: None,
            terminal: None,
            stage: CandidateStage::Commit,
        })
    }

    /// Posts one role commitment.
    ///
    /// Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error for an unknown role, wrong phase, or altered replay.
    pub fn commit(
        &mut self,
        role: RoleId,
        commitment: ScalarFor<P>,
        log: &mut impl LogAct,
    ) -> Result<()> {
        if let Some(existing) = self.commitments.get(&role) {
            return if *existing == commitment {
                Ok(())
            } else {
                self.abort_with(log, Error::ReplayMismatch)
            };
        }
        if self.stage != CandidateStage::Commit || self.command.role(role).is_err() {
            return self.abort_with(log, Error::WrongStage);
        }
        let mut encoder = Encoder::<P>::for_profile();
        encoder.put_scalar(&commitment);
        if let Err(error) = log.post(
            self.command.command,
            LogPhase::Commit,
            &role.bytes::<P>(),
            &encoder.finish(),
        ) {
            return self.abort_with(log, error);
        }
        self.commitments.insert(role, commitment);
        Ok(())
    }

    /// Closes the commit phase after every role posts.
    ///
    /// # Errors
    ///
    /// Returns an error and aborts when a role is missing.
    pub fn close_commitments(&mut self, log: &mut impl LogAct) -> Result<()> {
        if self.commit_closed {
            return Ok(());
        }
        if self.terminal.is_some() {
            return Err(Error::AlreadyTerminal);
        }
        if self.stage != CandidateStage::Commit
            || self.commitments.len() != self.command.roles.len()
            || self
                .command
                .roles
                .iter()
                .any(|role| !self.commitments.contains_key(&role.role))
        {
            return self.abort_with(log, Error::SupportMismatch);
        }
        if let Err(error) = log.close_phase(self.command.command, LogPhase::Commit) {
            return self.abort_with(log, error);
        }
        self.commit_closed = true;
        self.stage = CandidateStage::Open;
        Ok(())
    }

    /// Posts and validates one role opening.
    ///
    /// Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error and aborts for an invalid opening or altered replay.
    pub fn open(&mut self, opening: Opening<P>, log: &mut impl LogAct) -> Result<()> {
        let role = opening.role;
        if let Some(existing) = self.openings.get(&role) {
            return if existing == &opening {
                Ok(())
            } else {
                self.abort_with(log, Error::ReplayMismatch)
            };
        }
        if self.stage != CandidateStage::Open {
            return self.abort_with(log, Error::WrongStage);
        }
        let spec = match self.command.role(role) {
            Ok(value) => value,
            Err(error) => return self.abort_with(log, error),
        };
        let valid = opening
            .points
            .validate(&self.command.shape, spec.constant)
            .and_then(|()| {
                let commitment = self
                    .commitments
                    .get(&role)
                    .copied()
                    .ok_or(Error::CommitmentMismatch)?;
                if opening.commitment(&self.command)? == commitment {
                    Ok(())
                } else {
                    Err(Error::CommitmentMismatch)
                }
            });
        if let Err(error) = valid {
            return self.abort_with(log, error);
        }
        let bytes = match opening.to_bytes() {
            Ok(value) => value,
            Err(error) => return self.abort_with(log, error),
        };
        if let Err(error) = log.post(
            self.command.command,
            LogPhase::Open,
            &role.bytes::<P>(),
            &bytes,
        ) {
            return self.abort_with(log, error);
        }
        self.openings.insert(role, opening);
        Ok(())
    }

    /// Posts one local contribution and permits its private deliveries.
    ///
    /// # Errors
    ///
    /// Returns an error and aborts for a stale predecessor or invalid opening.
    pub fn open_contribution<'a>(
        &mut self,
        contribution: &'a Contribution<P>,
        log: &mut impl LogAct,
    ) -> Result<ReleasedContribution<'a, P>> {
        self.open(contribution.opening(), log)?;
        Ok(ReleasedContribution::new(contribution))
    }

    /// Closes the opening phase and returns the common target view.
    ///
    /// # Errors
    ///
    /// Returns an error and aborts when a role is missing.
    pub fn close_openings(&mut self, log: &mut impl LogAct) -> Result<CandidateView<P>> {
        if let Some(view) = &self.view {
            return Ok(view.clone());
        }
        if self.stage != CandidateStage::Open
            || self.openings.len() != self.command.roles.len()
            || self
                .command
                .roles
                .iter()
                .any(|role| !self.openings.contains_key(&role.role))
        {
            return self.abort_with(log, Error::SupportMismatch);
        }
        let view = match self.build_view() {
            Ok(value) => value,
            Err(error) => return self.abort_with(log, error),
        };
        if let Err(error) = log.close_phase(self.command.command, LogPhase::Open) {
            return self.abort_with(log, error);
        }
        self.stage = CandidateStage::Receipt;
        self.view = Some(view.clone());
        Ok(view)
    }

    /// Posts one authenticated target receipt.
    ///
    /// Exact replay is idempotent.
    ///
    /// # Errors
    ///
    /// Returns an error and aborts for a changed command, view, or target.
    pub fn receipt(&mut self, receipt: TargetReceipt<P>, log: &mut impl LogAct) -> Result<()> {
        if let Some(existing) = self.receipts.get(&receipt.target) {
            return if existing == &receipt {
                Ok(())
            } else {
                self.abort_with(log, Error::ReplayMismatch)
            };
        }
        if self.stage != CandidateStage::Receipt
            || receipt.command != self.command.command
            || !self.command.shape.targets().contains(&receipt.target)
        {
            return self.abort_with(log, Error::InvalidTranscript);
        }
        let Some(view) = &self.view else {
            return self.abort_with(log, Error::WrongStage);
        };
        if receipt.view != view.bytes {
            return self.abort_with(log, Error::InvalidTranscript);
        }
        let bytes = match receipt.to_bytes() {
            Ok(value) => value,
            Err(error) => return self.abort_with(log, error),
        };
        let mut role = Encoder::<P>::for_profile();
        receipt.target.encode(&mut role);
        if let Err(error) = log.post(
            self.command.command,
            LogPhase::Receipt,
            &role.finish(),
            &bytes,
        ) {
            return self.abort_with(log, error);
        }
        self.receipts.insert(receipt.target, receipt);
        Ok(())
    }

    /// Activates after every target receipt.
    ///
    /// # Errors
    ///
    /// Returns an error and aborts when a receipt is missing or the
    /// predecessor is stale.
    pub fn activate(&mut self, log: &mut impl LogAct) -> Result<Terminal> {
        if let Some(terminal) = self.terminal {
            return match terminal {
                Terminal::Activated(_) => Ok(terminal),
                Terminal::Aborted => Err(Error::AlreadyTerminal),
            };
        }
        self.prepare(log)?;
        match log.activate(self.command.command) {
            Ok(terminal) => {
                self.stage = CandidateStage::Terminal;
                self.terminal = Some(terminal);
                Ok(terminal)
            }
            Err(error) => self.abort_with(log, error),
        }
    }

    /// Aborts and retains the emitted prefix.
    ///
    /// # Errors
    ///
    /// Returns an error only when the transcript already activated.
    pub fn abort(&mut self, log: &mut impl LogAct) -> Result<Terminal> {
        if let Some(terminal) = self.terminal {
            return match terminal {
                Terminal::Aborted => Ok(terminal),
                Terminal::Activated(_) => Err(Error::AlreadyTerminal),
            };
        }
        let terminal = log.abort(self.command.command)?;
        self.stage = CandidateStage::Terminal;
        self.terminal = Some(terminal);
        Ok(terminal)
    }

    /// Returns the immutable command.
    #[must_use]
    pub const fn command(&self) -> &Command<P> {
        &self.command
    }

    fn prepare(&mut self, log: &mut impl LogAct) -> Result<()> {
        if self.stage == CandidateStage::Ready {
            return Ok(());
        }
        if self.stage != CandidateStage::Receipt
            || self.receipts.len() != self.command.shape.targets().len()
        {
            return self.abort_with(log, Error::SupportMismatch);
        }
        if let Err(error) = log.close_phase(self.command.command, LogPhase::Receipt) {
            return self.abort_with(log, error);
        }
        self.stage = CandidateStage::Ready;
        Ok(())
    }

    fn build_view(&self) -> Result<CandidateView<P>> {
        let commitments = self
            .commitments
            .iter()
            .map(|(role, value)| (*role, *value))
            .collect::<Vec<_>>();
        let openings = self.openings.values().cloned().collect::<Vec<_>>();
        let aggregate = aggregate_points(&openings)?;
        aggregate.validate(&self.command.shape, Element::from(self.command.anchor))?;
        let bytes = encode_candidate_view(&self.command, &commitments, &openings)?;
        Ok(CandidateView {
            command: self.command.clone(),
            commitments,
            openings,
            bytes,
            aggregate,
        })
    }

    fn abort_with<T>(&mut self, log: &mut impl LogAct, error: Error) -> Result<T> {
        if let Ok(terminal) = log.abort(self.command.command) {
            self.terminal = Some(terminal);
        }
        self.stage = CandidateStage::Terminal;
        Err(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CandidateStage {
    Commit,
    Open,
    Receipt,
    Ready,
    Terminal,
}

/// One person-global inner redistribution bundle.
pub struct InnerBundle<P: Profile = DefaultProfile> {
    candidates: BTreeMap<CommandId, Candidate<P>>,
}

impl<P: Profile> InnerBundle<P> {
    /// Starts identity and member candidates on one target shape.
    ///
    /// Every command starts before any commitment may open.
    ///
    /// # Errors
    ///
    /// Returns an error for fewer than two commands, duplicate identifiers or
    /// scopes, unequal target shapes, or a failed command start.
    pub fn new(mut commands: Vec<Command<P>>, log: &mut impl LogAct) -> Result<Self> {
        if commands.len() < 2 {
            return Err(Error::SupportMismatch);
        }
        commands.sort_unstable_by_key(Command::id);
        if commands.windows(2).any(|pair| pair[0].id() == pair[1].id()) {
            return Err(Error::DuplicateParticipant);
        }
        let scopes = commands.iter().map(Command::scope).collect::<BTreeSet<_>>();
        if scopes.len() != commands.len() {
            return Err(Error::DuplicateParticipant);
        }
        let shape = commands.first().ok_or(Error::EmptyInput)?.shape();
        if !matches!(shape, TargetShape::Single(_))
            || commands.iter().any(|command| command.shape() != shape)
        {
            return Err(Error::SupportMismatch);
        }

        let mut candidates = BTreeMap::new();
        for command in commands {
            let id = command.id();
            match Candidate::new(command, log) {
                Ok(candidate) => {
                    candidates.insert(id, candidate);
                }
                Err(error) => {
                    for candidate in candidates.values_mut() {
                        let _ = candidate.abort(log);
                    }
                    return Err(error);
                }
            }
        }
        Ok(Self { candidates })
    }

    /// Returns one component command.
    ///
    /// # Errors
    ///
    /// Returns [`Error::ParticipantNotFound`] when the command is absent.
    pub fn command(&self, command: CommandId) -> Result<&Command<P>> {
        self.candidates
            .get(&command)
            .map(Candidate::command)
            .ok_or(Error::ParticipantNotFound)
    }

    /// Posts one component commitment.
    ///
    /// # Errors
    ///
    /// Any failure aborts every component.
    pub fn commit(
        &mut self,
        command: CommandId,
        role: RoleId,
        commitment: ScalarFor<P>,
        log: &mut impl LogAct,
    ) -> Result<()> {
        let result = self
            .candidates
            .get_mut(&command)
            .ok_or(Error::ParticipantNotFound)
            .and_then(|candidate| candidate.commit(role, commitment, log));
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail(log, error),
        }
    }

    /// Closes every component's commitment phase.
    ///
    /// # Errors
    ///
    /// Any failure aborts every component.
    pub fn close_commitments(&mut self, log: &mut impl LogAct) -> Result<()> {
        let mut failure = None;
        for candidate in self.candidates.values_mut() {
            if let Err(error) = candidate.close_commitments(log) {
                failure = Some(error);
                break;
            }
        }
        if let Some(error) = failure {
            return self.fail(log, error);
        }
        Ok(())
    }

    /// Posts one component opening.
    ///
    /// # Errors
    ///
    /// Any failure aborts every component.
    pub fn open(
        &mut self,
        command: CommandId,
        opening: Opening<P>,
        log: &mut impl LogAct,
    ) -> Result<()> {
        let result = self
            .candidates
            .get_mut(&command)
            .ok_or(Error::ParticipantNotFound)
            .and_then(|candidate| candidate.open(opening, log));
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail(log, error),
        }
    }

    /// Posts one local component contribution and permits its private deliveries.
    ///
    /// # Errors
    ///
    /// Any failure aborts every component.
    pub fn open_contribution<'a>(
        &mut self,
        command: CommandId,
        contribution: &'a Contribution<P>,
        log: &mut impl LogAct,
    ) -> Result<ReleasedContribution<'a, P>> {
        let result = self
            .candidates
            .get_mut(&command)
            .ok_or(Error::ParticipantNotFound)
            .and_then(|candidate| candidate.open_contribution(contribution, log));
        match result {
            Ok(released) => Ok(released),
            Err(error) => self.fail(log, error),
        }
    }

    /// Closes every component's opening phase.
    ///
    /// # Errors
    ///
    /// Any failure aborts every component.
    pub fn close_openings(
        &mut self,
        log: &mut impl LogAct,
    ) -> Result<Vec<(CommandId, CandidateView<P>)>> {
        let mut views = Vec::with_capacity(self.candidates.len());
        let mut failure = None;
        for (command, candidate) in &mut self.candidates {
            match candidate.close_openings(log) {
                Ok(view) => views.push((*command, view)),
                Err(error) => {
                    failure = Some(error);
                    break;
                }
            }
        }
        if let Some(error) = failure {
            return self.fail(log, error);
        }
        Ok(views)
    }

    /// Posts one component target receipt.
    ///
    /// # Errors
    ///
    /// Any failure aborts every component.
    pub fn receipt(&mut self, receipt: TargetReceipt<P>, log: &mut impl LogAct) -> Result<()> {
        let result = self
            .candidates
            .get_mut(&receipt.command())
            .ok_or(Error::ParticipantNotFound)
            .and_then(|candidate| candidate.receipt(receipt, log));
        match result {
            Ok(()) => Ok(()),
            Err(error) => self.fail(log, error),
        }
    }

    /// Activates every component under one handle.
    ///
    /// # Errors
    ///
    /// Any failure aborts every component that can still abort.
    pub fn activate(&mut self, log: &mut impl LogAct) -> Result<Terminal> {
        let mut candidates = self.candidates.values_mut().collect::<Vec<_>>();
        activate_candidates(&mut candidates, log)
    }

    /// Aborts every component and retains each prefix.
    ///
    /// # Errors
    ///
    /// Returns an error if any component already activated.
    pub fn abort(&mut self, log: &mut impl LogAct) -> Result<Terminal> {
        let mut failure = None;
        for candidate in self.candidates.values_mut() {
            if let Err(error) = candidate.abort(log) {
                failure.get_or_insert(error);
            }
        }
        if let Some(error) = failure {
            return Err(error);
        }
        Ok(Terminal::Aborted)
    }

    fn fail<T>(&mut self, log: &mut impl LogAct, error: Error) -> Result<T> {
        for candidate in self.candidates.values_mut() {
            if candidate.terminal.is_none() {
                let _ = candidate.abort(log);
            }
        }
        Err(error)
    }
}

fn activate_candidates<P: Profile>(
    candidates: &mut [&mut Candidate<P>],
    log: &mut impl LogAct,
) -> Result<Terminal> {
    if candidates.is_empty() {
        return Err(Error::EmptyInput);
    }
    let shape = candidates[0].command.shape();
    if !matches!(shape, TargetShape::Single(_))
        || candidates
            .iter()
            .any(|candidate| candidate.command.shape() != shape)
    {
        for candidate in candidates.iter_mut() {
            let _ = candidate.abort(log);
        }
        return Err(Error::SupportMismatch);
    }
    if let Some(terminal) = candidates.first().and_then(|candidate| candidate.terminal) {
        if candidates
            .iter()
            .all(|candidate| candidate.terminal == Some(terminal))
        {
            return match terminal {
                Terminal::Activated(_) => Ok(terminal),
                Terminal::Aborted => Err(Error::AlreadyTerminal),
            };
        }
        return Err(Error::AlreadyTerminal);
    }
    if candidates
        .iter()
        .any(|candidate| candidate.terminal.is_some())
    {
        return Err(Error::AlreadyTerminal);
    }
    for index in 0..candidates.len() {
        if let Err(error) = candidates[index].prepare(log) {
            for candidate in candidates.iter_mut() {
                let _ = candidate.abort(log);
            }
            return Err(error);
        }
    }
    let commands = candidates
        .iter()
        .map(|candidate| candidate.command.command)
        .collect::<Vec<_>>();
    match log.activate_bundle(&commands) {
        Ok(terminal) => {
            for candidate in candidates {
                candidate.stage = CandidateStage::Terminal;
                candidate.terminal = Some(terminal);
            }
            Ok(terminal)
        }
        Err(error) => {
            for candidate in candidates {
                let _ = candidate.abort(log);
            }
            Err(error)
        }
    }
}

fn encode_candidate_view<P: Profile>(
    command: &Command<P>,
    commitments: &[(RoleId, ScalarFor<P>)],
    openings: &[Opening<P>],
) -> Result<Vec<u8>> {
    let mut encoder = Encoder::<P>::for_profile();
    encoder.put_u8(P::WIRE_ID);
    encoder.put_bytes(&command.to_bytes()?)?;
    encoder.put_u16(count_u16(commitments.len())?);
    for (role, commitment) in commitments {
        role.encode(&mut encoder);
        encoder.put_scalar(commitment);
    }
    encoder.put_u16(count_u16(openings.len())?);
    for opening in openings {
        encoder.put_bytes(&opening.to_bytes()?)?;
    }
    Ok(encoder.finish())
}
