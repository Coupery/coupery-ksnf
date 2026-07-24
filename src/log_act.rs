//! Append-only transcripts with activation compare-and-set.
//!
//! Each terminal handle must name one exact canonical transcript or canonical
//! bundle. Equal handles mean equal retained bytes. A counter or digest may
//! index that mapping, but cannot replace it.

use std::collections::{BTreeMap, BTreeSet};

use crate::types::{ActivationHandle, CommandId, ScopeId};
use crate::{Error, Result};

/// A redistribution transcript phase.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum LogPhase {
    /// Contributor commitments.
    Commit,
    /// Contributor openings.
    Open,
    /// Target receipts.
    Receipt,
}

/// One terminal transcript decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Terminal {
    /// The candidate did not install.
    Aborted,
    /// The candidate installed under this exact handle.
    Activated(ActivationHandle),
}

/// The common transcript and activation boundary.
///
/// An implementation must retain a permanent, injective mapping from every
/// activated transcript or canonical bundle to its handle. It must never reuse a
/// handle after restart, rollback, or branch replacement.
pub trait LogAct {
    /// Starts one command or accepts its exact replay.
    ///
    /// # Errors
    ///
    /// Returns an error for altered command bytes or a stale predecessor.
    fn begin(
        &mut self,
        scope: ScopeId,
        command: CommandId,
        predecessor: ActivationHandle,
        parameters: &[u8],
    ) -> Result<()>;

    /// Appends one role's first post in a phase.
    ///
    /// # Errors
    ///
    /// Returns an error for an altered replay, closed phase, stale predecessor,
    /// or terminal log.
    fn post(
        &mut self,
        command: CommandId,
        phase: LogPhase,
        role: &[u8],
        payload: &[u8],
    ) -> Result<()>;

    /// Closes one phase in order.
    ///
    /// # Errors
    ///
    /// Returns an error when another phase is open, the predecessor is stale,
    /// or the log is terminal.
    fn close_phase(&mut self, command: CommandId, phase: LogPhase) -> Result<()>;

    /// Terminates without installation.
    ///
    /// # Errors
    ///
    /// Returns an error when the command is absent or already activated.
    fn abort(&mut self, command: CommandId) -> Result<Terminal>;

    /// Installs after receipt close if the predecessor remains current.
    ///
    /// Exact replay returns the original handle. A different canonical
    /// transcript receives a different handle.
    ///
    /// # Errors
    ///
    /// Returns an error before receipt close, after abort, or when stale.
    fn activate(&mut self, command: CommandId) -> Result<Terminal>;

    /// Installs several commands under one terminal handle.
    ///
    /// Exact replay returns the original handle. Bundle membership and every
    /// command transcript form the handle's retained identity.
    ///
    /// # Errors
    ///
    /// Returns an error unless every receipt phase is closed and every
    /// predecessor remains current.
    fn activate_bundle(&mut self, commands: &[CommandId]) -> Result<Terminal>;

    /// Returns a scope's current activation handle.
    fn current(&self, scope: ScopeId) -> Option<ActivationHandle>;
}

/// A deterministic in-memory `LogAct` implementation.
///
/// Handles are injective only within this retained instance. The counter is a
/// test allocator, not a production handle scheme.
#[derive(Default)]
pub struct MemoryLog {
    current: BTreeMap<ScopeId, ActivationHandle>,
    transcripts: BTreeMap<CommandId, LogTranscript>,
    handles: BTreeSet<ActivationHandle>,
    activations: BTreeMap<ActivationHandle, Vec<CommandId>>,
    next_handle: u64,
}

impl MemoryLog {
    /// Installs one genesis handle.
    ///
    /// # Errors
    ///
    /// Returns [`Error::CommandMismatch`] when the scope already exists.
    pub fn install_genesis(&mut self, scope: ScopeId, handle: ActivationHandle) -> Result<()> {
        if self.current.contains_key(&scope) {
            return Err(Error::CommandMismatch);
        }
        self.current.insert(scope, handle);
        self.handles.insert(handle);
        Ok(())
    }

    /// Returns one retained transcript.
    #[must_use]
    pub fn transcript(&self, command: CommandId) -> Option<&LogTranscript> {
        self.transcripts.get(&command)
    }

    fn transcript_mut(&mut self, command: CommandId) -> Result<&mut LogTranscript> {
        self.transcripts
            .get_mut(&command)
            .ok_or(Error::ParticipantNotFound)
    }

    fn fresh_handle(&mut self) -> ActivationHandle {
        loop {
            self.next_handle = self.next_handle.wrapping_add(1);
            let mut bytes = [0_u8; 32];
            bytes[..8].copy_from_slice(b"KSNFLOG1");
            bytes[24..].copy_from_slice(&self.next_handle.to_be_bytes());
            let handle = ActivationHandle::new(bytes);
            if self.handles.insert(handle) {
                return handle;
            }
        }
    }
}

impl LogAct for MemoryLog {
    fn begin(
        &mut self,
        scope: ScopeId,
        command: CommandId,
        predecessor: ActivationHandle,
        parameters: &[u8],
    ) -> Result<()> {
        if let Some(existing) = self.transcripts.get(&command) {
            return if existing.scope == scope
                && existing.predecessor == predecessor
                && existing.parameters == parameters
            {
                Ok(())
            } else {
                Err(Error::CommandMismatch)
            };
        }
        if self.current.get(&scope) != Some(&predecessor) {
            return Err(Error::StalePredecessor);
        }
        self.transcripts.insert(
            command,
            LogTranscript {
                scope,
                predecessor,
                parameters: parameters.to_vec(),
                posts: BTreeMap::new(),
                next_phase: Some(LogPhase::Commit),
                terminal: None,
            },
        );
        Ok(())
    }

    fn post(
        &mut self,
        command: CommandId,
        phase: LogPhase,
        role: &[u8],
        payload: &[u8],
    ) -> Result<()> {
        let key = (phase, role.to_vec());
        {
            let transcript = self
                .transcripts
                .get(&command)
                .ok_or(Error::ParticipantNotFound)?;
            if let Some(existing) = transcript.posts.get(&key) {
                return if existing == payload {
                    Ok(())
                } else {
                    Err(Error::ReplayMismatch)
                };
            }
            if transcript.terminal.is_some() {
                return Err(Error::AlreadyTerminal);
            }
            if transcript.next_phase != Some(phase) {
                return Err(Error::PhaseClosed);
            }
            if self.current.get(&transcript.scope) != Some(&transcript.predecessor) {
                return Err(Error::StalePredecessor);
            }
        }
        self.transcript_mut(command)?
            .posts
            .insert(key, payload.to_vec());
        Ok(())
    }

    fn close_phase(&mut self, command: CommandId, phase: LogPhase) -> Result<()> {
        let next_phase = {
            let transcript = self
                .transcripts
                .get(&command)
                .ok_or(Error::ParticipantNotFound)?;
            if matches!(transcript.next_phase, Some(next) if next > phase)
                || transcript.next_phase.is_none()
            {
                return Ok(());
            }
            if transcript.terminal.is_some() {
                return Err(Error::AlreadyTerminal);
            }
            if self.current.get(&transcript.scope) != Some(&transcript.predecessor) {
                return Err(Error::StalePredecessor);
            }
            transcript.next_phase
        };
        match next_phase {
            Some(next) if next == phase => {
                self.transcript_mut(command)?.next_phase = match phase {
                    LogPhase::Commit => Some(LogPhase::Open),
                    LogPhase::Open => Some(LogPhase::Receipt),
                    LogPhase::Receipt => None,
                };
                Ok(())
            }
            _ => Err(Error::PhaseClosed),
        }
    }

    fn abort(&mut self, command: CommandId) -> Result<Terminal> {
        let transcript = self.transcript_mut(command)?;
        match transcript.terminal {
            Some(Terminal::Aborted) => Ok(Terminal::Aborted),
            Some(Terminal::Activated(_)) => Err(Error::AlreadyTerminal),
            None => {
                transcript.terminal = Some(Terminal::Aborted);
                Ok(Terminal::Aborted)
            }
        }
    }

    fn activate(&mut self, command: CommandId) -> Result<Terminal> {
        self.activate_bundle(&[command])
    }

    fn activate_bundle(&mut self, commands: &[CommandId]) -> Result<Terminal> {
        if commands.is_empty() {
            return Err(Error::EmptyInput);
        }
        let mut unique_commands = BTreeSet::new();
        let mut unique_scopes = BTreeSet::new();
        let mut records = Vec::with_capacity(commands.len());
        let mut replay = None;
        for command in commands {
            if !unique_commands.insert(*command) {
                return Err(Error::CommandMismatch);
            }
            let transcript = self
                .transcripts
                .get(command)
                .ok_or(Error::ParticipantNotFound)?;
            if !unique_scopes.insert(transcript.scope) {
                return Err(Error::CommandMismatch);
            }
            match transcript.terminal {
                Some(Terminal::Activated(handle)) => {
                    if !records.is_empty() {
                        return Err(Error::AlreadyTerminal);
                    }
                    match replay {
                        Some(existing) if existing != handle => {
                            return Err(Error::AlreadyTerminal);
                        }
                        _ => replay = Some(handle),
                    }
                }
                Some(Terminal::Aborted) => return Err(Error::AlreadyTerminal),
                None => {
                    if replay.is_some() {
                        return Err(Error::AlreadyTerminal);
                    }
                    if transcript.next_phase.is_some() {
                        return Err(Error::PhaseClosed);
                    }
                    if self.current.get(&transcript.scope) != Some(&transcript.predecessor) {
                        return Err(Error::StalePredecessor);
                    }
                    records.push((*command, transcript.scope));
                }
            }
        }
        let mut canonical_commands = commands.to_vec();
        canonical_commands.sort_unstable();
        if let Some(handle) = replay {
            return if self.activations.get(&handle) == Some(&canonical_commands) {
                Ok(Terminal::Activated(handle))
            } else {
                Err(Error::CommandMismatch)
            };
        }

        let handle = self.fresh_handle();
        for (_, scope) in &records {
            self.current.insert(*scope, handle);
        }
        for (command, _) in records {
            self.transcript_mut(command)?.terminal = Some(Terminal::Activated(handle));
        }
        self.activations.insert(handle, canonical_commands);
        Ok(Terminal::Activated(handle))
    }

    fn current(&self, scope: ScopeId) -> Option<ActivationHandle> {
        self.current.get(&scope).copied()
    }
}

/// One retained in-memory transcript.
pub struct LogTranscript {
    scope: ScopeId,
    predecessor: ActivationHandle,
    parameters: Vec<u8>,
    posts: BTreeMap<(LogPhase, Vec<u8>), Vec<u8>>,
    next_phase: Option<LogPhase>,
    terminal: Option<Terminal>,
}

impl LogTranscript {
    /// Returns the activation scope.
    #[must_use]
    pub const fn scope(&self) -> ScopeId {
        self.scope
    }

    /// Returns the predecessor handle.
    #[must_use]
    pub const fn predecessor(&self) -> ActivationHandle {
        self.predecessor
    }

    /// Returns the immutable command parameters.
    #[must_use]
    pub fn parameters(&self) -> &[u8] {
        &self.parameters
    }

    /// Returns one recorded post.
    #[must_use]
    pub fn post(&self, phase: LogPhase, role: &[u8]) -> Option<&[u8]> {
        self.posts.get(&(phase, role.to_vec())).map(Vec::as_slice)
    }

    /// Returns the next open phase.
    #[must_use]
    pub const fn next_phase(&self) -> Option<LogPhase> {
        self.next_phase
    }

    /// Returns the terminal decision.
    #[must_use]
    pub const fn terminal(&self) -> Option<Terminal> {
        self.terminal
    }
}
