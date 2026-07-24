//! Activation-log tests.

use coupery_ksnf::log_act::{LogAct, LogPhase, MemoryLog, Terminal};
use coupery_ksnf::types::{ActivationHandle, CommandId, ScopeId};
use coupery_ksnf::{Error, Result};

#[test]
fn activation_is_one_predecessor_compare_and_set() -> Result<()> {
    let scope = ScopeId::new([1; 32]);
    let predecessor = ActivationHandle::new([2; 32]);
    let command_1 = CommandId::new([3; 32]);
    let command_2 = CommandId::new([4; 32]);
    let mut log = MemoryLog::default();
    log.install_genesis(scope, predecessor)?;
    log.begin(scope, command_1, predecessor, b"candidate one")?;
    log.begin(scope, command_2, predecessor, b"candidate two")?;

    log.post(command_1, LogPhase::Commit, b"role", b"commit")?;
    log.close_phase(command_1, LogPhase::Commit)?;
    log.post(command_1, LogPhase::Open, b"role", b"open")?;
    log.close_phase(command_1, LogPhase::Open)?;
    log.post(command_1, LogPhase::Receipt, b"target", b"receipt")?;
    log.close_phase(command_1, LogPhase::Receipt)?;
    assert_eq!(
        log.post(command_1, LogPhase::Commit, b"role", b"commit"),
        Ok(())
    );
    let Terminal::Activated(handle) = log.activate(command_1)? else {
        return Err(Error::InvalidTranscript);
    };
    assert_eq!(log.current(scope), Some(handle));
    assert_eq!(log.activate(command_1)?, Terminal::Activated(handle));
    assert_eq!(
        log.post(command_1, LogPhase::Commit, b"role", b"changed"),
        Err(Error::ReplayMismatch)
    );

    assert_eq!(
        log.post(command_2, LogPhase::Commit, b"role", b"commit"),
        Err(Error::StalePredecessor)
    );
    assert_eq!(
        log.close_phase(command_2, LogPhase::Commit),
        Err(Error::StalePredecessor)
    );
    assert_eq!(log.activate(command_2), Err(Error::PhaseClosed));
    assert_eq!(log.abort(command_2)?, Terminal::Aborted);
    assert_eq!(log.current(scope), Some(handle));
    assert_eq!(
        log.begin(scope, command_1, predecessor, b"changed"),
        Err(Error::CommandMismatch)
    );
    Ok(())
}

#[test]
fn bundle_activation_advances_every_scope_or_none() -> Result<()> {
    let scope_1 = ScopeId::new([0x11; 32]);
    let scope_2 = ScopeId::new([0x12; 32]);
    let predecessor_1 = ActivationHandle::new([0x21; 32]);
    let predecessor_2 = ActivationHandle::new([0x22; 32]);
    let command_1 = CommandId::new([0x31; 32]);
    let command_2 = CommandId::new([0x32; 32]);
    let mut log = MemoryLog::default();
    log.install_genesis(scope_1, predecessor_1)?;
    log.install_genesis(scope_2, predecessor_2)?;
    log.begin(scope_1, command_1, predecessor_1, b"identity")?;
    log.begin(scope_2, command_2, predecessor_2, b"member")?;
    close_all(&mut log, command_1)?;
    close_all(&mut log, command_2)?;

    let Terminal::Activated(handle) = log.activate_bundle(&[command_1, command_2])? else {
        return Err(Error::InvalidTranscript);
    };
    assert_eq!(log.current(scope_1), Some(handle));
    assert_eq!(log.current(scope_2), Some(handle));
    assert_eq!(
        log.activate_bundle(&[command_2, command_1])?,
        Terminal::Activated(handle)
    );
    assert_eq!(
        log.activate_bundle(&[command_1]),
        Err(Error::CommandMismatch)
    );
    Ok(())
}

#[test]
fn memory_handles_are_stable_and_injective() -> Result<()> {
    let scope_1 = ScopeId::new([0x41; 32]);
    let scope_2 = ScopeId::new([0x42; 32]);
    let predecessor_1 = ActivationHandle::new([0x51; 32]);
    let predecessor_2 = ActivationHandle::new([0x52; 32]);
    let command_1 = CommandId::new([0x61; 32]);
    let command_2 = CommandId::new([0x62; 32]);
    let mut log = MemoryLog::default();
    log.install_genesis(scope_1, predecessor_1)?;
    log.install_genesis(scope_2, predecessor_2)?;
    log.begin(scope_1, command_1, predecessor_1, b"first transcript")?;
    log.begin(scope_2, command_2, predecessor_2, b"second transcript")?;
    close_all(&mut log, command_1)?;
    close_all(&mut log, command_2)?;

    let Terminal::Activated(handle_1) = log.activate(command_1)? else {
        return Err(Error::InvalidTranscript);
    };
    assert_eq!(log.activate(command_1)?, Terminal::Activated(handle_1));
    let Terminal::Activated(handle_2) = log.activate(command_2)? else {
        return Err(Error::InvalidTranscript);
    };
    assert_ne!(handle_1, handle_2);
    assert_eq!(
        log.transcript(command_1)
            .and_then(coupery_ksnf::log_act::LogTranscript::terminal),
        Some(Terminal::Activated(handle_1))
    );
    assert_eq!(
        log.transcript(command_2)
            .and_then(coupery_ksnf::log_act::LogTranscript::terminal),
        Some(Terminal::Activated(handle_2))
    );
    Ok(())
}

fn close_all(log: &mut MemoryLog, command: CommandId) -> Result<()> {
    log.close_phase(command, LogPhase::Commit)?;
    log.close_phase(command, LogPhase::Open)?;
    log.close_phase(command, LogPhase::Receipt)
}
