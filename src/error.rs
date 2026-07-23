//! Crate errors.

use core::fmt;

/// An error returned by `coupery-ksnf`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// An encoded object uses an unsupported version.
    UnsupportedVersion,
    /// An encoded object names another protocol.
    ProtocolMismatch,
    /// A point encoding is malformed.
    InvalidPoint,
    /// A nonidentity point was required.
    IdentityPoint,
    /// A scalar encoding is not canonical.
    InvalidScalar,
    /// A group-element tag is unknown.
    InvalidElementTag,
    /// An identity encoding has nonzero padding.
    InvalidIdentity,
    /// The input ended before the requested field.
    UnexpectedEnd {
        /// Byte offset at the start of the field.
        offset: usize,
        /// Number of bytes requested.
        needed: usize,
    },
    /// Bytes remain after a value was decoded.
    TrailingBytes {
        /// Byte offset of the first trailing byte.
        offset: usize,
    },
    /// A byte string is too long for the canonical length prefix.
    LengthOverflow,
    /// A polynomial or support is empty.
    EmptyInput,
    /// Two related lists have different lengths.
    LengthMismatch,
    /// A Shamir node is zero.
    ZeroNode,
    /// A Shamir support contains a node twice.
    DuplicateNode,
    /// A support contains a participant twice.
    DuplicateParticipant,
    /// An outer package contains a slot twice.
    DuplicateSlot,
    /// A requested participant is absent.
    ParticipantNotFound,
    /// Related values name different participants.
    ParticipantMismatch,
    /// A transcript fails a structural check.
    InvalidTranscript,
    /// A private member opening does not match its commitment.
    CommitmentMismatch,
    /// An encoded coefficient differs from the accepted support.
    CoefficientMismatch,
    /// A package differs from the accepted support.
    SupportMismatch,
    /// A nonce differs from the fixed commitment.
    NonceMismatch,
    /// A secret share differs from its public point.
    ShareMismatch,
    /// Another session holds the device lock.
    Busy,
    /// The session is permanently closed.
    Tombstoned,
    /// The call is invalid in the current stage.
    WrongStage,
    /// A same-session replay changed its input.
    ReplayMismatch,
    /// The reservation names another key epoch.
    EpochMismatch,
    /// A receiver-local delivery names another receiver.
    ReceiverMismatch,
    /// A command identifier already names different bytes.
    CommandMismatch,
    /// The activation predecessor is stale.
    StalePredecessor,
    /// A transcript phase is not open.
    PhaseClosed,
    /// A transcript already has a terminal decision.
    AlreadyTerminal,
    /// A nonce scalar is zero.
    ZeroNonce,
    /// A nonce sum is the identity.
    IdentityNonce,
    /// A partial signature is invalid.
    InvalidPartial,
    /// A final signature is invalid.
    InvalidSignature,
    /// Hash-to-field rejected its fixed domain.
    HashToField,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => f.write_str("unsupported version"),
            Self::ProtocolMismatch => f.write_str("protocol mismatch"),
            Self::InvalidPoint => f.write_str("invalid point"),
            Self::IdentityPoint => f.write_str("identity point"),
            Self::InvalidScalar => f.write_str("invalid scalar"),
            Self::InvalidElementTag => f.write_str("invalid group-element tag"),
            Self::InvalidIdentity => f.write_str("invalid identity encoding"),
            Self::UnexpectedEnd { offset, needed } => {
                write!(f, "need {needed} bytes at offset {offset}")
            }
            Self::TrailingBytes { offset } => write!(f, "trailing bytes at offset {offset}"),
            Self::LengthOverflow => f.write_str("length exceeds u32"),
            Self::EmptyInput => f.write_str("empty input"),
            Self::LengthMismatch => f.write_str("length mismatch"),
            Self::ZeroNode => f.write_str("zero Shamir node"),
            Self::DuplicateNode => f.write_str("duplicate Shamir node"),
            Self::DuplicateParticipant => f.write_str("duplicate participant"),
            Self::DuplicateSlot => f.write_str("duplicate slot"),
            Self::ParticipantNotFound => f.write_str("participant not found"),
            Self::ParticipantMismatch => f.write_str("participant mismatch"),
            Self::InvalidTranscript => f.write_str("invalid transcript"),
            Self::CommitmentMismatch => f.write_str("member commitment mismatch"),
            Self::CoefficientMismatch => f.write_str("coefficient mismatch"),
            Self::SupportMismatch => f.write_str("support mismatch"),
            Self::NonceMismatch => f.write_str("nonce mismatch"),
            Self::ShareMismatch => f.write_str("share mismatch"),
            Self::Busy => f.write_str("device busy"),
            Self::Tombstoned => f.write_str("session tombstoned"),
            Self::WrongStage => f.write_str("wrong stage"),
            Self::ReplayMismatch => f.write_str("altered replay"),
            Self::EpochMismatch => f.write_str("epoch mismatch"),
            Self::ReceiverMismatch => f.write_str("receiver mismatch"),
            Self::CommandMismatch => f.write_str("command mismatch"),
            Self::StalePredecessor => f.write_str("stale predecessor"),
            Self::PhaseClosed => f.write_str("phase closed"),
            Self::AlreadyTerminal => f.write_str("transcript already terminal"),
            Self::ZeroNonce => f.write_str("zero nonce"),
            Self::IdentityNonce => f.write_str("identity nonce"),
            Self::InvalidPartial => f.write_str("invalid partial signature"),
            Self::InvalidSignature => f.write_str("invalid signature"),
            Self::HashToField => f.write_str("hash-to-field failed"),
        }
    }
}

impl std::error::Error for Error {}

/// A result returned by `coupery-ksnf`.
pub type Result<T> = core::result::Result<T, Error>;
