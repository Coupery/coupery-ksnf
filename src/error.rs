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
    /// A Taproot tweak is outside the scalar field.
    InvalidTweak,
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
    /// An input has the wrong length.
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
    /// A Taproot output key differs from the expected key.
    OutputKeyMismatch,
    /// A Taproot message is not a 32-byte signature hash.
    InvalidSighash,
    /// Another session holds the device lock.
    Busy,
    /// The leaf attempt is permanently closed.
    AttemptClosed,
    /// A message names another leaf attempt.
    AttemptMismatch,
    /// The device issued every representable leaf attempt.
    AttemptExhausted,
    /// The call is invalid in the current stage.
    WrongStage,
    /// A same-session replay changed its input.
    ReplayMismatch,
    /// The reservation names another key epoch.
    EpochMismatch,
    /// The reservation deadline has passed.
    Expired,
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

impl Error {
    /// Returns a stable error code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::UnsupportedVersion => "unsupported_version",
            Self::ProtocolMismatch => "protocol_mismatch",
            Self::InvalidPoint => "invalid_point",
            Self::IdentityPoint => "identity_point",
            Self::InvalidScalar => "invalid_scalar",
            Self::InvalidTweak => "invalid_tweak",
            Self::InvalidElementTag => "invalid_element_tag",
            Self::InvalidIdentity => "invalid_identity",
            Self::UnexpectedEnd { .. } => "unexpected_end",
            Self::TrailingBytes { .. } => "trailing_bytes",
            Self::LengthOverflow => "length_overflow",
            Self::EmptyInput => "empty_input",
            Self::LengthMismatch => "length_mismatch",
            Self::ZeroNode => "zero_node",
            Self::DuplicateNode => "duplicate_node",
            Self::DuplicateParticipant => "duplicate_participant",
            Self::DuplicateSlot => "duplicate_slot",
            Self::ParticipantNotFound => "participant_not_found",
            Self::ParticipantMismatch => "participant_mismatch",
            Self::InvalidTranscript => "invalid_transcript",
            Self::CommitmentMismatch => "commitment_mismatch",
            Self::CoefficientMismatch => "coefficient_mismatch",
            Self::SupportMismatch => "support_mismatch",
            Self::NonceMismatch => "nonce_mismatch",
            Self::ShareMismatch => "share_mismatch",
            Self::OutputKeyMismatch => "output_key_mismatch",
            Self::InvalidSighash => "invalid_sighash",
            Self::Busy => "busy",
            Self::AttemptClosed => "attempt_closed",
            Self::AttemptMismatch => "attempt_mismatch",
            Self::AttemptExhausted => "attempt_exhausted",
            Self::WrongStage => "wrong_stage",
            Self::ReplayMismatch => "replay_mismatch",
            Self::EpochMismatch => "epoch_mismatch",
            Self::Expired => "expired",
            Self::ReceiverMismatch => "receiver_mismatch",
            Self::CommandMismatch => "command_mismatch",
            Self::StalePredecessor => "stale_predecessor",
            Self::PhaseClosed => "phase_closed",
            Self::AlreadyTerminal => "already_terminal",
            Self::ZeroNonce => "zero_nonce",
            Self::IdentityNonce => "identity_nonce",
            Self::InvalidPartial => "invalid_partial",
            Self::InvalidSignature => "invalid_signature",
            Self::HashToField => "hash_to_field",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedVersion => f.write_str("unsupported version"),
            Self::ProtocolMismatch => f.write_str("protocol mismatch"),
            Self::InvalidPoint => f.write_str("invalid point"),
            Self::IdentityPoint => f.write_str("identity point"),
            Self::InvalidScalar => f.write_str("invalid scalar"),
            Self::InvalidTweak => f.write_str("invalid Taproot tweak"),
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
            Self::OutputKeyMismatch => f.write_str("Taproot output key mismatch"),
            Self::InvalidSighash => f.write_str("invalid Taproot signature hash"),
            Self::Busy => f.write_str("device busy"),
            Self::AttemptClosed => f.write_str("leaf attempt closed"),
            Self::AttemptMismatch => f.write_str("leaf attempt mismatch"),
            Self::AttemptExhausted => f.write_str("leaf attempt counter exhausted"),
            Self::WrongStage => f.write_str("wrong stage"),
            Self::ReplayMismatch => f.write_str("altered replay"),
            Self::EpochMismatch => f.write_str("epoch mismatch"),
            Self::Expired => f.write_str("reservation expired"),
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
