//! Protocol identifiers.

use core::fmt;

macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
        pub struct $name([u8; 32]);

        impl $name {
            /// Creates an identifier from its bytes.
            #[must_use]
            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            /// Returns the identifier bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
    };
}

id_type!(
    /// A vault identifier.
    VaultId
);
id_type!(
    /// A person identifier.
    PersonId
);
id_type!(
    /// A device identifier.
    DeviceId
);
id_type!(
    /// A signing session identifier.
    SessionId
);
id_type!(
    /// A redistribution command identifier.
    CommandId
);
id_type!(
    /// An exact installed-transcript handle.
    ActivationHandle
);
id_type!(
    /// An independently activated state scope.
    ScopeId
);
id_type!(
    /// One installed sharing in the exposure ledger.
    BlockId
);

/// An outer sharing epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct OuterEpoch(u64);

impl OuterEpoch {
    /// Creates an outer epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the epoch number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// An inner sharing epoch.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InnerEpoch(u64);

impl InnerEpoch {
    /// Creates an inner epoch.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Returns the epoch number.
    #[must_use]
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A person's canonical position in an outer package.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct Slot(u16);

impl Slot {
    /// Creates a slot.
    #[must_use]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Returns the slot number.
    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}
