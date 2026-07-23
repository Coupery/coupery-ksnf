//! Key scopes and affine share translation.

use core::fmt;

use crate::algebra::{Element, Point, SecretScalar};
use crate::types::{ActivationHandle, InnerEpoch, OuterEpoch, PersonId, VaultId};

macro_rules! point_type {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Eq, PartialEq)]
        pub struct $name(Point);

        impl $name {
            /// Wraps a nonidentity point.
            #[must_use]
            pub const fn new(point: Point) -> Self {
                Self(point)
            }

            /// Returns the point.
            #[must_use]
            pub const fn point(self) -> Point {
                self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
    };
}

point_type!(
    /// A stable person identity key.
    IdentityKey
);
point_type!(
    /// A vault-local member point.
    MemberPoint
);
point_type!(
    /// A stable vault verification key.
    VaultKey
);
point_type!(
    /// A public point for one device share.
    SharePoint
);

/// The installed blocks that define one person's signing state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnchorId {
    vault: VaultId,
    person: PersonId,
    identity: ActivationHandle,
    member: ActivationHandle,
}

impl AnchorId {
    /// Creates an anchor identifier.
    #[must_use]
    pub const fn new(
        vault: VaultId,
        person: PersonId,
        identity: ActivationHandle,
        member: ActivationHandle,
    ) -> Self {
        Self {
            vault,
            person,
            identity,
            member,
        }
    }

    /// Returns the vault identifier.
    #[must_use]
    pub const fn vault(self) -> VaultId {
        self.vault
    }

    /// Returns the person identifier.
    #[must_use]
    pub const fn person(self) -> PersonId {
        self.person
    }

    /// Returns the identity-block handle.
    #[must_use]
    pub const fn identity(self) -> ActivationHandle {
        self.identity
    }

    /// Returns the member-block handle.
    #[must_use]
    pub const fn member(self) -> ActivationHandle {
        self.member
    }
}

/// The epochs and handles bound into one member transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KeyEpoch {
    outer: OuterEpoch,
    inner: InnerEpoch,
    anchor: AnchorId,
}

impl KeyEpoch {
    /// Creates a key epoch.
    #[must_use]
    pub const fn new(outer: OuterEpoch, inner: InnerEpoch, anchor: AnchorId) -> Self {
        Self {
            outer,
            inner,
            anchor,
        }
    }

    /// Returns the outer epoch.
    #[must_use]
    pub const fn outer(self) -> OuterEpoch {
        self.outer
    }

    /// Returns the inner epoch.
    #[must_use]
    pub const fn inner(self) -> InnerEpoch {
        self.inner
    }

    /// Returns the installed block handles.
    #[must_use]
    pub const fn anchor(self) -> AnchorId {
        self.anchor
    }
}

/// Computes `member - identity` for one device.
#[must_use]
pub fn anchor_share(member: &SecretScalar, identity: &SecretScalar) -> SecretScalar {
    member.expose(|member| identity.expose(|identity| SecretScalar::new(*member - identity)))
}

/// Recomputes a member signing share as `identity + anchor`.
#[must_use]
pub fn signing_share(identity: &SecretScalar, anchor: &SecretScalar) -> SecretScalar {
    identity.expose(|identity| anchor.expose(|anchor| SecretScalar::new(*identity + anchor)))
}

/// Checks the affine relation between public share points.
#[must_use]
pub fn verify_anchor(identity: SharePoint, anchor: Element, member: SharePoint) -> bool {
    Element::from(identity.point()) + anchor == Element::from(member.point())
}
