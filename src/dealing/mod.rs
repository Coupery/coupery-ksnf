//! Commit-before-open same-key redistribution.

mod candidate;
mod contribution;
mod shape;
mod target;

pub use candidate::{Candidate, InnerBundle};
pub use contribution::{Contribution, ContributionPoints, Opening, PrivateShare};
pub use shape::{
    Command, OuterShape, OuterTarget, RoleId, RoleSpec, SingleShape, TargetDevice, TargetId,
    TargetShape,
};
pub use target::{
    CandidateView, InstalledShare, PendingShare, TargetAccumulator, TargetReady, TargetReceipt,
};

use crate::encoding::Decoder;
use crate::{Error, Result};

const VERSION: u8 = 1;

fn expect_version(decoder: &mut Decoder<'_>) -> Result<()> {
    if decoder.get_u8()? == VERSION {
        Ok(())
    } else {
        Err(Error::UnsupportedVersion)
    }
}

fn count_u16(value: usize) -> Result<u16> {
    u16::try_from(value).map_err(|_| Error::LengthOverflow)
}
