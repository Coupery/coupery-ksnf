//! Signs with two of three people and two of three devices per person.

mod support;

use coupery_ksnf::Result;
use coupery_ksnf::profile::Secp256k1;

fn main() -> Result<()> {
    let vault = support::two_of_three::<Secp256k1>([0x42; 32])?;
    let signature = support::sign_plain(&vault)?;

    signature.verify(vault.vault_key, &vault.message)?;
    assert_eq!(vault.outer.participants().len(), 2);
    assert_eq!(signature.to_bytes().len(), 65);
    Ok(())
}
