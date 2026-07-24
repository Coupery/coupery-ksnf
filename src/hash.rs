//! Domain-separated hashes.

use crate::Result;
use crate::algebra::ScalarFor;
use crate::profile::Profile;

pub use crate::profile::HashDomain as Domain;

pub fn to_scalar_for<P: Profile>(domain: Domain, message: &[u8]) -> Result<ScalarFor<P>> {
    P::hash_to_scalar(domain, message)
}

#[cfg(all(test, feature = "secp256k1"))]
mod tests {
    use super::{Domain, to_scalar_for};
    use crate::Result;
    use crate::algebra::Scalar;

    #[test]
    fn domains_are_stable_and_distinct() -> Result<()> {
        let message = b"coupery-ksnf";
        let outputs = [Domain::Deal, Domain::Member, Domain::Nonce, Domain::Bind]
            .map(|domain| to_scalar_for::<crate::profile::Secp256k1>(domain, message))
            .into_iter()
            .collect::<Result<Vec<_>>>()?;

        for (index, output) in outputs.iter().enumerate() {
            assert!(!outputs[..index].contains(output));
        }

        let actual = outputs.iter().map(scalar_hex).collect::<Vec<_>>();
        assert_eq!(
            actual,
            [
                "8e7329b6c0000ddd0251a73c17b1fac1aec8983a92dd358582e289c9f8021bf5",
                "d56eb6cdfaba507dc1c8bccb131094c1bd84d31369f7f6f3a127eade8ff6c184",
                "258f61650d54e60d33eb587e37d423948795161e438f33b0efb9b1cdf0e84c06",
                "bf0b18eef6d140af37fca842d45c1f84cb1178d568bdb413f16e5451457b12d3",
            ]
        );
        Ok(())
    }

    fn scalar_hex(scalar: &Scalar) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";

        let mut encoded = String::with_capacity(64);
        for byte in scalar.to_bytes() {
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        encoded
    }
}
