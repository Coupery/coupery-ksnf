use serde_json::Value;

mod dealing;
mod leaf;
mod signing;

pub struct VectorCase {
    pub name: &'static str,
    pub value: Value,
}

pub fn all() -> Result<Vec<VectorCase>, Box<dyn std::error::Error>> {
    Ok(vec![
        named("sign-outer-2of3-inner-2of3", signing::primary())?,
        named("sign-alternate-supports", signing::alternate())?,
        named("receiver-interleaving", leaf::interleaving())?,
        named("leaf-replay-and-close", leaf::lifecycle())?,
        named("inner-veto-retry-activate", dealing::inner())?,
        named("outer-reshare", dealing::outer())?,
        named("dealing-invalid", dealing::invalid())?,
        named("multi-vault-identity-reuse", signing::multi_vault())?,
    ])
}

fn named(
    name: &str,
    result: Result<VectorCase, Box<dyn std::error::Error>>,
) -> Result<VectorCase, Box<dyn std::error::Error>> {
    result.map_err(|error| std::io::Error::other(format!("{name}: {error}")).into())
}

pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let bytes = bytes.as_ref();
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

pub const fn vector(name: &'static str, value: Value) -> VectorCase {
    VectorCase { name, value }
}
