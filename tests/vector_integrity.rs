//! Released vector byte checks.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fs;
use std::path::Path;

use sha2::{Digest as _, Sha256};

const FILES: &[(&str, &[u8], &str)] = &[
    (
        "test-vectors/v1-ed25519/README.md",
        include_bytes!("../test-vectors/v1-ed25519/README.md"),
        "da2c78a22316b61d726f88a3798f41f1132eb9b94e91e2bc3ec4e0046dc5a0bd",
    ),
    (
        "test-vectors/v1-ed25519/mixed-supports.json",
        include_bytes!("../test-vectors/v1-ed25519/mixed-supports.json"),
        "0fe562ee563b2e4a1d293f4d8fd3653889e050752f64704639e0035004c3ecbf",
    ),
    (
        "test-vectors/v1-ed25519/nested-webauthn.json",
        include_bytes!("../test-vectors/v1-ed25519/nested-webauthn.json"),
        "d17d46965bc876b6dcaa3e92d0fd44d2a5aa04747d367e8ddf5aaad2295707f9",
    ),
    (
        "test-vectors/v1-ed25519/refresh.json",
        include_bytes!("../test-vectors/v1-ed25519/refresh.json"),
        "76b69f82919eac4a1df826a2548a020d895fcfb83cc5cc614011f60c7b573bed",
    ),
    (
        "test-vectors/v1-ed25519/reshare.json",
        include_bytes!("../test-vectors/v1-ed25519/reshare.json"),
        "96357aa5610637421cb91d86d230e26dced315938fe76a52220eb8fde46d52c1",
    ),
    (
        "test-vectors/v1/dealing-invalid.json",
        include_bytes!("../test-vectors/v1/dealing-invalid.json"),
        "79f8fafcd3341f780d813d79d37b2e28a7eb5acf16dde393ee9755383c067736",
    ),
    (
        "test-vectors/v1/inner-veto-retry-activate.json",
        include_bytes!("../test-vectors/v1/inner-veto-retry-activate.json"),
        "bbcecb6a40efd48a86565f8809eb043b38cdb637aa14347db89900d6df71a9d3",
    ),
    (
        "test-vectors/v1/leaf-replay-and-close.json",
        include_bytes!("../test-vectors/v1/leaf-replay-and-close.json"),
        "b0374aacd09e76a98e943ef4785e8b648d619cd8be3c06ce9fa2ac8c2cff7062",
    ),
    (
        "test-vectors/v1/multi-vault-identity-reuse.json",
        include_bytes!("../test-vectors/v1/multi-vault-identity-reuse.json"),
        "b15e3eaa1381631a1960f3cd09357100bd4d14317e3938f62c2862b8f56f3a52",
    ),
    (
        "test-vectors/v1/outer-reshare.json",
        include_bytes!("../test-vectors/v1/outer-reshare.json"),
        "bd70d8807662728ea33b468aefbb5b8610b160c30a24ab9e1409ad7515c88966",
    ),
    (
        "test-vectors/v1/receiver-interleaving.json",
        include_bytes!("../test-vectors/v1/receiver-interleaving.json"),
        "ad4773750d54d0ab3ef5df17d7f5869534addbe5e58c5650fb6293a25127d9c3",
    ),
    (
        "test-vectors/v1/sign-alternate-supports.json",
        include_bytes!("../test-vectors/v1/sign-alternate-supports.json"),
        "f5fe82a19dd06c310ca396d1a6245cb14b6fefbe13ccc974cde3a4a162f51021",
    ),
    (
        "test-vectors/v1/sign-outer-2of3-inner-2of3.json",
        include_bytes!("../test-vectors/v1/sign-outer-2of3-inner-2of3.json"),
        "2f3cba19c3be8c7338bdd066d860ac7b757d319fa1553cd6b47531fdfc7c9505",
    ),
    (
        "test-vectors/v1-tr/README.md",
        include_bytes!("../test-vectors/v1-tr/README.md"),
        "e8693733990c325762734d5db3819ac2bc07ae372eac37c60b5b232fc2d7a092",
    ),
    (
        "test-vectors/v1-tr/taproot-keypath-2of2.json",
        include_bytes!("../test-vectors/v1-tr/taproot-keypath-2of2.json"),
        "5a20d3d411dfed40e4bfbfbfa649d6cdd975b3aadbf207586f738946512575a3",
    ),
    (
        "test-vectors/v1-tr/taproot-keypath-mixed-inner.json",
        include_bytes!("../test-vectors/v1-tr/taproot-keypath-mixed-inner.json"),
        "0bc6f38f32bc0319b1e80089478ef18b867e86926e7c5c9f4c7171efdb5ed0bb",
    ),
    (
        "test-vectors/v1-tr/taproot-keypath-with-tree-2of2.json",
        include_bytes!("../test-vectors/v1-tr/taproot-keypath-with-tree-2of2.json"),
        "4c2a0cb51a5450961a357a7a523040d7aa76adc14b627ecd8c58805fe5dd33d8",
    ),
];

#[test]
fn released_vectors_do_not_change() {
    for (path, bytes, expected) in FILES {
        let actual = format!("{:x}", Sha256::digest(bytes));
        assert_eq!(&actual, expected, "{path}");
    }
}

#[test]
fn released_vector_manifest_is_exhaustive() -> Result<(), Box<dyn StdError>> {
    let expected = FILES
        .iter()
        .map(|(path, _, _)| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut actual = BTreeSet::new();
    for directory in ["v1", "v1-ed25519", "v1-tr"] {
        let relative = format!("test-vectors/{directory}");
        for entry in fs::read_dir(root.join(&relative))? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                actual.insert(format!(
                    "{relative}/{}",
                    entry.file_name().to_string_lossy()
                ));
            }
        }
    }
    assert_eq!(actual, expected);
    Ok(())
}
