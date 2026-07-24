# Public API snapshots

These files record the module-qualified expert API and the crate-root driver
facade. They are generated with `cargo-public-api 0.52.0`, simplified output,
and `nightly-2026-04-27` rustdoc.

`minimal.txt` disables all profiles. `secp256k1.txt` and `ed25519.txt` record
each plain profile alone. `all.txt` enables every feature. CI rejects any
unreviewed difference.

Regenerate the files after an intentional API change:

```sh
cargo +nightly-2026-04-27 public-api -sss --color never --no-default-features > public-api/minimal.txt
cargo +nightly-2026-04-27 public-api -sss --color never --no-default-features --features secp256k1 > public-api/secp256k1.txt
cargo +nightly-2026-04-27 public-api -sss --color never --no-default-features --features ed25519 > public-api/ed25519.txt
cargo +nightly-2026-04-27 public-api -sss --color never --all-features > public-api/all.txt
```
