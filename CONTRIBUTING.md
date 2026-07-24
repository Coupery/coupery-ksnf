# Contributing

Keep the core within the boundary in [`README.md`](README.md). Discuss broader
changes in an issue before writing code.

Run the release gate before opening a pull request:

```sh
cargo fmt --all -- --check
cargo check --all-targets --all-features --locked
cargo test --all-targets --all-features --locked
cargo test --doc --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --all-features --no-deps --locked
cargo package --locked
```

Add one test for each new invariant. Change the profile version when published
protocol bytes change. Intentional public API changes must update the snapshots
in [`public-api/`](public-api/).

Report security flaws through [`SECURITY.md`](SECURITY.md).
