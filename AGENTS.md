# Coupery KSNF

## Goal

Build a minimal, composable Rust implementation of Key-Stable Nested FROST.
Match the paper's plain-Schnorr, Shamir, depth-two construction exactly.

The crate should be easy to read, hard to misuse, and useful as a base for
other cryptographic applications.

## Scope

- Keep modules small and orthogonal.
- Pass state through typed values. Avoid hidden state.
- Keep transport, storage, policy, DKG, BIP-340, Taproot, and recursive depth
  outside the core.
- Depend on public crates only. Do not depend on Sudo.
- Preserve the theorem boundary in every API claim.

## Rust

- Use Rust 2024 with MSRV 1.85.
- Forbid unsafe code.
- Document every public item.
- Return typed errors. Library code must not panic.
- Zeroize secret scalars, shares, nonces, and polynomials.
- Do not derive `Clone`, `Copy`, `Serialize`, or `Deserialize` for secret or
  one-use state.
- Encode protocol bytes by hand. A serde format is never canonical protocol
  syntax.
- Prefer types that make invalid states unrepresentable.

## Prose

- Use the fewest words that preserve meaning.
- A comment must explain a security invariant or a choice the code cannot
  express.
- Delete narration, headings inside functions, and restated code.
- Review every comment, doc comment, error, README line, and release note with
  the `no-ai-slop` skill.
- Do not use em dashes as rhythm.

## Tests

- Give each load-bearing invariant one decisive test.
- Avoid duplicate tests and broad snapshots.
- Use vectors for canonical bytes and end-to-end equations.
- Use focused negative tests for refusal and state transitions.
- Test public behavior. Do not expose internals for tests.

## Done

The crate is done when another implementation can reproduce its bytes and
results from the vectors, each theorem-side obligation has a code-side check,
and the public API needs no Sudo context.
