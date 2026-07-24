# Ed25519 v1 vectors

These files fix `coupery-ksnf/ed25519/v1`. They cover nested signing,
different accepted device supports, same-roster refresh, and device reshare.

All byte strings are lowercase hexadecimal. Values under `test_only_secret`
are public test fixtures and must never seed a live key or nonce.

Released files are immutable. Their SHA-256 digests are pinned by
`tests/vector_integrity.rs`.
