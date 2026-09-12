# Local Quantus Fork — Verification Checklist

Reviewed baseline: `Quantus-Network/quantus-cli` v2.2.2, commit `b98083bf29a3bee5a121affd723431d3654c3247`.

Run these from the repository root after applying the local hardening edits:

```text
cargo fmt --all -- --check
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
cargo audit
```

For a release candidate, also build in locked mode and exercise both hot- and cold-wallet workflows against a disposable wallet and a local/test node:

```text
cargo build --release --locked
cargo test --release --all-features --locked
```

## Manual security checks

1. `ws://127.0.0.1:9944` and `ws://localhost:9944` must still work.
2. `ws://<remote-host>:9944` must fail unless `QUANTUS_ALLOW_INSECURE_REMOTE_WS=1` is deliberately set.
3. `wss://<remote-host>` must remain accepted.
4. A password or mnemonic file larger than 64 KiB must be rejected before it is read into memory.
5. A wallet JSON whose cleartext `name` is changed without re-encrypting the payload must fail integrity validation on unlock.
6. `quantus storage list --pallet <name>` must return a normal error rather than panic if metadata lookup unexpectedly fails.
7. Multisend confirmation must return a normal error if stdin/stdout is unavailable rather than panic.
8. On Windows, inspect `%USERPROFILE%\.quantus\wallets` ACLs. The current upstream code has no Windows equivalent of the Unix `0700` directory / `0600` file enforcement; fixing this is a priority follow-up.
9. Treat environment-variable passwords as automation-only. Prefer the masked prompt or a tightly permissioned password file.
10. Verify release artifacts independently before distributing binaries. The upstream self-updater verifies SHA-256, but the checksum and archive originate from the same GitHub release and are not independently signed.
11. On Windows, run the test suite with a clean `%USERPROFILE%\.quantus\wallets` snapshot and confirm tests do not create `export-leak.json`, `export-file.json`, `src.json`, or `crystal_alice.json` there.
12. `cargo test --all-features` should run the library tests once; the binary target should no longer re-run the same module test suite.
13. `cargo clippy --all-targets --all-features -- -D warnings` must be warning-free, including on Windows.
