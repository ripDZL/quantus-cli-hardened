# Quantus CLI v2.2.2 — Local Fork Security Audit

**Baseline:** `Quantus-Network/quantus-cli` v2.2.2
**Reviewed commit:** `b98083bf29a3bee5a121affd723431d3654c3247`
**Audit type:** focused static review and conservative hardening pass
**Not a formal cryptographic proof or third-party penetration test.**

## Executive assessment

The upstream CLI is substantially more security-conscious than many early-stage wallet projects. Sensitive command-line password arguments are rejected, wallet payloads use Argon2id plus AES-256-GCM, private-key and mnemonic debug output is redacted, wallet file creation has strong Unix anti-symlink/atomic-write protections, runtime identity is checked before signing, and the self-updater verifies release SHA-256 values with download-size caps.

The local hardening pass therefore avoids changing Quantus cryptography, derivation, transaction encoding, or consensus-facing logic. It addresses five lower-risk but meaningful attack/robustness surfaces while preserving the existing wallet format.

## Findings

| ID | Severity | Finding | Status in local fork |
|---|---|---|---|
| QCLI-01 | **Medium** | Plaintext remote `ws://` RPC endpoints are accepted. A network attacker can tamper with RPC traffic even though runtime identity checks reduce some risk. | **Patched**: plaintext WebSocket is restricted to loopback by default; explicit env opt-in is required for remote development endpoints. |
| QCLI-02 | **Medium** | Windows lacks an equivalent to Unix wallet-directory `0700`, wallet-file `0600`, and owner-only secret-file validation. | **Open / priority follow-up**: requires native Windows ACL work rather than a superficial warning. |
| QCLI-03 | **Low–Medium** | `EncryptedWallet.name` is cleartext and was not cross-checked against the name inside the authenticated encrypted payload. | **Patched**: unlock now rejects a mismatched envelope name. |
| QCLI-04 | **Low** | Password/mnemonic files are read into a `String` without an explicit size bound. | **Patched**: 64 KiB cap before read. |
| QCLI-05 | **Low** | Storage metadata code contains two `unwrap()` sites after earlier validation steps; unexpected metadata behavior could panic the process. | **Patched**: normal error path. |
| QCLI-06 | **Low** | Multisend confirmation uses `unwrap()` for stdout flush/stdin read, permitting a panic on broken/closed I/O. | **Patched**: normal error path. |
| QCLI-07 | **Medium (supply chain)** | Self-update SHA-256 protects integrity but not independent authenticity because archive and checksum are sibling GitHub release assets. | **Open**: recommend signed release manifests/assets with an embedded verification key or equivalent provenance mechanism. |
| QCLI-08 | **Advisory** | Wallet Argon2id profile is fixed at roughly 19 MiB, t=2, p=1. This is interoperable and DoS-resistant, but high-value custody may justify a versioned stronger KDF profile. | **Open / format-v3 candidate**. |
| QCLI-09 | **Advisory** | Passwords may be supplied through environment variables. This is convenient for automation but can broaden secret exposure depending on OS/process model. | **Document / de-emphasize for interactive use**. |

## Positive controls verified in source

### Secret handling

- Raw `--password/-p` input is explicitly rejected so passwords do not land in normal process argument listings or shell history.
- Interactive password and mnemonic input uses hidden terminal input.
- Unix secret files are required to be regular files owned by the effective user with no group/other permission bits.
- Unix secret-file opening avoids blocking on FIFOs and rejects non-regular files after opening the handle.
- `QuantumKeyPair` custom `Debug` output redacts the private key.
- `WalletData` custom `Debug` output redacts the mnemonic.
- Private-key and mnemonic buffers have explicit zeroization paths.

### Keystore

- Wallet payload encryption uses Argon2id + AES-256-GCM.
- The Argon2 profile is frozen and strictly validated on decrypt; a crafted wallet file cannot ask the CLI to allocate arbitrary Argon2 memory/CPU.
- AES-GCM authentication failures are treated as bad-password/corruption failures.
- The public wallet address is checked against the address derived from decrypted key material.
- Current wallet format does not persist the Argon2 digest; legacy files that embedded key material are detected and prevented from being re-saved without migration.
- Wallet names reject path traversal, separators, control characters, and Windows-reserved filename characters.
- Unix writes use unpredictable `create_new` temporary files and `O_NOFOLLOW`, with owner-only permissions and atomic replacement behavior.

### Chain/RPC

- Diagnostic URLs strip embedded credentials before logging.
- Runtime version/identity is checked before transaction signing/submission in the normal client path.
- Runtime version and metadata are fetched from a consistent best-block hash to reduce upgrade-boundary mismatches.

### Self updater

- Release archive SHA-256 is verified before extraction/replacement.
- Checksum and archive downloads have explicit maximum sizes.
- The updater itself documents that same-release checksums are integrity protection, not independent authenticity.

### Upstream CI signals

- The current reviewed v2.2.2 commit had a scheduled **Chain Exercise Suite** run complete successfully on September 12, 2026.
- The repository also has a scheduled reusable **Dependency cooldown audit** workflow. The most recent surfaced run completed successfully on September 7, 2026, but it ran against the prior v2.1.3 revision rather than this exact v2.2.2 commit. Treat that as a positive maintenance signal, not a substitute for running `cargo audit` on the local fork.

## Local hardening changes

### 1. Secure remote RPC by default

`src/chain/client.rs`

- `wss://` remains accepted.
- `ws://127.x.x.x`, `ws://localhost`, and `ws://[::1]` remain accepted for local nodes.
- Other plaintext `ws://` endpoints are refused.
- A deliberate development override is available as `QUANTUS_ALLOW_INSECURE_REMOTE_WS=1`.

This protects normal signing workflows from accidentally using a remote plaintext WebSocket endpoint while retaining local-node compatibility.

### 2. Bound secret-file reads

`src/wallet/password.rs`

Password and mnemonic files are capped at 64 KiB before `read_to_string`. Real secrets are orders of magnitude smaller; the bound prevents an accidental or attacker-controlled path from becoming an unbounded allocation/read.

### 3. Bind wallet name to encrypted contents

`src/wallet/keystore.rs`

The cleartext `EncryptedWallet.name` is now compared with `WalletData.name` after authenticated decryption. An envelope-name edit is rejected as an integrity failure.

This does **not** redesign the wallet format or add AEAD associated data, so compatibility remains intact.

### 4. Remove avoidable panic on metadata lookup

`src/cli/storage.rs`

Both runtime metadata `unwrap()` sites are replaced with explicit `QuantusError` paths.

### 5. Remove avoidable panic in transaction confirmation I/O

`src/cli/multisend.rs`

stdout flush and stdin read errors now propagate as normal CLI errors.


### 6. Windows-safe test wallet isolation

`src/wallet/mod.rs`, `src/cli/wallet.rs`, `src/cli/wormhole.rs`

A Windows validation run exposed an upstream test-isolation flaw: tests set `HOME` and then call `WalletManager::new()`, but `dirs::home_dir()` uses the Windows Known Folder API (`FOLDERID_Profile`) and ignores `HOME`. The first test target can therefore create fixture wallets under the real `%USERPROFILE%\.quantus\wallets` directory.

v1.2 adds a **test-only** `QUANTUS_TEST_WALLETS_DIR` override guarded by RAII restoration and updates the affected tests to use temporary wallet directories. Production builds do not recognize or use this test override.

### 7. Remove duplicate binary/library module compilation

`src/main.rs`

The binary target previously re-declared the same modules already exported by `src/lib.rs`. `cargo test --all-features` consequently ran nearly the entire unit-test suite twice (321 tests in the library target, then 319 in the binary target). The second run collided with wallet fixtures left by the first. v1.2 makes the binary import the `quantus_cli` library crate instead of re-declaring those modules.

### 8. Windows Clippy cleanliness

`src/bins.rs`

A helper import used only by a `#[cfg(unix)]` test was unconditional, producing an unused-import warning on Windows. v1.2 gates the import with `#[cfg(unix)]`, preventing that warning from becoming a hard failure under `cargo clippy ... -D warnings`.

## Priority follow-up work

### A. Windows ACL hardening — priority 1

The largest platform-specific gap is Windows. Upstream permission hardening is mostly `#[cfg(unix)]`. A proper fix should use Windows security descriptors/ACL APIs to ensure the wallet directory and wallet/secret files grant access only to the current user (plus only the minimum required system/administrative principals, depending on the chosen policy). Avoid implementing this by shelling out to `icacls` inside the wallet runtime.

A `quantus doctor` command should also inspect the resulting ACLs and fail loudly on insecure custody paths.

### B. Wallet format v3 with authenticated envelope metadata

A future migration can use AEAD associated data (AAD) to authenticate cleartext metadata such as:

- wallet name
- public address
- wallet type
- creation timestamp / format version

It can simultaneously introduce a stronger, versioned Argon2id profile while retaining migration logic for v1/v2.

### C. Independently signed updates

Add signed release manifests or signed archives. The public verification key should be pinned in the application or verification should use a comparably strong provenance mechanism. SHA-256 files published in the same release are not sufficient against release-account compromise.

### D. Dependency and supply-chain policy

The reviewed `Cargo.toml` already pins several versions specifically to avoid 2026 RustSec advisories. Continue with:

- `cargo audit` in CI
- `cargo deny` for advisories/licenses/sources
- locked release builds (`--locked`)
- pin Git dependencies by immutable commit SHA in addition to/replacing mutable tag trust where operationally practical
- SBOM/provenance generation for release artifacts

### E. Secret-source policy

For normal interactive use, prefer the hidden prompt. Treat `QUANTUS_WALLET_PASSWORD*` environment variables as automation compatibility rather than the recommended path. Consider OS-native credential stores for automation in a desktop-oriented fork.

## Validation limitation for this review

The audit environment could inspect the exact GitHub source revision but could not perform the full Windows build itself. A user-run Windows validation of v1.1 did compile the project and completed the library test target with **321/321 passing**; the subsequent binary test target exposed the Windows test-isolation defect described above and stopped before Clippy/audit. v1.2 addresses that defect. The bootstrap/resume process remains pinned to the exact reviewed commit and refuses to patch another revision. Complete the verification checklist before using the fork with real funds.

---

# Hardening v1.3 Addendum — 2026-09-12

Base upstream:
- Quantus CLI v2.2.2
- Commit: b98083bf29a3bee5a121affd723431d3654c3247

Additional v1.3 changes:
- Strengthened plaintext WebSocket RPC policy.
- Loopback WebSocket exceptions now require a literal loopback IPv4/IPv6 address or localhost.
- DNS names such as 127.attacker.example are explicitly rejected.
- Added regression tests for loopback hostname spoofing.
- Updated chacha20 from the yanked 0.10.1 release to 0.10.2 through Cargo.lock.
- Preserved Windows test-wallet isolation.
- Removed duplicate binary-side unit-test compilation.
- Confirmed 64 KiB secret-file size limits.
- Preserved wallet envelope/name consistency validation.
- Replaced audited panic-prone unwrap paths with error propagation.

Validation:
- cargo test --all-features: 321 passed, 0 failed.
- cargo clippy --all-targets --all-features -- -D warnings: passed.
- cargo check --all-features --locked: passed.
- git diff --check: passed.
- cargo audit: completed with no blocking vulnerability failure.

RustSec residual warnings:
- derivative 2.2.0: unmaintained
- instant 0.1.13: unmaintained
- libsecp256k1 0.7.2: unmaintained; inherited through Substrate sp-core
- paste 1.0.15: unmaintained
- proc-macro-error2 2.0.1: unmaintained
- lru 0.12.5: two unsoundness advisories remain in Cargo.lock

The lru 0.12.5 package is not reachable from the resolved build graph:
- cargo tree -i lru@0.12.5: no dependency path
- cargo tree --target all -i lru@0.12.5: no dependency path
- cargo tree --all-features --target all -i lru@0.12.5: no dependency path

No forced override was applied because doing so would introduce dependency risk without affecting a reachable build path.

The libsecp256k1 warning is inherited from the Substrate dependency stack and is not locally replaced because a crypto implementation substitution should be handled through a compatible upstream Substrate migration rather than an unreviewed wallet-level override.
