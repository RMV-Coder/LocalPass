# Security Policy

LocalPass is a fully local password and secrets manager. Its security posture is
the product, so this document states plainly what LocalPass protects, what it
cannot, how to report a vulnerability, and the cryptography it uses. It
complements the full threat model in [PRD.md](PRD.md) §8 and the architecture in
[docs/architecture.md](docs/architecture.md).

> **Pre-1.0 — not yet audited. Do not store real secrets.**
> LocalPass is under active development and has **not** undergone the external
> security audit that is a hard gate before 1.0 (PRD §10 R1, §9.1). The on-disk
> storage format may still change. As the [README](README.md) says: not yet
> ready for real secrets.

---

## Supported versions

| Version | Supported |
|---------|-----------|
| `main` (pre-release) | Yes — this is the only supported line. |
| Tagged releases | None yet. There are no 1.0 (or any) releases. |

Pre-1.0, **only the `main` branch is supported.** There is no backport or LTS
policy yet; fixes land on `main`.

---

## Reporting a vulnerability

Please report security issues **privately** — do not open a public GitHub issue,
pull request, or discussion for a suspected vulnerability.

<!-- TODO(pre-1.0): replace the placeholder below with the real disclosure
     channel before any public release. Recommended: enable GitHub Security
     Advisories (private vulnerability reporting) on the repository AND publish a
     dedicated security contact address (e.g. security@localpass.example) with a
     PGP key. Neither exists yet. -->

- **Preferred (once enabled): GitHub Security Advisories** — "Report a
  vulnerability" on the repository's Security tab. *(TODO: private vulnerability
  reporting is not yet enabled on the repo.)*
- **Email:** `TODO-SECURITY-CONTACT@localpass.invalid` *(placeholder — no real
  security address exists yet; this must be set before 1.0.)*

### What to include

- A clear description of the issue and its impact.
- Step-by-step reproduction (a proof-of-concept, minimal repro, or failing test
  is ideal).
- Affected component (crate/binary), commit hash, OS, and toolchain version.
- Whether the issue is already public anywhere.
- Do **not** include real secrets or third parties' data in your report.

### What to expect

Because LocalPass is pre-1.0 and (at the time of writing) maintained by a small
team, we cannot promise a formal SLA yet. Our intended posture:

- Acknowledge receipt within a few business days.
- Work with you privately on a fix and a coordinated disclosure timeline.
- Credit you in the advisory/release notes unless you prefer to remain anonymous.

A **bug bounty is planned at General Availability** (PRD §10 R1); there is no
paid bounty during the pre-1.0 phase.

---

## Security model summary (plain language)

Full detail is in [PRD.md](PRD.md) §8 (threat model) and
[docs/architecture.md](docs/architecture.md) §5 (security boundaries). In short:

### What LocalPass protects

- **Your data at rest.** Everything sensitive on disk — secret values, titles,
  usernames, URLs, tags, custom-field names *and* values, notes, and vault/folder
  names — is encrypted with XChaCha20-Poly1305 under a per-item, per-version key.
  A thief with a stolen vault file and no keys learns only minimal structural
  metadata (item count, timestamps/edit cadence, creation ordering), never
  secrets (PRD §8 T1; [docs/specs/vault-format.md](docs/specs/vault-format.md)
  §6, §12).
- **Against offline brute force.** Your master password is stretched with
  Argon2id and combined with a locally-generated **128-bit Secret Key** (à la
  1Password). Even a weak master password is not offline-brute-forceable from the
  vault file alone, because the attacker also needs the Secret Key (PRD §8 T1,
  T12).
- **Your data in sync transit.** Sync ships an end-to-end-encrypted operation
  log. Every operation is encrypted under the vault key and Ed25519-signed over
  its full form (including the ciphertext); a per-device sequence number and
  BLAKE3 hash chain make any drop, replay, rollback, or tamper detectable and
  alarmed. The transport channel is fully untrusted — a malicious file host or
  relay sees only ciphertext and cannot forge, reorder, or silently drop
  operations ([docs/specs/sync-protocol.md](docs/specs/sync-protocol.md) §5;
  PRD §8 T5, T13).
- **Against other local users, up to OS boundaries.** The background daemon
  exposes keys only over a same-user-only IPC channel (a Windows named pipe whose
  DACL grants only your SID; a Unix socket with `0700`/`0600` permissions plus a
  `SO_PEERCRED` same-uid check). No localhost TCP port is ever opened, avoiding
  the local-port-hijack class of bugs. The browser bridge is native-messaging,
  fill-scoped, and origin-re-validated server-side (PRD §8 T7, T8).

### What LocalPass cannot protect against

Stated honestly, as every serious manager must:

- **An attacker with same-user code execution while the vault is unlocked.**
  Once keys are in the daemon's memory, malware running as *you* can, in
  principle, reach them. LocalPass reduces blast radius (zeroize-on-drop, short
  auto-lock, fill-only extension scope) but this is not fully defensible
  (PRD §8 T3).
- **A coerced user** ("$5 wrench"). Out of scope for technical mitigation
  (PRD §8 T15).
- **A backdoored OS or hardware.** LocalPass assumes the operating system,
  kernel, and hardware are not backdoored (PRD §8 standing assumptions).

### No cloud recovery — the doctrine

**There is no cloud reset and no recovery service.** LocalPass never uploads your
keys anywhere. Your secrets are protected by your master password *and* your
128-bit **Secret Key**. If you lose your master password, your Secret Key, **and**
all your devices, your data is gone — by design (PRD §4.11, §10 R6). This is why:

- The **Secret Key** is generated locally at setup, stored on-device, and printed
  in your **Emergency Kit** — print it and store it offline.
- Automatic local backups are on by default, and `localpass backup verify`
  confirms a backup is actually recoverable with your current credentials.
- The export archive uses the standard **age** format, decryptable with the
  standalone `age` tool, so you are never locked into LocalPass even if the
  project disappears (PRD §6.9, §10 R9).

> At MVP the Secret Key is stored in a `<profile>/secret-key` file (owner-only on
> Unix) as the documented stand-in for OS-keychain storage; OS-keychain and
> biometric/hardware unlock are Phase 2 (PRD §4.3;
> [LESSONS.md](LESSONS.md)). Keep your printed Emergency Kit as the authoritative
> offline copy.

---

## Cryptography summary

The only crate permitted to use cryptographic primitives is `lp-crypto`, which
exposes a small, misuse-resistant, high-level API (PRD §6.2). Everything else
consumes it. Constructions are deliberately boring and standard (PRD §5.1).

| Primitive | Where / crate | Role (one line) |
|-----------|---------------|-----------------|
| **Argon2id** | `lp-crypto` (`argon2`) | Password KDF: stretches the master password (memory-hard) before key derivation. |
| **HKDF-SHA-256** | `lp-crypto` (`hkdf`, `sha2`) | Key mixing / subkey derivation: combines the Argon2id output with the Secret Key into the MUK, and derives the IndexKey; every label is domain-separated under `localpass/v1/`. |
| **XChaCha20-Poly1305** | `lp-crypto` (`chacha20poly1305`) | Symmetric AEAD: encrypts every at-rest and in-transit payload as an Envelope v1 (`0x01 ‖ 24-byte nonce ‖ ciphertext+tag`); 192-bit random nonces are safe at scale. |
| **X25519** | `lp-crypto` (`x25519-dalek`) | Asymmetric key agreement: age-style sealing of keys/payloads to a recipient device's public key (for cross-device key transport); low-order points are rejected. |
| **Ed25519** | `lp-crypto` (`ed25519-dalek`) | Signatures: signs each sync operation (device authorship / non-repudiation) and is the SSH-key trust-anchor algorithm; reserved for membership + release signing. |
| **BLAKE3** | `lp-crypto` (`blake3`) | Integrity hashing: the per-device sync-log hash chain (`prev_hash`) and content-addressing; **not** a KDF. |
| **HMAC-SHA-1** | `lp-crypto` (`hmac`, `sha1`) | **TOTP only** (RFC 6238 / authenticator-app interop). SHA-1 is confined to the `totp` module and must never be used for general hashing, KDF, or signatures anywhere else. |

Additional hygiene enforced in `lp-crypto` (see its module docs): `zeroize`-on-drop
for all secret types, redacting `Debug`, constant-time equality (`subtle`) for key
comparison, opaque single-variant decryption failure (no padding/AAD oracles),
mandatory `localpass/v1/` domain-separation labels, purpose-bound key wrapping via
AAD, and versioned format headers instead of runtime crypto negotiation
(downgrade resistance). The core forbids `unsafe` (`#![forbid(unsafe_code)]`); the
OS CSPRNG (`getrandom`) is the only randomness source. Alternate suites noted in
the PRD (AES-256-GCM for FIPS-leaning deployments) are reserved in the format but
not the MVP default (PRD §5.2; vault-format.md §9).

---

## Known dependency advisories

Supply-chain scanning (`cargo deny`, run in CI) is clean except for two
documented, accepted advisories on transitive dependencies (rationale recorded
in [`deny.toml`](deny.toml)):

- **RUSTSEC-2023-0071 (`rsa` — "Marvin" timing side-channel).** The `rsa` crate
  has a non-constant-time implementation whose timing leaks key bits *during
  decryption* over a network (a padding-oracle vector). LocalPass pulls `rsa`
  only via `ssh-key` and uses it **only to sign** with a user's RSA SSH key in
  the local SSH agent — it performs **no RSA decryption anywhere**, and signing
  runs over a same-user-only local pipe on a client-chosen hash, not on
  attacker-supplied ciphertext exposed to a network observer. The advisory's
  vector therefore does not apply. **Mitigation: prefer Ed25519 SSH keys** (the
  recommended default); RSA exists for interoperability. A tracked follow-up
  will feature-gate RSA so the default build omits the `rsa` crate entirely.
- **RUSTSEC-2026-0173 (`proc-macro-error2` — unmaintained).** A compile-time
  proc-macro pulled transitively by `age`'s error-message localization. It ships
  no runtime code and is an "unmaintained" notice, not a vulnerability; it will
  drop when `age` updates its i18n stack.

---

## External audit status

An **independent external security audit of the core cryptography is a hard gate
before 1.0** (PRD §2.2, §9.1 "MVP acceptance gates", §10 R1). **It has not yet
happened.** Until it does — and until the storage format is frozen — treat
LocalPass as pre-release software and do not store secrets you cannot afford to
lose or expose.
