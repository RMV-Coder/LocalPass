//! The `clap` v4 command tree — the documented CLI contract (PRD §4.4).
//!
//! Everything here is declarative: the structs/enums *are* the interface and
//! the generated `--help`. Command behaviour lives in [`crate::commands`].
//!
//! ## Global conventions
//!
//! - `--profile <dir>` overrides the platform default profile directory.
//! - `--no-input` forbids interactive prompts (for scripts): a command that
//!   would prompt fails instead.
//! - `--json`, where offered, prints stable machine-readable output documented
//!   per-command.
//!
//! ## Secret handling (hard rules, PRD §4.4)
//!
//! Secret values are **never** accepted as help examples, never logged, and
//! never printed unless the user asks (`item get --reveal` / `--field`).
//! Passwords come from a hidden TTY prompt, `--password-stdin`, or the
//! `LOCALPASS_PASSWORD` environment variable (documented as script-only; env
//! vars can leak into process listings — piping to `--password-stdin` is
//! preferred).

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// LocalPass — a fully local password & secrets manager (CLI).
#[derive(Debug, Parser)]
#[command(
    name = "localpass",
    version,
    about = "LocalPass — fully local, offline password & secrets manager.",
    long_about = "LocalPass CLI: create an account, manage vaults and items, and generate \
secrets — all offline, encrypted at rest.\n\n\
UNLOCK: commands that touch a vault read the on-device Secret Key from \
<profile>/secret-key and prompt for the master password. For scripts, pipe the \
password via --password-stdin, or set LOCALPASS_PASSWORD (WARNING: environment \
variables can be visible in process listings and inherited by children — prefer \
--password-stdin).\n\n\
SECRET KEY STORAGE: the 128-bit Secret Key is stored on this device in a plain \
file at <profile>/secret-key with owner-only permissions. This is the MVP \
stand-in for OS-keychain integration (PRD §4.3; keychain is P2). Keep your \
printed Emergency Kit as the authoritative offline copy.\n\n\
EXIT CODES: 0 ok, 1 user error (bad args / not found), 2 authentication \
failure, 3 internal error."
)]
pub struct Cli {
    /// Profile directory (default: platform data dir, e.g. %APPDATA%\localpass
    /// or ~/.local/share/localpass).
    #[arg(long, global = true, value_name = "DIR")]
    pub profile: Option<PathBuf>,

    /// Never prompt interactively; fail instead (for non-interactive scripts).
    #[arg(long, global = true)]
    pub no_input: bool,

    /// Read the master password from stdin (one line) instead of prompting.
    #[arg(long, global = true)]
    pub password_stdin: bool,

    /// Ignore any running daemon and unlock directly for this command (the
    /// pre-daemon behaviour). Does not stop or affect a running daemon.
    #[arg(long, global = true)]
    pub no_daemon: bool,

    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
///
/// The `item` variants carry the wide `add`/`edit` flag structs; the whole
/// `Cli` is parsed exactly once at startup and never held in bulk, so the size
/// disparity between variants is intentional (boxing would only add ceremony to
/// a short-lived parse value).
#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Create the account: set a master password and generate the Emergency Kit.
    Init(InitArgs),

    /// Show profile path, whether an account exists, and the vault count.
    Status {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Manage vaults.
    Vault {
        #[command(subcommand)]
        command: VaultCommand,
    },

    /// Manage items (add / get / list / edit / rm / history / restore).
    Item {
        #[command(subcommand)]
        command: ItemCommand,
    },

    /// Store, list, download, and remove encrypted file attachments on an item
    /// (PRD §4.1). Blobs are encrypted at rest beside the vault; the plaintext
    /// only leaves the vault when you explicitly `attach get --out <path>`.
    Attach {
        #[command(subcommand)]
        command: AttachCommand,
    },

    /// Search items by title, tag, or type across a vault.
    Search {
        /// The query text (matched case-insensitively).
        query: String,
        /// Restrict to one item type.
        #[arg(long = "type", value_enum, value_name = "TYPE")]
        item_type: Option<ItemType>,
        /// Vault to search (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Generate a random password or passphrase (never stored; printed once).
    Generate(GenerateArgs),

    /// Audit a vault's passwords for weak, reused, common, or short secrets
    /// (the offline "Watchtower" check). Never prints secret values.
    #[command(long_about = "Offline password-health audit — flags WEAK (low \
entropy), SHORT, COMMON (in a bundled leaked-password list), and REUSED \
passwords across a vault. Runs entirely locally: no network, no Have I Been \
Pwned. The report is metadata only — item titles, field names, lengths, an \
entropy estimate, and issue flags — never a secret value.")]
    Health {
        /// Vault to audit (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },

    /// Manage the master password.
    Password {
        #[command(subcommand)]
        command: PasswordCommand,
    },

    /// Run a command with secrets injected into its environment (PRD §4.8).
    Run(RunArgs),

    /// Export, import, and diff `.env` sets (PRD §4.8).
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },

    /// Import items from another password manager's export (PRD §4.6).
    Import(ImportArgs),

    /// Export items — the recoverable age archive, or guarded plaintext (§4.6).
    Export(ExportArgs),

    /// Unlock the vault in the background daemon so later commands don't
    /// re-prompt. Starts the daemon if it isn't running, then sends the
    /// password to it (over the same-user-only local IPC channel).
    Unlock,

    /// Lock the background daemon now, dropping its unlocked keys from memory.
    /// A no-op (still exits 0) if no daemon is running.
    Lock,

    /// Manage the background daemon (start / stop / status).
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },

    /// Create, list, verify, and restore encrypted profile backups (PRD §4.11).
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },

    /// (Re)generate the Emergency Kit file — the Secret Key + recovery
    /// instructions — anytime (PRD §4.11). Requires unlock; never writes into
    /// the profile directory (that would defeat the kit's purpose).
    Kit(KitArgs),

    /// Sync a vault's op log over a shared file channel (setup / push / pull /
    /// status). File-based log shipping is the MVP-default sync (PRD §11 #6).
    Sync {
        #[command(subcommand)]
        command: SyncCommand,
    },

    /// Device pairing: export this device's identity and trust a peer device.
    Device {
        #[command(subcommand)]
        command: DeviceCommand,
    },

    /// Open or close **pairing mode** — the time-boxed window that must be on to
    /// trust a new device (`device-pairing.md` §4).
    Pairing {
        #[command(subcommand)]
        command: PairingCommand,
    },

    /// Manage vault-backed SSH keys and the SSH agent (PRD §4.8).
    Ssh {
        #[command(subcommand)]
        command: SshCommand,
    },

    /// Print the current TOTP code for a `totp` item (PRD §4.1 / §4.4).
    Totp(TotpArgs),

    /// Show the device-local audit log (PRD §4.9): unlocks, failed unlocks,
    /// secret reveals, edits, exports, and shares — ids + timestamps, never a
    /// secret value. `--verify` re-checks the tamper-evident hash chain.
    Audit(AuditArgs),

    /// Register or unregister the browser autofill native-messaging host
    /// (PRD §4.7 / §6.7). Points Chrome/Firefox at the `localpass-native-host`
    /// binary via the per-OS manifest (+ HKCU registry key on Windows).
    Browser {
        #[command(subcommand)]
        command: BrowserCommand,
    },
}

/// `localpass browser ...`
#[derive(Debug, Subcommand)]
#[command(
    long_about = "Register the LocalPass browser-autofill native-messaging host.\n\n\
The browser extension talks to LocalPass over Chrome/Firefox NATIVE MESSAGING — \
NOT a localhost port (PRD §4.7 avoids that whole class of local-port-hijack \
bugs). For the browser to launch the host, it needs a native-messaging host \
MANIFEST that names the host (com.localpass.host), the path to the installed \
`localpass-native-host` binary, and the extension allowlist.\n\n\
`browser register` writes that manifest to the correct per-OS location and, on \
Windows, the HKCU registry value that points the browser at it. `browser \
unregister` removes them (idempotent).\n\n\
EXTENSION ID: LocalPass has no published extension id yet, so a documented \
PLACEHOLDER id is used unless you pass --extension-id. The allowlist is the \
browser-enforced gate on WHICH extension may connect, so set the real id before \
relying on autofill.\n\n\
The host itself holds NO keys: it bridges to the daemon with a FILL-SCOPED \
capability only (non-secret candidates + a single-item, origin-re-validated \
fill)."
)]
pub enum BrowserCommand {
    /// Write the native-messaging manifest(s) (+ Windows registry key).
    Register {
        /// Register for Chrome / Chromium.
        #[arg(long)]
        chrome: bool,
        /// Register for Firefox.
        #[arg(long)]
        firefox: bool,
        /// Register for all supported browsers (the default if no browser flag
        /// is given).
        #[arg(long)]
        all: bool,
        /// The extension id to allowlist (default: a documented placeholder).
        /// For Chrome this is the 32-char extension id; for Firefox the addon id.
        #[arg(long, value_name = "ID")]
        extension_id: Option<String>,
        /// Path to the installed `localpass-native-host` binary (default: the
        /// one sitting next to this `localpass` binary).
        #[arg(long, value_name = "PATH")]
        host_path: Option<PathBuf>,
    },
    /// Remove the native-messaging manifest(s) (+ Windows registry key).
    Unregister {
        /// Unregister Chrome / Chromium.
        #[arg(long)]
        chrome: bool,
        /// Unregister Firefox.
        #[arg(long)]
        firefox: bool,
        /// Unregister all supported browsers (the default if no browser flag is
        /// given).
        #[arg(long)]
        all: bool,
    },
}

/// `localpass totp <title-or-id> [flags]`
#[derive(Debug, Args)]
#[command(
    long_about = "Print the current TOTP (RFC 6238) code for a totp item.\n\n\
The code is computed LOCALLY from the item's stored base32 secret — nothing \
leaves your machine. The 6-8 digit CODE is printed to STDOUT and the human hint \
`expires in Ns` to STDERR, so a pipe (`localpass totp GitHub | clip`) captures \
only the code.\n\n\
The target must be a `totp`-type item; any other type is a clear usage error \
(pass an otpauth:// URI to `item add --type totp` to create one).\n\n\
DAEMON: when the background daemon is unlocked, the code is computed inside the \
daemon and only the finished digits cross the IPC channel — the secret never \
does. Otherwise LocalPass unlocks directly, decodes the secret, computes, and \
zeroizes it.\n\n\
--json prints {code, seconds_remaining, period, digits, algo}. --watch reprints \
the code each time the period rolls over (Ctrl-C to stop); it polls the clock \
on a short sleep rather than busy-waiting."
)]
pub struct TotpArgs {
    /// The totp item (title or id).
    pub target: String,

    /// Vault to look in (name or id).
    #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
    pub vault: String,

    /// Emit machine-readable JSON ({code, seconds_remaining, period, digits, algo}).
    #[arg(long)]
    pub json: bool,

    /// Reprint the code on every new period until interrupted (Ctrl-C).
    #[arg(long, conflicts_with = "json")]
    pub watch: bool,
}

/// `localpass audit [--since <dur|ts>] [--json] [--verify]`
#[derive(Debug, Args)]
#[command(long_about = "Show this device's local audit log (PRD §4.9).\n\n\
LocalPass keeps a per-device, append-only, tamper-evident (hash-chained) audit \
log of security-relevant actions: successful and FAILED unlocks, reads that \
REVEAL a secret value (item get --reveal / --field, localpass:// references, \
autofill fills, TOTP codes), item edits (create/update/delete/restore), \
exports, and device/vault shares.\n\n\
The log holds ONLY non-secret metadata — item and vault IDs, kinds, and \
timestamps. It NEVER contains a secret value, a password, or an item/vault NAME \
(names are encrypted everywhere else; the log is plaintext). A masked `item \
get` (no --reveal), `list`, and `search` are NOT logged as reads — only an \
actual reveal is.\n\n\
Records print oldest-first (chronological). --since filters to recent activity \
(a duration like `7d`/`24h`/`30m`, or a unix-millis timestamp). --json emits a \
stable array. --verify re-checks the hash chain and per-device sequence: it \
exits 0 on an intact chain and NON-ZERO (with a clear message) if any record \
was altered, deleted, or reordered.")]
pub struct AuditArgs {
    /// Only show records at or after this point: a duration back from now
    /// (`7d`, `24h`, `30m`, `90s`) or an absolute unix-millis timestamp.
    #[arg(long, value_name = "DURATION_OR_TS")]
    pub since: Option<String>,

    /// Emit machine-readable JSON (a stable array of records).
    #[arg(long)]
    pub json: bool,

    /// Verify the tamper-evident hash chain instead of printing records. Exits 0
    /// if intact, non-zero if any record was altered, deleted, or reordered.
    #[arg(long)]
    pub verify: bool,
}

/// `localpass ssh ...`
#[derive(Debug, Subcommand)]
#[command(long_about = "Vault-backed SSH keys and the SSH agent (PRD §4.8).\n\n\
The background daemon serves an SSH agent on a same-user-only endpoint (Windows \
named pipe `\\\\.\\pipe\\openssh-ssh-agent`, which Windows OpenSSH uses by \
default; Unix `$XDG_RUNTIME_DIR/localpass/ssh-agent.sock` — set \
SSH_AUTH_SOCK to it). Every `ssh_key` item across your unlocked vaults becomes \
an agent identity; private keys never touch disk and are read from the vault at \
sign time (a rotated key is used immediately).\n\n\
`ssh list` shows the identities the agent would serve without needing ssh-add. \
`ssh generate` creates a keypair in memory and stores it (printing only the \
public key). `ssh public` prints an item's public key for authorized_keys.\n\n\
The agent starts with the daemon by default; run `localpass daemon start` (or \
`localpass unlock`) to bring it up, and `localpass daemon status` to see its \
endpoint and identity count. On Windows, stop Microsoft's own agent first if it \
owns the pipe name: `Stop-Service ssh-agent`.")]
pub enum SshCommand {
    /// List the identities the agent would serve (fingerprint, comment, algo)
    /// across all vaults — without needing ssh-add.
    List {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Generate an SSH keypair in memory and store it as an ssh_key item. Only
    /// the public key is printed; the private key never touches disk.
    #[command(
        long_about = "Generate an SSH keypair and store it in a vault (PRD §4.1).\n\n\
The keypair is generated IN MEMORY with the OS CSPRNG and stored as an ssh_key \
item (OpenSSH-format private key inside the encrypted payload, plus the public \
key and SHA-256 fingerprint). ONLY the public key is printed — the private key \
is never written to disk or echoed. Once stored, the key is served by the SSH \
agent automatically."
    )]
    Generate {
        /// The item title for the new key.
        #[arg(long)]
        title: String,
        /// Vault to store the key in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// The key algorithm.
        #[arg(long, value_enum, default_value = "ed25519")]
        algo: SshAlgo,
        /// A comment for the public key (default: the title).
        #[arg(long)]
        comment: Option<String>,
        /// Emit machine-readable JSON (the public key + fingerprint).
        #[arg(long)]
        json: bool,
    },
    /// Print an item's public key (for authorized_keys).
    Public {
        /// The ssh_key item (title or id).
        target: String,
        /// Vault to look in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
    },
}

/// The SSH key algorithms `localpass ssh generate` can produce (PRD §4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SshAlgo {
    /// Ed25519 (recommended: small, fast, modern).
    Ed25519,
    /// RSA-4096.
    Rsa4096,
}

/// `localpass sync ...`
#[derive(Debug, Subcommand)]
#[command(
    long_about = "Sync a vault's encrypted op log over a shared file channel.\n\n\
LocalPass's default sync ships the op log as immutable, end-to-end-encrypted \
segment files under a directory you replicate with any \"dumb\" channel \
(Syncthing, a USB drive, a network share). There is NO networking in the \
critical path and the channel is fully untrusted: every op is Ed25519-signed \
and hash-chained, so a malicious channel cannot forge, drop, replay, or reorder \
ops without detection (PRD §8 T5/T13).\n\n\
WORKFLOW: `sync setup --dir <shared-dir>` enrolls a vault (once per device); \
`sync push` publishes this device's ops; `sync pull` verifies + merges peers' \
ops into your vault; `sync status` shows per-device progress.\n\n\
PAIRING: only devices you have trusted (`device trust`) are accepted as op \
authors. Live mDNS/SAS pairing is a LATER wave; today you exchange identity \
strings out-of-band (`device export-identity` / `device trust`)."
)]
pub enum SyncCommand {
    /// Enroll a vault for file-based sync under a shared directory.
    Setup {
        /// The shared sync-root directory (replicated by Syncthing/USB/etc.).
        #[arg(long, value_name = "DIR")]
        dir: PathBuf,
        /// The vault to enroll (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
    },
    /// Publish this device's ops (and re-publishable peer ops) to the channel.
    Push {
        /// The vault to push (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify and merge peers' ops from the channel into this vault.
    #[command(
        long_about = "Pull peers' ops from the shared channel into this vault.\n\n\
Every incoming op is verified (signature, per-device sequence gaplessness, \
hash-chain link, Lamport monotonicity) before it is merged. A genuine gap (an \
earlier segment not yet delivered) holds later ops PENDING and is not an alarm; \
a replay/rollback/tamper QUARANTINES the offending device (and everything after \
it) and is surfaced as an alarm, while other devices keep syncing.\n\n\
The merge is deterministic and never loses data: concurrent edits resolve by a \
total order and the losing edit is preserved as a retrievable version; an edit \
always wins over a concurrent delete."
    )]
    Pull {
        /// The vault to pull into (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show per-device sequence high-water marks + pending/quarantined counts.
    Status {
        /// The vault to report on (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Join vaults another of your devices shared to this one.
    #[command(long_about = "Adopt shared vaults from a sync root.\n\n\
Scans <DIR>/<vault-id>/keys/ for VaultKey blobs sealed to THIS device (shipped \
by `vault share-to-device` on the sharing device), imports each one (registering \
the vault locally), enrolls the vault for sync under <DIR>, and pulls its items. \
Run this on a second device after it has been trusted by the first.")]
    Adopt {
        /// The shared sync-root directory.
        #[arg(long, value_name = "DIR")]
        dir: PathBuf,
    },
}

/// `localpass device ...`
#[derive(Debug, Subcommand)]
#[command(long_about = "Device pairing groundwork.\n\n\
Exchange device identities out-of-band and trust a peer so its ops are accepted \
on sync. Full live pairing (mDNS discovery + a spoken 6-word SAS phrase) is a \
LATER wave; today you copy an identity string between devices and confirm its \
fingerprint by hand.")]
pub enum DeviceCommand {
    /// Print this device's public identity string (share it with a peer).
    ExportIdentity {
        /// Emit machine-readable JSON (identity string + fingerprint).
        #[arg(long)]
        json: bool,
    },
    /// Trust a peer device from its identity string (after confirming its
    /// fingerprint). Only trusted devices are accepted as op authors on sync.
    #[command(
        long_about = "Trust a peer device so its ops are accepted on sync.\n\n\
Paste the peer's `device export-identity` string. LocalPass shows the peer's \
FINGERPRINT and asks you to confirm it matches what the peer sees \
out-of-band (defeats a man-in-the-middle). Type 'yes' to confirm, or pass \
--fingerprint <fp> to confirm non-interactively (it must match)."
    )]
    Trust {
        /// The peer's identity string (from `device export-identity`).
        identity: String,
        /// A human label for the peer ("laptop").
        #[arg(long)]
        label: Option<String>,
        /// Confirm the fingerprint non-interactively (must match the peer's).
        #[arg(long, value_name = "FP")]
        fingerprint: Option<String>,
    },
}

/// `localpass pairing ...`
#[derive(Debug, Subcommand)]
#[command(long_about = "Open or close pairing mode (device-pairing.md §4).\n\n\
Pairing mode is a per-device, time-boxed (3-minute) window that must be ON for \
the daemon to accept trusting a NEW device — an already-trusted device keeps \
syncing regardless, so leaving it off is safe. It lives in the running daemon's \
unlocked session, so these commands talk to the daemon. The direct \
`device trust` path (used with --no-daemon or no daemon running) is not gated by \
pairing mode.")]
pub enum PairingCommand {
    /// Open the pairing-mode window (3 minutes) so a new device can be trusted.
    Enable,
    /// Close the pairing-mode window now.
    Disable,
    /// Show whether pairing mode is on, and the seconds remaining if so.
    Status {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `localpass backup ...`
#[derive(Debug, Subcommand)]
pub enum BackupCommand {
    /// Create a consistent snapshot of the account store + all live vaults.
    #[command(long_about = "Create an encrypted backup snapshot (PRD §4.11).\n\n\
The snapshot is taken with SQLite's Online Backup API, so it is consistent even \
while the vault is in use — never a raw file copy. Every file is the same \
end-to-end-encrypted format as your live profile and is safe on untrusted \
storage (an external drive, a NAS). A plaintext manifest.json records file \
hashes and item counts (no secrets).\n\n\
By default backups go under <profile>/backups/<UTC-timestamp>/. Use --to to \
target an external drive or NAS. After a successful create, backups beyond \
--keep (default 30) are pruned; a failed create never deletes anything.")]
    Create {
        /// Destination root for the timestamped backup dir (default:
        /// `<profile>/backups`). Point this at an external drive or NAS.
        #[arg(long, value_name = "DIR")]
        to: Option<PathBuf>,
        /// How many backups to keep after this create (oldest beyond N pruned).
        #[arg(long, value_name = "N")]
        keep: Option<usize>,
    },
    /// List available backups (timestamp, size, item counts) from their
    /// manifests.
    List {
        /// Where to look for backups (default: `<profile>/backups`).
        #[arg(long, value_name = "DIR")]
        from: Option<PathBuf>,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Verify a backup: file hashes, SQLite integrity, and — with your password
    /// — that it is actually recoverable with your current credentials.
    #[command(long_about = "Verify a backup (PRD §4.11 `backup verify`).\n\n\
Runs three checks:\n  \
1. HASHES     — every file matches the BLAKE3 hash in the manifest.\n  \
2. INTEGRITY  — every SQLite file opens and passes PRAGMA integrity_check.\n  \
3. RECOVERABLE— unlock the backup with your master password + Secret Key, \
unwrap each vault key, and decrypt one item.\n\n\
Checks 1-2 need no password. Check 3 proves the backup is recoverable with your \
CURRENT credentials; a wrong password fails check 3 (exit 2) while checks 1-2 \
still pass. Pass --no-recover to skip check 3.")]
    Verify {
        /// The backup to verify: a timestamp (looked up under --from) or a full
        /// path to a backup directory.
        #[arg(value_name = "TIMESTAMP_OR_PATH")]
        backup: String,
        /// Where to resolve a bare timestamp (default: `<profile>/backups`).
        #[arg(long, value_name = "DIR")]
        from: Option<PathBuf>,
        /// Skip check 3 (the credential-based recoverability check).
        #[arg(long)]
        no_recover: bool,
    },
    /// Restore a full profile (or a single item) from a backup.
    #[command(long_about = "Restore from a backup (PRD §4.11).\n\n\
FULL RESTORE (default): replaces the live profile with the backup. Your current \
live files are FIRST moved to <profile>/backups/pre-restore-<ts>/ (never \
deleted), then the backup is copied into place atomically. Refused if a daemon \
is running for this profile — run `localpass daemon stop` first.\n\n\
SINGLE ITEM (--item): decrypts one item from the backup and re-creates it in \
the live vault as a NEW version (not a byte-copy); the op chain stays valid. \
Requires your password to open the backup.")]
    Restore {
        /// The backup to restore from: a timestamp (under --from) or a path.
        #[arg(value_name = "TIMESTAMP_OR_PATH")]
        backup: String,
        /// Where to resolve a bare timestamp (default: `<profile>/backups`).
        #[arg(long, value_name = "DIR")]
        from: Option<PathBuf>,
        /// Restore only this single item (title or id) instead of the whole
        /// profile. Requires --vault to name the source/destination vault.
        #[arg(long, value_name = "TITLE_OR_ID")]
        item: Option<String>,
        /// The vault (name or id) for a single-item restore.
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Skip the confirmation prompt for a full restore.
        #[arg(long)]
        force: bool,
    },
}

/// `localpass init [--kit-out <path>]`
#[derive(Debug, Args)]
pub struct InitArgs {
    /// Also write the Emergency Kit to this file (outside the profile). The kit
    /// is always printed to stdout regardless; this additionally saves a copy.
    /// The file contains your Secret Key — print it, store it offline, delete it.
    #[arg(long, value_name = "PATH")]
    pub kit_out: Option<PathBuf>,

    /// Format for the --kit-out file (text or html).
    #[arg(long = "kit-format", value_enum, default_value = "text")]
    pub kit_format: KitFormat,
}

/// `localpass kit [--out <path>] [--format text|html]`
#[derive(Debug, Args)]
#[command(long_about = "(Re)generate the Emergency Kit file (PRD §4.11).\n\n\
The kit contains your Secret Key display string, the profile path, the creation \
date, step-by-step recovery instructions, and the no-recovery doctrine. It \
requires unlock and reads the on-device Secret Key file; if that file is \
missing, pass --secret-key to supply it.\n\n\
WHERE IT GOES: writing the kit INTO the profile defeats its purpose, so this \
command REFUSES to write inside the profile directory. With no --out it writes \
to your Documents directory. The file contains your Secret Key in cleartext — \
print it, store it offline, then DELETE the file.\n\n\
FORMAT: text (default) or html (a print-friendly single file).")]
pub struct KitArgs {
    /// Where to write the kit. Must be OUTSIDE the profile directory. Default:
    /// `<Documents>/localpass-emergency-kit.<ext>`.
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// Output format.
    #[arg(long, value_enum, default_value = "text")]
    pub format: KitFormat,

    /// Supply the Secret Key display string directly (required if the on-device
    /// secret-key file is missing).
    #[arg(long, value_name = "LP1-...")]
    pub secret_key: Option<String>,
}

/// Output format for the Emergency Kit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum KitFormat {
    /// A plain-text `.txt` file.
    Text,
    /// A print-friendly single-file HTML document.
    Html,
}

/// `localpass daemon ...`
#[derive(Debug, Subcommand)]
pub enum DaemonCommand {
    /// Start the background daemon (detached) if it isn't already running.
    /// Waits until it answers a Ping. A friendly no-op if already running.
    Start {
        /// Idle auto-lock timeout in seconds (0 = never). Overrides the
        /// LOCALPASS_AUTOLOCK_SECS env var and the 600s default.
        #[arg(long, value_name = "SECS")]
        autolock: Option<u64>,
        /// Ask the daemon to log request kinds + timings to its stderr (never
        /// secrets). Mainly useful when running the daemon in the foreground.
        #[arg(long)]
        verbose: bool,
    },
    /// Stop the running daemon (drops keys, removes the socket/pipe). A friendly
    /// no-op if none is running.
    Stop,
    /// Show whether the daemon is running and, if so, its lock state.
    Status {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
}

/// `localpass run [flags] -- <command> [args...]`
///
/// Resolves secrets **once**, at spawn, into the child's environment. Plaintext
/// exists only in this process's memory and the child's environment — never on
/// disk, and never in the child's argv beyond what you passed.
#[derive(Debug, Args)]
#[command(
    long_about = "Run a command with secrets injected as environment variables.\n\n\
Sources are layered; on a KEY conflict, later sources override earlier ones:\n  \
1. --env-set <item>   all entries of an env-set item (repeatable)\n  \
2. --env-file <path>  dotenv lines; values may be localpass:// / op:// \
references (resolved) or literals (passed through). Repeatable; applied in \
flag order, after --env-set.\n  \
3. -e KEY=<reference>  ad-hoc single mappings (highest precedence)\n\n\
REFERENCES (PRD §4.8): localpass://<vault>/<item>/<field> and the alias \
op://<vault>/<item>/<field> resolve identically. <vault> is a name or id, \
<item> a title or id, <field> a field name (or an env-set entry key). \
Percent-encoding (%XX) in a segment is decoded.\n\n\
The child environment is the parent environment plus the resolved vars \
(resolved vars override inherited ones). With --no-inherit the child gets ONLY \
the resolved vars plus a minimal passthrough (PATH, SYSTEMROOT, TEMP/TMP, \
HOME/USERPROFILE, and a few OS essentials) for basic operability.\n\n\
SPAWN: on Unix, LocalPass calls exec() and is replaced by the child (it \
vanishes from the process tree, and the child's exit code is the shell's). On \
Windows there is no exec: LocalPass spawns the child with inherited stdio, \
waits, and exits with the child's exit code.\n\n\
ERRORS: an unresolvable reference exits 1, naming the failing KEY and reference \
(never a resolved value); a wrong password / Secret Key exits 2."
)]
pub struct RunArgs {
    /// Default vault for bare references and env-sets that omit a vault
    /// (name or id).
    #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
    pub vault: String,

    /// Inject all entries of an env-set item (title or id). Repeatable; later
    /// sets override earlier ones on a KEY conflict.
    #[arg(long = "env-set", value_name = "TITLE_OR_ID")]
    pub env_sets: Vec<String>,

    /// Load a dotenv file whose values may be references (resolved) or literals
    /// (passed through). Repeatable; applied in flag order after --env-set.
    #[arg(long = "env-file", value_name = "PATH")]
    pub env_files: Vec<PathBuf>,

    /// Ad-hoc mapping `KEY=<reference>` (highest precedence). Repeatable.
    #[arg(short = 'e', value_name = "KEY=REF")]
    pub env: Vec<String>,

    /// Give the child ONLY the resolved vars plus a minimal passthrough
    /// (PATH, SYSTEMROOT, TEMP/TMP, HOME/USERPROFILE, …) — do not inherit the
    /// full parent environment.
    #[arg(long)]
    pub no_inherit: bool,

    /// The command to run, then its arguments (everything after `--`).
    #[arg(trailing_var_arg = true, required = true, value_name = "COMMAND")]
    pub command: Vec<String>,
}

/// `localpass env ...`
#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// Export an env-set to stdout (or a 0600 file) in a chosen format.
    #[command(long_about = "Materialize an env-set's variables.\n\n\
By default this prints plaintext secrets to stdout — an explicit, DISCOURAGED \
path (the stdout leaks into your shell history, scrollback, and any pipe). \
Prefer `localpass run`, which never writes secrets to disk or a terminal. Use \
--file to write a 0600 file (Unix) instead of stdout.\n\n\
FORMATS: dotenv (KEY=value, default), shell (export KEY='...' with safe \
single-quote escaping), json (a flat object).")]
    Export {
        /// The env-set item to export (title or id).
        env_set: String,
        /// Vault to look in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Output format.
        #[arg(long, value_enum, default_value = "dotenv")]
        format: EnvFormat,
        /// Write to this file with 0600 permissions (Unix) instead of stdout.
        #[arg(long, value_name = "PATH")]
        file: Option<PathBuf>,
    },
    /// Import a dotenv file into a new env-set item (values never echoed).
    Import {
        /// The dotenv file to import.
        path: PathBuf,
        /// The title for the new env-set item.
        #[arg(long = "as", value_name = "TITLE")]
        title: String,
        /// Vault to create the item in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
    },
    /// Diff a dotenv file against a stored env-set (keys only; values never
    /// printed). Exits 1 if they differ.
    Diff {
        /// The dotenv file.
        path: PathBuf,
        /// The env-set item to compare against (title or id).
        env_set: String,
        /// Vault to look in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
    },
}

/// Output format for `env export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EnvFormat {
    /// `KEY=value` lines.
    Dotenv,
    /// `export KEY='value'` lines with single-quote escaping.
    Shell,
    /// A flat JSON object.
    Json,
}

/// The source format for `localpass import`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ImportFormat {
    /// 1Password `.1pux` export (a ZIP containing export.data).
    #[value(name = "1password")]
    OnePassword,
    /// Bitwarden unencrypted JSON export.
    Bitwarden,
    /// LastPass CSV export.
    Lastpass,
    /// Generic CSV with an explicit column mapping (`--map field=COLUMN`).
    Csv,
    /// A `.env` file → one env-set item.
    Env,
    /// KeePass KDBX 4 database (AES-256 / Argon2; prompts for the password).
    Kdbx,
    /// A LocalPass age archive (re-import of `localpass export age`).
    Age,
}

/// `localpass import <format> <path> [flags]`
#[derive(Debug, Args)]
#[command(
    long_about = "Import items from another password manager's export.\n\n\
FORMATS: 1password (.1pux), bitwarden (JSON), lastpass (CSV), csv (generic, \
needs --map), env (.env → one env-set), kdbx (KeePass KDBX 4, AES-256/Argon2), \
age (a LocalPass age archive).\n\n\
The input file is only READ — it is never modified or deleted. On a partial \
parse, LocalPass imports every entry it understands and reports the count plus \
the titles it skipped (never a secret value).\n\n\
GENERIC CSV: map columns with repeated --map, e.g. \
--map title=Name --map username=Login --map password=Secret. Only title is \
required.\n\n\
KDBX / AGE: pass the database/archive passphrase via --kdbx-password-stdin \
(read from stdin) or you will be prompted."
)]
pub struct ImportArgs {
    /// The source format.
    #[arg(value_enum)]
    pub format: ImportFormat,

    /// Path to the export file to import.
    pub path: PathBuf,

    /// Vault to create the imported items in (name or id).
    #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
    pub vault: String,

    /// Column mapping for generic CSV: `field=COLUMN` (repeatable). `field` is
    /// one of title/username/password/url/notes.
    #[arg(long = "map", value_name = "FIELD=COLUMN")]
    pub map: Vec<String>,

    /// Title for the new env-set (env format only; default: the file stem).
    #[arg(long = "as", value_name = "TITLE")]
    pub title: Option<String>,

    /// Read the KDBX / age archive passphrase from stdin instead of prompting.
    #[arg(long)]
    pub kdbx_password_stdin: bool,
}

/// The target format for `localpass export`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ExportFormat {
    /// age-encrypted, recoverable archive (decryptable by the standalone `age`
    /// tool). The default and only safe export.
    Age,
    /// Plaintext JSON (ALL secrets in cleartext) — requires the guard flag.
    Json,
    /// Plaintext CSV (login-style columns in cleartext) — requires the guard.
    Csv,
    /// A single env-set item → dotenv `KEY=value` lines.
    Dotenv,
}

/// `localpass export <format> <path> [flags]`
#[derive(Debug, Args)]
#[command(long_about = "Export items to a file.\n\n\
FORMATS: age (encrypted, recoverable with the standalone `age` tool — the \
recommended exit hatch), json / csv (PLAINTEXT, all secrets in cleartext — \
guarded), dotenv (one env-set → KEY=value lines).\n\n\
age: you are prompted for a passphrase twice (or pipe it once via \
--passphrase-stdin). The archive is `age -d`-decryptable: \
`age -d out.age | tar -xO vault.json` yields the item JSON.\n\n\
PLAINTEXT (json/csv): refused unless you pass --i-understand-plaintext-export. \
These write your secrets UNENCRYPTED to disk — avoid unless you truly need it.\n\n\
dotenv: pass --env-set <title|id> to choose the env-set item to render.")]
pub struct ExportArgs {
    /// The target format.
    #[arg(value_enum)]
    pub format: ExportFormat,

    /// Output file path.
    pub path: PathBuf,

    /// Vault(s) to export (name or id). Repeatable; default: `personal`.
    /// Ignored by `dotenv` (which exports a single env-set item).
    #[arg(long, value_name = "NAME_OR_ID")]
    pub vault: Vec<String>,

    /// Required acknowledgement for the plaintext json/csv formats: without it,
    /// those formats refuse to run.
    #[arg(long)]
    pub i_understand_plaintext_export: bool,

    /// Read the age passphrase from stdin (one line) instead of prompting twice.
    #[arg(long)]
    pub passphrase_stdin: bool,

    /// The env-set item (title or id) to render for the `dotenv` format.
    #[arg(long = "env-set", value_name = "TITLE_OR_ID")]
    pub env_set: Option<String>,
}

/// `localpass vault ...`
#[derive(Debug, Subcommand)]
pub enum VaultCommand {
    /// List all vaults.
    List {
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Create a new vault.
    Create {
        /// The vault name.
        name: String,
    },
    /// Show per-vault storage statistics (items, versions, trash, index
    /// segments, file size) — the PRD's "very visible storage statistics".
    Stats {
        /// The vault (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Prune old item versions to reclaim local storage (PRD §11 #8). The
    /// current version is never touched; ops are never touched.
    #[command(
        long_about = "Prune old item versions (PRD §11 #8, keep-forever + prune tooling).\n\n\
Removes item versions that are (a) NOT the current version, (b) beyond the \
newest --keep-last of each item, and (c) older than --older-than if given. The \
current version always survives. The op log is NEVER touched — prune is a LOCAL \
storage-reclaim operation; pruned versions stay reconstructable from ops until \
log compaction exists.\n\n\
--dry-run prints the report without deleting. A real run asks for confirmation \
unless --force."
    )]
    Prune {
        /// The vault (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Keep the newest N versions of each item (default 10).
        #[arg(long, default_value_t = 10, value_name = "N")]
        keep_last: u32,
        /// Only prune versions older than this age (e.g. `365d`, `12h`, `30m`).
        #[arg(long, value_name = "DURATION")]
        older_than: Option<String>,
        /// Show what would be pruned without deleting anything.
        #[arg(long)]
        dry_run: bool,
        /// Skip the confirmation prompt for a real prune.
        #[arg(long)]
        force: bool,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Share this vault's key to one of your other (trusted) devices via the
    /// sync channel, so that device can open the vault after `sync pull`.
    #[command(long_about = "Share a vault to another of your devices.\n\n\
Seals this vault's key to the target device's public key and ships it through \
the vault's sync directory (`keys/`); the peer imports it on `sync pull`. This \
is single-user multi-device (PRD §4.5 team sharing is P2).\n\n\
NOTE: in this build the sealed-key TRANSPORT + shipping are wired, but the \
final unwrap step needs a key-transport primitive that is intentionally held \
behind the crypto boundary; the command reports this clearly. Op sync and \
device pairing are fully functional without it.")]
    ShareToDevice {
        /// The target device id (from the peer's `device export-identity`).
        device_id: String,
        /// The vault to share (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
    },
}

/// `localpass password ...`
#[derive(Debug, Subcommand)]
pub enum PasswordCommand {
    /// Change the master password (prompts for old, then new twice).
    Change,
}

/// `localpass item ...`
///
/// `Add`/`Edit` carry the wide shared content flags; like [`Command`], this is
/// a one-shot parse value, so the variant-size disparity is accepted rather
/// than boxed.
#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum ItemCommand {
    /// Add a new item.
    Add(ItemAddArgs),
    /// Get an item (masked by default).
    Get {
        /// The item title or id.
        target: String,
        /// Vault to look in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Reveal secret field values (otherwise masked).
        #[arg(long)]
        reveal: bool,
        /// Print exactly one field's raw value to stdout (for scripting).
        #[arg(long, value_name = "NAME")]
        field: Option<String>,
        /// Emit machine-readable JSON (secrets included only with --reveal).
        #[arg(long)]
        json: bool,
    },
    /// List items in a vault (never prints secret values).
    List {
        /// Vault to list (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Edit an item (same flags as `add`); creates a new version.
    Edit(ItemEditArgs),
    /// Move an item to the trash (30-day default retention).
    Rm {
        /// The item title or id.
        target: String,
        /// Vault to look in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        force: bool,
    },
    /// Show an item's version history.
    History {
        /// The item title or id.
        target: String,
        /// Vault to look in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Restore a prior version as a new current version.
    Restore {
        /// The item title or id.
        target: String,
        /// The version number to restore.
        #[arg(long, value_name = "N")]
        version: i64,
        /// Vault to look in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
    },
}

/// `localpass attach ...`
#[derive(Debug, Subcommand)]
#[command(long_about = "Encrypted file attachments on an item (PRD §4.1).\n\n\
Store an arbitrary file (a certificate, a service-account.json, a binary secret) \
encrypted at rest, bound to an item. Blobs live beside the vault as \
content-addressed ciphertext — the bytes are NEVER stored in the database and \
NEVER leave the vault except when you explicitly run `attach get --out <path>`, \
which writes the decrypted file to a path you choose.\n\n\
Each attachment is sealed with its own key, wrapped by the item's key, so a \
stolen vault file (without your master password + Secret Key) reveals neither \
the file contents nor its name.\n\n\
LIMITATION: attachments are LOCAL-ONLY in this build — they are not part of the \
sync op log, so they do not replicate to your other devices yet. There is a \
50 MiB size cap per file.\n\n\
This command always unlocks directly (the daemon-proxied path is a later wave).")]
pub enum AttachCommand {
    /// Attach a file to an item (reads the file, encrypts it into the vault).
    Add {
        /// The item to attach to (title or id).
        item: String,
        /// Path to the file to attach.
        path: PathBuf,
        /// Vault the item lives in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Store under this filename instead of the source file's name.
        #[arg(long, value_name = "FILENAME")]
        name: Option<String>,
    },
    /// List an item's attachments (id, name, size). Never prints blob bytes.
    List {
        /// The item (title or id).
        item: String,
        /// Vault the item lives in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Emit machine-readable JSON.
        #[arg(long)]
        json: bool,
    },
    /// Download (decrypt) an attachment to a file you choose.
    #[command(long_about = "Write a decrypted attachment to a path you choose.\n\n\
The attachment is identified by its id (from `attach list`) or its name. The \
decrypted plaintext lands at <path> — that is inherent to saving a file; treat \
the destination as sensitive. On Unix the file is written with 0600 \
permissions. Refuses to overwrite an existing file unless --force.")]
    Get {
        /// The item the attachment belongs to (title or id).
        item: String,
        /// The attachment to fetch: its id or its name.
        attachment: String,
        /// Where to write the decrypted file.
        #[arg(long, value_name = "PATH")]
        out: PathBuf,
        /// Vault the item lives in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Overwrite the output path if it already exists.
        #[arg(long)]
        force: bool,
    },
    /// Remove an attachment (confirm unless --force).
    Rm {
        /// The item the attachment belongs to (title or id).
        item: String,
        /// The attachment id to remove.
        attachment: String,
        /// Vault the item lives in (name or id).
        #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
        vault: String,
        /// Skip the confirmation prompt.
        #[arg(long)]
        force: bool,
    },
}

/// The six MVP item types (mirrors `lp_vault::TypeData` variants).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ItemType {
    /// Username / password / URLs.
    Login,
    /// A secure note (Markdown).
    Note,
    /// An API key / token.
    ApiKey,
    /// An ordered `.env` bundle.
    EnvSet,
    /// An SSH key pair.
    SshKey,
    /// A TOTP secret.
    Totp,
}

impl ItemType {
    /// The `lp_vault` type-string tag (e.g. `"login"`, `"env_set"`).
    #[must_use]
    pub fn type_str(self) -> &'static str {
        match self {
            ItemType::Login => "login",
            ItemType::Note => "note",
            ItemType::ApiKey => "api_key",
            ItemType::EnvSet => "env_set",
            ItemType::SshKey => "ssh_key",
            ItemType::Totp => "totp",
        }
    }
}

/// Shared field/content flags for `item add` and `item edit`.
///
/// On `add`, these build the item. On `edit`, provided flags overlay the
/// current payload (see [`crate::commands::item`]).
#[derive(Debug, Args)]
pub struct ContentArgs {
    /// Vault to write to (name or id).
    #[arg(long, default_value = "personal", value_name = "NAME_OR_ID")]
    pub vault: String,

    /// Username (login items).
    #[arg(long)]
    pub username: Option<String>,

    /// Password value, or `-` to read it from stdin (one line).
    ///
    /// WARNING: passing a secret directly on the command line exposes it in
    /// process listings (`ps`, Task Manager) and your shell history. Prefer
    /// `--password -` (pipe it), or `--generate` to never handle it yourself.
    #[arg(long, conflicts_with = "generate")]
    pub password: Option<String>,

    /// Generate a random password instead of supplying one.
    #[arg(long)]
    pub generate: bool,

    /// Primary URL (login items).
    #[arg(long)]
    pub url: Option<String>,

    /// Free-form note body (Markdown for note items).
    #[arg(long)]
    pub note: Option<String>,

    /// Tag to attach (repeatable).
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,

    /// Custom text field `key=value` (repeatable).
    #[arg(long = "field", value_name = "KEY=VALUE")]
    pub fields: Vec<String>,

    /// Custom hidden (secret) field `key=value` (repeatable).
    ///
    /// WARNING: the value is visible in process listings and shell history.
    /// Prefer `--secret-field-stdin NAME` (reads the value from stdin) for
    /// anything sensitive.
    #[arg(long = "secret-field", value_name = "KEY=VALUE")]
    pub secret_fields: Vec<String>,

    /// Add a hidden (secret) field named NAME, reading its value from stdin
    /// (one line) — keeps the secret out of argv. Use at most once per command.
    #[arg(long = "secret-field-stdin", value_name = "NAME")]
    pub secret_field_stdin: Option<String>,

    /// env-set entry `KEY=VALUE` (repeatable; env-set items).
    ///
    /// WARNING: the value is visible in process listings and shell history. For
    /// bulk secrets prefer `--from-env-file`, or import with `env import`.
    #[arg(long = "env", value_name = "KEY=VALUE")]
    pub env: Vec<String>,

    /// Load env-set entries from a `.env` file (KEY=VALUE lines).
    #[arg(long, value_name = "PATH")]
    pub from_env_file: Option<PathBuf>,
}

/// `localpass item add`
#[derive(Debug, Args)]
pub struct ItemAddArgs {
    /// Item type.
    #[arg(
        long = "type",
        value_enum,
        default_value = "login",
        value_name = "TYPE"
    )]
    pub item_type: ItemType,

    /// Item title. Required, except with `--otpauth-uri`, where it defaults to
    /// the URI's issuer/account label.
    #[arg(long)]
    pub title: Option<String>,

    /// For `--type totp`: populate the item from an `otpauth://totp/...` URI
    /// (the string a 2FA QR code encodes). The secret, issuer, account,
    /// algorithm, digits, and period are parsed from the URI; `otpauth://hotp`
    /// is rejected (counter-based HOTP is not supported). Overrides the
    /// per-field flags for a totp item.
    #[arg(long, value_name = "URI")]
    pub otpauth_uri: Option<String>,

    #[command(flatten)]
    pub content: ContentArgs,
}

/// `localpass item edit`
#[derive(Debug, Args)]
pub struct ItemEditArgs {
    /// The item title or id to edit.
    pub target: String,

    /// New title (optional).
    #[arg(long)]
    pub title: Option<String>,

    #[command(flatten)]
    pub content: ContentArgs,
}

/// `localpass generate`
#[derive(Debug, Args)]
pub struct GenerateArgs {
    /// Password length in characters (ignored with --words).
    #[arg(long, default_value_t = 24, value_name = "N")]
    pub length: usize,

    /// Generate a diceware passphrase of this many EFF-wordlist words instead
    /// of a character password.
    #[arg(long, value_name = "N")]
    pub words: Option<usize>,

    /// Exclude symbols from the password charset (letters + digits only).
    #[arg(long)]
    pub no_symbols: bool,

    /// Word separator for passphrases (default "-").
    #[arg(long, default_value = "-", value_name = "SEP")]
    pub separator: String,

    /// Emit machine-readable JSON (the secret plus its entropy estimate).
    #[arg(long)]
    pub json: bool,
}
