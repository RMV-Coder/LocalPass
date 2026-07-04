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
    Init,

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
    /// KeePass KDBX 4 database (not yet supported; see docs).
    Kdbx,
    /// A LocalPass age archive (re-import of `localpass export age`).
    Age,
}

/// `localpass import <format> <path> [flags]`
#[derive(Debug, Args)]
#[command(
    long_about = "Import items from another password manager's export.\n\n\
FORMATS: 1password (.1pux), bitwarden (JSON), lastpass (CSV), csv (generic, \
needs --map), env (.env → one env-set), kdbx (KeePass — NOT yet supported), \
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

    /// Item title (required).
    #[arg(long)]
    pub title: String,

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
