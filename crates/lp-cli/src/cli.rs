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

    /// Password value. Mutually exclusive with --generate.
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
    #[arg(long = "secret-field", value_name = "KEY=VALUE")]
    pub secret_fields: Vec<String>,

    /// env-set entry `KEY=VALUE` (repeatable; env-set items).
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
