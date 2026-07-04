//! `localpass generate` — print a random password or passphrase with its
//! entropy. No unlock; nothing is stored.

use anyhow::Result;
use serde_json::json;

use crate::cli::GenerateArgs;
use crate::generate;

/// Run `localpass generate`.
///
/// # Errors
///
/// Fails on a zero length/word count or if the OS CSPRNG is unavailable.
pub fn run(args: &GenerateArgs) -> Result<()> {
    let (generated, kind) = if let Some(words) = args.words {
        (generate::passphrase(words, &args.separator)?, "passphrase")
    } else {
        (
            generate::password(args.length, !args.no_symbols)?,
            "password",
        )
    };

    if args.json {
        let obj = json!({
            "kind": kind,
            "secret": generated.secret,
            "entropy_bits": round2(generated.entropy_bits),
        });
        println!("{}", serde_json::to_string_pretty(&obj)?);
    } else {
        // The secret on its own line (clean for piping); entropy to stderr so a
        // `localpass generate | pbcopy` pipe copies only the secret.
        println!("{}", generated.secret);
        eprintln!("entropy: {:.1} bits", generated.entropy_bits);
    }
    Ok(())
}

/// Round to two decimals for stable JSON output.
fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}
