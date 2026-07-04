//! Integration tests for `localpass run` and `localpass env` (PRD §4.8), plus
//! the Task #9 (ISO timestamp) and Task #10 (stdin secret entry) polish.
//!
//! Each `init` runs Argon2id (~1s), so tests batch many assertions over one
//! initialized profile. The child spawned by `run` is a shell builtin that
//! echoes an env var: on Windows `cmd /c echo %KEY%`, on Unix `sh -c echo
//! "$KEY"`. Assertions that depend on Unix `exec` semantics are `cfg`-guarded;
//! everything else passes on Windows (the required CI target).

mod common;

use common::TestProfile;
use predicates::prelude::*;
use predicates::str::contains;

/// Spawn a child that prints the value of environment variable `name`, portable
/// across Windows (`cmd /c echo %name%`) and Unix (`sh -c 'printf %s "$name"'`).
/// Returns the args after `run`'s `--`.
fn echo_var_args(name: &str) -> Vec<String> {
    #[cfg(windows)]
    {
        vec![
            "cmd".into(),
            "/c".into(),
            "echo".into(),
            format!("%{name}%"),
        ]
    }
    #[cfg(not(windows))]
    {
        vec![
            "sh".into(),
            "-c".into(),
            format!("printf '%s\\n' \"${name}\""),
        ]
    }
}

/// Add a login item with a known password field so references can target it.
fn add_login(profile: &TestProfile, title: &str, username: &str, password: &str) {
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "login",
            "--title",
            title,
            "--username",
            username,
            "--password",
            password,
        ])
        .assert()
        .success();
}

/// A `localpass run` fixture: one env-set item and one login item live in the
/// default `personal` vault. Exercises `-e` (both schemes), `--env-set`,
/// layering precedence, `--no-inherit`, unresolvable references, and child exit
/// code passthrough — all against a single initialized profile.
#[test]
fn run_injects_resolves_layers_and_passes_exit_code() {
    let profile = TestProfile::initialized();

    // A login whose password we will reference.
    add_login(&profile, "GitHub", "octocat", "gh_secret_val");

    // An env-set with two entries; one key (SHARED) will be overridden later.
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "env-set",
            "--title",
            "myapp",
            "--env",
            "FROM_SET=set_value",
            "--env",
            "SHARED=from_set",
        ])
        .assert()
        .success();

    // --- 1) -e KEY=localpass://... resolves and the child sees it ----------
    profile
        .cmd()
        .args(["run", "-e", "MY_TOKEN=localpass://personal/GitHub/password"])
        .arg("--")
        .args(echo_var_args("MY_TOKEN"))
        .assert()
        .success()
        .stdout(contains("gh_secret_val"));

    // --- 2) op:// alias resolves identically -------------------------------
    profile
        .cmd()
        .args(["run", "-e", "MY_TOKEN=op://personal/GitHub/password"])
        .arg("--")
        .args(echo_var_args("MY_TOKEN"))
        .assert()
        .success()
        .stdout(contains("gh_secret_val"));

    // --- 3) --env-set injects all entries ----------------------------------
    profile
        .cmd()
        .args(["run", "--env-set", "myapp"])
        .arg("--")
        .args(echo_var_args("FROM_SET"))
        .assert()
        .success()
        .stdout(contains("set_value"));

    // --- 4) layering precedence: env-set < -e ------------------------------
    // SHARED comes from the env-set as "from_set" but is overridden by -e.
    profile
        .cmd()
        .args([
            "run",
            "--env-set",
            "myapp",
            "-e",
            "SHARED=localpass://personal/GitHub/password",
        ])
        .arg("--")
        .args(echo_var_args("SHARED"))
        .assert()
        .success()
        .stdout(contains("gh_secret_val"))
        .stdout(contains("from_set").not());

    // --- 5) unresolvable reference → exit 1, KEY named, no secret leaked ----
    profile
        .cmd()
        .args(["run", "-e", "BAD=localpass://personal/GitHub/nope"])
        .arg("--")
        .args(echo_var_args("BAD"))
        .assert()
        .failure()
        .code(1)
        .stderr(contains("BAD"))
        .stderr(contains("gh_secret_val").not());

    // --- 6) child exit code passthrough ------------------------------------
    // `cmd /c exit 7` / `sh -c 'exit 7'` → the whole command exits 7.
    let exit_args: Vec<String> = {
        #[cfg(windows)]
        {
            vec!["cmd".into(), "/c".into(), "exit".into(), "7".into()]
        }
        #[cfg(not(windows))]
        {
            vec!["sh".into(), "-c".into(), "exit 7".into()]
        }
    };
    profile
        .cmd()
        .args(["run"])
        .arg("--")
        .args(&exit_args)
        .assert()
        .code(7);
}

/// `--env-file` with reference and literal values, layered after `--env-set`
/// and before `-e`. Confirms references in a committed `.env` resolve while
/// plain values pass through, and the full precedence chain env-set < env-file
/// < -e.
#[test]
fn run_env_file_resolves_references_and_layers() {
    let profile = TestProfile::initialized();
    add_login(&profile, "DB", "svc", "db_password_xyz");

    // A committed-style .env: one reference, one literal.
    let env_path = profile.path().join("app.env");
    std::fs::write(
        &env_path,
        "# app config\nDATABASE_URL=localpass://personal/DB/password\nPLAIN=literal_value\n",
    )
    .unwrap();

    // Reference in the file resolves.
    profile
        .cmd()
        .args(["run", "--env-file"])
        .arg(&env_path)
        .arg("--")
        .args(echo_var_args("DATABASE_URL"))
        .assert()
        .success()
        .stdout(contains("db_password_xyz"));

    // Literal in the file passes through untouched.
    profile
        .cmd()
        .args(["run", "--env-file"])
        .arg(&env_path)
        .arg("--")
        .args(echo_var_args("PLAIN"))
        .assert()
        .success()
        .stdout(contains("literal_value"));

    // Precedence: env-file overrides an env-set on the same key.
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "env-set",
            "--title",
            "base",
            "--env",
            "PLAIN=from_set",
        ])
        .assert()
        .success();
    profile
        .cmd()
        .args(["run", "--env-set", "base", "--env-file"])
        .arg(&env_path)
        .arg("--")
        .args(echo_var_args("PLAIN"))
        .assert()
        .success()
        .stdout(contains("literal_value"))
        .stdout(contains("from_set").not());
}

/// `--no-inherit` hides a parent-set canary variable, while the resolved var is
/// still present.
#[test]
fn run_no_inherit_hides_parent_env() {
    let profile = TestProfile::initialized();
    add_login(&profile, "Svc", "u", "resolved_secret");

    // With inheritance (default): the canary passes through.
    profile
        .cmd()
        .env("CANARY_VAR", "canary_present")
        .args(["run", "-e", "X=localpass://personal/Svc/password"])
        .arg("--")
        .args(echo_var_args("CANARY_VAR"))
        .assert()
        .success()
        .stdout(contains("canary_present"));

    // With --no-inherit: the canary is gone (echo of an unset var yields no
    // value). On Windows, `echo %CANARY_VAR%` prints the literal token when
    // unset, so we assert the *value* is absent rather than the token.
    profile
        .cmd()
        .env("CANARY_VAR", "canary_present")
        .args([
            "run",
            "--no-inherit",
            "-e",
            "X=localpass://personal/Svc/password",
        ])
        .arg("--")
        .args(echo_var_args("CANARY_VAR"))
        .assert()
        .success()
        .stdout(contains("canary_present").not());

    // But the resolved var IS present under --no-inherit.
    profile
        .cmd()
        .args([
            "run",
            "--no-inherit",
            "-e",
            "X=localpass://personal/Svc/password",
        ])
        .arg("--")
        .args(echo_var_args("X"))
        .assert()
        .success()
        .stdout(contains("resolved_secret"));
}

/// `env export` in all three formats; import→export round-trips; import skips
/// comments and handles quotes; diff detects drift without printing values.
#[test]
fn env_export_import_diff_round_trip() {
    let profile = TestProfile::initialized();

    // Import a .env with a comment, blank line, export prefix, and quotes.
    let src = profile.path().join("in.env");
    std::fs::write(
        &src,
        "# header\n\nDATABASE_URL=postgres://localhost\nexport TOKEN=\"sk_live_secret\"\nPLAIN=hello\n",
    )
    .unwrap();

    profile
        .cmd()
        .args(["env", "import"])
        .arg(&src)
        .args(["--as", "imported"])
        .assert()
        .success()
        .stdout(contains("imported 3"))
        // The value must never be echoed by import.
        .stdout(contains("sk_live_secret").not());

    // export dotenv: values present, normalized KEY=value (quotes stripped).
    profile
        .cmd()
        .args(["env", "export", "imported", "--format", "dotenv"])
        .assert()
        .success()
        .stdout(contains("DATABASE_URL=postgres://localhost\n"))
        .stdout(contains("TOKEN=sk_live_secret\n"))
        .stdout(contains("PLAIN=hello\n"));

    // export shell: export KEY='...' lines.
    profile
        .cmd()
        .args(["env", "export", "imported", "--format", "shell"])
        .assert()
        .success()
        .stdout(contains("export TOKEN='sk_live_secret'\n"))
        .stdout(contains("export DATABASE_URL='postgres://localhost'\n"));

    // export json: parses and has the keys/values.
    let out = profile
        .cmd()
        .args(["env", "export", "imported", "--format", "json"])
        .output()
        .unwrap();
    let v: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("json export is valid JSON");
    assert_eq!(v["TOKEN"], "sk_live_secret");
    assert_eq!(v["DATABASE_URL"], "postgres://localhost");

    // --- diff: identical file → exit 0, no drift ---------------------------
    let same = profile.path().join("same.env");
    std::fs::write(
        &same,
        "DATABASE_URL=postgres://localhost\nTOKEN=sk_live_secret\nPLAIN=hello\n",
    )
    .unwrap();
    profile
        .cmd()
        .args(["env", "diff"])
        .arg(&same)
        .arg("imported")
        .assert()
        .success()
        .stdout(contains("no drift"));

    // --- diff: drift (added / removed / changed) → exit 1, values hidden ----
    let drifted = profile.path().join("drift.env");
    std::fs::write(
        &drifted,
        // DATABASE_URL removed; TOKEN changed; NEWKEY added; PLAIN unchanged.
        "TOKEN=different_secret\nPLAIN=hello\nNEWKEY=added_secret\n",
    )
    .unwrap();
    profile
        .cmd()
        .args(["env", "diff"])
        .arg(&drifted)
        .arg("imported")
        .assert()
        .failure()
        .code(1)
        .stdout(contains("NEWKEY")) // only-in-file
        .stdout(contains("DATABASE_URL")) // only-in-item
        .stdout(contains("TOKEN")) // changed
        .stdout(contains("(differs)"))
        // No secret VALUE from either side may appear.
        .stdout(contains("different_secret").not())
        .stdout(contains("added_secret").not())
        .stdout(contains("sk_live_secret").not());
}

/// `env export --file` writes to a file (not stdout) and does not print the
/// secret to stdout.
#[test]
fn env_export_to_file_keeps_stdout_clean() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "env-set",
            "--title",
            "e",
            "--env",
            "K=filesecret",
        ])
        .assert()
        .success();

    let out_path = profile.path().join("out.env");
    profile
        .cmd()
        .args(["env", "export", "e", "--file"])
        .arg(&out_path)
        .assert()
        .success()
        // stdout must not carry the secret; the confirmation goes to stderr.
        .stdout(contains("filesecret").not());

    let written = std::fs::read_to_string(&out_path).unwrap();
    assert!(written.contains("K=filesecret"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&out_path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "export --file must be 0600");
    }
}

/// Task #10: `--password -` and `--secret-field-stdin` read from stdin, keeping
/// the secret out of argv; and the leakage WARNING appears in --help.
#[test]
fn stdin_secret_entry_and_help_warning() {
    let profile = TestProfile::initialized();

    // --password - reads the password from stdin.
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "login",
            "--title",
            "StdinLogin",
            "--username",
            "u",
            "--password",
            "-",
        ])
        .write_stdin("piped_password\n")
        .assert()
        .success();
    profile
        .cmd()
        .args(["item", "get", "StdinLogin", "--field", "password"])
        .assert()
        .success()
        .stdout("piped_password\n");

    // --secret-field-stdin NAME reads one hidden field's value from stdin.
    profile
        .cmd()
        .args([
            "item",
            "add",
            "--type",
            "login",
            "--title",
            "SecretFieldLogin",
            "--username",
            "u",
            "--secret-field-stdin",
            "api_token",
        ])
        .write_stdin("tok_from_stdin\n")
        .assert()
        .success();
    profile
        .cmd()
        .args(["item", "get", "SecretFieldLogin", "--field", "api_token"])
        .assert()
        .success()
        .stdout("tok_from_stdin\n");

    // The leakage warning appears in `item add --help`.
    profile
        .cmd()
        .args(["item", "add", "--help"])
        .assert()
        .success()
        .stdout(contains("process listings"))
        .stdout(contains("--secret-field-stdin"));
}

/// Task #9: `item list` renders UPDATED as an ISO 8601 UTC timestamp
/// (`YYYY-MM-DD HH:MMZ`), not raw unix millis.
#[test]
fn item_list_shows_iso_timestamp() {
    let profile = TestProfile::initialized();
    profile
        .cmd()
        .args(["item", "add", "--title", "Dated", "--username", "u"])
        .assert()
        .success();

    profile
        .cmd()
        .args(["item", "list"])
        .assert()
        .success()
        // A YYYY-MM-DD HH:MMZ column: match the year prefix and the trailing Z.
        .stdout(predicate::str::is_match(r"20\d\d-\d\d-\d\d \d\d:\d\dZ").unwrap());
}
