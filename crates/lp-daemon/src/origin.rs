#![forbid(unsafe_code)]
//! Registrable-domain (eTLD+1) origin matching for browser autofill
//! (PRD §4.7 / §8 T7).
//!
//! The browser native-messaging host asks the daemon which login items match a
//! page's origin, and — for a specific user-chosen item — asks it to reveal that
//! item's credentials. **Both** the candidate filter and the reveal re-check use
//! the matching rule implemented here, so the daemon (not the extension) is the
//! authority on whether an item's stored URL matches the page (defense in depth,
//! [`crate::engine`]).
//!
//! # What "match" means
//!
//! Two hosts match iff they share the same **registrable domain** — the public
//! suffix plus one label ("eTLD+1"). `login.example.com` and `www.example.com`
//! both have the registrable domain `example.com`, so they match;
//! `evil-example.com` and `example.com.evil.com` do **not**. This is the
//! anti-phishing rule from PRD §4.7: autofill keys on the registrable domain,
//! never the bare host and never a substring.
//!
//! # eTLD+1 without a full public-suffix list (documented MVP limitation)
//!
//! A byte-exact eTLD+1 computation needs the Mozilla Public Suffix List (the
//! ~9 000-entry table of every registry suffix, including wildcard and exception
//! rules). Pulling a PSL crate (`psl` bakes the whole list into the binary;
//! `publicsuffix` needs the list shipped/downloaded) is a real dependency- and
//! binary-size cost we deliberately defer for the MVP (matches the crate's
//! minimal-dependency ethos — the daemon's only non-workspace deps are
//! serde/ssh-key/platform bindings).
//!
//! Instead we use a **conservative heuristic**:
//!
//! 1. Take the last label (the TLD, e.g. `com`, `uk`, `jp`).
//! 2. If the last **two** labels are a known multi-part public suffix from a
//!    small built-in [`MULTI_PART_SUFFIXES`] set (e.g. `co.uk`, `com.au`,
//!    `co.jp`), the registrable domain is the last **three** labels.
//! 3. Otherwise the registrable domain is the last **two** labels.
//!
//! ## The limitation, stated plainly
//!
//! This is correct for the overwhelming majority of real sites and for every
//! multi-part suffix in the built-in set. It is **imperfect** for registry
//! suffixes not in the set: for a ccTLD-with-second-level like `example.co.nz`
//! (if `co.nz` is not listed) the heuristic would compute the registrable domain
//! as `co.nz` and could over-match `other.co.nz`. The mitigation posture:
//!
//! - The built-in set covers the common second-level registrars people actually
//!   hit (see [`MULTI_PART_SUFFIXES`]); extend it as needed.
//! - The failure mode is **over-matching within a shared registry suffix**, never
//!   matching across unrelated domains: `example.com` can never match
//!   `evil-example.com` or `example.com.evil.com` under this rule, so the core
//!   T7 phishing protection (a lookalike registrable domain never matches) holds.
//! - **Never** treating a bare public suffix as a registrable domain is enforced:
//!   a host that *is* exactly a (built-in) public suffix — `com`, `co.uk` — has
//!   no registrable domain and [`registrable_domain`] returns `None`, so such an
//!   origin can never be filled.
//!
//! A full PSL is tracked as a follow-up; the wire protocol and the daemon-side
//! re-check do not change when it lands — only [`registrable_domain`]'s internals.
//!
//! # Shared-hosting suffixes (the PSL "private" section)
//!
//! Platforms that give every customer a subdomain — `myapp.vercel.app`,
//! `alice.github.io`, `shop.herokuapp.com` — are public suffixes too: each
//! customer's site is its own registrable domain, and anyone can register a
//! neighbour. Treating `vercel.app` as an ordinary registrable domain would
//! fill a login saved for `myapp.vercel.app` on `attacker.vercel.app`. The
//! built-in [`PRIVATE_SUFFIXES`] set covers the common platforms, and matching
//! uses the **longest** known suffix, so three-label suffixes such as
//! `web.core.windows.net` work as well.
//!
//! # Scheme
//!
//! A login saved with an `https://` URL never matches an `http://` page on the
//! same domain: offering or filling it there would hand the credential to a
//! page an on-path attacker can rewrite (see [`url_matches_origin`]).
//!
//! # Origin parsing
//!
//! [`registrable_domain`] accepts either a bare host (`example.com`) or a full
//! origin/URL (`https://login.example.com:8443/path`) and extracts the host. It
//! rejects IP literals (v4 and bracketed v6) and `localhost` as having **no**
//! registrable domain — an IP or loopback is not a registry-delegated name, so
//! autofill by registrable domain does not apply (documented; a future exact-URL
//! match mode could special-case `localhost` for dev, but it must not go through
//! the registrable-domain path).

/// Common multi-part public suffixes (second-level registry domains). If a
/// host's last two labels are one of these, its registrable domain is its last
/// three labels. This is a pragmatic, extensible subset of the Mozilla Public
/// Suffix List (see the module docs for the limitation this implies).
///
/// Kept lowercase and sorted for readability; lookups lowercase the input first.
pub const MULTI_PART_SUFFIXES: &[&str] = &[
    // United Kingdom
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk", "ac.uk", "gov.uk", "nhs.uk",
    // Australia
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au", // Japan
    "co.jp", "ne.jp", "or.jp", "go.jp", "ac.jp", // Brazil
    "com.br", "net.br", "org.br", "gov.br", // India
    "co.in", "net.in", "org.in", "gen.in", "firm.in", "gov.in", // New Zealand
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz", // South Africa
    "co.za", "org.za", "net.za", "gov.za", // South Korea
    "co.kr", "or.kr", "go.kr", // China
    "com.cn", "net.cn", "org.cn", "gov.cn", // Others frequently encountered
    "com.mx", "com.tr", "com.sg", "com.hk", "com.tw", "co.il", "com.ar", "com.pl",
];

/// Shared-hosting suffixes from the Public Suffix List's private section: every
/// customer subdomain under one of these is its own registrable domain. A
/// pragmatic subset of the platforms people actually deploy to; extend as
/// needed (same maintenance model as [`MULTI_PART_SUFFIXES`]).
pub const PRIVATE_SUFFIXES: &[&str] = &[
    // Frontend and static hosting
    "vercel.app",
    "now.sh",
    "netlify.app",
    "netlify.com",
    "pages.dev",
    "workers.dev",
    "github.io",
    "gitlab.io",
    "bitbucket.io",
    "surge.sh",
    "web.app",
    "firebaseapp.com",
    "onrender.com",
    "fly.dev",
    "glitch.me",
    "replit.app",
    "repl.co",
    "deno.dev",
    "vercel.sh",
    "azurestaticapps.net",
    "amplifyapp.com",
    "cloudfront.net",
    // Application platforms
    "herokuapp.com",
    "appspot.com",
    "azurewebsites.net",
    "cloudapp.net",
    "elasticbeanstalk.com",
    "run.app",
    "ondigitalocean.app",
    "railway.app",
    "up.railway.app",
    "web.core.windows.net",
    "blob.core.windows.net",
    // Tunnels and previews
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
    "loca.lt",
    // Site builders and blogs
    "blogspot.com",
    "wordpress.com",
    "wixsite.com",
    "myshopify.com",
    "tumblr.com",
    "webflow.io",
    "carrd.co",
    "notion.site",
];

/// The longest built-in public suffix (registry multi-part or shared-hosting)
/// that `host` ends with on a label boundary, if any. `host` is lowercased.
fn known_suffix(host: &str) -> Option<&'static str> {
    MULTI_PART_SUFFIXES
        .iter()
        .chain(PRIVATE_SUFFIXES)
        .copied()
        .filter(|suffix| host == *suffix || host.ends_with(&format!(".{suffix}")))
        .max_by_key(|suffix| suffix.len())
}

/// The scheme of a full URL/origin, lowercased (`https`), or `None` for a bare
/// host.
#[must_use]
pub fn scheme_of(origin: &str) -> Option<String> {
    let s = origin.trim();
    let (scheme, _) = s.split_once("://")?;
    let valid = !scheme.is_empty()
        && scheme
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    valid.then(|| scheme.to_ascii_lowercase())
}

/// Extract the **host** component from a bare host or a full origin/URL.
///
/// Accepts `example.com`, `//example.com`, `https://user@example.com:443/x`,
/// `http://example.com`, etc. Lowercases the result and strips a trailing dot
/// (the DNS root). Returns `None` if no plausible host remains.
#[must_use]
pub fn host_of(origin: &str) -> Option<String> {
    let s = origin.trim();
    if s.is_empty() {
        return None;
    }
    // Drop a scheme (`scheme://`) if present.
    let after_scheme = match s.find("://") {
        Some(i) => &s[i + 3..],
        None => s.strip_prefix("//").unwrap_or(s),
    };
    // The authority ends at the first '/', '?', or '#'.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Strip userinfo ("user:pass@").
    let host_port = match authority.rsplit_once('@') {
        Some((_, hp)) => hp,
        None => authority,
    };
    // Strip a port. IPv6 literals are bracketed ("[::1]:443"); handle the bracket
    // form first so the ':' inside the address is not mistaken for a port sep.
    let host = if let Some(rest) = host_port.strip_prefix('[') {
        // Bracketed IPv6 — take up to the closing bracket.
        rest.split(']').next().unwrap_or(rest)
    } else if let Some((h, _port)) = host_port.rsplit_once(':') {
        // Only treat as host:port if the tail is all digits; otherwise (no port)
        // keep the whole thing. A bare host never contains ':'.
        let (h2, port) = (h, host_port.rsplit_once(':').map(|(_, p)| p).unwrap_or(""));
        if !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
            h2
        } else {
            host_port
        }
    } else {
        host_port
    };
    let host = host.trim_end_matches('.').trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(host)
}

/// Whether `host` is an IPv4/IPv6 literal or `localhost` — none of which have a
/// registrable domain (see the module docs). `host` must already be lowercased.
fn is_ip_or_localhost(host: &str) -> bool {
    if host == "localhost" {
        return true;
    }
    // Bracketed or bare IPv6 (contains ':').
    if host.contains(':') {
        return true;
    }
    // IPv4 dotted-quad: four all-numeric labels.
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() == 4
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.parse::<u8>().is_ok())
    {
        return true;
    }
    false
}

/// Whether the whole `host` is itself a (built-in) public suffix — a bare TLD
/// (`com`), a known multi-part suffix (`co.uk`), or a shared-hosting suffix
/// (`vercel.app`). Such a host has no registrable domain and must never be
/// filled. `host` must be lowercased.
fn is_bare_public_suffix(host: &str) -> bool {
    // A single label is always a bare TLD (or an intranet single name); no
    // registrable domain either way.
    !host.contains('.') || known_suffix(host) == Some(host)
}

/// Compute the **registrable domain** (eTLD+1) of `origin`, or `None` if it has
/// none (an IP literal, `localhost`, or a bare public suffix).
///
/// `origin` may be a bare host or a full origin/URL; see [`host_of`]. The result
/// is lowercased. See the module docs for the heuristic and its documented
/// limitation.
///
/// # Examples
///
/// ```
/// use lp_daemon::origin::registrable_domain;
/// assert_eq!(registrable_domain("www.example.com").as_deref(), Some("example.com"));
/// assert_eq!(registrable_domain("https://login.example.co.uk/x").as_deref(), Some("example.co.uk"));
/// assert_eq!(registrable_domain("com"), None);
/// assert_eq!(registrable_domain("co.uk"), None);
/// assert_eq!(registrable_domain("127.0.0.1"), None);
/// ```
#[must_use]
pub fn registrable_domain(origin: &str) -> Option<String> {
    let host = host_of(origin)?;
    if is_ip_or_localhost(&host) {
        return None;
    }
    if is_bare_public_suffix(&host) {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    // Must have at least two labels to have a registrable domain.
    if labels.len() < 2 {
        return None;
    }
    // The registrable domain is one label in front of the longest known public
    // suffix (multi-part registry or shared hosting); with none known, the
    // suffix is the TLD and the registrable domain is the last two labels.
    let suffix_labels = known_suffix(&host).map_or(1, |suffix| suffix.split('.').count());
    let take = suffix_labels + 1;
    if labels.len() < take {
        // The host IS the suffix (handled above, but guard again).
        return None;
    }
    Some(labels[labels.len() - take..].join("."))
}

/// Whether a stored `url` (from a login item) matches `origin` by registrable
/// domain. This is the single authoritative match predicate used by both the
/// candidate filter and the reveal re-check.
///
/// Returns `false` unless **both** the stored URL and the origin resolve to the
/// same non-empty registrable domain. A stored URL with no registrable domain
/// (blank, an IP, a bare suffix) never matches anything.
///
/// **No scheme downgrade:** a login saved with an `https://` URL does not match
/// an `http://` origin. A bare stored host (no scheme) states no preference and
/// matches either.
#[must_use]
pub fn url_matches_origin(url: &str, origin: &str) -> bool {
    if scheme_of(url).as_deref() == Some("https") && scheme_of(origin).as_deref() == Some("http") {
        return false;
    }
    match (registrable_domain(url), registrable_domain(origin)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_extraction_from_full_urls() {
        assert_eq!(
            host_of("https://login.example.com:8443/x?y#z").as_deref(),
            Some("login.example.com")
        );
        assert_eq!(
            host_of("http://user:pass@example.com/").as_deref(),
            Some("example.com")
        );
        assert_eq!(host_of("//example.com").as_deref(), Some("example.com"));
        assert_eq!(host_of("Example.COM").as_deref(), Some("example.com"));
        assert_eq!(host_of("example.com.").as_deref(), Some("example.com"));
        assert_eq!(host_of("https://[::1]:443/").as_deref(), Some("::1"));
        assert_eq!(host_of(""), None);
        assert_eq!(host_of("   "), None);
    }

    #[test]
    fn simple_registrable_domain() {
        assert_eq!(
            registrable_domain("example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("www.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("login.example.com").as_deref(),
            Some("example.com")
        );
        assert_eq!(
            registrable_domain("a.b.c.example.com").as_deref(),
            Some("example.com")
        );
    }

    #[test]
    fn multi_part_suffix_registrable_domain() {
        assert_eq!(
            registrable_domain("example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable_domain("www.example.co.uk").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            registrable_domain("shop.example.com.au").as_deref(),
            Some("example.com.au")
        );
        assert_eq!(
            registrable_domain("x.y.example.co.jp").as_deref(),
            Some("example.co.jp")
        );
    }

    #[test]
    fn bare_public_suffix_has_no_registrable_domain() {
        assert_eq!(registrable_domain("com"), None);
        assert_eq!(registrable_domain("co.uk"), None);
        assert_eq!(registrable_domain("com.au"), None);
        assert_eq!(registrable_domain("uk"), None);
    }

    #[test]
    fn ip_and_localhost_have_no_registrable_domain() {
        assert_eq!(registrable_domain("127.0.0.1"), None);
        assert_eq!(registrable_domain("192.168.1.1"), None);
        assert_eq!(registrable_domain("http://127.0.0.1:8080/"), None);
        assert_eq!(registrable_domain("localhost"), None);
        assert_eq!(registrable_domain("http://localhost:3000/"), None);
        assert_eq!(registrable_domain("[::1]"), None);
        assert_eq!(registrable_domain("https://[fe80::1]/"), None);
    }

    #[test]
    fn phishing_lookalikes_do_not_match() {
        // The core T7 property.
        assert!(!url_matches_origin(
            "https://example.com",
            "https://evil-example.com"
        ));
        assert!(!url_matches_origin(
            "https://example.com",
            "https://example.com.evil.com"
        ));
        assert!(!url_matches_origin(
            "https://example.com",
            "https://notexample.com"
        ));
        // Cross-registrable-domain never matches.
        assert!(!url_matches_origin("https://a.co.uk", "https://b.co.uk"));
    }

    #[test]
    fn same_registrable_domain_matches_across_subdomains() {
        assert!(url_matches_origin(
            "https://example.com",
            "https://www.example.com"
        ));
        assert!(url_matches_origin(
            "https://login.example.com/signin",
            "https://example.com"
        ));
        assert!(url_matches_origin(
            "https://www.example.co.uk",
            "https://shop.example.co.uk"
        ));
    }

    #[test]
    fn blank_or_suffix_url_never_matches() {
        assert!(!url_matches_origin("", "https://example.com"));
        assert!(!url_matches_origin("com", "https://example.com"));
        assert!(!url_matches_origin("https://example.com", ""));
    }

    #[test]
    fn https_logins_never_match_an_http_page() {
        assert!(!url_matches_origin(
            "https://example.com/login",
            "http://example.com"
        ));
        assert!(!url_matches_origin(
            "https://login.example.com",
            "HTTP://www.example.com/"
        ));
        assert!(url_matches_origin(
            "https://example.com/login",
            "https://www.example.com"
        ));
    }

    #[test]
    fn an_http_login_still_matches_http_and_https() {
        assert!(url_matches_origin(
            "http://intranet.example.com",
            "http://intranet.example.com"
        ));
        assert!(url_matches_origin(
            "http://example.com",
            "https://example.com"
        ));
    }

    #[test]
    fn a_bare_stored_host_matches_either_scheme() {
        assert!(url_matches_origin("example.com", "http://example.com"));
        assert!(url_matches_origin("example.com", "https://example.com"));
    }

    #[test]
    fn scheme_parsing() {
        assert_eq!(scheme_of("HTTPS://x.com").as_deref(), Some("https"));
        assert_eq!(scheme_of("http://x.com").as_deref(), Some("http"));
        assert_eq!(
            scheme_of("chrome-extension://abc").as_deref(),
            Some("chrome-extension")
        );
        assert_eq!(scheme_of("x.com"), None);
        assert_eq!(scheme_of("//x.com"), None);
        assert_eq!(scheme_of("1http://x.com"), None);
    }

    #[test]
    fn tenants_of_a_shared_hosting_platform_are_separate_sites() {
        assert_eq!(
            registrable_domain("myapp.vercel.app").as_deref(),
            Some("myapp.vercel.app")
        );
        assert_eq!(
            registrable_domain("https://preview-1.myapp.vercel.app").as_deref(),
            Some("myapp.vercel.app")
        );
        assert!(!url_matches_origin(
            "https://myapp.vercel.app",
            "https://attacker.vercel.app"
        ));
        assert!(!url_matches_origin(
            "https://alice.github.io/",
            "https://mallory.github.io"
        ));
        assert!(!url_matches_origin(
            "https://shop.herokuapp.com",
            "https://evil.herokuapp.com"
        ));
        assert!(url_matches_origin(
            "https://myapp.vercel.app/login",
            "https://myapp.vercel.app"
        ));
    }

    #[test]
    fn a_bare_shared_hosting_suffix_has_no_registrable_domain() {
        for host in [
            "vercel.app",
            "github.io",
            "https://herokuapp.com/",
            "web.core.windows.net",
        ] {
            assert_eq!(registrable_domain(host), None, "{host}");
        }
    }

    #[test]
    fn the_longest_known_suffix_wins() {
        // `web.core.windows.net` (3 labels) beats nothing shorter being listed.
        assert_eq!(
            registrable_domain("mysite.web.core.windows.net").as_deref(),
            Some("mysite.web.core.windows.net")
        );
        // `up.railway.app` beats `railway.app`.
        assert_eq!(
            registrable_domain("svc.up.railway.app").as_deref(),
            Some("svc.up.railway.app")
        );
        assert_eq!(
            registrable_domain("svc.railway.app").as_deref(),
            Some("svc.railway.app")
        );
    }

    #[test]
    fn the_platforms_own_sites_are_unaffected() {
        // The platform's apex domains are ordinary registrable domains.
        assert_eq!(
            registrable_domain("vercel.com").as_deref(),
            Some("vercel.com")
        );
        assert_eq!(
            registrable_domain("www.github.com").as_deref(),
            Some("github.com")
        );
        assert!(url_matches_origin(
            "https://github.com/login",
            "https://gist.github.com"
        ));
    }

    #[test]
    fn suffix_matching_is_label_aligned() {
        // `notvercel.app` must not be treated as under `vercel.app`.
        assert_eq!(
            registrable_domain("a.notvercel.app").as_deref(),
            Some("notvercel.app")
        );
    }
}
