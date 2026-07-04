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
/// (`com`) or a known multi-part suffix (`co.uk`). Such a host has no
/// registrable domain and must never be filled. `host` must be lowercased.
fn is_bare_public_suffix(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    match labels.len() {
        // A single label is always a bare TLD (or an intranet single name); no
        // registrable domain either way.
        0 | 1 => true,
        2 => MULTI_PART_SUFFIXES.contains(&host),
        _ => false,
    }
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
    // If the last two labels form a known multi-part suffix, the registrable
    // domain is the last three; else the last two.
    let last_two = labels[labels.len() - 2..].join(".");
    let take = if MULTI_PART_SUFFIXES.contains(&last_two.as_str()) {
        // Need a label in front of the multi-part suffix; without one it is a
        // bare public suffix (already handled above, but guard again).
        if labels.len() < 3 {
            return None;
        }
        3
    } else {
        2
    };
    Some(labels[labels.len() - take..].join("."))
}

/// Whether a stored `url` (from a login item) matches `origin` by registrable
/// domain. This is the single authoritative match predicate used by both the
/// candidate filter and the reveal re-check.
///
/// Returns `false` unless **both** the stored URL and the origin resolve to the
/// same non-empty registrable domain. A stored URL with no registrable domain
/// (blank, an IP, a bare suffix) never matches anything.
#[must_use]
pub fn url_matches_origin(url: &str, origin: &str) -> bool {
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
}
