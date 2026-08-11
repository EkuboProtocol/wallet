//! What is actually known about a dapp, kept apart from what it merely says.
//!
//! A `wc_sessionPropose` carries a name, a description, a URL, and some icon
//! links, all of them typed by whoever wrote the dapp. None of it is attested
//! by anything. A wallet that renders those four strings as a tidy identity
//! card has not told the reviewer anything they can act on — it has laundered
//! four claims into what looks like a fact.
//!
//! So this module derives the small amount that *is* checkable and labels the
//! rest as claimed:
//!
//! * The **host** of the URL the dapp gave. This is the only field with a
//!   structure that can be wrong, and it is the one a person can compare
//!   against the address bar they opened the site from. It leads the display
//!   for that reason.
//! * Whether that URL is `https`, and whether the icons come from the same
//!   host as the site.
//! * Whether the *name* contains a domain that disagrees with the host — a
//!   dapp calling itself `uniswap.org` while serving from `claim-rewards.xyz`
//!   is the exact shape of the attack this screen exists to catch.
//!
//! Nothing here reaches the network. There is no allowlist of known-good
//! dapps and no reputation lookup: both would need a third party, and a
//! wallet that says "verified" on someone else's authority has moved the
//! decision somewhere the owner cannot see it. What this produces is
//! material for a person to judge, never a verdict.

use url::Url;
use walletconnect_session::protocol::AppMetadata;

/// How much dapp-authored text is drawn before it is cut. Long enough for a
/// real name or a sentence of description, short enough that a wall of text
/// cannot push the warnings below it off a small screen.
const MAX_CLAIM_CHARACTERS: usize = 120;

/// How many distinct icon hosts are named on screen.
///
/// A dapp says how many icons it has, so a proposal can name thousands of
/// hosts, and each one is a line of the review a person reads before exposing
/// an account. Eight is more than any real dapp uses and few enough to stay
/// beside the warnings rather than pushing them off the screen. What is above
/// the cap is counted and said, never dropped quietly.
const MAX_ICON_HOSTS: usize = 8;

/// The site a dapp says it is, once its URL has been parsed.
pub struct Site {
    /// The host, lowercased. The part worth comparing against an address bar.
    pub host: String,
    pub scheme: String,
}

impl Site {
    /// Whether the transport the dapp names for itself is an encrypted one.
    #[must_use]
    pub fn is_secure(&self) -> bool {
        self.scheme == "https"
    }
}

/// Everything this wallet can say about the dapp on the other end.
pub struct DappIdentity {
    /// Derived from the claimed URL. `None` when there was no URL or it did
    /// not parse.
    pub site: Option<Site>,
    /// The URL exactly as claimed, for a reviewer who wants to see the whole
    /// thing rather than just its host.
    pub url: Option<String>,
    pub name: Option<String>,
    pub description: Option<String>,
    /// Hosts the icons are served from: deduplicated, sorted, and no more than
    /// [`MAX_ICON_HOSTS`] of them, because a dapp chooses how many icons it
    /// lists and every distinct host among them would otherwise be drawn. When
    /// some are left out, a caution says how many. Not fetched — this wallet
    /// draws no images and makes no request a dapp could observe.
    pub icon_hosts: Vec<String>,
    /// Things a reviewer should weigh. Never a verdict, and never a reason to
    /// refuse on its own: a legitimate dapp can trip any of these.
    pub cautions: Vec<String>,
}

impl DappIdentity {
    /// Read a proposal's metadata.
    #[must_use]
    pub fn of(metadata: &AppMetadata) -> Self {
        let name = claim(&metadata.name);
        let url = claim(&metadata.url);
        let site = url.as_deref().and_then(parse_site);

        // Every distinct host first, because whether *any* icon comes from
        // somewhere other than the site is the caution below and dropping one
        // early would answer that question wrong. Only what is drawn is
        // bounded.
        let all_icon_hosts: std::collections::BTreeSet<String> = metadata
            .icons
            .iter()
            .filter_map(|icon| parse_site(icon).map(|site| site.host))
            .collect();
        let icon_hosts: Vec<String> = all_icon_hosts
            .iter()
            .take(MAX_ICON_HOSTS)
            .cloned()
            .collect();

        let mut cautions = Vec::new();
        match (&url, &site) {
            (None, _) => cautions.push(
                "This dapp did not say which site it is. There is nothing here to compare \
                 against the page you opened."
                    .to_owned(),
            ),
            (Some(_), None) => cautions.push(
                "This dapp's URL could not be parsed, so there is no host to compare against \
                 the page you opened."
                    .to_owned(),
            ),
            (Some(_), Some(site)) => {
                if !site.is_secure() {
                    cautions.push(format!(
                        "This dapp names itself over `{}` rather than https.",
                        site.scheme
                    ));
                }
                if let Some(claimed) = disagreeing_domain(name.as_deref(), &site.host) {
                    cautions.push(format!(
                        "It calls itself `{claimed}` but serves from `{}`. A site impersonating \
                         another one looks exactly like this.",
                        site.host
                    ));
                }
                let foreign: Vec<&String> = all_icon_hosts
                    .iter()
                    .filter(|host| !same_site(host, &site.host))
                    .collect();
                if !foreign.is_empty() {
                    cautions.push(format!(
                        "Its icons are served from {}, not from {}.",
                        listed(&foreign),
                        site.host
                    ));
                }
            }
        }
        if name.is_none() {
            cautions.push("This dapp did not give itself a name.".to_owned());
        }
        // Said rather than silently dropped: a review that shows eight of forty
        // hosts without saying so is describing a different dapp than the one
        // proposing.
        if all_icon_hosts.len() > icon_hosts.len() {
            cautions.push(format!(
                "It lists icons on {} different hosts; the {MAX_ICON_HOSTS} above are the ones \
                 shown.",
                all_icon_hosts.len()
            ));
        }

        Self {
            site,
            url,
            name,
            description: claim(&metadata.description),
            icon_hosts,
            cautions,
        }
    }

    /// One line naming the dapp, for a status line or a plan's source.
    ///
    /// The host leads when there is one: a name is whatever the dapp typed,
    /// and the host is the thing a person can check.
    #[must_use]
    pub fn headline(&self) -> String {
        match (&self.name, &self.site) {
            (Some(name), Some(site)) => format!("{name} ({})", site.host),
            (None, Some(site)) => site.host.clone(),
            (Some(name), None) => format!("{name} (no site given)"),
            (None, None) => "an unnamed dapp".to_owned(),
        }
    }

    /// The host, or a stand-in saying there was not one. For the label that
    /// has to say *something* in a fixed slot.
    #[must_use]
    pub fn host_or_unknown(&self) -> String {
        self.site
            .as_ref()
            .map_or_else(|| "not stated".to_owned(), |site| site.host.clone())
    }
}

/// Dapp-authored text, made safe to draw and bounded, or `None` when what is
/// left says nothing.
///
/// The `None` case is not just the empty string: a name of one zero-width
/// space survives `trim` and disappears in the sanitizer, and a caller that
/// tested the input for emptiness would still draw an empty field.
#[must_use]
pub fn claim(value: &str) -> Option<String> {
    let safe = crate::sanitize::stripped_capped(value.trim(), MAX_CLAIM_CHARACTERS);
    (!safe.trim().is_empty()).then_some(safe)
}

/// At most [`MAX_ICON_HOSTS`] hosts as a sentence fragment, with a count
/// standing in for the rest. The count is the point: a caution that listed
/// eight of forty would read as a complete list of eight.
fn listed(hosts: &[&String]) -> String {
    let shown: Vec<&str> = hosts
        .iter()
        .take(MAX_ICON_HOSTS)
        .map(|host| host.as_str())
        .collect();
    let joined = shown.join(", ");
    match hosts.len() - shown.len() {
        0 => joined,
        rest => format!("{joined} and {rest} more"),
    }
}

/// The host and scheme of a URL, lowercased.
fn parse_site(value: &str) -> Option<Site> {
    let url = Url::parse(value).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    Some(Site {
        host,
        scheme: url.scheme().to_ascii_lowercase(),
    })
}

/// Whether two hosts are the same site, treating a subdomain as part of it.
///
/// Label-suffix matching, not registrable-domain matching: without a public
/// suffix list this cannot tell `example.co.uk` from `co.uk`. It is used only
/// to decide whether to *mention* something to a reviewer, so erring toward
/// "same" — staying quiet — is the right direction for it to be wrong in.
fn same_site(host: &str, site: &str) -> bool {
    host == site
        || host
            .strip_suffix(site)
            .is_some_and(|rest| rest.ends_with('.'))
        || site
            .strip_suffix(host)
            .is_some_and(|rest| rest.ends_with('.'))
}

/// A domain spelled inside the dapp's *name* that disagrees with the host it
/// actually serves from.
///
/// A name is free text, so most names have no domain in them and this finds
/// nothing. The case it exists for is the one where the name is chosen to be
/// read as an address — `app.uniswap.org` — while the site behind it is not
/// that address at all.
fn disagreeing_domain(name: Option<&str>, host: &str) -> Option<String> {
    let name = name?;
    name.split(|character: char| character.is_whitespace() || matches!(character, '(' | ')' | ','))
        .map(|token| token.trim_matches(|character: char| !character.is_alphanumeric()))
        .find(|token| looks_like_a_domain(token) && !same_site(&token.to_ascii_lowercase(), host))
        .map(str::to_ascii_lowercase)
}

/// Whether a token reads as a hostname rather than as a word.
///
/// Deliberately strict: a false positive here accuses a legitimate dapp of
/// impersonation on the one screen where the reviewer is deciding whether to
/// trust it, which spends the warning's credibility for nothing.
fn looks_like_a_domain(token: &str) -> bool {
    let Some((_, last)) = token.rsplit_once('.') else {
        return false;
    };
    // A real top-level label: at least two characters and all alphabetic, so
    // "v1.2" and "0.5" are not domains.
    last.len() >= 2
        && last
            .chars()
            .all(|character| character.is_ascii_alphabetic())
        && token
            .split('.')
            .all(|label| !label.is_empty() && label.chars().all(is_host_character))
}

fn is_host_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '-'
}

#[cfg(test)]
#[path = "dapp_identity_test.rs"]
mod tests;
