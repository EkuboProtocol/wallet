//! Tests for [`super`].

use super::*;

fn metadata(name: &str, url: &str) -> AppMetadata {
    AppMetadata {
        name: name.to_owned(),
        url: url.to_owned(),
        description: String::new(),
        icons: Vec::new(),
    }
}

#[test]
fn the_host_is_derived_from_the_claimed_url() {
    let identity = DappIdentity::of(&metadata("Example", "https://App.Example.com/connect?x=1"));
    let site = identity.site.expect("a parseable URL has a host");
    assert_eq!(site.host, "app.example.com");
    assert_eq!(site.scheme, "https");
    assert!(site.is_secure());
    assert!(identity.cautions.is_empty(), "{:?}", identity.cautions);
}

#[test]
fn the_headline_leads_with_something_checkable() {
    let named = DappIdentity::of(&metadata("Example", "https://example.com"));
    assert_eq!(named.headline(), "Example (example.com)");

    // A name is whatever the dapp typed; the host is the part a person can
    // compare against their address bar, so it survives when the name does not.
    let anonymous = DappIdentity::of(&metadata("", "https://example.com"));
    assert_eq!(anonymous.headline(), "example.com");

    let siteless = DappIdentity::of(&metadata("Example", ""));
    assert_eq!(siteless.headline(), "Example (no site given)");

    let nothing = DappIdentity::of(&metadata("", ""));
    assert_eq!(nothing.headline(), "an unnamed dapp");
    assert_eq!(nothing.host_or_unknown(), "not stated");
}

#[test]
fn a_dapp_that_names_no_site_is_said_to_have_named_none() {
    let identity = DappIdentity::of(&metadata("Example", ""));
    assert!(identity.site.is_none());
    assert!(
        identity
            .cautions
            .iter()
            .any(|caution| caution.contains("did not say which site")),
        "{:?}",
        identity.cautions
    );
}

#[test]
fn an_unparseable_url_is_reported_rather_than_dropped() {
    let identity = DappIdentity::of(&metadata("Example", "not a url"));
    assert!(identity.site.is_none());
    assert!(identity.url.is_some(), "the claim itself is still shown");
    assert!(
        identity
            .cautions
            .iter()
            .any(|caution| caution.contains("could not be parsed")),
        "{:?}",
        identity.cautions
    );
}

#[test]
fn a_site_that_is_not_https_is_mentioned() {
    let identity = DappIdentity::of(&metadata("Example", "http://example.com"));
    assert!(!identity.site.as_ref().unwrap().is_secure());
    assert!(
        identity
            .cautions
            .iter()
            .any(|caution| caution.contains("rather than https")),
        "{:?}",
        identity.cautions
    );
}

#[test]
fn a_name_spelling_a_domain_it_does_not_serve_from_is_the_headline_warning() {
    // The whole shape of the attack this screen exists to catch: the name is
    // chosen to be read as an address, and the address is somewhere else.
    let identity = DappIdentity::of(&metadata(
        "app.uniswap.org",
        "https://claim-rewards.example",
    ));
    let caution = identity
        .cautions
        .iter()
        .find(|caution| caution.contains("calls itself"))
        .unwrap_or_else(|| panic!("no impersonation caution: {:?}", identity.cautions));
    assert!(caution.contains("app.uniswap.org"), "{caution}");
    assert!(caution.contains("claim-rewards.example"), "{caution}");
}

#[test]
fn a_name_that_matches_its_own_site_says_nothing() {
    for (name, url) in [
        ("app.example.com", "https://app.example.com"),
        // A subdomain of the site it names, and the reverse, are both the
        // same site as far as this is concerned.
        ("example.com", "https://app.example.com"),
        ("app.example.com", "https://example.com"),
    ] {
        let identity = DappIdentity::of(&metadata(name, url));
        assert!(
            identity.cautions.is_empty(),
            "{name} at {url} warned: {:?}",
            identity.cautions
        );
    }
}

#[test]
fn an_ordinary_name_is_never_mistaken_for_a_domain() {
    // A false positive accuses a legitimate dapp of impersonation on the one
    // screen where the reviewer is deciding whether to trust it.
    for name in [
        "Uniswap",
        "Example Exchange",
        "Aave v3.1",
        "Perps 0.5 beta",
        "Sign in with Ethereum",
        "1inch",
        "app v2",
    ] {
        let identity = DappIdentity::of(&metadata(name, "https://example.com"));
        assert!(
            identity.cautions.is_empty(),
            "{name} was read as a domain: {:?}",
            identity.cautions
        );
    }
}

#[test]
fn icons_from_somewhere_else_are_mentioned_and_never_fetched() {
    let mut with_icons = metadata("Example", "https://example.com");
    with_icons.icons = vec![
        "https://cdn.elsewhere.net/icon.png".to_owned(),
        "https://cdn.elsewhere.net/icon2.png".to_owned(),
        "https://example.com/logo.png".to_owned(),
    ];
    let identity = DappIdentity::of(&with_icons);
    // Deduplicated, and the site's own host is not called foreign.
    assert_eq!(identity.icon_hosts, ["cdn.elsewhere.net", "example.com"]);
    let caution = identity
        .cautions
        .iter()
        .find(|caution| caution.contains("icons"))
        .unwrap_or_else(|| panic!("{:?}", identity.cautions));
    assert!(caution.contains("cdn.elsewhere.net"), "{caution}");
    assert!(!caution.contains("example.com,"), "{caution}");
}

#[test]
fn icons_on_the_dapps_own_site_say_nothing() {
    let mut same = metadata("Example", "https://example.com");
    same.icons = vec!["https://cdn.example.com/icon.png".to_owned()];
    let identity = DappIdentity::of(&same);
    assert!(identity.cautions.is_empty(), "{:?}", identity.cautions);
}

#[test]
fn dapp_authored_text_cannot_redraw_the_screen_it_lands_on() {
    let hostile = "Uni\u{202e}swap\u{200b} \u{2066}official\u{2069}";
    let identity = DappIdentity::of(&AppMetadata {
        name: hostile.to_owned(),
        description: hostile.to_owned(),
        url: "https://example.com".to_owned(),
        icons: Vec::new(),
    });
    for text in [identity.name.unwrap(), identity.description.unwrap()] {
        for character in ['\u{202e}', '\u{200b}', '\u{2066}', '\u{2069}'] {
            assert!(!text.contains(character), "{character:?} survived: {text}");
        }
    }
}

#[test]
fn a_claim_is_capped_and_an_empty_one_is_nothing() {
    assert!(claim(&"a".repeat(5_000)).unwrap().chars().count() <= 130);
    assert_eq!(claim(""), None);
    assert_eq!(claim("   "), None);
    assert_eq!(claim("\u{200b}"), None);
    assert_eq!(claim(" Example "), Some("Example".to_owned()));
}
