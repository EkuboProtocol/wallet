use super::*;
use crate::core::predicate::Match;

fn context() -> PolicyContext {
    PolicyContext::default()
}

fn matcher(value: serde_json::Value) -> SourceMatcher {
    serde_json::from_value(value).expect("matcher parses")
}

/// The tag is the channel and the fields live inside it, so the two cannot
/// come apart. A matcher for one channel never answers for another.
#[test]
fn a_matcher_answers_only_for_its_own_channel() {
    let subject = matcher(serde_json::json!({"walletconnect": {}}));
    assert_eq!(
        subject.evaluate(
            &RequestSource::walletconnect(Some("https://app.ekubo.org/")),
            &context()
        ),
        Match::Yes
    );
    for other in [
        RequestSource::agent(Some("codex"), None),
        RequestSource::automation("7"),
        RequestSource::Unknown,
    ] {
        assert_eq!(subject.evaluate(&other, &context()), Match::No, "{other:?}");
    }
}

/// The issue's two examples, spelled the way a policy spells them.
#[test]
fn the_two_asks_from_the_issue_are_writable() {
    let dapp = matcher(serde_json::json!({
        "walletconnect": {"domain": {"in": ["app.ekubo.org", "ekubo.org"]}}
    }));
    assert_eq!(
        dapp.evaluate(
            &RequestSource::walletconnect(Some("https://app.ekubo.org/swap?a=1")),
            &context()
        ),
        Match::Yes
    );
    assert_eq!(
        dapp.evaluate(
            &RequestSource::walletconnect(Some("https://claim-rewards.xyz/")),
            &context()
        ),
        Match::No
    );

    let codex = matcher(serde_json::json!({"agent": {"client": {"eq": "codex"}}}));
    assert_eq!(
        codex.evaluate(&RequestSource::agent(Some("codex"), None), &context()),
        Match::Yes
    );
    assert_eq!(
        codex.evaluate(&RequestSource::agent(Some("claude_code"), None), &context()),
        Match::No
    );
}

/// A domain is compared as a host, so the scheme, port, path, and case of the
/// URL a dapp typed cannot smuggle a match past an `eq`.
#[test]
fn a_claimed_domain_is_reduced_to_its_host() {
    let subject =
        matcher(serde_json::json!({"walletconnect": {"domain": {"eq": "app.ekubo.org"}}}));
    for claimed in [
        "https://APP.Ekubo.ORG/",
        "https://app.ekubo.org:443/swap#x",
        "http://app.ekubo.org/",
    ] {
        assert_eq!(
            subject.evaluate(&RequestSource::walletconnect(Some(claimed)), &context()),
            Match::Yes,
            "{claimed}"
        );
    }
    for claimed in [
        "https://app.ekubo.org.evil.xyz/",
        "https://ekubo.org/",
        "not a url",
    ] {
        assert_eq!(
            subject.evaluate(&RequestSource::walletconnect(Some(claimed)), &context()),
            Match::No,
            "{claimed}"
        );
    }
}

/// Naming a field at all requires the request to carry it. This is what makes
/// adding a source matcher a narrowing rather than a widening, so it is
/// checked rather than assumed.
#[test]
fn a_named_field_the_request_does_not_carry_is_a_mismatch() {
    let any_domain = matcher(serde_json::json!({"walletconnect": {"domain": "any_value"}}));
    assert_eq!(
        any_domain.evaluate(&RequestSource::WalletConnect { domain: None }, &context()),
        Match::No
    );
    assert_eq!(
        any_domain.evaluate(
            &RequestSource::walletconnect(Some("https://ekubo.org")),
            &context()
        ),
        Match::Yes
    );

    // An inline plan has no host, so a rule that names one refuses it.
    let served = matcher(serde_json::json!({"agent": {"plan_host": "any_value"}}));
    assert_eq!(
        served.evaluate(&RequestSource::agent(Some("codex"), None), &context()),
        Match::No
    );
    assert_eq!(
        served.evaluate(
            &RequestSource::agent(Some("codex"), Some("mcp.ekubo.org")),
            &context()
        ),
        Match::Yes
    );
}

/// Nothing matches an unknown source. A row stored before the column existed
/// must not fall into a rule written afterwards.
#[test]
fn an_unknown_source_matches_nothing() {
    for value in [
        serde_json::json!({"walletconnect": {}}),
        serde_json::json!({"agent": {}}),
        serde_json::json!({"automation": {}}),
    ] {
        assert_eq!(
            matcher(value.clone()).evaluate(&RequestSource::Unknown, &context()),
            Match::No,
            "{value}"
        );
    }
}

/// Coverage is field-wise within one channel and never crosses channels, so
/// the permission diff cannot call an agent rule a narrowing of a dapp rule.
#[test]
fn coverage_is_proved_within_a_channel_and_never_across_them() {
    let any_dapp = matcher(serde_json::json!({"walletconnect": {}}));
    let one_dapp = matcher(serde_json::json!({"walletconnect": {"domain": {"eq": "ekubo.org"}}}));
    let two_dapps = matcher(serde_json::json!({
        "walletconnect": {"domain": {"in": ["ekubo.org", "app.ekubo.org"]}}
    }));
    assert!(one_dapp.is_narrower_than(&any_dapp));
    assert!(one_dapp.is_narrower_than(&two_dapps));
    assert!(!any_dapp.is_narrower_than(&one_dapp));
    assert!(!two_dapps.is_narrower_than(&one_dapp));

    let any_agent = matcher(serde_json::json!({"agent": {}}));
    assert!(!any_agent.is_narrower_than(&any_dapp));
    assert!(!any_dapp.is_narrower_than(&any_agent));

    let codex = matcher(serde_json::json!({"agent": {"client": {"eq": "codex"}}}));
    let codex_from_host = matcher(serde_json::json!({
        "agent": {"client": {"eq": "codex"}, "plan_host": {"eq": "mcp.ekubo.org"}}
    }));
    assert!(codex_from_host.is_narrower_than(&codex));
    assert!(!codex.is_narrower_than(&codex_from_host));
}

/// The permission diff has to say whose word the rule takes, because that is
/// the one thing a reviewer cannot recover from the rest of the line.
#[test]
fn the_description_says_which_parts_are_claims() {
    let dapp = matcher(serde_json::json!({"walletconnect": {"domain": {"eq": "ekubo.org"}}}));
    let described = dapp.describe();
    assert!(described.contains("claiming"), "{described}");
    assert!(described.contains("ekubo.org"), "{described}");

    let agent = matcher(serde_json::json!({"agent": {"client": {"eq": "codex"}}}));
    let described = agent.describe();
    assert!(described.contains("self-identifying"), "{described}");

    // An automation id is proved, so it is not hedged.
    let automation = matcher(serde_json::json!({"automation": {"id": {"eq": "7"}}}));
    let described = automation.describe();
    assert!(described.contains("installed automation"), "{described}");
    assert!(!described.contains("claim"), "{described}");
}

/// A predicate a string can never answer is refused where it is written,
/// rather than installing and silently never matching.
#[test]
fn a_predicate_a_string_cannot_answer_is_refused_at_the_field() {
    for refused in [
        serde_json::json!({"walletconnect": {"domain": {"gt": "5"}}}),
        serde_json::json!({"agent": {"client": {"each": "any_value"}}}),
        serde_json::json!({"automation": {"id": {"selector": {"abi": "transfer(address to)"}}}}),
    ] {
        assert!(
            serde_json::from_value::<SourceMatcher>(refused.clone()).is_err(),
            "{refused} was accepted"
        );
    }
}

/// A channel this build does not know, or a field it does not know, is an
/// error rather than a matcher that quietly constrains less than it says.
#[test]
fn an_unknown_channel_or_field_is_refused() {
    for refused in [
        serde_json::json!({"telepathy": {}}),
        serde_json::json!({"walletconnect": {"clietn": "any_value"}}),
        serde_json::json!({"agent": {"domain": {"eq": "ekubo.org"}}}),
    ] {
        assert!(
            serde_json::from_value::<SourceMatcher>(refused.clone()).is_err(),
            "{refused} was accepted"
        );
    }
}

/// The stored form round-trips, because a pending row holds it as text and
/// the review that reads it back has to evaluate the same source the
/// automatic path did.
#[test]
fn a_request_source_round_trips_through_its_stored_form() {
    for source in [
        RequestSource::Unknown,
        RequestSource::walletconnect(Some("https://app.ekubo.org/")),
        RequestSource::walletconnect(None),
        RequestSource::agent(Some("codex"), Some("mcp.ekubo.org")),
        RequestSource::agent(None, None),
        RequestSource::automation("42"),
    ] {
        let stored = serde_json::to_string(&source).expect("source serializes");
        let read: RequestSource = serde_json::from_str(&stored).expect("source parses");
        assert_eq!(read, source, "{stored}");
    }
}
