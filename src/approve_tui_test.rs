//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::approval::ApprovalKind;
use crossterm::event::KeyModifiers;

fn press(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn screen() -> ReviewScreen {
    ReviewScreen::new(vec![vec![Span::plain("summary")]])
}

#[test]
fn the_cursor_starts_on_reject_and_enter_there_rejects() {
    let mut review = screen();
    assert!(!review.on_approve, "reject is the default");
    assert_eq!(
        review.handle_key(press(KeyCode::Enter)),
        Some(ReviewAction::Decide(ApprovalDecision::Rejected))
    );
}

#[test]
fn every_way_out_reads_as_rejection() {
    for key in [
        press(KeyCode::Esc),
        press(KeyCode::Char('q')),
        KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL),
        KeyEvent::new(KeyCode::Char('d'), KeyModifiers::CONTROL),
    ] {
        let mut review = screen();
        review.on_approve = true;
        review.reached_end = true;
        assert_eq!(
            review.handle_key(key),
            Some(ReviewAction::Decide(ApprovalDecision::Rejected)),
            "{key:?} must reject even with approve highlighted"
        );
    }
}

#[test]
fn approving_takes_a_deliberate_move_and_a_fully_seen_document() {
    let mut review = screen();
    review.handle_key(press(KeyCode::Tab));
    assert!(review.on_approve);
    // The end has not been on screen: Enter refuses and explains.
    assert_eq!(review.handle_key(press(KeyCode::Enter)), None);
    assert!(review.notice.is_some(), "the refusal says why");
    review.reached_end = true;
    assert_eq!(
        review.handle_key(press(KeyCode::Enter)),
        Some(ReviewAction::Decide(ApprovalDecision::Approved))
    );
}

#[test]
fn scrolling_keys_move_the_viewport_and_never_decide() {
    let mut review = screen();
    review.viewport = 5;
    review.max_offset = 100;
    for key in [
        KeyCode::Down,
        KeyCode::Char('j'),
        KeyCode::PageDown,
        KeyCode::Char(' '),
        KeyCode::Char('f'),
        KeyCode::End,
        KeyCode::Char('G'),
        KeyCode::Up,
        KeyCode::PageUp,
        KeyCode::Home,
    ] {
        assert_eq!(review.handle_key(press(key)), None, "{key:?} only scrolls");
    }
    review.handle_key(press(KeyCode::Down));
    assert_eq!(review.offset, 1);
    review.handle_key(press(KeyCode::PageDown));
    assert_eq!(review.offset, 6);
    review.handle_key(press(KeyCode::Home));
    assert_eq!(review.offset, 0);
}

#[test]
fn the_document_carries_facts_warnings_digest_and_payload_sanitized() {
    let request = ApprovalRequest::new(
        ApprovalKind::MessageSignature,
        "Approve message signature",
        "Sign these exact bytes.",
    )
    .fact("Wallet", "main")
    .warning("verify\u{1b}[2Jevery byte")
    .digest("0xabc");
    let payload = vec![vec![Span::plain("hello world")]];
    let document = review_document(&request, payload);
    let text = fullscreen::lines_to_text(&document, |text, _| text.to_owned());
    assert!(text.contains("Sign these exact bytes."));
    assert!(text.contains("Wallet   main"), "labels align in a column");
    assert!(text.contains("Digest   0xabc"));
    assert!(text.contains(&format!("Request  {}", request.id)));
    assert!(text.contains("hello world"), "the payload is appended");
    assert!(
        !text.contains('\u{1b}'),
        "stored text cannot carry escapes into the review"
    );
    let line_with = |needle: &str| {
        document
            .iter()
            .position(|line| line.iter().any(|span| span.text.contains(needle)))
            .expect(needle)
    };
    assert!(
        line_with("⚠") > line_with("hello world"),
        "warnings come last, where the end-gate guarantees they are seen"
    );
}

#[test]
fn sections_render_headings_aligned_facts_and_sign_toned_amounts() {
    let request = ApprovalRequest::new(
        ApprovalKind::PolicyException,
        "Approve policy exception",
        "Review this plan.",
    )
    .fact("Wallet", "main")
    .section("Simulated net balance changes (excludes live gas)")
    .fact("ETH (native)", "-0.05 ETH (-50000000000000000 base units)")
    .fact("USDC (0xa0b8)", "+1.5 USDC (+1500000 base units)")
    .section("Call 1 of 1 — Normal")
    .fact("Calldata", "36 bytes; selector 0xa9059cbb")
    .fact("", "a9059cbb00000000");
    let document = review_document(&request, Vec::new());
    let text = fullscreen::lines_to_text(&document, |text, _| text.to_owned());
    assert!(text.contains("Simulated net balance changes"));
    assert!(text.contains("Call 1 of 1"));

    let toned = |needle: &str| {
        document
            .iter()
            .flatten()
            .find(|span| span.text.contains(needle))
            .and_then(|span| span.tone)
    };
    assert_eq!(toned("-0.05 ETH"), Some(Tone::Danger), "outflows read red");
    assert_eq!(
        toned("+1.5 USDC"),
        Some(Tone::Success),
        "inflows read green"
    );
    assert_eq!(
        toned("Call 1 of 1"),
        Some(Tone::Emphasis),
        "headings are emphasized"
    );
    // The continuation row (empty label) starts at the value column, under
    // the calldata summary rather than at the label column.
    assert!(text.contains("   a9059cbb00000000"), "{text}");
}

#[test]
fn wrapped_fact_values_hang_at_the_value_column() {
    let label = Span::toned("  Reads as  ", Tone::Muted);
    let line = vec![label, Span::plain("word ".repeat(12).trim_end())];
    let wrapped = wrap_document(std::slice::from_ref(&line), 40);
    assert!(wrapped.len() > 1, "the value is long enough to wrap");
    for continuation in &wrapped[1..] {
        assert_eq!(
            continuation[0].text,
            " ".repeat(12),
            "continuations start at the value column, not the left edge"
        );
    }
    // An indent that would starve the continuation of width is ignored.
    let narrow = wrap_document(&[line], 14);
    assert!(
        narrow[1..]
            .iter()
            .all(|row| !row[0].text.starts_with("            ")),
        "{narrow:?}"
    );
    // Lines without a leading muted label — headings, warnings, payload —
    // wrap from the left edge as before.
    let heading = vec![Span::toned("word ".repeat(12).trim_end(), Tone::Emphasis)];
    let plain = wrap_document(&[heading], 40);
    assert!(plain.len() > 1);
    assert!(!plain[1][0].text.starts_with(' '), "{plain:?}");
}

fn document(text: &str) -> Vec<Line> {
    vec![vec![Span::plain(text)]]
}

#[test]
fn re_simulation_is_offered_only_where_it_means_something() {
    let mut review = screen();
    // A typed-data or message review has no simulation behind it.
    assert_eq!(review.handle_key(press(KeyCode::Char('r'))), None);
    review.refreshable = true;
    assert_eq!(
        review.handle_key(press(KeyCode::Char('r'))),
        Some(ReviewAction::Refresh)
    );
}

/// The security property of a refresh: a reviewer who has scrolled a document
/// to its end has earned the right to approve *that* document. A refresh that
/// replaces it takes that evidence away, because the end they saw belongs to
/// text no longer on screen.
#[test]
fn a_changed_document_withdraws_the_right_to_approve() {
    let mut review = screen();
    review.refreshable = true;
    review.reached_end = true;
    review.on_approve = true;
    review.offset = 42;

    review.begin_refresh();
    review.finish_refresh(RefreshOutcome::Document(document("a different summary")));

    assert!(!review.reached_end, "the end of the new document is unseen");
    assert!(!review.on_approve, "the cursor returns to Reject");
    assert_eq!(review.offset, 0, "the new document starts at the top");
    assert_eq!(
        review.handle_key(press(KeyCode::Enter)),
        Some(ReviewAction::Decide(ApprovalDecision::Rejected)),
        "Enter on Reject still rejects"
    );
}

/// The converse: re-simulating an unchanged review must not punish the
/// reviewer by making them scroll it again, or they learn to hold Enter.
#[test]
fn an_unchanged_document_keeps_the_reading_it_already_had() {
    let mut review = ReviewScreen::new(document("summary"));
    review.refreshable = true;
    review.reached_end = true;
    review.offset = 7;

    review.begin_refresh();
    review.finish_refresh(RefreshOutcome::Document(document("summary")));

    assert!(review.reached_end, "nothing changed, so nothing is unread");
    assert_eq!(review.offset, 7, "the scroll position survives");
    assert!(
        review
            .notice
            .as_deref()
            .is_some_and(|notice| notice.contains("nothing changed")),
        "the reviewer is told the refresh found nothing: {:?}",
        review.notice
    );
}

/// Beginning a refresh alone must move the cursor off Approve, before any
/// document arrives: the moment the reviewer asks for new numbers, the old
/// ones stop being something to approve.
#[test]
fn asking_for_a_refresh_immediately_disarms_approve() {
    let mut review = screen();
    review.refreshable = true;
    review.reached_end = true;
    review.on_approve = true;
    review.begin_refresh();
    assert!(!review.on_approve);
    assert!(review.waiting_message().is_some(), "the wait is visible");
}

#[test]
fn a_failed_refresh_says_so_and_changes_nothing_else() {
    let mut review = ReviewScreen::new(document("summary"));
    review.refreshable = true;
    review.reached_end = true;
    review.offset = 3;

    review.begin_refresh();
    review.finish_refresh(RefreshOutcome::Failed("every endpoint refused".to_owned()));

    assert!(review.refreshing.is_none(), "the wait ended");
    assert!(review.reached_end, "the document was not replaced");
    assert_eq!(review.offset, 3);
    assert_eq!(review.document, document("summary"));
    assert!(
        review
            .notice
            .as_deref()
            .is_some_and(|notice| notice.contains("every endpoint refused")),
        "the reviewer is told why: {:?}",
        review.notice
    );
}

/// The waiting message counts real time, so a slow chain reads as slow rather
/// than as a frozen screen.
#[test]
fn the_wait_reports_elapsed_seconds() {
    let mut review = screen();
    review.begin_refresh();
    let first = review.waiting_message().expect("a wait is in progress");
    assert!(first.ends_with("Re-simulating…"), "{first}");
    for _ in 0..(1000 / REFRESH_TICK_MILLIS) {
        review.tick();
    }
    let later = review.waiting_message().expect("still waiting");
    assert!(later.ends_with("Re-simulating… 1s"), "{later}");
    // The glyph moves, so a stalled RPC still reads as a live screen.
    assert_ne!(
        first.chars().next(),
        later.chars().next(),
        "the spinner has to animate: {first} then {later}"
    );
}

#[test]
fn the_refresh_key_is_advertised_only_where_it_works() {
    let mut review = screen();
    assert!(
        !review.hints().contains("re-simulate"),
        "a review with no simulation must not offer one: {}",
        review.hints()
    );
    review.refreshable = true;
    assert!(
        review.hints().contains("r re-simulate"),
        "the key has to be discoverable: {}",
        review.hints()
    );
}
