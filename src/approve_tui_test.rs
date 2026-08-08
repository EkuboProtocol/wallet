//! Tests for [`super`].
//!
//! Out of line so the audit corpus is production code: V12 bills measured
//! bytes and excludes `*_test.rs` by default. A `#[path]` child module has
//! exactly the privacy access an inline one does, so nothing these can reach
//! changes, and the test paths are the ones they always were.

use super::*;
use crate::approval::ApprovalKind;
use crossterm::event::KeyModifiers;

/// A terminal wide enough that no legend has to shed anything, so a test
/// about *whether* a key is advertised is not also a test about layout.
const WIDE: usize = 200;

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
        !review.hints(WIDE).contains("re-simulate"),
        "a review with no simulation must not offer one: {}",
        review.hints(WIDE)
    );
    review.refreshable = true;
    assert!(
        review.hints(WIDE).contains("r re-simulate"),
        "the key has to be discoverable: {}",
        review.hints(WIDE)
    );
}

#[test]
fn a_decision_taken_without_the_screen_still_shows_the_document() {
    // Run 6251, finding 186993. `--decision approve` answers the question in
    // advance, which is a legitimate thing for a script or a remote session to
    // do; it is not a reason to withhold what the answer is about. This path
    // once printed a JSON transcript before opening the screen, that dump was
    // removed as unread scrollback, and nothing replaced it here — so the one
    // review that exists because a policy asked a question or a simulation
    // failed became the one that showed no target, value, or digest.
    let request = ApprovalRequest::new(
        ApprovalKind::Transaction,
        "Approve a transfer",
        "Sending 1000 USDC to a new address",
    )
    .fact("Wallet", "main")
    .fact("Network", "ethereum")
    .section("Call 1")
    .fact("Target", "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48")
    .fact("Value", "0")
    .warning("no policy rule covers this transaction")
    .digest("0xabc123");

    let text = crate::approve_tui::review_document_text(&request, Vec::new());
    for shown in [
        "Sending 1000 USDC",
        "main",
        "ethereum",
        "Call 1",
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
        "0xabc123",
        "no policy rule covers this transaction",
    ] {
        assert!(text.contains(shown), "the document omits {shown:?}: {text}");
    }
    // The request id is what a reviewer quotes when something goes wrong.
    assert!(text.contains(&request.id.to_string()), "{text}");
}

fn switchable_screen() -> ReviewScreen {
    let mut review = ReviewScreen::new(document("primary review"));
    review.choices = vec![
        document("primary review"),
        document("cold review"),
        document("hot review"),
    ];
    review.choice_labels = vec!["primary".to_owned(), "cold".to_owned(), "hot".to_owned()];
    review
}

#[test]
fn switching_accounts_is_offered_only_where_there_is_a_choice() {
    // One account is not a choice, and a key that silently does nothing is
    // worse than one that was never advertised.
    let mut only_one = ReviewScreen::new(document("summary"));
    only_one.choices = vec![document("summary")];
    only_one.choice_labels = vec!["primary".to_owned()];
    assert!(!only_one.switchable());
    assert_eq!(only_one.handle_key(press(KeyCode::Char('a'))), None);
    assert_eq!(only_one.choice, 0);
    assert!(
        !only_one.hints(WIDE).contains("Tab account"),
        "{}",
        only_one.hints(WIDE)
    );

    let mut several = switchable_screen();
    assert!(several.switchable());
    assert_eq!(several.handle_key(press(KeyCode::Char('a'))), None);
    assert_eq!(several.choice, 1);
    assert!(
        several.hints(WIDE).contains("Tab account"),
        "{}",
        several.hints(WIDE)
    );
}

#[test]
fn switching_cycles_through_every_account_and_wraps() {
    let mut review = switchable_screen();
    for expected in [1, 2, 0, 1] {
        review.handle_key(press(KeyCode::Char('a')));
        assert_eq!(review.choice, expected);
    }
}

#[test]
fn the_document_on_screen_is_the_selected_accounts_own() {
    let mut review = switchable_screen();
    review.handle_key(press(KeyCode::Char('a')));
    assert_eq!(review.document, document("cold review"));
    review.handle_key(press(KeyCode::Char('a')));
    assert_eq!(review.document, document("hot review"));
}

/// The same property a changed re-simulation has, for the same reason:
/// scrolling one account's review to the end is not having read another's.
/// Without this, reading `primary` to the end and then switching would leave
/// Approve live over a document nobody had looked at.
#[test]
fn switching_accounts_withdraws_the_right_to_approve() {
    let mut review = switchable_screen();
    review.reached_end = true;
    review.on_approve = true;
    review.offset = 42;

    review.handle_key(press(KeyCode::Char('a')));

    assert!(!review.reached_end, "the new account's review is unseen");
    assert!(!review.on_approve, "the cursor returns to Reject");
    assert_eq!(review.offset, 0, "the new review starts at the top");
    assert_eq!(
        review.handle_key(press(KeyCode::Enter)),
        Some(ReviewAction::Decide(ApprovalDecision::Rejected)),
        "Enter on Reject still rejects"
    );
}

#[test]
fn the_footer_and_the_notice_name_the_account_now_selected() {
    // A legend saying only that a switch is possible does not say which
    // account is about to be connected, and that is the fact being decided.
    let mut review = switchable_screen();
    review.handle_key(press(KeyCode::Char('a')));
    let hints = review.hints(WIDE);
    assert!(hints.contains("cold"), "{hints}");
    assert!(hints.contains("2/3"), "{hints}");
    let notice = review.notice.clone().expect("a switch says what it did");
    assert!(notice.contains("cold"), "{notice}");
}

#[test]
fn tab_moves_through_the_accounts_when_there_are_accounts_to_move_through() {
    let mut review = switchable_screen();
    review.handle_key(press(KeyCode::Tab));
    assert_eq!(review.choice, 1);
    assert_eq!(review.document, document("cold review"));

    // And backwards, wrapping.
    review.handle_key(press(KeyCode::BackTab));
    assert_eq!(review.choice, 0);
    review.handle_key(press(KeyCode::BackTab));
    assert_eq!(review.choice, 2);
}

#[test]
fn the_decision_cursor_keeps_the_arrow_keys_while_tab_drives_the_list() {
    let mut review = switchable_screen();
    assert!(!review.on_approve);
    review.handle_key(press(KeyCode::Right));
    assert!(review.on_approve, "→ must still reach Approve");
    assert_eq!(review.choice, 0, "→ must not change the account");
    review.handle_key(press(KeyCode::Left));
    assert!(!review.on_approve);

    // The legend has to teach that split rather than the usual one.
    let hints = review.hints(WIDE);
    assert!(hints.contains("Tab account"), "{hints}");
    assert!(hints.contains("←→"), "{hints}");
}

#[test]
fn tab_still_toggles_the_decision_on_a_review_with_no_list() {
    // Every other review in the program keeps the binding it always had.
    let mut review = screen();
    review.handle_key(press(KeyCode::Tab));
    assert!(review.on_approve, "Tab must still reach Approve here");
    assert!(
        review.hints(WIDE).contains("Tab switch"),
        "{}",
        review.hints(WIDE)
    );
}

/// The reason giving Tab to the list is safe: on this screen Tab can only
/// move *away* from approving. A Tab and an Enter buffered before the screen
/// was drawn cannot approve anything, which is the case the drain and the
/// scroll-to-the-end rule both exist for.
#[test]
fn tab_can_never_carry_a_review_towards_approval() {
    let mut review = switchable_screen();
    review.reached_end = true;
    review.on_approve = true;

    review.handle_key(press(KeyCode::Tab));

    assert!(!review.on_approve, "the cursor returned to Reject");
    assert!(!review.reached_end, "the new review is unread");
    assert_eq!(
        review.handle_key(press(KeyCode::Enter)),
        Some(ReviewAction::Decide(ApprovalDecision::Rejected))
    );
}

/// The footer is one line and the renderer cuts whatever does not fit. What
/// gets cut is the *end* of the legend — which is where the way out of this
/// screen used to sit — so the legend has to shed segments deliberately.
#[test]
fn the_key_legend_fits_the_terminal_it_is_drawn_in() {
    let mut review = switchable_screen();
    review.refreshable = true;
    for width in [200, 120, 80, 60, 40, 30, 20, 12, 5, 1] {
        let hints = review.hints(width);
        assert!(
            crate::render::display_width(&hints) <= width.max(3),
            "at width {width} the legend was {} columns: {hints}",
            crate::render::display_width(&hints)
        );
    }
}

#[test]
fn the_way_out_survives_the_narrowest_terminal() {
    // Esc is the escape hatch. A reviewer who cannot see any other key must
    // still be able to see that one, so it is the last thing dropped.
    let mut review = switchable_screen();
    review.refreshable = true;
    for width in [200, 80, 40, 20, 12] {
        let hints = review.hints(width);
        assert!(hints.contains("Esc"), "width {width} lost Esc: {hints}");
    }
}

#[test]
fn a_narrow_terminal_keeps_the_account_indicator_readable() {
    // Which account is about to be connected is the fact this screen exists
    // to decide, so its counter outlives the prose around it.
    let mut review = switchable_screen();
    review.handle_key(press(KeyCode::Tab));
    let hints = review.hints(45);
    assert!(hints.contains("2/3"), "{hints}");
}

#[test]
fn a_decision_label_is_shortened_rather_than_left_to_be_cut() {
    // "Approve — scroll to the end of the document first" cut to "Approve"
    // reads as an invitation to press it. Every phrasing must stay whole.
    let phrasings = [
        "Approve — scroll to the end of the document first",
        "Approve — read it all first",
    ];
    assert_eq!(fitting(80, &phrasings), phrasings[0]);
    assert_eq!(fitting(30, &phrasings), phrasings[1]);
    // Narrower than every phrasing: the shortest complete one, never a
    // fragment of a longer one.
    assert_eq!(
        fitting(
            3,
            &["Approve — sign this exact action", "Approve — sign this"]
        ),
        "Approve — sign this"
    );
}

/// Render a whole review screen at a given size, as text.
fn rendered(request: &ApprovalRequest, width: u16, height: u16) -> String {
    let mut review = ReviewScreen::new(review_document(request, Vec::new()));
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| draw(frame, "Approve a dapp connection", &mut review))
        .unwrap();
    let buffer = terminal.backend().buffer().clone();
    (0..buffer.area.height)
        .map(|row| {
            (0..buffer.area.width)
                .map(|column| buffer[(column, row)].symbol())
                .collect::<String>()
                .trim_end()
                .to_owned()
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The facts a connection turns on have to be legible without scrolling on a
/// small terminal, because a screen that requires scrolling to see the site
/// and the account is a screen most people approve without seeing them.
#[test]
fn the_deciding_facts_are_on_the_first_screen_of_a_small_terminal() {
    let request = ApprovalRequest::new(
        ApprovalKind::PolicyException,
        "Approve a dapp connection",
        "Let this dapp propose transactions and signatures from this account.",
    )
    .fact("Site", "app.example.com")
    .fact("Name", "Example Exchange")
    .fact("Account", "primary")
    .fact("Address", "0x1111111111111111111111111111111111111111")
    .section("What this session will allow")
    .fact("Chain", "Ethereum (eip155:1)")
    .fact("Can call", "eth_sendTransaction");

    // 40x20 is a split pane on a laptop, and narrower than any default.
    let screen = rendered(&request, 40, 20);
    for expected in ["app.example.com", "primary", "Ethereum"] {
        assert!(
            screen.contains(expected),
            "{expected} not on screen:\n{screen}"
        );
    }
    for line in screen.lines() {
        assert!(
            crate::render::display_width(line) <= 40,
            "line wider than the terminal: {line:?}"
        );
    }
    assert!(screen.contains("Esc"), "no way out shown:\n{screen}");
}

#[test]
fn the_connection_review_shows_every_account_with_a_cursor_on_one() {
    let request = ApprovalRequest::new(
        ApprovalKind::PolicyException,
        "Approve a dapp connection",
        "Let this dapp propose transactions and signatures from this account.",
    )
    .fact("Site", "app.example.com")
    .fact("Name", "Example Exchange")
    .fact("Account", "primary")
    .fact("Address", "0x1111111111111111111111111111111111111111")
    .section("Connect as")
    .fact("▸ primary", "0x1111111111111111111111111111111111111111")
    .fact("  cold", "0x2222222222222222222222222222222222222222")
    .fact("  hot", "0x3333333333333333333333333333333333333333")
    .fact("", "Tab moves between them; ← and → choose reject/approve.")
    .section("What this session will allow")
    .fact("Chain", "Ethereum (eip155:1)");

    let screen = rendered(&request, 64, 28);
    for account in ["primary", "cold", "hot"] {
        assert!(screen.contains(account), "{account} missing:\n{screen}");
    }
    assert!(screen.contains('▸'), "no cursor on the list:\n{screen}");
    for row in screen.lines() {
        assert!(crate::render::display_width(row) <= 64, "{row:?}");
    }
}
