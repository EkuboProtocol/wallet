//! Tests for [`super`].
//!
//! What a dapp may ask for, and every refusal between, is tested in
//! `dapp_test.rs` alongside the module that decides it. What is left here is
//! the terminal: the connection review's own document, and the handovers that
//! keep exactly one surface reading keystrokes.

use super::*;

#[test]
fn an_empty_list_reads_as_none_rather_than_as_nothing() {
    assert_eq!(join_or_none(&[]), "none");
    assert_eq!(
        join_or_none(&["eip155:1".to_owned(), "eip155:10".to_owned()]),
        "eip155:1, eip155:10"
    );
}

/// The session screen must not blink out when a request is merely answered.
///
/// Suspending the idle surface leaves the alternate screen, and the session
/// loop re-enters it on its next turn — so a `suspend_idle` covering every
/// request made the whole screen flash on every answer, including for methods
/// that draw nothing at all. Only a path that actually draws may release it,
/// which since the split means the three `resolve_*` methods on
/// [`TerminalSurface`].
///
/// Read from the source because there is nothing else to read: the defect is a
/// terminal doing something visible, and no assertion about a return value
/// catches it.
#[test]
fn answering_a_request_does_not_release_the_session_screen() {
    let source = include_str!("connect.rs");
    let start = source
        .find("async fn handle_request")
        .expect("handle_request is gone");
    let body = &source[start..];
    let end = body[1..]
        .find("\n    fn ")
        .or_else(|| body[1..].find("\n    async fn "))
        .expect("handle_request has no successor")
        + 1;
    // The call, not the name: the comment in that body explains why the call
    // is absent, and a test that cannot tell them apart fails on the
    // explanation.
    assert!(
        !body[..end].contains("suspend_idle()"),
        "handle_request suspends the idle surface for every request, which flashes the session \
         screen on each answer. Suspend inside the path that draws instead."
    );
}

mod legal_currency_tests {
    //! The claim in the kernel matches what the kernel does.
    //!
    //! Where a dapp session rechecks acceptance is tested in `dapp_test.rs`;
    //! this is about the sentence the kernel prints about itself.

    /// The sentence this replaces said the signing paths repeated the check as
    /// defense in depth. They do not -- `load_matching_signer`, which every
    /// signature in the process passes through, never sees it -- and a comment
    /// asserting a security property the code does not have is worse than no
    /// comment, because it is what a reader checks instead of the code.
    #[test]
    fn the_kernel_does_not_claim_a_check_it_does_not_make() {
        let legal = include_str!("../crates/ekubo-wallet-core/src/legal.rs");
        assert!(
            !legal.contains("the signing paths repeat it as defense in depth"),
            "the signing paths do not call this"
        );
        assert!(
            legal.contains("It is **not** called by the signing paths themselves"),
            "and the doc comment says so, with what closing that would take"
        );
    }
}

mod disconnect_intent_tests {
    //! A disconnect asked for once stays asked for.

    /// The flag has to belong to the session, not to the surface that happened
    /// to be on screen when the key was pressed. `suspend_idle` drops the view
    /// around every review and `enter_idle` builds a new one, so a `q`,
    /// Escape, or Ctrl-C that lands while relay delivery wins the session
    /// `select!` used to set a flag on a view that was then thrown away --
    /// and the replacement started out saying no. The disconnect was not
    /// delayed, it was gone, and the dapp stayed connected to a person who
    /// believed they had left.
    ///
    /// Read from the source because standing the race up needs a relay, a
    /// settled session, and a terminal. What is checkable is the ownership:
    /// one flag, constructed once with the session, handed to each view.
    #[test]
    fn the_disconnect_flag_outlives_the_screen_that_recorded_it() {
        let screen = include_str!("connect_screen.rs");
        assert!(
            !screen.contains("let quit = Arc::new(AtomicBool::new(false));"),
            "an idle view must not mint its own disconnect flag; it is handed the session's"
        );
        assert!(
            screen.contains("pub fn start(state: Arc<Mutex<SessionState>>, quit: Arc<AtomicBool>)"),
            "the view takes the flag rather than making one"
        );

        let connect = include_str!("connect.rs");
        assert_eq!(
            connect.matches("Arc::new(AtomicBool::new(false))").count(),
            1,
            "exactly one disconnect flag exists, and the session owns it"
        );
        assert!(
            connect
                .contains("IdleView::start(Arc::clone(&surface.state), Arc::clone(&surface.quit))"),
            "every view started shares that one flag"
        );
    }
}

mod fresh_input_tests {
    //! A keystroke typed at one surface is not an answer to the next one.

    /// `confirm_review` starts its decision on the safe answer, but a buffered
    /// `Tab` toggles it and a buffered `Enter` returns it -- so two keystrokes
    /// typed at whatever was previously on the terminal affirm a document
    /// nobody saw. It is the shared confirmation behind legal acceptance,
    /// policy proposals, network proposals, and direct network edits.
    ///
    /// `approve_tui` and the inline prompts already drained. The fix is not a
    /// third call site but the one door: `Screen::enter` is the only route
    /// into the alternate screen, so draining there covers every full-screen
    /// surface that exists and every one added later.
    #[test]
    fn entering_the_alternate_screen_discards_earlier_keystrokes() {
        let fullscreen = include_str!("fullscreen.rs");
        let enter = fullscreen
            .split_once("pub(crate) fn enter() -> Result<Self> {")
            .expect("Screen::enter is declared")
            .1;
        let body = enter.split_once("\n    }").expect("its body ends").0;
        let drained = body
            .find("drain_type_ahead")
            .expect("entering a screen drains what was typed at the last one");
        let raw = body
            .find("enable_raw_mode")
            .expect("raw mode is enabled first");
        let entered = body
            .find("EnterAlternateScreen")
            .expect("the screen is then entered");
        assert!(
            raw < drained,
            "drain after enabling raw mode, or the keystrokes are still in the line discipline"
        );
        assert!(
            drained < entered,
            "drain before the screen exists, so nothing can be read at it first"
        );
    }

    /// And that door is the only one. A surface that entered the alternate
    /// screen by itself would skip the drain without changing this file.
    #[test]
    fn there_is_exactly_one_route_into_the_alternate_screen() {
        let mut entries = 0;
        for source in [
            include_str!("fullscreen.rs"),
            include_str!("approve_tui.rs"),
            include_str!("pager.rs"),
            include_str!("tx_browser.rs"),
            include_str!("connect_screen.rs"),
        ] {
            entries += source
                .lines()
                .filter(|line| {
                    line.contains("EnterAlternateScreen") && !line.trim_start().starts_with("//")
                })
                .filter(|line| !line.contains("terminal::{"))
                .count();
        }
        assert_eq!(
            entries, 1,
            "every full-screen surface must take the terminal through `Screen::enter`"
        );
    }
}
