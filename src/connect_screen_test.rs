//! Tests for [`super`].

use super::*;

fn line(text: &str) -> Line {
    vec![Span::plain(text)]
}

/// Render the idle surface at a given size, as text.
fn rendered(state: &SessionState, width: u16, height: u16) -> String {
    let backend = ratatui::backend::TestBackend::new(width, height);
    let mut terminal = ratatui::Terminal::new(backend).unwrap();
    terminal.draw(|frame| draw_idle(frame, state)).unwrap();
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

fn connected() -> SessionState {
    SessionState {
        title: "Connected to app.example.com".to_owned(),
        header: vec![
            fact("Site", "app.example.com"),
            fact("Account", "primary"),
            fact("Address", "0x1111111111111111111111111111111111111111"),
            Vec::new(),
        ],
        log: Vec::new(),
        status: "Connected".to_owned(),
    }
}

#[test]
fn the_log_is_bounded_and_keeps_the_newest() {
    let mut state = SessionState::default();
    for index in 0..(MAX_LOG_LINES + 50) {
        state.push(line(&format!("event {index}")));
    }
    assert_eq!(state.log.len(), MAX_LOG_LINES);
    // The oldest went, not the newest: the last thing that happened is the
    // one being waited on.
    let last = crate::fullscreen::lines_to_text(&state.log[state.log.len() - 1..], |text, _| {
        text.to_owned()
    });
    assert!(
        last.contains(&format!("event {}", MAX_LOG_LINES + 49)),
        "{last}"
    );
}

#[test]
fn who_the_session_is_with_never_scrolls_away() {
    // The identity block is the context every log line has to be read
    // against. A busy dapp must not be able to push it off the top.
    let mut state = connected();
    for index in 0..200 {
        state.push(line(&format!("personal_sign {index}")));
    }
    let screen = rendered(&state, 60, 20);
    println!("{screen}");
    assert!(screen.contains("app.example.com"), "{screen}");
    assert!(screen.contains("primary"), "{screen}");
    // And the newest events are the ones on screen.
    assert!(screen.contains("personal_sign 199"), "{screen}");
    assert!(!screen.contains("personal_sign 0 "), "{screen}");
}

#[test]
fn the_surface_fits_a_small_terminal() {
    let mut state = connected();
    state.push(line("eth_sendTransaction on eip155:1"));
    for (width, height) in [(80, 24), (60, 20), (40, 14), (30, 10)] {
        let screen = rendered(&state, width, height);
        for row in screen.lines() {
            assert!(
                crate::render::display_width(row) <= width as usize,
                "at {width}x{height} a row overflowed: {row:?}"
            );
        }
        assert!(
            screen.contains('q'),
            "at {width}x{height} the way out was not shown:\n{screen}"
        );
    }
}

#[test]
fn the_footer_says_what_the_session_is_doing_and_how_to_leave() {
    let state = connected();
    let wide = footer_hints(&state, 80);
    assert!(wide.contains("Connected"), "{wide}");
    assert!(wide.contains("Ctrl-C"), "{wide}");

    // Narrow: the status and the way out survive, the prose does not.
    let narrow = footer_hints(&state, 24);
    assert!(narrow.contains('q'), "{narrow}");
    assert!(crate::render::display_width(&narrow) <= 24, "{narrow}");

    // Narrower than any phrasing: still the way out.
    assert_eq!(footer_hints(&state, 3), "q quits");
}

#[test]
fn an_event_is_stamped_so_a_log_read_later_still_has_an_order() {
    let logged = event(Tone::Info, "personal_sign on eip155:1");
    let text = crate::fullscreen::lines_to_text(&[logged], |text, _| text.to_owned());
    assert!(text.contains("personal_sign on eip155:1"), "{text}");
    // HH:MM:SS and two spaces.
    assert!(
        text.chars().take(8).filter(|c| *c == ':').count() == 2,
        "no timestamp: {text}"
    );
}

#[test]
fn a_fact_label_is_padded_so_values_line_up() {
    // A block of facts is scannable only if the values share a column; ragged
    // ones have to be read line by line.
    let text = crate::fullscreen::lines_to_text(
        &[fact("Site", "example.com"), fact("Account", "primary")],
        |text, _| text.to_owned(),
    );
    assert!(text.contains("Site     example.com"), "{text}");
    assert!(text.contains("Account  primary"), "{text}");
}
