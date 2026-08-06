//! One implementation of text safety for everything the wallet shows a human.
//!
//! Anything the wallet did not author — token symbols, message bodies,
//! descriptor text, aliases, RPC error strings — can carry terminal control
//! sequences or Unicode bidirectional controls. Control characters can redraw
//! or fake wallet chrome; bidirectional controls visually reorder rendered
//! text, letting stored data swap the apparent direction of an amount or an
//! address. Every module that puts untrusted text in front of the owner
//! routes through these helpers, so the disallowed set cannot drift between
//! surfaces.

/// Unicode bidirectional controls: the LRM/RLM marks, the embedding and
/// override forms plus their terminator, and the isolate forms. They are
/// format characters — `char::is_control` is false for all of them — but
/// they reorder rendered text just as destructively.
#[must_use]
pub const fn is_bidirectional_control(character: char) -> bool {
    matches!(
        character,
        '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'
    )
}

/// The set no rendered surface accepts: control characters and Unicode
/// bidirectional controls.
#[must_use]
pub fn is_disallowed(character: char) -> bool {
    character.is_control() || is_bidirectional_control(character)
}

/// Every disallowed character, newlines included, becomes a space.
///
/// For a value that has to stay on the one line it was given: a label, a
/// fact, an alias. A newline here would let stored text draw what looks like
/// an additional line of the wallet's own chrome.
#[must_use]
pub fn terminal_safe_line(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if is_disallowed(character) {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// Newlines survive; every other disallowed character becomes a space.
#[must_use]
pub fn terminal_safe_multiline(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character != '\n' && is_disallowed(character) {
                ' '
            } else {
                character
            }
        })
        .collect()
}

/// Disallowed characters are removed outright and the result is capped, for
/// stored fields like token symbols and descriptor text where even a
/// placeholder space would be attacker-steered padding.
#[must_use]
pub fn stripped_capped(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|character| !is_disallowed(*character))
        .take(max_chars)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_and_bidirectional_characters_never_survive() {
        // An ANSI escape cannot start a sequence, and a right-to-left
        // override cannot reorder what the reviewer reads.
        assert_eq!(terminal_safe_line("a\u{1b}[31mb"), "a [31mb");
        assert_eq!(terminal_safe_line("pay \u{202e}000 1"), "pay  000 1");
        assert_eq!(terminal_safe_line("x\u{2066}y\u{2069}z"), "x y z");
        assert_eq!(terminal_safe_multiline("a\u{202e}b\nc"), "a b\nc");
        assert_eq!(stripped_capped("E\u{202e}TH\u{7f}", 8), "ETH");
    }

    #[test]
    fn caps_count_characters_not_bytes() {
        assert_eq!(stripped_capped("éééé", 2), "éé");
    }
}
