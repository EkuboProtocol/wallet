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

/// Unicode bidirectional controls: the LRM/RLM marks, the Arabic letter mark,
/// the embedding and override forms plus their terminator, and the isolate
/// forms. They are format characters — `char::is_control` is false for all of
/// them — but they reorder rendered text just as destructively.
#[must_use]
pub const fn is_bidirectional_control(character: char) -> bool {
    matches!(
        character,
        '\u{061c}'
            | '\u{200e}'
            | '\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
    )
}

/// Characters that occupy no width and so cannot be seen in what they change.
///
/// Bidirectional controls reorder text; these hide inside it. A zero-width
/// space splits `USDC` into two runs that still read as `USDC`, so two stored
/// values that a person cannot tell apart compare as different — and the one
/// they are looking at is not the one that was checked. A soft hyphen does the
/// same and is not a control character by any standard predicate. The tag
/// block is worse still: it encodes entire ASCII strings invisibly.
///
/// Excluding the zero-width joiners costs correct rendering of scripts that
/// need them and of emoji sequences. That is a real loss, taken deliberately:
/// these helpers guard identifiers, amounts, and addresses — text where being
/// unable to see a character is the whole attack — not prose.
#[must_use]
pub const fn is_invisible_format(character: char) -> bool {
    matches!(
        character,
        '\u{00ad}'                  // soft hyphen
            | '\u{180e}'            // Mongolian vowel separator
            | '\u{200b}'..='\u{200d}' // zero-width space, non-joiner, joiner
            | '\u{2060}'..='\u{2064}' // word joiner and invisible operators
            | '\u{feff}'            // zero-width no-break space / BOM
            | '\u{e0000}'..='\u{e007f}' // tag characters
    )
}

/// Characters that end a line without being control characters.
///
/// `char::is_control` is a property of the C0 and C1 blocks, and these two are
/// in neither: they are ordinary printable-category punctuation that a great
/// many renderers nonetheless treat as a hard line break. Every other line
/// ending this file cares about — `\n`, `\r`, the C1 NEL — is a control
/// character and was already covered, which is exactly why these two were not.
///
/// [`terminal_safe_line`]'s whole contract is that its result occupies the one
/// line it was given. A stored alias, label, or descriptor carrying `U+2028`
/// could break that line in a transcript or a platform dialog and draw what
/// looks like the wallet's own next line — separating an authentication prompt
/// from the subject it names.
#[must_use]
pub const fn is_line_separator(character: char) -> bool {
    matches!(character, '\u{2028}' | '\u{2029}')
}

/// The set no rendered surface accepts: control characters, Unicode
/// bidirectional controls, zero-width format characters, and the two
/// printable-category line separators.
#[must_use]
pub fn is_disallowed(character: char) -> bool {
    character.is_control()
        || is_bidirectional_control(character)
        || is_invisible_format(character)
        || is_line_separator(character)
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
#[path = "sanitize_test.rs"]
mod tests;
