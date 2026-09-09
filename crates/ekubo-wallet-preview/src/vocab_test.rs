use super::*;

#[test]
fn the_fixed_prefix_keeps_its_indices() {
    assert_eq!(token_of("<pad>"), PAD);
    assert_eq!(token_of("<unk>"), UNK);
    assert_eq!(token_of("<bos>"), BOS);
    assert_eq!(token_of("<eos>"), EOS);
}

#[test]
fn every_slot_reference_round_trips() {
    for index in 0..MAX_SLOTS {
        let token = slot_token(index).expect("slot below the cap has a token");
        assert_eq!(token_of(&slot_piece(index)), token);
        assert_eq!(slot_index(token), Some(index));
    }
    assert_eq!(slot_token(MAX_SLOTS), None);
}

/// Slot references are the one part of the vocabulary whose numbering carries
/// meaning to code outside the model, so nothing structural may sit inside
/// their range.
#[test]
fn nothing_but_a_slot_reference_reads_as_a_slot() {
    for piece in FIXED {
        assert_eq!(slot_index(token_of(piece)), None, "{piece}");
    }
    for piece in learned_pieces() {
        assert_eq!(slot_index(token_of(piece)), None, "{piece}");
    }
}

#[test]
fn an_unknown_piece_is_unk_and_renders_as_nothing() {
    assert_eq!(token_of("\u{1f4a5} not a piece"), UNK);
    assert_eq!(text_of(UNK), None);
}

/// Structural tags are input-side only. If the decoder ever emitted one,
/// printing it would show a reader `<warn>`.
#[test]
fn structural_tags_never_render() {
    for piece in FIXED {
        if *piece == "<unk>" {
            continue;
        }
        assert_eq!(text_of(token_of(piece)), None, "{piece} rendered");
    }
}

#[test]
fn a_token_past_the_vocabulary_renders_as_nothing() {
    assert_eq!(
        text_of(Token::try_from(size()).expect("the vocabulary fits a token")),
        None
    );
    assert_eq!(text_of(Token::MAX), None);
}

#[test]
fn every_slot_kind_has_a_distinct_tag_in_the_vocabulary() {
    let kinds = [
        SlotKind::Amount,
        SlotKind::Token,
        SlotKind::Address,
        SlotKind::Data,
        SlotKind::Number,
        SlotKind::Flag,
        SlotKind::Protocol,
        SlotKind::Action,
    ];
    let mut tokens: Vec<Token> = kinds.iter().map(|kind| kind_token(*kind)).collect();
    tokens.sort_unstable();
    tokens.dedup();
    assert_eq!(tokens.len(), kinds.len());
    assert!(!tokens.contains(&UNK));
}

/// The property the whole design rests on, asserted over the committed file
/// rather than trusted to the generator that wrote it.
///
/// The Rust tokenizer lifts anything beginning with a digit into a slot, so it
/// can never *teach* the model a digit-leading word. A vocabulary entry the
/// tokenizer could not have produced is one the decoder can emit but nothing
/// trained it to place -- and for a value, that is precisely the fabrication
/// slotization exists to make impossible. A regenerated `vocab.txt` that
/// harvests words from slot texts instead of tokenized pieces fails here.
#[test]
fn no_learned_piece_can_stand_for_a_value() {
    for piece in learned_pieces() {
        let first = piece.chars().next().expect("no empty piece is loaded");
        assert!(
            !first.is_ascii_digit(),
            "{piece:?} begins with a digit, so the decoder could emit it as a value"
        );
        assert!(
            !piece.contains("0x"),
            "{piece:?} looks like an address or a data blob"
        );
        let hexish = piece.len() >= 8 && piece.chars().all(|c| c.is_ascii_hexdigit());
        assert!(!hexish, "{piece:?} is a bare run of hex digits");
    }
}

/// Every learned piece is either punctuation the renderer knows how to place,
/// or a word the scanner would fold to this exact form.
#[test]
fn every_learned_piece_is_one_the_scanner_could_have_emitted() {
    for piece in learned_pieces() {
        if piece.chars().all(|c| !c.is_alphanumeric()) {
            assert_eq!(
                piece.chars().count(),
                1,
                "{piece:?} is multi-character punctuation"
            );
            continue;
        }
        assert_eq!(
            piece,
            piece.to_lowercase(),
            "{piece:?} is not folded to lowercase, so the scanner would never match it"
        );
        assert!(
            piece.chars().all(|c| c.is_alphanumeric() || c == '_'),
            "{piece:?} contains a character the word scanner stops at"
        );
    }
}
