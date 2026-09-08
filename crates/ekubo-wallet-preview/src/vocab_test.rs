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
    ];
    let mut tokens: Vec<Token> = kinds.iter().map(|kind| kind_token(*kind)).collect();
    tokens.sort_unstable();
    tokens.dedup();
    assert_eq!(tokens.len(), kinds.len());
    assert!(!tokens.contains(&UNK));
}
