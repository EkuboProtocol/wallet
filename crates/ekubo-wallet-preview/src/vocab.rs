//! The model's vocabulary: a fixed prefix defined here, then the words the
//! corpus taught it.
//!
//! Splitting it in two is deliberate. The prefix -- padding, sequence markers,
//! the structural tags [`crate::slots`] emits, and one entry per slot
//! reference -- has indices that must not move, because the slot reference
//! `<s3>` means "the fourth lifted value" to the rendering code and not merely
//! "whatever id the corpus happened to assign". Regenerating the corpus
//! reshuffles the learned words freely; it can never renumber a slot.
//!
//! The learned half is `model/vocab.txt`, one piece per line, written by the
//! training pipeline and committed beside the weights. Loading it is
//! infallible by construction: a line that duplicates a fixed piece is
//! skipped, so a stale file costs coverage rather than correctness.

use crate::slots::{MAX_SLOTS, SlotKind};
use std::{collections::HashMap, sync::LazyLock};

/// A vocabulary index.
pub type Token = u32;

/// Fixed pieces, in index order. Nothing may be inserted or reordered here:
/// append only, and regenerate the weights when you do.
const FIXED: &[&str] = &[
    "<pad>",
    "<unk>",
    "<bos>",
    "<eos>",
    "<calls>",
    "<call>",
    "<target>",
    "<value>",
    "<field>",
    "<warn>",
    "<opaque>",
    "<n0>",
    "<n1>",
    "<n2>",
    "<n3>",
    "<n4>",
    "<nfew>",
    "<nmany>",
    "<amount>",
    "<token>",
    "<address>",
    "<data>",
    "<number>",
    "<flag>",
];

/// The padding token. Positions holding it are masked out of attention and
/// carry no loss.
pub const PAD: Token = 0;
/// The token every out-of-vocabulary piece maps to.
pub const UNK: Token = 1;
/// Start of sequence.
pub const BOS: Token = 2;
/// End of sequence. Decoding stops here.
pub const EOS: Token = 3;

/// Where the slot references begin. `<s0>` is `SLOT_BASE`, `<s1>` the next,
/// and so on for [`MAX_SLOTS`] entries.
///
/// Written as a literal rather than derived from `FIXED.len()`, because this
/// number is the thing that must not move: the assertion below is what fails
/// the build when someone inserts a fixed piece instead of appending one.
const SLOT_BASE: Token = 24;
const _: () = assert!(
    SLOT_BASE as usize == FIXED.len(),
    "a fixed piece was inserted or removed; slot references would renumber and every committed weight would mean something else"
);

/// Where the learned words begin.
const LEARNED_BASE: Token = 72;
const _: () = assert!(SLOT_BASE as usize + MAX_SLOTS == LEARNED_BASE as usize);

/// The learned half, exactly as committed.
const LEARNED_SOURCE: &str = include_str!("../model/vocab.txt");

struct Vocabulary {
    pieces: Vec<String>,
    by_piece: HashMap<String, Token>,
}

static VOCABULARY: LazyLock<Vocabulary> = LazyLock::new(build);

fn build() -> Vocabulary {
    let mut pieces: Vec<String> = FIXED.iter().map(|piece| (*piece).to_string()).collect();
    pieces.extend((0..MAX_SLOTS).map(|index| format!("<s{index}>")));
    let mut by_piece = HashMap::new();
    let mut next: Token = 0;
    let mut assign = |piece: &str, by_piece: &mut HashMap<String, Token>| {
        by_piece.insert(piece.to_string(), next);
        next += 1;
    };
    for piece in &pieces {
        assign(piece, &mut by_piece);
    }
    // A line that duplicates a fixed piece is skipped rather than shadowing
    // it, so a stale file costs coverage and never correctness.
    for line in LEARNED_SOURCE.lines() {
        let piece = line.trim_end_matches('\r');
        if piece.is_empty() || by_piece.contains_key(piece) {
            continue;
        }
        assign(piece, &mut by_piece);
        pieces.push(piece.to_string());
    }
    Vocabulary { pieces, by_piece }
}

/// How many tokens the embedding table and the output head are sized for.
#[must_use]
pub fn size() -> usize {
    VOCABULARY.pieces.len()
}

/// The token for a piece, or [`UNK`].
#[must_use]
pub fn token_of(piece: &str) -> Token {
    VOCABULARY.by_piece.get(piece).copied().unwrap_or(UNK)
}

/// The piece a token stands for, or `None` for an index this vocabulary does
/// not have -- which is what a weights file trained against a larger
/// vocabulary would produce.
#[must_use]
pub fn text_of(token: Token) -> Option<&'static str> {
    VOCABULARY
        .pieces
        .get(token as usize)
        .map(String::as_str)
        .filter(|piece| !piece.starts_with('<') || piece.starts_with("<s"))
        .filter(|piece| *piece != "<unk>")
}

/// The piece a token stands for, structural tags included.
///
/// [`text_of`] is the renderer's view and hides everything a reader must never
/// see; this is the corpus writer's view, which needs the structural tags
/// because they are most of what the model reads.
#[must_use]
pub fn piece_of(token: Token) -> Option<&'static str> {
    VOCABULARY.pieces.get(token as usize).map(String::as_str)
}

/// The written form of a slot reference.
#[must_use]
pub fn slot_piece(index: usize) -> String {
    format!("<s{index}>")
}

/// The slot a token refers to, or `None` when it refers to none.
#[must_use]
pub fn slot_index(token: Token) -> Option<usize> {
    (SLOT_BASE..LEARNED_BASE)
        .contains(&token)
        .then(|| (token - SLOT_BASE) as usize)
}

/// The token for a slot reference. Indices at or past [`MAX_SLOTS`] have none.
#[must_use]
pub fn slot_token(index: usize) -> Option<Token> {
    if index >= MAX_SLOTS {
        return None;
    }
    Token::try_from(index).ok().map(|index| SLOT_BASE + index)
}

/// The token standing for a slot kind in the model's input.
#[must_use]
pub fn kind_token(kind: SlotKind) -> Token {
    token_of(kind.tag())
}

/// Every learned piece, for the training pipeline to check its corpus against.
pub fn learned_pieces() -> impl Iterator<Item = &'static str> {
    VOCABULARY.pieces[LEARNED_BASE as usize..]
        .iter()
        .map(String::as_str)
}

#[cfg(test)]
#[path = "vocab_test.rs"]
mod tests;
