//! Slotization: the reason a generated summary cannot misstate a value.
//!
//! The model never sees a digit and never emits one. Before tokenization every
//! concrete value in a decoded reading -- amounts, addresses, token labels,
//! raw data, bare integers -- is lifted out into a numbered slot, and the
//! model's input carries only the value's *kind* (`<amount>`, `<address>`, …)
//! followed by its slot reference (`<s0>`, `<s1>`, …). The summary decoder
//! emits the same slot references, and rendering substitutes each one with the
//! slot's verbatim text.
//!
//! So the failure a language model would ordinarily be able to commit here --
//! rendering `transfer 100 USDC` for calldata that moves 1000 -- is not a
//! matter of how well it was trained. There is no path from the weights to a
//! digit: the only thing a forward pass chooses is *which* already-decoded
//! value to name, and every candidate came from the deterministic
//! interpretation the review already displays. A wrong choice is a visibly
//! wrong sentence next to the authoritative field list, not a plausible
//! forgery.
//!
//! [`Slotized::render`] enforces the other half: a slot reference outside the
//! table is dropped rather than printed, so a malformed decode degrades to a
//! shorter sentence and never to `<s7>` shown to a human.

use crate::vocab::{self, Token};

/// A protocol name longer than this is not a protocol name; the reading is
/// something else that happens to contain an em dash.
const MAX_PROTOCOL_CHARS: usize = 40;

/// Values past this many are still shown to the model as a bare kind tag, but
/// cannot be referenced by the summary. Long plans therefore lose the ability
/// to name their last values rather than growing the vocabulary without bound.
pub const MAX_SLOTS: usize = 48;

/// Input tokens past this many are dropped. A plan long enough to reach it is
/// summarized from its beginning, which is where its first and most
/// consequential calls are.
pub const MAX_INPUT_TOKENS: usize = 512;

/// The padded widths a batch of plans may have.
///
/// Every distinct tensor shape makes the GPU backend compile a fresh kernel
/// and reserve fresh buffers for it. Padding to whatever the longest plan in a
/// batch happened to be gives almost every batch its own shape, which on an
/// integrated GPU with a small carve-out is how a run runs out of memory
/// rather than merely how it runs slowly. Training pads to these same widths,
/// so the shapes the model is fitted on are the shapes it later runs on.
pub const WIDTHS: [usize; 5] = [32, 64, 128, 256, 512];

/// The width a plan of this length is padded to.
#[must_use]
pub fn width_for(length: usize) -> usize {
    WIDTHS
        .iter()
        .copied()
        .find(|width| length <= *width)
        .unwrap_or(MAX_INPUT_TOKENS)
}

/// The longest summary the decoder may produce, in tokens, and the width every
/// training summary is padded to.
///
/// One constant for both on purpose. The decoder learns a positional embedding
/// per step, so a step beyond the width the corpus padded to is a position
/// nothing ever trained -- decoding into that range would produce whatever an
/// untouched embedding row happens to encode. The longest summary the label
/// table produces is seventeen tokens, so this fits every one with room over.
pub const MAX_SUMMARY_TOKENS: usize = 20;

/// What kind of value a slot holds. The kind is what the model reasons over;
/// the text is what a reader ends up seeing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SlotKind {
    /// A quantity with a unit: `1000.5 USDC (0xA0b8…)`, or a base-unit
    /// rendering of a token with no known decimals.
    Amount,
    /// A token named by symbol and bound to its address.
    Token,
    /// A 20-byte address, with the owner's own-account annotation if it had
    /// one.
    Address,
    /// Opaque bytes: a hash, a signature, an inner calldata blob.
    Data,
    /// A bare integer with no unit -- a nonce, a fee tier, a tick, a count.
    Number,
    /// A boolean rendered as a word.
    Flag,
    /// The protocol a descriptor declares itself to belong to: "Aave DAO",
    /// "Ekubo Protocol", "1inch Network".
    ///
    /// A slot rather than ordinary words, for three reasons. It is the single
    /// most recognizable thing in a transaction -- somebody who cannot read
    /// calldata still knows whether they meant to be talking to Lido -- so it
    /// has to survive into the summary intact. Lifting it means the model
    /// *points at* the name the descriptor declared instead of generating one,
    /// so it cannot answer "Aave" for a Lido transaction any more than it can
    /// invent an amount. And several real protocol names begin with a digit --
    /// `1inch` -- which the amount scanner would otherwise tear in half, and
    /// which could never be a vocabulary word without breaking the rule that
    /// nothing the decoder can emit begins with a digit.
    Protocol,
}

impl SlotKind {
    /// The vocabulary token that stands for this kind in the model's input.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Amount => "<amount>",
            Self::Token => "<token>",
            Self::Address => "<address>",
            Self::Data => "<data>",
            Self::Number => "<number>",
            Self::Flag => "<flag>",
            Self::Protocol => "<protocol>",
        }
    }
}

/// One lifted value: what it is, and the exact text it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Slot {
    pub kind: SlotKind,
    /// Verbatim, exactly as the deterministic interpretation rendered it.
    /// Nothing rewrites this between lifting and rendering.
    pub text: String,
    /// Which call of the plan this value came from.
    ///
    /// Slot numbering is plan-global, but a summary template is written per
    /// call -- "the first amount" means the first amount *of this step*, not
    /// of everything before it. Without this, a template for the second call
    /// of an approve-then-swap plan would resolve its roles against the
    /// approval's values.
    pub call: usize,
}

/// A decoded reading with its values lifted out.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Slotized {
    /// The model's input token ids.
    pub tokens: Vec<Token>,
    /// The lifted values, indexed by slot number.
    pub slots: Vec<Slot>,
}

/// One call of a plan, as the deterministic interpretation left it.
///
/// This mirrors what `ekubo_wallet_core::approval_summary::StepInterpretation`
/// carries, restated here so the model crate stays a leaf: it depends on no
/// wallet code, and the desktop binary does the one small conversion.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "train", derive(serde::Serialize, serde::Deserialize))]
pub struct CallSummary {
    /// The descriptor or standard-call reading, absent when nothing decoded.
    pub description: Option<String>,
    /// Labeled field lines from a matching ERC-7730 descriptor.
    pub details: Vec<String>,
    /// Warnings the deterministic interpretation attached to the call.
    pub warnings: Vec<String>,
    /// The call's target, already labeled.
    pub target: String,
    /// The call's native value, already rendered with its currency.
    pub native_value: String,
}

/// A whole plan: every call, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "train", derive(serde::Serialize, serde::Deserialize))]
pub struct PlanDocument {
    pub calls: Vec<CallSummary>,
}

impl PlanDocument {
    /// True when nothing in the plan decoded to anything nameable *and*
    /// nothing is being sent.
    ///
    /// The engine answers `Unrecognized` for these without a forward pass:
    /// there is no signal to classify, and spending a dispatch to guess at one
    /// is the confident-noise failure this model must not have.
    ///
    /// Native value is the exception, and it is the case that matters. A call
    /// nobody decoded which is also *sending two and a half ether* is not a
    /// plan with nothing to say about it -- the amount is the whole story, the
    /// slotizer lifts it, and returning no sentence there left the most
    /// alarming transaction in the list as the only one with no words next to
    /// it.
    #[must_use]
    pub fn is_opaque(&self) -> bool {
        self.nothing_decoded()
            && self
                .calls
                .iter()
                .all(|call| is_zero_value(&call.native_value))
    }

    /// True when no call in the plan decoded to anything nameable.
    ///
    /// Separate from [`Self::is_opaque`] because these two facts want
    /// different answers. A plan nobody decoded that also sends nothing has
    /// no signal at all and skips the model entirely. One that sends *value*
    /// still has something worth saying -- the amount -- so the model writes
    /// the sentence, but the class is not up for prediction: nothing decoded
    /// is something we know rather than something to guess at, and letting the
    /// model answer "claim" for an unreadable call that is moving ether is
    /// exactly the confident noise this surface must not produce.
    #[must_use]
    pub fn nothing_decoded(&self) -> bool {
        self.calls
            .iter()
            .all(|call| call.description.is_none() && call.details.is_empty())
    }
}

/// Lift every value out of a plan and tokenize what remains.
#[must_use]
pub fn slotize(document: &PlanDocument) -> Slotized {
    let mut builder = Builder::default();
    builder.push_literal("<bos>");
    let count = document.calls.len();
    builder.push_literal("<calls>");
    builder.push_count(count);
    for (index, call) in document.calls.iter().enumerate() {
        builder.call = index;
        builder.push_literal("<call>");
        match &call.description {
            Some(description) => builder.push_description(description),
            None => builder.push_literal("<opaque>"),
        }
        builder.push_literal("<target>");
        builder.push_text(&call.target);
        if !is_zero_value(&call.native_value) {
            builder.push_literal("<value>");
            builder.push_text(&call.native_value);
        }
        for detail in &call.details {
            builder.push_literal("<field>");
            builder.push_text(detail);
        }
        for warning in &call.warnings {
            builder.push_literal("<warn>");
            builder.push_text(warning);
        }
    }
    builder.push_literal("<eos>");
    builder.finish()
}

/// Whether a rendered native value is zero, without reparsing the number: the
/// renderer writes a leading `0 ` or a bare `0` for nothing, and anything else
/// starts with a nonzero digit.
fn is_zero_value(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty()
        || trimmed == "0"
        || trimmed.split_whitespace().next().is_some_and(|amount| {
            amount
                .chars()
                .all(|character| character == '0' || character == '.')
        })
}

impl Slotized {
    /// The slots one call contributed, in the order they were lifted.
    ///
    /// This is what resolves a template's roles: `{amount1}` is the first
    /// [`SlotKind::Amount`] this call produced.
    pub fn call_slots(&self, call: usize) -> impl Iterator<Item = (usize, &Slot)> {
        self.slots
            .iter()
            .enumerate()
            .filter(move |(_, slot)| slot.call == call)
    }

    /// The plan-global index of the `nth` slot of `kind` within one call,
    /// counting from zero -- the resolution a template role needs.
    #[must_use]
    pub fn role(&self, call: usize, kind: SlotKind, nth: usize) -> Option<usize> {
        self.call_slots(call)
            .filter(|(_, slot)| slot.kind == kind)
            .nth(nth)
            .map(|(index, _)| index)
    }

    /// Render a decoded summary by substituting each slot reference with its
    /// verbatim text.
    ///
    /// A reference to a slot this plan does not have is dropped. That is the
    /// only thing that can go wrong at this boundary, and dropping is the
    /// right answer: the sentence loses a noun, which reads as a defect, where
    /// printing the reference would read as a value.
    #[must_use]
    pub fn render(&self, summary: &[Token]) -> String {
        let mut rendered = String::new();
        for token in summary {
            let Some(piece) = vocab::text_of(*token) else {
                continue;
            };
            let text = match vocab::slot_index(*token) {
                Some(index) => match self.slots.get(index) {
                    Some(slot) => slot.text.as_str(),
                    None => continue,
                },
                None => piece,
            };
            if text.is_empty() {
                continue;
            }
            let joins_left = matches!(text, "," | "." | ";" | ":" | ")" | "%");
            if !rendered.is_empty() && !joins_left && !rendered.ends_with('(') {
                rendered.push(' ');
            }
            rendered.push_str(text);
        }
        rendered
    }
}

/// Accumulates tokens and slots while scanning.
#[derive(Default)]
struct Builder {
    tokens: Vec<Token>,
    slots: Vec<Slot>,
    call: usize,
}

impl Builder {
    fn push_literal(&mut self, piece: &str) {
        if self.tokens.len() < MAX_INPUT_TOKENS {
            self.tokens.push(vocab::token_of(piece));
        }
    }

    /// Small counts are their own tokens; anything larger is just "many".
    /// How many calls a plan has changes how it should read, but only up to a
    /// point, and past it the difference stops being a distinction the
    /// summary draws.
    fn push_count(&mut self, count: usize) {
        let piece = match count {
            0 => "<n0>",
            1 => "<n1>",
            2 => "<n2>",
            3 => "<n3>",
            4 => "<n4>",
            5..=8 => "<nfew>",
            _ => "<nmany>",
        };
        self.push_literal(piece);
    }

    /// Lift a value into a slot and emit its kind tag plus its reference.
    ///
    /// Past [`MAX_SLOTS`] the kind tag is still emitted -- the model should
    /// know an amount was there -- but no reference is, so the decoder has no
    /// way to name it. A value it cannot reference is one it cannot misrender.
    fn push_slot(&mut self, kind: SlotKind, text: String) {
        self.push_literal(kind.tag());
        if self.slots.len() >= MAX_SLOTS {
            return;
        }
        let index = self.slots.len();
        self.slots.push(Slot {
            kind,
            text,
            call: self.call,
        });
        self.push_literal(&vocab::slot_piece(index));
    }

    fn finish(self) -> Slotized {
        Slotized {
            tokens: self.tokens,
            slots: self.slots,
        }
    }

    /// Scan a call's one-line reading, lifting the protocol name first.
    ///
    /// The descriptor engine renders this as `Owner — intent`, so the part
    /// before the em dash is the protocol the registry declares. Lifting it
    /// keeps the name a reviewer recognizes intact and verbatim, rather than
    /// letting it fall through the word scanner that would lowercase
    /// "Aave DAO" and split "1inch" around its leading digit.
    fn push_description(&mut self, text: &str) {
        if let Some((owner, intent)) = text.split_once(" \u{2014} ")
            && !owner.is_empty()
            && owner.chars().count() <= MAX_PROTOCOL_CHARS
        {
            self.push_slot(SlotKind::Protocol, owner.to_owned());
            self.push_text(intent);
            return;
        }
        self.push_text(text);
    }

    /// Scan one line, lifting values and keeping words.
    fn push_text(&mut self, text: &str) {
        let characters: Vec<char> = text.chars().collect();
        let mut at = 0;
        while at < characters.len() {
            if self.tokens.len() >= MAX_INPUT_TOKENS {
                return;
            }
            let character = characters[at];
            if character.is_whitespace() {
                at += 1;
            } else if let Some(next) = self.scan_value(&characters, at) {
                at = next;
            } else if character.is_alphanumeric() || character == '_' {
                at = self.scan_word(&characters, at);
            } else {
                self.push_literal(&character.to_string());
                at += 1;
            }
        }
    }

    /// Try every value shape at this position, longest first.
    fn scan_value(&mut self, characters: &[char], at: usize) -> Option<usize> {
        scan_hex(characters, at)
            .or_else(|| scan_amount(characters, at))
            .or_else(|| scan_token_label(characters, at))
            .or_else(|| scan_flag(characters, at))
            .map(|scanned| {
                self.push_slot(scanned.kind, scanned.text);
                scanned.end
            })
    }

    /// A run of word characters, folded to lowercase so `Approve` and
    /// `approve` are one vocabulary entry.
    fn scan_word(&mut self, characters: &[char], at: usize) -> usize {
        let mut end = at;
        while end < characters.len()
            && (characters[end].is_alphanumeric() || characters[end] == '_')
        {
            end += 1;
        }
        let word: String = characters[at..end].iter().collect();
        self.push_literal(&word.to_lowercase());
        end
    }
}

/// One matched value and where it ended.
struct Scanned {
    kind: SlotKind,
    text: String,
    end: usize,
}

impl Scanned {
    fn new(kind: SlotKind, characters: &[char], at: usize, end: usize) -> Self {
        Self {
            kind,
            text: characters[at..end].iter().collect(),
            end,
        }
    }
}

fn is_hex_digit(character: char) -> bool {
    character.is_ascii_hexdigit()
}

/// How many characters a token symbol may have before the thing in front of an
/// address stops looking like a symbol. `display_symbol` upstream is stricter
/// still; this only has to avoid swallowing a sentence.
const MAX_SYMBOL_CHARS: usize = 12;

/// Consume a run of characters satisfying `accept`, answering where it ended.
fn run(characters: &[char], at: usize, accept: impl Fn(char) -> bool) -> usize {
    let mut end = at;
    while end < characters.len() && accept(characters[end]) {
        end += 1;
    }
    end
}

/// Match a literal at a position, answering where it ended.
fn literal(characters: &[char], at: usize, expected: &str) -> Option<usize> {
    let mut end = at;
    for wanted in expected.chars() {
        if characters.get(end).copied()? != wanted {
            return None;
        }
        end += 1;
    }
    Some(end)
}

/// `0x` followed by hex digits: exactly forty of them is an address, any other
/// nonzero count is opaque data.
///
/// An address absorbs a trailing ` (your account …)`, because that annotation
/// is *about* this address. Splitting the two would let a summary name the
/// address without the fact that it is the owner's own -- which is precisely
/// the distinction the annotation exists to draw.
fn scan_hex(characters: &[char], at: usize) -> Option<Scanned> {
    let body = literal(characters, at, "0x")?;
    let hex_end = run(characters, body, is_hex_digit);
    if hex_end == body {
        return None;
    }
    if hex_end - body != 40 {
        return Some(Scanned::new(SlotKind::Data, characters, at, hex_end));
    }
    let end = literal(characters, hex_end, " (your account ")
        .map(|open| run(characters, open, |character| character != ')'))
        .and_then(|close| literal(characters, close, ")"))
        .unwrap_or(hex_end);
    Some(Scanned::new(SlotKind::Address, characters, at, end))
}

/// A token symbol bound to its address: `USDC (0xA0b8…)`.
///
/// The bound form is the only one lifted as a token. A bare symbol with no
/// address beside it is left as an ordinary word, because that is all the
/// upstream renderer promises it is.
fn scan_token_label(characters: &[char], at: usize) -> Option<Scanned> {
    let end = scan_bound_symbol(characters, at)?;
    Some(Scanned::new(SlotKind::Token, characters, at, end))
}

/// The shared `SYMBOL (0x…)` shape, answering where it ended.
fn scan_bound_symbol(characters: &[char], at: usize) -> Option<usize> {
    if !characters.get(at)?.is_alphabetic() {
        return None;
    }
    let symbol_end = run(characters, at, |character| {
        character.is_alphanumeric() || character == '.' || character == '-'
    });
    if symbol_end - at > MAX_SYMBOL_CHARS {
        return None;
    }
    let open = literal(characters, symbol_end, " (0x")?;
    let hex_end = run(characters, open, is_hex_digit);
    if hex_end - open != 40 {
        return None;
    }
    literal(characters, hex_end, ")")
}

/// A quantity. Digits, optionally fractional, optionally carrying a unit.
///
/// A number with no unit is a [`SlotKind::Number`] -- a tick, a fee tier, a
/// deadline -- unless it is fractional, which nothing but a quantity is.
fn scan_amount(characters: &[char], at: usize) -> Option<Scanned> {
    if !characters.get(at)?.is_ascii_digit() {
        return None;
    }
    let whole_end = run(characters, at, |character| character.is_ascii_digit());
    let (number_end, fractional) = match literal(characters, whole_end, ".")
        .map(|point| run(characters, point, |character| character.is_ascii_digit()))
        .filter(|fraction_end| *fraction_end > whole_end + 1)
    {
        Some(fraction_end) => (fraction_end, true),
        None => (whole_end, false),
    };
    if let Some(end) = scan_unit(characters, number_end) {
        return Some(Scanned::new(SlotKind::Amount, characters, at, end));
    }
    let kind = if fractional {
        SlotKind::Amount
    } else {
        SlotKind::Number
    };
    Some(Scanned::new(kind, characters, at, number_end))
}

/// The unit trailing a number, if it has one: a bound token label, a bare
/// all-uppercase ticker, or the `base units of …` rendering used when a
/// token's decimals are unknown.
fn scan_unit(characters: &[char], at: usize) -> Option<usize> {
    if let Some(open) = literal(characters, at, " base units of ") {
        return Some(
            scan_bound_symbol(characters, open)
                .or_else(|| scan_hex(characters, open).map(|scanned| scanned.end))
                .unwrap_or_else(|| run(characters, open, |character| !character.is_whitespace())),
        );
    }
    let open = literal(characters, at, " ")?;
    if let Some(end) = scan_bound_symbol(characters, open) {
        return Some(end);
    }
    // A bare ticker only. Requiring uppercase is what keeps `1 more call`
    // from being lifted as a quantity of `more`.
    let end = run(characters, open, |character| {
        character.is_ascii_uppercase() || character.is_ascii_digit()
    });
    let length = end - open;
    (2..=MAX_SYMBOL_CHARS).contains(&length).then_some(end)
}

/// A boolean rendered as a word by a descriptor field.
fn scan_flag(characters: &[char], at: usize) -> Option<Scanned> {
    for word in ["true", "false"] {
        if let Some(end) = literal(characters, at, word)
            && !characters
                .get(end)
                .is_some_and(|next| next.is_alphanumeric() || *next == '_')
        {
            return Some(Scanned::new(SlotKind::Flag, characters, at, end));
        }
    }
    None
}

#[cfg(test)]
#[path = "slots_test.rs"]
mod tests;
