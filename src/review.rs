use crate::approval::{ReviewDecision, ReviewDocument};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_REVIEW_GENERATION: AtomicU64 = AtomicU64::new(1);

fn next_review_generation() -> u64 {
    NEXT_REVIEW_GENERATION
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .expect("review generation space exhausted")
}

/// Security-relevant state for one focused native review.
///
/// Every input event carries the generation it was rendered from. Refreshing
/// increments that generation, so a delayed click from the old document can
/// never approve its replacement.
#[derive(Clone, Debug)]
pub struct ReviewState {
    document: ReviewDocument,
    generation: u64,
    selected: ReviewDecision,
    viewed_to_end: bool,
    scroll_offset: f32,
}

impl ReviewState {
    #[must_use]
    pub fn new(document: ReviewDocument) -> Self {
        Self {
            document,
            generation: next_review_generation(),
            selected: ReviewDecision::Reject,
            viewed_to_end: false,
            scroll_offset: 0.0,
        }
    }

    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    #[must_use]
    pub const fn selected(&self) -> ReviewDecision {
        self.selected
    }

    #[must_use]
    pub const fn approve_enabled(&self) -> bool {
        self.viewed_to_end
    }

    #[must_use]
    pub const fn scroll_offset(&self) -> f32 {
        self.scroll_offset
    }

    #[must_use]
    pub const fn document(&self) -> &ReviewDocument {
        &self.document
    }

    pub fn mark_viewed_to_end(&mut self, generation: u64) -> bool {
        if generation != self.generation {
            return false;
        }
        self.viewed_to_end = true;
        true
    }

    pub fn set_scroll_offset(&mut self, generation: u64, offset: f32) -> bool {
        if generation != self.generation {
            return false;
        }
        self.scroll_offset = offset.max(0.0);
        true
    }

    pub fn select(&mut self, generation: u64, decision: ReviewDecision) -> bool {
        if generation != self.generation
            || (decision == ReviewDecision::Approve && !self.viewed_to_end)
        {
            return false;
        }
        self.selected = decision;
        true
    }

    pub fn refresh(&mut self, document: ReviewDocument) {
        let identity_changed = self.document.identity != document.identity;
        self.document = document;
        self.generation = next_review_generation();
        self.selected = ReviewDecision::Reject;
        self.viewed_to_end = false;
        if identity_changed {
            self.scroll_offset = 0.0;
        }
    }
}

#[cfg(test)]
#[path = "review_test.rs"]
mod tests;
