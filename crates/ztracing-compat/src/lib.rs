//! Permissively licensed tracing facade for the Apache-2.0 GPUI crates.
//!
//! The wallet does not enable Zed's profiler integration. GPUI and `sum_tree`
//! only require the ordinary `tracing` types, span macros, and `instrument`
//! attribute, so this crate exposes those APIs directly without pulling in
//! Zed's GPL-licensed logging stack.

pub use tracing::{
    Level, Span, debug_span, error_span, event, field, info_span, instrument, span, trace_span,
    warn_span,
};

/// Compatibility entry point for applications that initialize the optional
/// Zed profiler. The wallet uses its own `tracing-subscriber`, so no global
/// subscriber is installed here.
pub const fn init() {}
