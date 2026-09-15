//! Core and desktop use one owner stream protocol.
pub use ekubo_wallet_core::owner_stream_protocol::*;

#[cfg(test)]
#[path = "owner_stream_protocol_test.rs"]
mod tests;
