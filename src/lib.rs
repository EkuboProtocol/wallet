pub mod cli;
pub mod config;
pub mod core;
pub mod custody;
pub mod human_presence;
pub mod mcp;
pub mod pending;
pub mod policy_store;
pub mod rpc;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
