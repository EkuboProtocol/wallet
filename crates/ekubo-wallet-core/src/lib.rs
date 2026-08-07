//! The security kernel of the ekubo-wallet workspace.
//!
//! Everything between untrusted bytes and a signature lives in this crate:
//! plan fetching and digest verification, policy evaluation, simulation,
//! the signing orchestrator and its guard ladders, key custody, owner
//! authentication, review-content generation, and the encrypted stores. The
//! binary crate above supplies only presentation (CLI, TUI, MCP adapters);
//! an audit of what this wallet can sign reads this crate.

#[cfg(all(feature = "test-hooks", not(debug_assertions)))]
compile_error!("the test-hooks feature must never be enabled in a release build");

pub mod abi_decoder;
pub mod address_book;
pub mod approval;
pub mod approval_summary;
pub mod clear_signing;
pub mod config;
pub mod core;
pub mod custody;
pub mod execution;
pub mod fork;
pub mod human_presence;
pub mod input_validation;
pub mod legal;
pub mod message;
pub mod orchestrator;
pub mod pending;
pub mod plan_fetch;
pub mod policy_context;
pub mod policy_store;
pub mod reconcile;
pub mod rpc;
pub mod sanitize;
pub(crate) mod signature_requests;
pub mod simulation;
pub mod simulation_store;
pub mod token_list;
pub mod token_store;
pub mod typed_data;
