//! The security kernel of the ekubo-wallet workspace.
//!
//! Everything between untrusted bytes and a signature lives in this crate:
//! plan fetching and digest verification, policy evaluation, simulation,
//! the signing orchestrator and its guard ladders, key custody, owner
//! authentication, review-content generation, and the encrypted stores. The
//! binary crate above supplies only presentation (GPUI and MCP adapters);
//! an audit of what this wallet can sign reads this crate.

#[cfg(all(feature = "test-hooks", not(debug_assertions)))]
compile_error!("the test-hooks feature must never be enabled in a release build");

pub mod abi_decoder;
pub mod agent_authority;
pub mod approval;
pub mod approval_summary;
pub mod automation;
pub mod automation_scheduler;
pub mod automation_store;
pub mod chain_client;
pub mod clear_signing;
pub mod config;
pub mod core;
mod credential_store;
pub mod custody;
pub mod custody_envelope;
pub mod custody_provisioning;
pub mod custody_relay;
pub mod custody_staging;
pub mod database_staging;
pub mod default_tokens;
pub mod desktop_store;
/// Debug-build-only scratch sessions. Never compiled into a release binary.
#[cfg(debug_assertions)]
pub mod ephemeral;
pub mod execution;
pub mod fork;
pub mod fourbyte;
pub mod human_presence;
pub mod input_validation;
pub mod legal;
#[cfg(target_os = "linux")]
pub mod linux_provisioning_client;
#[cfg(target_os = "linux")]
pub mod linux_provisioning_io;
pub mod mcp_companions;
pub mod message;
pub mod migration_transfer;
pub mod networks;
pub mod orchestrator;
pub mod pending;
pub mod plan_fetch;
pub mod policy_store;
#[cfg(target_os = "linux")]
pub mod polkit;
pub mod preview_evidence;
pub mod provisioning_io;
pub mod reconcile;
pub mod rpc;
pub mod sanitize;
mod sealed;
#[cfg(any(target_os = "linux", target_os = "windows", test))]
mod service_custody;
#[cfg(target_os = "linux")]
pub mod service_presence;
#[cfg(target_os = "linux")]
pub mod service_storage;
pub(crate) mod signature_requests;
pub mod signature_review;
pub mod simulation;
pub mod simulation_store;
pub mod sql;
pub mod token_list;
pub mod token_prices;
pub mod token_store;
pub mod typed_data;
pub mod update_trust;
#[cfg(any(target_os = "windows", test))]
pub mod windows_service_config;
#[cfg(any(target_os = "windows", test))]
pub mod windows_service_identity;
#[cfg(any(target_os = "windows", test))]
pub mod windows_service_manager;

#[cfg(any(target_os = "windows", test))]
pub mod windows_owner_pipe;
#[cfg(any(target_os = "windows", test))]
mod windows_security;
#[cfg(target_os = "windows")]
pub mod windows_service_custody;
#[cfg(any(target_os = "windows", test))]
pub mod windows_service_storage;

#[cfg(any(target_os = "linux", target_os = "windows", test))]
mod service_profile_lock;

#[cfg(any(target_os = "windows", test))]
pub mod windows_provisioning_pipe;

#[cfg(target_os = "windows")]
pub mod windows_provisioning_client;
