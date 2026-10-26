//! Runman node agent.
//!
//! The agent keeps one long-lived gRPC stream to the platform
//! (`AgentGateway.Connect`, see `proto/agent.proto`) and drives the local
//! services behind the traits in [`backend`]. The wire protocol is shared with
//! the platform and must stay byte-compatible with the Go agent it replaces.

pub mod backend;
pub mod config;
pub mod detect;
pub mod fake;
pub mod local_wg;
#[cfg(target_os = "linux")]
pub mod metrics;
pub mod model;
pub mod platform;
pub mod proto;
#[cfg(target_os = "linux")]
pub mod runtime;
pub mod updater;
pub mod web;
