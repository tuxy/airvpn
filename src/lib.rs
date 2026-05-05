//! AirVPN Rust library client.
//!
//! This library provides an ergonomic builder-pattern API for authenticating with
//! AirVPN, fetching WireGuard configurations, and querying the public status API.
//!
//! # Quick start
//!
//! ```no_run
//! use airvpn::AirVPN;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let config = AirVPN::builder()
//!     .credentials("user", "pass")
//!     .server("Algorab")
//!     .build()
//!     .await?;
//!
//! println!("{}", config.to_conf());
//!
//! let status = AirVPN::fetch_status().await?;
//! for server in &status.servers {
//!     println!("{}: {:?}", server.public_name, server.health);
//! }
//! # Ok(())
//! # }
//! ```

pub mod client;
pub mod constants;
pub mod errors;
pub mod protocol;
pub mod status;
pub mod wireguard;

pub use client::{AirVPN, AirVPNBuilder};
pub use constants::{
    DEFAULT_BOOTSTRAP_URLS, DEFAULT_RSA_EXPONENT, DEFAULT_RSA_MODULUS, DEFAULT_WIREGUARD_PORT,
    DOCUMENT_VERSION,
};
pub use errors::Error;
pub use protocol::EncryptedRequest;
pub use status::*;
pub use wireguard::{ServerInfo, WireGuardConfig};