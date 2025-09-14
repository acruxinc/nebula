//! Nebula Universal Development and Production Server
//! 
//! A cross-platform development server that supports any programming language
//! and framework with built-in DNS, DHCP, TLS, and deployment management.

pub mod cli;
pub mod core;
pub mod network;
pub mod platform;
pub mod utils;
pub mod error;

pub use core::NebulaServer;
pub use error::{NebulaError, Result};

/// Re-export commonly used types
pub mod prelude {
    pub use crate::error::{NebulaError, Result};
    pub use crate::cli::{Cli, NebulaConfig};
    pub use crate::core::NebulaServer;
    pub use crate::utils::{CertificateManager, LanguageDetector, ProjectInfo};
}
