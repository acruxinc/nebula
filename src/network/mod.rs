pub mod dns;
pub mod dhcp;
pub mod proxy;
pub mod tls;

pub use dns::DnsServer;
pub use dhcp::DhcpServer;
pub use proxy::ReverseProxy;
pub use tls::TlsManager;

use crate::error::{NebulaError, Result as NebulaResult};
use std::net::{IpAddr, SocketAddr};
use tracing::{debug, warn};

/// Network utilities and helpers
pub struct NetworkUtils;

impl NetworkUtils {
    /// Check if a port is available on all interfaces
    pub async fn is_port_available(port: u16) -> bool {
        Self::is_port_available_on("0.0.0.0", port).await &&
        Self::is_port_available_on("::1", port).await
    }

    /// Check if a port is available on a specific interface
    pub async fn is_port_available_on(addr: &str, port: u16) -> bool {
        match format!("{}:{}", addr, port).parse::<SocketAddr>() {
            Ok(socket_addr) => {
                match tokio::net::TcpListener::bind(socket_addr).await {
                    Ok(_) => true,
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }

    /// Get the local IP address
    pub fn get_local_ip() -> NebulaResult<IpAddr> {
        local_ip_address::local_ip()
            .map_err(|e| NebulaError::network(format!("Failed to get local IP: {}", e)))
    }

    /// Validate IP address string
    pub fn validate_ip_address(ip: &str) -> NebulaResult<IpAddr> {
        ip.parse()
            .map_err(|_| NebulaError::invalid_domain(format!("Invalid IP address: {}", ip)))
    }

    /// Validate domain name
    pub fn validate_domain_name(domain: &str) -> NebulaResult<()> {
        if domain.is_empty() {
            return Err(NebulaError::invalid_domain("Domain cannot be empty"));
        }

        if domain.len() > 253 {
            return Err(NebulaError::invalid_domain("Domain name too long"));
        }

        // Basic domain validation
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 {
            return Err(NebulaError::invalid_domain("Domain must have at least one dot"));
        }

        for part in parts {
            if part.is_empty() {
                return Err(NebulaError::invalid_domain("Domain part cannot be empty"));
            }
            if part.len() > 63 {
                return Err(NebulaError::invalid_domain("Domain part too long"));
            }
            if !part.chars().all(|c| c.is_alphanumeric() || c == '-') {
                return Err(NebulaError::invalid_domain("Domain contains invalid characters"));
            }
            if part.starts_with('-') || part.ends_with('-') {
                return Err(NebulaError::invalid_domain("Domain part cannot start or end with hyphen"));
            }
        }

        Ok(())
    }

    /// Check if domain is a development domain
    pub fn is_dev_domain(domain: &str) -> bool {
        domain.ends_with(".dev") || 
        domain.ends_with(".nebula.com") || 
        domain.ends_with(".localhost") ||
        domain == "localhost"
    }

    /// Normalize domain name (convert to lowercase, remove trailing dot)
    pub fn normalize_domain(domain: &str) -> String {
        domain.to_lowercase().trim_end_matches('.').to_string()
    }
}
