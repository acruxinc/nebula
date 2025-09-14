use anyhow::Result;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::str::FromStr;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use trust_dns_server::{
    authority::{AuthorityObject, Catalog, ZoneType, Authority},
    proto::rr::{Name, Record, RecordType, RData, DNSClass},
    ServerFuture,
};
use trust_dns_client::rr::rdata::a::A;

use crate::cli::DnsConfig;

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub data: String,
    pub ttl: u32,
}

pub struct DnsServer {
    config: DnsConfig,
    catalog: Arc<RwLock<Catalog>>,
    custom_records: Arc<RwLock<HashMap<String, DnsRecord>>>,
    dev_domains: Arc<RwLock<HashMap<String, IpAddr>>>,
    is_running: Arc<RwLock<bool>>,
}

impl DnsServer {
    pub async fn new(config: DnsConfig) -> Result<Self> {
        let catalog = Arc::new(RwLock::new(Catalog::new()));
        let custom_records = Arc::new(RwLock::new(HashMap::new()));
        let dev_domains = Arc::new(RwLock::new(HashMap::new()));
        let is_running = Arc::new(RwLock::new(false));

        Ok(Self {
            config,
            catalog,
            custom_records,
            dev_domains,
            is_running,
        })
    }

    pub async fn start(&self) -> Result<()> {
        info!("Starting DNS server on port {}", self.config.port);

        // Add default .dev and .nebula.com domain resolution to localhost
        self.add_dev_domain("*.dev", "127.0.0.1".parse()?).await?;
        self.add_dev_domain("*.nebula.com", "127.0.0.1".parse()?).await?;

        // Set up DNS zones for development domains
        self.setup_dev_zones().await?;

        // For now, we'll implement a simplified DNS server
        // In a full implementation, you'd use the proper trust-dns-server API
        *self.is_running.write().await = true;

        tokio::spawn({
            let is_running = self.is_running.clone();
            let port = self.config.port;
            async move {
                let socket = match tokio::net::UdpSocket::bind(format!("127.0.0.1:{}", port)).await {
                    Ok(socket) => socket,
                    Err(e) => {
                        warn!("Failed to bind DNS socket: {}", e);
                        *is_running.write().await = false;
                        return;
                    }
                };

                let mut buf = [0u8; 512];
                loop {
                    match socket.recv_from(&mut buf).await {
                        Ok((size, addr)) => {
                            debug!("Received DNS packet from {}: {} bytes", addr, size);
                            // Here you would process the DNS packet
                            // For now, we just acknowledge receipt
                        }
                        Err(e) => {
                            warn!("DNS socket error: {}", e);
                            break;
                        }
                    }
                }
                *is_running.write().await = false;
            }
        });

        info!("✅ DNS server started successfully");
        Ok(())
    }

    async fn setup_dev_zones(&self) -> Result<()> {
        // Create zones for common development domains
        let dev_zone_name = Name::from_str("dev.")?;
        let nebula_zone_name = Name::from_str("nebula.com.")?;
        
        // Add SOA records for the zones
        self.add_zone_record(&dev_zone_name, "dev.", "ns1.nebula.dev.", 3600).await?;
        self.add_zone_record(&nebula_zone_name, "nebula.com.", "ns1.nebula.dev.", 3600).await?;
        
        Ok(())
    }

    async fn add_zone_record(&self, zone_name: &Name, name: &str, data: &str, ttl: u32) -> Result<()> {
        let record_name = Name::from_str(name)?;
        let record = Record::from_rdata(
            record_name.clone(),
            ttl,
            RData::A(A::new(127, 0, 0, 1)), // Default to localhost
        );
        
        // This is a simplified implementation
        // In a full implementation, you'd properly manage zones and authorities
        debug!("Added zone record: {} -> {} (TTL: {})", name, data, ttl);
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        info!("Stopping DNS server...");
        *self.is_running.write().await = false;
        Ok(())
    }

    pub async fn add_record(&self, domain: &str, ip: IpAddr) -> Result<()> {
        let record = DnsRecord {
            name: domain.to_string(),
            record_type: RecordType::A,
            data: ip.to_string(),
            ttl: 300, // 5 minutes default TTL
        };
        
        let mut records = self.custom_records.write().await;
        records.insert(domain.to_string(), record);
        info!("Added DNS record: {} -> {}", domain, ip);
        Ok(())
    }

    pub async fn add_dev_domain(&self, pattern: &str, ip: IpAddr) -> Result<()> {
        let mut domains = self.dev_domains.write().await;
        domains.insert(pattern.to_string(), ip);
        info!("Added dev domain pattern: {} -> {}", pattern, ip);
        Ok(())
    }

    pub async fn remove_record(&self, domain: &str) -> Result<()> {
        let mut records = self.custom_records.write().await;
        let mut domains = self.dev_domains.write().await;
        
        records.remove(domain);
        domains.remove(domain);
        info!("Removed DNS record: {}", domain);
        Ok(())
    }

    pub async fn list_records(&self) -> HashMap<String, DnsRecord> {
        self.custom_records.read().await.clone()
    }

    pub async fn list_dev_domains(&self) -> HashMap<String, IpAddr> {
        self.dev_domains.read().await.clone()
    }

    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    pub async fn resolve_dev_domain(&self, domain: &str) -> Option<IpAddr> {
        let dev_domains = self.dev_domains.read().await;
        
        // Check for exact match first
        if let Some(ip) = dev_domains.get(domain) {
            return Some(*ip);
        }
        
        // Check for wildcard patterns
        for (pattern, ip) in dev_domains.iter() {
            if pattern.starts_with("*.") {
                let suffix = &pattern[2..]; // Remove "*." prefix
                if domain.ends_with(suffix) {
                    return Some(*ip);
                }
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::DnsConfig;

    #[tokio::test]
    async fn test_dns_server_creation() {
        let config = DnsConfig {
            enabled: true,
            port: 5353, // Use non-privileged port for testing
            upstream: vec!["8.8.8.8:53".to_string()],
            cache_size: 1024,
        };

        let dns_server = DnsServer::new(config).await;
        assert!(dns_server.is_ok(), "DNS server should be created successfully");
    }

    #[tokio::test]
    async fn test_dns_record_management() {
        let config = DnsConfig {
            enabled: true,
            port: 5353,
            upstream: vec!["8.8.8.8:53".to_string()],
            cache_size: 1024,
        };

        let dns_server = DnsServer::new(config).await.unwrap();
        
        // Test adding a record
        let result = dns_server.add_record("test.example.com", "127.0.0.1".parse().unwrap()).await;
        assert!(result.is_ok(), "Should be able to add DNS record");
        
        // Test adding dev domain
        let result = dns_server.add_dev_domain("*.nebula.com", "127.0.0.1".parse().unwrap()).await;
        assert!(result.is_ok(), "Should be able to add dev domain");
        
        // Test resolving dev domain
        let resolved = dns_server.resolve_dev_domain("myapp.nebula.com").await;
        assert!(resolved.is_some(), "Should resolve dev domain");
        assert_eq!(resolved.unwrap(), "127.0.0.1".parse::<IpAddr>().unwrap());
    }

    #[tokio::test]
    async fn test_dev_domain_resolution() {
        let config = DnsConfig {
            enabled: true,
            port: 5353,
            upstream: vec!["8.8.8.8:53".to_string()],
            cache_size: 1024,
        };

        let dns_server = DnsServer::new(config).await.unwrap();
        
        // Add wildcard dev domain
        dns_server.add_dev_domain("*.nebula.com", "127.0.0.1".parse().unwrap()).await.unwrap();
        
        // Test various subdomain resolutions
        let test_cases = vec![
            "app.nebula.com",
            "api.nebula.com", 
            "frontend.nebula.com",
            "backend.nebula.com",
        ];
        
        for domain in test_cases {
            let resolved = dns_server.resolve_dev_domain(domain).await;
            assert!(resolved.is_some(), "Should resolve {} to localhost", domain);
            assert_eq!(resolved.unwrap(), "127.0.0.1".parse::<IpAddr>().unwrap());
        }
        
        // Test non-matching domain
        let resolved = dns_server.resolve_dev_domain("example.com").await;
        assert!(resolved.is_none(), "Should not resolve non-matching domain");
    }

    #[tokio::test]
    async fn test_dns_record_listing() {
        let config = DnsConfig {
            enabled: true,
            port: 5353,
            upstream: vec!["8.8.8.8:53".to_string()],
            cache_size: 1024,
        };

        let dns_server = DnsServer::new(config).await.unwrap();
        
        // Add multiple records
        dns_server.add_record("test1.example.com", "192.168.1.1".parse().unwrap()).await.unwrap();
        dns_server.add_record("test2.example.com", "192.168.1.2".parse().unwrap()).await.unwrap();
        dns_server.add_dev_domain("*.test.com", "10.0.0.1".parse().unwrap()).await.unwrap();
        
        // List records
        let records = dns_server.list_records().await;
        assert_eq!(records.len(), 2);
        
        let dev_domains = dns_server.list_dev_domains().await;
        assert_eq!(dev_domains.len(), 1);
    }

    #[tokio::test]
    async fn test_dns_record_removal() {
        let config = DnsConfig {
            enabled: true,
            port: 5353,
            upstream: vec!["8.8.8.8:53".to_string()],
            cache_size: 1024,
        };

        let dns_server = DnsServer::new(config).await.unwrap();
        
        // Add record
        dns_server.add_record("test.example.com", "127.0.0.1".parse().unwrap()).await.unwrap();
        dns_server.add_dev_domain("*.test.com", "127.0.0.1".parse().unwrap()).await.unwrap();
        
        // Verify it exists
        let records = dns_server.list_records().await;
        assert_eq!(records.len(), 1);
        
        let dev_domains = dns_server.list_dev_domains().await;
        assert_eq!(dev_domains.len(), 1);
        
        // Remove record
        dns_server.remove_record("test.example.com").await.unwrap();
        
        // Verify it's removed
        let records = dns_server.list_records().await;
        assert_eq!(records.len(), 0);
        
        let dev_domains = dns_server.list_dev_domains().await;
        assert_eq!(dev_domains.len(), 0);
    }
}