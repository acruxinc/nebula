use anyhow::Result;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::cli::NebulaConfig;
use crate::network::{DnsServer, DhcpServer, ReverseProxy};
use crate::utils::{certificates::CertificateManager, ports::PortManager};

pub mod config;
pub mod process;
pub mod server;
pub mod scheduler;

#[derive(Clone)]
pub struct NebulaServer {
    config: Arc<RwLock<NebulaConfig>>,
    cert_manager: Arc<CertificateManager>,
    port_manager: Arc<PortManager>,
    dns_server: Option<Arc<DnsServer>>,
    dhcp_server: Option<Arc<DhcpServer>>,
    reverse_proxy: Option<Arc<ReverseProxy>>,
}

impl NebulaServer {
    pub async fn new(config: NebulaConfig) -> Result<Self> {
        info!("Initializing Nebula server for domain: {}", config.domain);

        let config = Arc::new(RwLock::new(config));
        let cert_manager = Arc::new(CertificateManager::new().await?);
        let port_manager = Arc::new(PortManager::new());

        Ok(Self {
            config,
            cert_manager,
            port_manager,
            dns_server: None,
            dhcp_server: None,
            reverse_proxy: None,
        })
    }

    pub async fn run(&self) -> Result<()> {
        let config = self.config.read().await;
        
        // Resolve ports
        let (http_port, https_port) = self.resolve_ports(&config).await?;
        info!("Using ports - HTTP: {}, HTTPS: {}", http_port, https_port);

        // Generate certificates if needed
        if !config.no_dns {
            self.cert_manager
                .ensure_certificate(&config.domain, config.force_certs)
                .await?;
        }

        // Start DNS server
        let dns_server = if !config.no_dns {
            let dns = Arc::new(DnsServer::new(config.dns.clone()).await?);
            dns.start().await?;
            Some(dns)
        } else {
            None
        };

        // Start DHCP server
        let dhcp_server = if !config.no_dhcp && config.dhcp.enabled {
            let dhcp = Arc::new(DhcpServer::new(config.dhcp.clone()).await?);
            dhcp.start().await?;
            Some(dhcp)
        } else {
            None
        };

        // Start reverse proxy
        let proxy = Arc::new(
            ReverseProxy::new(
                https_port,
                http_port,
                &config.domain,
                self.cert_manager.clone(),
            )
            .await?,
        );
        proxy.start().await?;

        // Start development command
        let dev_process = process::DevProcess::new(&config.dev_command, config.project_dir.clone())?;
        let _dev_handle = dev_process.start().await?;

        info!("🚀 Nebula is ready!");
        info!("   HTTP:  http://{}:{}", config.domain, http_port);
        info!("   HTTPS: https://{}:{}", config.domain, https_port);

        // Wait for shutdown signal
        drop(config); // Release the read lock
        self.wait_for_shutdown(dns_server, dhcp_server, Some(proxy))
            .await
    }

    async fn resolve_ports(&self, config: &NebulaConfig) -> Result<(u16, u16)> {
        let http_port = if config.http_port == 0 {
            self.port_manager.find_free_port().await?
        } else {
            config.http_port
        };

        let https_port = if config.https_port == 0 {
            self.port_manager.find_free_port().await?
        } else {
            config.https_port
        };

        // Validate ports are available
        self.port_manager.validate_port_available(http_port).await?;
        self.port_manager.validate_port_available(https_port).await?;

        Ok((http_port, https_port))
    }

    async fn wait_for_shutdown(
        &self,
        dns_server: Option<Arc<DnsServer>>,
        dhcp_server: Option<Arc<DhcpServer>>,
        reverse_proxy: Option<Arc<ReverseProxy>>,
    ) -> Result<()> {
        // Wait for Ctrl+C
        signal::ctrl_c().await?;
        info!("Shutdown signal received, cleaning up...");

        // Graceful shutdown
        if let Some(proxy) = reverse_proxy {
            if let Err(e) = proxy.stop().await {
                warn!("Error stopping reverse proxy: {}", e);
            }
        }

        if let Some(dns) = dns_server {
            if let Err(e) = dns.stop().await {
                warn!("Error stopping DNS server: {}", e);
            }
        }

        if let Some(dhcp) = dhcp_server {
            if let Err(e) = dhcp.stop().await {
                warn!("Error stopping DHCP server: {}", e);
            }
        }

        info!("✅ Nebula shutdown complete");
        Ok(())
    }
}
