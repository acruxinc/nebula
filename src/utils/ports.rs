use anyhow::Result;
use std::net::{TcpListener, TcpStream, SocketAddr};
use std::time::Duration;
use tokio::time::timeout;
use tracing::debug;

pub struct PortManager;

impl PortManager {
    pub fn new() -> Self {
        Self
    }

    pub async fn find_free_port(&self) -> Result<u16> {
        self.find_free_port_in_range(1024, 65535).await
    }

    pub async fn find_free_port_in_range(&self, start: u16, end: u16) -> Result<u16> {
        for port in start..=end {
            if self.is_port_available(port).await {
                debug!("Found free port: {}", port);
                return Ok(port);
            }
        }
        
        Err(anyhow::anyhow!("No free ports available in range {}-{}", start, end))
    }

    pub async fn is_port_available(&self, port: u16) -> bool {
        match TcpListener::bind(format!("127.0.0.1:{}", port)) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    pub async fn validate_port_available(&self, port: u16) -> Result<()> {
        if !self.is_port_available(port).await {
            return Err(anyhow::anyhow!("Port {} is not available", port));
        }
        Ok(())
    }

    pub async fn wait_for_port(&self, port: u16, timeout_secs: u64) -> Result<()> {
        let addr: SocketAddr = format!("127.0.0.1:{}", port).parse()?;
        
        let result = timeout(
            Duration::from_secs(timeout_secs),
            self.wait_for_port_connection(addr)
        ).await;

        match result {
            Ok(Ok(_)) => {
                debug!("Port {} is now accepting connections", port);
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(anyhow::anyhow!("Timeout waiting for port {} to be ready", port)),
        }
    }

    async fn wait_for_port_connection(&self, addr: SocketAddr) -> Result<()> {
        loop {
            match TcpStream::connect(&addr) {
                Ok(_) => return Ok(()),
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    pub async fn find_free_port_pair(&self) -> Result<(u16, u16)> {
        let first = self.find_free_port().await?;
        
        // Try to find a second port that's different from the first
        for _ in 0..10 {
            let second = self.find_free_port().await?;
            if second != first {
                return Ok((first, second));
            }
        }
        
        Err(anyhow::anyhow!("Could not find two distinct free ports"))
    }

    pub async fn check_privileged_port(&self, port: u16) -> bool {
        port < 1024
    }

    pub async fn suggest_alternative_port(&self, port: u16) -> u16 {
        if port < 1024 {
            // Suggest non-privileged alternative
            port + 8000
        } else {
            // Try next available port
            self.find_free_port_in_range(port + 1, 65535)
                .await
                .unwrap_or(port + 1000)
        }
    }
}
