use anyhow::Result;
use std::collections::HashMap;
use std::net::{TcpListener, TcpStream, SocketAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, warn, info};

use crate::error::{NebulaError, Result as NebulaResult};

#[derive(Clone)]
pub struct PortManager {
    reserved_ports: Arc<RwLock<HashMap<u16, String>>>,
    port_range: PortRange,
    preferred_ports: Vec<u16>,
}

#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Clone)]
pub struct PortInfo {
    pub port: u16,
    pub is_available: bool,
    pub process_name: Option<String>,
    pub process_id: Option<u32>,
    pub protocol: PortProtocol,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PortProtocol {
    Tcp,
    Udp,
    Both,
}

#[derive(Debug, Clone)]
pub struct PortScanResult {
    pub open_ports: Vec<PortInfo>,
    pub closed_ports: Vec<u16>,
    pub scan_duration: Duration,
}

impl PortManager {
    pub fn new() -> Self {
        Self {
            reserved_ports: Arc::new(RwLock::new(HashMap::new())),
            port_range: PortRange::default(),
            preferred_ports: vec![3000, 3001, 3002, 3003, 8000, 8080, 8081, 9000],
        }
    }

    pub fn new_with_range(start: u16, end: u16) -> Self {
        Self {
            reserved_ports: Arc::new(RwLock::new(HashMap::new())),
            port_range: PortRange { start, end },
            preferred_ports: vec![3000, 3001, 3002, 3003, 8000, 8080, 8081, 9000],
        }
    }

    /// Find a free port in the default range
    pub async fn find_free_port(&self) -> NebulaResult<u16> {
        // First try preferred ports
        for &port in &self.preferred_ports {
            if self.is_port_available(port).await {
                self.reserve_port(port, "auto-assigned".to_string()).await?;
                return Ok(port);
            }
        }

        // Then try the configured range
        self.find_free_port_in_range(self.port_range.start, self.port_range.end).await
    }

    /// Find a free port in a specific range
    pub async fn find_free_port_in_range(&self, start: u16, end: u16) -> NebulaResult<u16> {
        if start >= end {
            return Err(NebulaError::validation("Invalid port range: start must be less than end"));
        }

        for port in start..=end {
            if self.is_port_available(port).await {
                self.reserve_port(port, "range-assigned".to_string()).await?;
                debug!("Found free port: {}", port);
                return Ok(port);
            }
        }
        
        Err(NebulaError::port_unavailable(start))
    }

    /// Check if a specific port is available
    pub async fn is_port_available(&self, port: u16) -> bool {
        // Check if already reserved
        {
            let reserved = self.reserved_ports.read().await;
            if reserved.contains_key(&port) {
                return false;
            }
        }

        // Check if port is actually available on the system
        self.check_port_system_availability(port, PortProtocol::Tcp).await &&
        self.check_port_system_availability(port, PortProtocol::Udp).await
    }

    /// Check if a port is available for a specific protocol
    async fn check_port_system_availability(&self, port: u16, protocol: PortProtocol) -> bool {
        match protocol {
            PortProtocol::Tcp | PortProtocol::Both => {
                // Try IPv4
                if !self.check_tcp_port_ipv4(port) {
                    return false;
                }
                // Try IPv6
                if !self.check_tcp_port_ipv6(port) {
                    return false;
                }
            }
            PortProtocol::Udp => {
                // For UDP, we'll do a simpler check
                if !self.check_udp_port(port) {
                    return false;
                }
            }
        }
        true
    }

    fn check_tcp_port_ipv4(&self, port: u16) -> bool {
        match TcpListener::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn check_tcp_port_ipv6(&self, port: u16) -> bool {
        match TcpListener::bind(SocketAddr::new(Ipv6Addr::LOCALHOST.into(), port)) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    fn check_udp_port(&self, port: u16) -> bool {
        match std::net::UdpSocket::bind(SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port)) {
            Ok(_) => true,
            Err(_) => false,
        }
    }

    /// Reserve a port for a specific purpose
    pub async fn reserve_port(&self, port: u16, purpose: String) -> NebulaResult<()> {
        if !self.check_port_system_availability(port, PortProtocol::Both).await {
            return Err(NebulaError::port_unavailable(port));
        }

        let mut reserved = self.reserved_ports.write().await;
        if reserved.contains_key(&port) {
            return Err(NebulaError::already_exists(format!("Port {} is already reserved", port)));
        }

        reserved.insert(port, purpose);
        debug!("Reserved port {} for: {}", port, reserved.get(&port).unwrap());
        Ok(())
    }

    /// Release a reserved port
    pub async fn release_port(&self, port: u16) -> NebulaResult<()> {
        let mut reserved = self.reserved_ports.write().await;
        if reserved.remove(&port).is_some() {
            debug!("Released port {}", port);
            Ok(())
        } else {
            Err(NebulaError::not_found(format!("Port {} was not reserved", port)))
        }
    }

    /// Get all reserved ports
    pub async fn get_reserved_ports(&self) -> HashMap<u16, String> {
        self.reserved_ports.read().await.clone()
    }

    /// Validate that a port is available and not reserved
    pub async fn validate_port_available(&self, port: u16) -> NebulaResult<()> {
        if port == 0 {
            return Err(NebulaError::validation("Port cannot be 0"));
        }

        if port < 1024 && !self.is_privileged() {
            return Err(NebulaError::permission_denied(format!("Port {} requires privileged access", port)));
        }

        if !self.is_port_available(port).await {
            return Err(NebulaError::port_unavailable(port));
        }

        Ok(())
    }

    /// Wait for a port to become available or a service to start
    pub async fn wait_for_port(&self, port: u16, timeout_secs: u64) -> NebulaResult<()> {
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
        
        let result = tokio::time::timeout(
            Duration::from_secs(timeout_secs),
            self.wait_for_port_connection(addr)
        ).await;

        match result {
            Ok(Ok(_)) => {
                debug!("Port {} is now accepting connections", port);
                Ok(())
            }
            Ok(Err(e)) => Err(e),
            Err(_) => Err(NebulaError::timeout(format!("Timeout waiting for port {} to be ready", port))),
        }
    }

    async fn wait_for_port_connection(&self, addr: SocketAddr) -> NebulaResult<()> {
        loop {
            match TcpStream::connect(&addr) {
                Ok(_) => return Ok(()),
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Find multiple free ports
    pub async fn find_free_ports(&self, count: usize) -> NebulaResult<Vec<u16>> {
        let mut ports = Vec::new();
        
        for _ in 0..count {
            let port = self.find_free_port().await?;
            ports.push(port);
        }
        
        Ok(ports)
    }

    /// Find a pair of consecutive free ports
    pub async fn find_free_port_pair(&self) -> NebulaResult<(u16, u16)> {
        for port in self.port_range.start..self.port_range.end {
            if self.is_port_available(port).await && self.is_port_available(port + 1).await {
                self.reserve_port(port, "pair-first".to_string()).await?;
                self.reserve_port(port + 1, "pair-second".to_string()).await?;
                return Ok((port, port + 1));
            }
        }
        
        Err(NebulaError::port_unavailable(self.port_range.start))
    }

    /// Check if running with elevated privileges
    fn is_privileged(&self) -> bool {
        #[cfg(unix)]
        {
            unsafe { libc::geteuid() == 0 }
        }
        #[cfg(windows)]
        {
            // On Windows, assume we have privileges if we can bind to port 80
            TcpListener::bind("127.0.0.1:80").is_ok()
        }
    }

    /// Suggest an alternative port if the requested one is unavailable
    pub async fn suggest_alternative_port(&self, requested_port: u16) -> u16 {
        // Try nearby ports first
        for offset in 1..=10 {
            let alt_port = requested_port + offset;
            if alt_port <= 65535 && self.is_port_available(alt_port).await {
                return alt_port;
            }
        }

        // Try preferred ports
        for &port in &self.preferred_ports {
            if port != requested_port && self.is_port_available(port).await {
                return port;
            }
        }

        // Fall back to finding any free port
        self.find_free_port().await.unwrap_or(requested_port + 1000)
    }

    /// Get detailed information about a port
    pub async fn get_port_info(&self, port: u16) -> PortInfo {
        let is_available = self.is_port_available(port).await;
        let (process_name, process_id) = if !is_available {
            self.get_port_process_info(port).await
        } else {
            (None, None)
        };

        PortInfo {
            port,
            is_available,
            process_name,
            process_id,
            protocol: PortProtocol::Tcp, // Default to TCP
        }
    }

    /// Get process information for a port (platform-specific)
    async fn get_port_process_info(&self, port: u16) -> (Option<String>, Option<u32>) {
        #[cfg(unix)]
        {
            self.get_port_process_info_unix(port).await
        }
        #[cfg(windows)]
        {
            self.get_port_process_info_windows(port).await
        }
    }

    #[cfg(unix)]
    async fn get_port_process_info_unix(&self, port: u16) -> (Option<String>, Option<u32>) {
        use std::process::Command;

        // Try using lsof to find process using the port
        let output = Command::new("lsof")
            .args(&["-i", &format!(":{}", port), "-t"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let pid_str = String::from_utf8_lossy(&output.stdout);
                if let Ok(pid) = pid_str.trim().parse::<u32>() {
                    // Get process name
                    let name_output = Command::new("ps")
                        .args(&["-p", &pid.to_string(), "-o", "comm="])
                        .output();
                    
                    if let Ok(name_output) = name_output {
                        if name_output.status.success() {
                            let process_name = String::from_utf8_lossy(&name_output.stdout).trim().to_string();
                            return (Some(process_name), Some(pid));
                        }
                    }
                    
                    return (None, Some(pid));
                }
            }
        }

        (None, None)
    }

    #[cfg(windows)]
    async fn get_port_process_info_windows(&self, port: u16) -> (Option<String>, Option<u32>) {
        use std::process::Command;

        // Use netstat to find process using the port
        let output = Command::new("netstat")
            .args(&["-ano", "-p", "tcp"])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let netstat_output = String::from_utf8_lossy(&output.stdout);
                for line in netstat_output.lines() {
                    if line.contains(&format!(":{}", port)) && line.contains("LISTENING") {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if let Some(pid_str) = parts.last() {
                            if let Ok(pid) = pid_str.parse::<u32>() {
                                // Get process name using tasklist
                                let name_output = Command::new("tasklist")
                                    .args(&["/FI", &format!("PID eq {}", pid), "/FO", "CSV", "/NH"])
                                    .output();
                                
                                if let Ok(name_output) = name_output {
                                    if name_output.status.success() {
                                        let tasklist_output = String::from_utf8_lossy(&name_output.stdout);
                                        if let Some(line) = tasklist_output.lines().next() {
                                            let parts: Vec<&str> = line.split(',').collect();
                                            if let Some(name) = parts.first() {
                                                let process_name = name.trim_matches('"').to_string();
                                                return (Some(process_name), Some(pid));
                                            }
                                        }
                                    }
                                }
                                
                                return (None, Some(pid));
                            }
                        }
                    }
                }
            }
        }

        (None, None)
    }

    /// Scan a range of ports to see which are open
    pub async fn scan_port_range(&self, start: u16, end: u16, timeout_ms: u64) -> NebulaResult<PortScanResult> {
        let scan_start = std::time::Instant::now();
        let mut open_ports = Vec::new();
        let mut closed_ports = Vec::new();

        let timeout_duration = Duration::from_millis(timeout_ms);

        for port in start..=end {
            let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
            
            match tokio::time::timeout(timeout_duration, TcpStream::connect(&addr)).await {
                Ok(Ok(_)) => {
                    let port_info = self.get_port_info(port).await;
                    open_ports.push(port_info);
                }
                _ => {
                    closed_ports.push(port);
                }
            }
        }

        let scan_duration = scan_start.elapsed();

        Ok(PortScanResult {
            open_ports,
            closed_ports,
            scan_duration,
        })
    }

    /// Check if a service is running on a specific port
    pub async fn is_service_running(&self, port: u16) -> bool {
        let addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
        
        match tokio::time::timeout(Duration::from_millis(1000), TcpStream::connect(&addr)).await {
            Ok(Ok(_)) => true,
            _ => false,
        }
    }

    /// Get system's ephemeral port range
    pub fn get_ephemeral_port_range(&self) -> PortRange {
        #[cfg(target_os = "linux")]
        {
            // Try to read from /proc/sys/net/ipv4/ip_local_port_range
            if let Ok(content) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range") {
                let parts: Vec<&str> = content.trim().split_whitespace().collect();
                if parts.len() == 2 {
                    if let (Ok(start), Ok(end)) = (parts[0].parse(), parts[1].parse()) {
                        return PortRange { start, end };
                    }
                }
            }
            PortRange { start: 32768, end: 60999 } // Linux default
        }
        
        #[cfg(target_os = "macos")]
        {
            PortRange { start: 49152, end: 65535 } // macOS default
        }
        
        #[cfg(target_os = "windows")]
        {
            PortRange { start: 49152, end: 65535 } // Windows Vista+ default
        }
        
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            PortRange { start: 32768, end: 65535 } // Generic default
        }
    }

    /// Release all reserved ports
    pub async fn release_all_ports(&self) {
        let mut reserved = self.reserved_ports.write().await;
        let count = reserved.len();
        reserved.clear();
        info!("Released {} reserved ports", count);
    }

    /// Get statistics about port usage
    pub async fn get_port_statistics(&self) -> PortStatistics {
        let reserved = self.reserved_ports.read().await;
        let total_reserved = reserved.len();
        
        // Count available ports in range (this is expensive, so we sample)
        let sample_size = std::cmp::min(100, self.port_range.end - self.port_range.start);
        let mut available_count = 0;
        
        for i in 0..sample_size {
            let port = self.port_range.start + (i * (self.port_range.end - self.port_range.start) / sample_size);
            if self.is_port_available(port).await {
                available_count += 1;
            }
        }
        
        let estimated_available = (available_count as f32 / sample_size as f32 * 
                                  (self.port_range.end - self.port_range.start) as f32) as usize;

        PortStatistics {
            total_reserved,
            estimated_available,
            port_range: self.port_range.clone(),
            preferred_ports: self.preferred_ports.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PortStatistics {
    pub total_reserved: usize,
    pub estimated_available: usize,
    pub port_range: PortRange,
    pub preferred_ports: Vec<u16>,
}

impl Default for PortRange {
    fn default() -> Self {
        Self {
            start: 3000,
            end: 9999,
        }
    }
}

impl Default for PortManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_port_manager_creation() {
        let port_manager = PortManager::new();
        let stats = port_manager.get_port_statistics().await;
        
        assert_eq!(stats.total_reserved, 0);
        assert!(!stats.preferred_ports.is_empty());
    }

    #[tokio::test]
    async fn test_find_free_port() {
        let port_manager = PortManager::new();
        let port = port_manager.find_free_port().await;
        
        assert!(port.is_ok(), "Should find a free port");
        let port = port.unwrap();
        assert!(port >= 1024, "Port should be non-privileged");
    }

    #[tokio::test]
    async fn test_port_reservation() {
        let port_manager = PortManager::new();
        let port = port_manager.find_free_port().await.unwrap();
        
        // Port should already be reserved by find_free_port
        let reserved = port_manager.get_reserved_ports().await;
        assert!(reserved.contains_key(&port), "Port should be reserved");
        
        // Release the port
        let result = port_manager.release_port(port).await;
        assert!(result.is_ok(), "Should release port successfully");
        
        // Port should no longer be reserved
        let reserved = port_manager.get_reserved_ports().await;
        assert!(!reserved.contains_key(&port), "Port should no longer be reserved");
    }

    #[tokio::test]
    async fn test_port_validation() {
        let port_manager = PortManager::new();
        
        // Test invalid port
        let result = port_manager.validate_port_available(0).await;
        assert!(result.is_err(), "Port 0 should be invalid");
        
        // Test privileged port (if not running as root)
        if !port_manager.is_privileged() {
            let result = port_manager.validate_port_available(80).await;
            assert!(result.is_err(), "Port 80 should require privileges");
        }
    }

    #[tokio::test]
    async fn test_port_pair_finding() {
        let port_manager = PortManager::new();
        let result = port_manager.find_free_port_pair().await;
        
        assert!(result.is_ok(), "Should find a free port pair");
        let (port1, port2) = result.unwrap();
        assert_eq!(port2, port1 + 1, "Ports should be consecutive");
    }

    #[tokio::test]
    async fn test_multiple_ports() {
        let port_manager = PortManager::new();
        let ports = port_manager.find_free_ports(3).await;
        
        assert!(ports.is_ok(), "Should find multiple free ports");
        let ports = ports.unwrap();
        assert_eq!(ports.len(), 3, "Should return requested number of ports");
        
        // All ports should be unique
        let mut unique_ports = ports.clone();
        unique_ports.sort();
        unique_ports.dedup();
        assert_eq!(unique_ports.len(), ports.len(), "All ports should be unique");
    }

    #[tokio::test]
    async fn test_port_availability_check() {
        let port_manager = PortManager::new();
        
        // Find a free port
        let port = port_manager.find_free_port().await.unwrap();
        
        // Create a listener on that port
        let _listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        
        // Port should no longer be available
        assert!(!port_manager.is_port_available(port).await, "Port should not be available when in use");
    }

    #[tokio::test]
    async fn test_ephemeral_port_range() {
        let port_manager = PortManager::new();
        let range = port_manager.get_ephemeral_port_range();
        
        assert!(range.start < range.end, "Range start should be less than end");
        assert!(range.start >= 1024, "Ephemeral range should start above 1024");
        assert!(range.end <= 65535, "Ephemeral range should end at or below 65535");
    }

    #[tokio::test]
    async fn test_port_info() {
        let port_manager = PortManager::new();
        let port = port_manager.find_free_port().await.unwrap();
        
        let port_info = port_manager.get_port_info(port).await;
        assert_eq!(port_info.port, port);
        // Note: is_available might be false if the port was reserved
    }

    #[tokio::test]
    async fn test_suggest_alternative_port() {
        let port_manager = PortManager::new();
        
        // Suggest alternative for a commonly used port
        let alternative = port_manager.suggest_alternative_port(3000).await;
        assert!(alternative > 0, "Should suggest a valid alternative port");
        assert!(alternative != 3000 || port_manager.is_port_available(3000).await, 
               "Should suggest different port if original is unavailable");
    }

    #[tokio::test]
    async fn test_service_running_check() {
        let port_manager = PortManager::new();
        let port = port_manager.find_free_port().await.unwrap();
        
        // No service should be running initially
        assert!(!port_manager.is_service_running(port).await, "No service should be running on free port");
        
        // Start a service
        let _listener = TcpListener::bind(format!("127.0.0.1:{}", port)).unwrap();
        
        // Now service should be detected as running
        assert!(port_manager.is_service_running(port).await, "Service should be detected as running");
    }
}
