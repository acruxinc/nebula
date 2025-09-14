use anyhow::Result;
use std::sync::Arc;
use tokio::signal;
use tokio::sync::{RwLock, broadcast, Mutex};
use tracing::{info, warn, error, debug};
use std::collections::HashMap;
use std::time::Duration;

use crate::cli::NebulaConfig;
use crate::network::{DnsServer, DhcpServer, ReverseProxy};
use crate::utils::{CertificateManager, PortManager};
use crate::core::{DevProcess, NebulaScheduler};
use crate::error::{NebulaError, Result as NebulaResult};

#[derive(Clone)]
pub struct NebulaServer {
    config: Arc<RwLock<NebulaConfig>>,
    cert_manager: Arc<CertificateManager>,
    port_manager: Arc<PortManager>,
    dns_server: Option<Arc<DnsServer>>,
    dhcp_server: Option<Arc<DhcpServer>>,
    reverse_proxy: Option<Arc<ReverseProxy>>,
    scheduler: Option<Arc<NebulaScheduler>>,
    dev_process: Arc<Mutex<Option<DevProcess>>>,
    shutdown_tx: Arc<Mutex<Option<broadcast::Sender<()>>>>,
    metrics: Arc<ServerMetrics>,
    state: Arc<RwLock<ServerState>>,
}

#[derive(Debug, Default)]
pub struct ServerMetrics {
    pub start_time: std::time::Instant,
    pub requests_total: std::sync::atomic::AtomicU64,
    pub requests_errors: std::sync::atomic::AtomicU64,
    pub active_connections: std::sync::atomic::AtomicU64,
    pub dns_queries: std::sync::atomic::AtomicU64,
    pub dhcp_leases: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone)]
pub struct ServerState {
    pub status: ServerStatus,
    pub ports: HashMap<String, u16>,
    pub pid: Option<u32>,
    pub uptime: Duration,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ServerStatus {
    Starting,
    Running,
    Stopping,
    Stopped,
    Error,
}

impl Default for ServerState {
    fn default() -> Self {
        Self {
            status: ServerStatus::Stopped,
            ports: HashMap::new(),
            pid: None,
            uptime: Duration::default(),
            last_error: None,
        }
    }
}

impl NebulaServer {
    pub async fn new(config: NebulaConfig) -> NebulaResult<Self> {
        info!("Initializing Nebula server for domain: {}", config.domain);

        // Validate configuration
        config.validate()?;

        let config = Arc::new(RwLock::new(config));
        let cert_manager = Arc::new(CertificateManager::new().await?);
        let port_manager = Arc::new(PortManager::new());
        let metrics = Arc::new(ServerMetrics::default());
        
        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Self {
            config,
            cert_manager,
            port_manager,
            dns_server: None,
            dhcp_server: None,
            reverse_proxy: None,
            scheduler: None,
            dev_process: Arc::new(Mutex::new(None)),
            shutdown_tx: Arc::new(Mutex::new(Some(shutdown_tx))),
            metrics,
            state: Arc::new(RwLock::new(ServerState::default())),
        })
    }

    pub async fn run(&self) -> NebulaResult<()> {
        self.update_status(ServerStatus::Starting).await;
        
        let config = self.config.read().await;
        info!("Starting Nebula server in {:?} mode", config.mode);

        // Resolve and validate ports
        let (http_port, https_port) = self.resolve_ports(&config).await?;
        info!("Using ports - HTTP: {}, HTTPS: {}", http_port, https_port);

        // Update state with ports
        {
            let mut state = self.state.write().await;
            state.ports.insert("http".to_string(), http_port);
            state.ports.insert("https".to_string(), https_port);
            state.pid = std::process::id().into();
        }

        // Generate certificates if needed
        if !config.no_dns {
            info!("Ensuring certificates for domain: {}", config.domain);
            self.cert_manager
                .ensure_certificate(&config.domain, config.force_certs)
                .await?;
        }

        // Start DNS server
        let dns_server = if !config.no_dns && config.dns.enabled {
            info!("Starting DNS server on port {}", config.dns.port);
            let dns = Arc::new(DnsServer::new(config.dns.clone()).await?);
            dns.start().await?;
            
            // Add development domain mappings
            dns.add_dev_domain("*.nebula.com", "127.0.0.1".parse().unwrap()).await?;
            dns.add_dev_domain("*.dev", "127.0.0.1".parse().unwrap()).await?;
            
            Some(dns)
        } else {
            info!("DNS server disabled");
            None
        };

        // Start DHCP server
        let dhcp_server = if !config.no_dhcp && config.dhcp.enabled {
            info!("Starting DHCP server");
            let dhcp = Arc::new(DhcpServer::new(config.dhcp.clone()).await?);
            dhcp.start().await?;
            Some(dhcp)
        } else {
            info!("DHCP server disabled");
            None
        };

        // Start scheduler for production deployments
        let scheduler = if config.scheduler.enabled {
            info!("Starting deployment scheduler");
            let sched = Arc::new(NebulaScheduler::new(config.scheduler.clone()).await?);
            sched.start().await?;
            Some(sched)
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

        // Start development process if in development mode
        let dev_process = if config.is_development() {
            info!("Starting development process: {}", config.dev_command);
            let mut process = DevProcess::new(
                &config.dev_command,
                config.get_project_dir(),
                config.get_environment(),
            ).await?;
            
            process.start().await?;
            Some(process)
        } else {
            None
        };

        // Store components
        let mut server = self.clone();
        server.dns_server = dns_server;
        server.dhcp_server = dhcp_server;
        server.reverse_proxy = Some(proxy);
        server.scheduler = scheduler;
        
        if let Some(process) = dev_process {
            *server.dev_process.lock().await = Some(process);
        }

        drop(config); // Release the read lock

        // Start health monitoring
        let health_handle = self.start_health_monitoring().await?;

        // Start file watcher if hot reload is enabled
        let watcher_handle = if server.config.read().await.hot_reload {
            Some(self.start_file_watcher().await?)
        } else {
            None
        };

        // Save server state
        self.save_server_state().await?;

        self.update_status(ServerStatus::Running).await;

        info!("🚀 Nebula is ready!");
        let config = self.config.read().await;
        info!("   HTTP:  http://{}:{}", config.domain, http_port);
        info!("   HTTPS: https://{}:{}", config.domain, https_port);
        
        if config.is_development() {
            info!("   Development mode active with hot reload");
        }

        // Wait for shutdown signal
        let shutdown_rx = {
            let shutdown_tx = self.shutdown_tx.lock().await;
            shutdown_tx.as_ref().unwrap().subscribe()
        };

        self.wait_for_shutdown(shutdown_rx, health_handle, watcher_handle).await
    }

    pub async fn shutdown(&self) -> NebulaResult<()> {
        info!("🛑 Shutting down Nebula server...");
        self.update_status(ServerStatus::Stopping).await;

        // Signal shutdown
        {
            let shutdown_tx = self.shutdown_tx.lock().await;
            if let Some(tx) = shutdown_tx.as_ref() {
                let _ = tx.send(());
            }
        }

        // Stop development process
        if let Some(mut process) = self.dev_process.lock().await.take() {
            if let Err(e) = process.stop().await {
                warn!("Error stopping development process: {}", e);
            }
        }

        // Stop reverse proxy
        if let Some(ref proxy) = self.reverse_proxy {
            if let Err(e) = proxy.stop().await {
                warn!("Error stopping reverse proxy: {}", e);
            }
        }

        // Stop DNS server
        if let Some(ref dns) = self.dns_server {
            if let Err(e) = dns.stop().await {
                warn!("Error stopping DNS server: {}", e);
            }
        }

        // Stop DHCP server
        if let Some(ref dhcp) = self.dhcp_server {
            if let Err(e) = dhcp.stop().await {
                warn!("Error stopping DHCP server: {}", e);
            }
        }

        // Stop scheduler
        if let Some(ref scheduler) = self.scheduler {
            if let Err(e) = scheduler.stop().await {
                warn!("Error stopping scheduler: {}", e);
            }
        }

        // Clean up server state
        self.cleanup_server_state().await?;

        self.update_status(ServerStatus::Stopped).await;
        info!("✅ Nebula shutdown complete");
        Ok(())
    }

    async fn resolve_ports(&self, config: &NebulaConfig) -> NebulaResult<(u16, u16)> {
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
        if !self.port_manager.is_port_available(http_port).await {
            if config.http_port == 0 {
                // Try to find another port
                let alternative = self.port_manager.find_free_port().await?;
                warn!("Port {} unavailable, using {} instead", http_port, alternative);
                return self.resolve_ports(&NebulaConfig {
                    http_port: alternative,
                    ..config.clone()
                }).await;
            } else {
                return Err(NebulaError::port_unavailable(http_port));
            }
        }

        if !self.port_manager.is_port_available(https_port).await {
            if config.https_port == 0 {
                let alternative = self.port_manager.find_free_port().await?;
                warn!("Port {} unavailable, using {} instead", https_port, alternative);
                return self.resolve_ports(&NebulaConfig {
                    https_port: alternative,
                    ..config.clone()
                }).await;
            } else {
                return Err(NebulaError::port_unavailable(https_port));
            }
        }

        Ok((http_port, https_port))
    }

    async fn start_health_monitoring(&self) -> NebulaResult<tokio::task::JoinHandle<()>> {
        let server = self.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        if let Err(e) = server.perform_health_checks().await {
                            error!("Health check failed: {}", e);
                            server.update_last_error(&e.to_string()).await;
                        }
                    }
                    _ = server.shutdown_signal() => {
                        debug!("Health monitoring stopped");
                        break;
                    }
                }
            }
        });
        
        Ok(handle)
    }

    async fn start_file_watcher(&self) -> NebulaResult<tokio::task::JoinHandle<()>> {
        use notify::{Watcher, RecursiveMode, Event, EventKind};
        use tokio::sync::mpsc;
        
        let (tx, mut rx) = mpsc::channel(100);
        let config = self.config.read().await;
        let watch_dir = config.get_project_dir();
        let patterns = config.dev.watch_patterns.clone();
        let ignore_patterns = config.dev.ignore_patterns.clone();
        let restart_delay = Duration::from_millis(config.dev.restart_delay);
        
        // Create watcher
        let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            if let Ok(event) = res {
                let _ = tx.blocking_send(event);
            }
        })?;

        watcher.watch(&watch_dir, RecursiveMode::Recursive)?;
        
        let server = self.clone();
        let handle = tokio::spawn(async move {
            let mut last_restart = std::time::Instant::now();
            
            loop {
                tokio::select! {
                    event = rx.recv() => {
                        if let Some(event) = event {
                            if server.should_restart_for_event(&event, &patterns, &ignore_patterns).await {
                                // Debounce restarts
                                if last_restart.elapsed() > restart_delay {
                                    info!("File change detected, restarting development process...");
                                    if let Err(e) = server.restart_dev_process().await {
                                        error!("Failed to restart development process: {}", e);
                                    }
                                    last_restart = std::time::Instant::now();
                                }
                            }
                        }
                    }
                    _ = server.shutdown_signal() => {
                        debug!("File watcher stopped");
                        break;
                    }
                }
            }
        });
        
        Ok(handle)
    }

    async fn should_restart_for_event(
        &self,
        event: &notify::Event,
        patterns: &[String],
        ignore_patterns: &[String],
    ) -> bool {
        use notify::EventKind;
        
        // Only restart on modify events
        if !matches!(event.kind, EventKind::Modify(_)) {
            return false;
        }

        for path in &event.paths {
            let path_str = path.to_string_lossy();
            
            // Check ignore patterns first
            for ignore_pattern in ignore_patterns {
                if glob_match(ignore_pattern, &path_str) {
                    return false;
                }
            }
            
            // Check watch patterns
            for pattern in patterns {
                if glob_match(pattern, &path_str) {
                    return true;
                }
            }
        }
        
        false
    }

    async fn restart_dev_process(&self) -> NebulaResult<()> {
        let mut dev_process = self.dev_process.lock().await;
        
        if let Some(ref mut process) = dev_process.as_mut() {
            process.restart().await?;
        }
        
        Ok(())
    }

    async fn perform_health_checks(&self) -> NebulaResult<()> {
        // Check development process health
        if let Some(process) = self.dev_process.lock().await.as_ref() {
            if !process.is_running() {
                warn!("Development process is not running, attempting restart...");
                drop(process);
                self.restart_dev_process().await?;
            }
        }

        // Check DNS server health
        if let Some(ref dns) = self.dns_server {
            if !dns.is_healthy().await {
                warn!("DNS server health check failed");
            }
        }

        // Check DHCP server health
        if let Some(ref dhcp) = self.dhcp_server {
            if !dhcp.is_healthy().await {
                warn!("DHCP server health check failed");
            }
        }

        // Check reverse proxy health
        if let Some(ref proxy) = self.reverse_proxy {
            if !proxy.is_healthy().await {
                warn!("Reverse proxy health check failed");
            }
        }

        // Update uptime
        {
            let mut state = self.state.write().await;
            state.uptime = self.metrics.start_time.elapsed();
        }

        Ok(())
    }

    async fn wait_for_shutdown(
        &self,
        mut shutdown_rx: broadcast::Receiver<()>,
        health_handle: tokio::task::JoinHandle<()>,
        watcher_handle: Option<tokio::task::JoinHandle<()>>,
    ) -> NebulaResult<()> {
        // On Unix include SIGTERM handling; on non-Unix just wait for shutdown or Ctrl+C.
        #[cfg(unix)]
        {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                }
                _ = signal::ctrl_c() => {
                    info!("Ctrl+C received");
                }
                _ = async {
                    // Register for SIGTERM; log errors instead of using the `?` operator inside the async block.
                    match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                        Ok(mut sigterm) => {
                            sigterm.recv().await;
                        }
                        Err(e) => {
                            error!("Failed to register SIGTERM handler: {}", e);
                        }
                    }
                } => {
                    info!("SIGTERM received");
                }
            }
        }

        #[cfg(not(unix))]
        {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Shutdown signal received");
                }
                _ = signal::ctrl_c() => {
                    info!("Ctrl+C received");
                }
            }
        }

        // Cancel background tasks
        health_handle.abort();
        if let Some(handle) = watcher_handle {
            handle.abort();
        }

        self.shutdown().await
    }

    async fn shutdown_signal(&self) -> () {
        let mut rx = {
            let shutdown_tx = self.shutdown_tx.lock().await;
            shutdown_tx.as_ref().unwrap().subscribe()
        };
        let _ = rx.recv().await;
    }

    async fn save_server_state(&self) -> NebulaResult<()> {
        use tokio::fs;
        
        let state = self.state.read().await;
        let nebula_dir = std::path::PathBuf::from(".nebula");
        fs::create_dir_all(&nebula_dir).await?;

        // Save state as JSON
        let state_json = serde_json::to_string_pretty(&*state)?;
        fs::write(nebula_dir.join("server.json"), state_json).await?;

        // Save PID file
        if let Some(pid) = state.pid {
            fs::write(nebula_dir.join("nebula.pid"), pid.to_string()).await?;
        }

        // Save ports information
        let ports_json = serde_json::to_string_pretty(&state.ports)?;
        fs::write(nebula_dir.join("ports.json"), ports_json).await?;

        debug!("Server state saved");
        Ok(())
    }

    async fn cleanup_server_state(&self) -> NebulaResult<()> {
        use tokio::fs;
        
        let files_to_remove = vec![
            ".nebula/server.json",
            ".nebula/nebula.pid", 
            ".nebula/ports.json",
        ];

        for file in files_to_remove {
            let path = std::path::PathBuf::from(file);
            if path.exists() {
                if let Err(e) = fs::remove_file(&path).await {
                    warn!("Failed to remove {}: {}", file, e);
                }
            }
        }

        Ok(())
    }

    async fn update_status(&self, status: ServerStatus) -> () {
        let mut state = self.state.write().await;
        state.status = status;
    }

    async fn update_last_error(&self, error: &str) -> () {
        let mut state = self.state.write().await;
        state.last_error = Some(error.to_string());
    }

    // Public API methods
    pub async fn get_status(&self) -> ServerState {
        self.state.read().await.clone()
    }

    pub async fn get_metrics(&self) -> ServerMetrics {
        // Clone the metrics (atomic values will be read)
        ServerMetrics {
            start_time: self.metrics.start_time,
            requests_total: std::sync::atomic::AtomicU64::new(
                self.metrics.requests_total.load(std::sync::atomic::Ordering::Relaxed)
            ),
            requests_errors: std::sync::atomic::AtomicU64::new(
                self.metrics.requests_errors.load(std::sync::atomic::Ordering::Relaxed)
            ),
            active_connections: std::sync::atomic::AtomicU64::new(
                self.metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed)
            ),
            dns_queries: std::sync::atomic::AtomicU64::new(
                self.metrics.dns_queries.load(std::sync::atomic::Ordering::Relaxed)
            ),
            dhcp_leases: std::sync::atomic::AtomicU64::new(
                self.metrics.dhcp_leases.load(std::sync::atomic::Ordering::Relaxed)
            ),
        }
    }

    pub async fn reload_config(&self, new_config: NebulaConfig) -> NebulaResult<()> {
        new_config.validate()?;
        
        let mut config = self.config.write().await;
        *config = new_config;
        
        info!("Configuration reloaded");
        Ok(())
    }

    pub fn get_dns_server(&self) -> Option<Arc<DnsServer>> {
        self.dns_server.clone()
    }

    pub fn get_dhcp_server(&self) -> Option<Arc<DhcpServer>> {
        self.dhcp_server.clone()
    }

    pub fn get_scheduler(&self) -> Option<Arc<NebulaScheduler>> {
        self.scheduler.clone()
    }
}

// Helper function for glob matching
fn glob_match(pattern: &str, text: &str) -> bool {
    // Simple glob matching implementation
    // In a real implementation, you'd use a proper glob library
    if pattern.contains("**") {
        let parts: Vec<&str> = pattern.split("**").collect();
        if parts.len() == 2 {
            return text.starts_with(parts[0]) && text.ends_with(parts[1]);
        }
    }
    
    if pattern.contains('*') {
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            return text.starts_with(parts[0]) && text.ends_with(parts[1]);
        }
    }
    
    pattern == text
}

impl Default for ServerMetrics {
    fn default() -> Self {
        Self {
            start_time: std::time::Instant::now(),
            requests_total: std::sync::atomic::AtomicU64::new(0),
            requests_errors: std::sync::atomic::AtomicU64::new(0),
            active_connections: std::sync::atomic::AtomicU64::new(0),
            dns_queries: std::sync::atomic::AtomicU64::new(0),
            dhcp_leases: std::sync::atomic::AtomicU64::new(0),
        }
    }
}

// Implement Serialize for ServerState
impl serde::Serialize for ServerState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let mut state = serializer.serialize_struct("ServerState", 5)?;
        state.serialize_field("status", &format!("{:?}", self.status))?;
        state.serialize_field("ports", &self.ports)?;
        state.serialize_field("pid", &self.pid)?;
        state.serialize_field("uptime_seconds", &self.uptime.as_secs())?;
        state.serialize_field("last_error", &self.last_error)?;
        state.end()
    }
}
