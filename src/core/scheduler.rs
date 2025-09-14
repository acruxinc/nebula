use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use tracing::{info, warn, error, debug};
use uuid::Uuid;
use chrono::{DateTime, Utc};
use std::time::Duration;

use crate::error::{NebulaError, Result as NebulaResult};
use crate::core::DevProcess;
use crate::utils::PortManager;
use crate::network::ReverseProxy;
use crate::utils::CertificateManager;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub tld: String,
    pub build_path: PathBuf,
    pub status: DeploymentStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub config: DeploymentConfig,
    pub metrics: DeploymentMetrics,
    pub health_status: HealthStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeploymentStatus {
    Created,
    Building,
    Built,
    Starting,
    Running,
    Stopping,
    Stopped,
    Failed,
    Unhealthy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub port: u16,
    pub https_enabled: bool,
    pub auto_ssl: bool,
    pub environment_vars: HashMap<String, String>,
    pub health_check_path: Option<String>,
    pub health_check_interval: u32,
    pub health_check_timeout: u32,
    pub restart_policy: RestartPolicy,
    pub max_restarts: u32,
    pub startup_timeout: u32,
    pub shutdown_timeout: u32,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RestartPolicy {
    Always,
    OnFailure,
    Never,
    UnlessStopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub memory_mb: Option<u32>,
    pub cpu_percent: Option<u32>,
    pub disk_mb: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentMetrics {
    pub start_count: u32,
    pub restart_count: u32,
    pub last_restart: Option<DateTime<Utc>>,
    pub uptime_seconds: u64,
    pub request_count: u64,
    pub error_count: u64,
    pub cpu_usage: f32,
    pub memory_usage: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthStatus {
    pub is_healthy: bool,
    pub last_check: Option<DateTime<Utc>>,
    pub consecutive_failures: u32,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    pub storage_path: PathBuf,
    pub default_tld: String,
    pub max_concurrent_deployments: usize,
    pub auto_cleanup: bool,
    pub cleanup_after_days: u32,
    pub health_check_interval: u32,
    pub deployment_timeout: u32,
    pub proxy_config: ProxyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    pub enable_compression: bool,
    pub enable_caching: bool,
    pub cache_ttl: u32,
    pub max_body_size: u64,
    pub timeout: u32,
}

#[derive(Clone)]
pub struct NebulaScheduler {
    config: SchedulerConfig,
    deployments: Arc<RwLock<HashMap<String, Deployment>>>,
    running_processes: Arc<RwLock<HashMap<String, Arc<Mutex<DevProcess>>>>>,
    proxies: Arc<RwLock<HashMap<String, Arc<ReverseProxy>>>>,
    port_manager: Arc<PortManager>,
    cert_manager: Arc<CertificateManager>,
    health_checker: Arc<HealthChecker>,
    is_running: Arc<RwLock<bool>>,
}

pub struct HealthChecker {
    client: reqwest::Client,
}

impl NebulaScheduler {
    pub async fn new(config: SchedulerConfig) -> NebulaResult<Self> {
        // Ensure storage directory exists
        tokio::fs::create_dir_all(&config.storage_path).await
            .map_err(|e| NebulaError::config(format!("Failed to create storage directory: {}", e)))?;
        
        let port_manager = Arc::new(PortManager::new());
        let cert_manager = Arc::new(CertificateManager::new().await?);
        let health_checker = Arc::new(HealthChecker::new());

        let scheduler = Self {
            config,
            deployments: Arc::new(RwLock::new(HashMap::new())),
            running_processes: Arc::new(RwLock::new(HashMap::new())),
            proxies: Arc::new(RwLock::new(HashMap::new())),
            port_manager,
            cert_manager,
            health_checker,
            is_running: Arc::new(RwLock::new(false)),
        };
        
        // Load existing deployments
        scheduler.load_deployments().await?;
        
        Ok(scheduler)
    }

    pub async fn start(&self) -> NebulaResult<()> {
        info!("Starting deployment scheduler...");
        
        {
            let mut running = self.is_running.write().await;
            if *running {
                return Err(NebulaError::already_exists("Scheduler is already running"));
            }
            *running = true;
        }

        // Start health check loop
        let scheduler_clone = self.clone();
        tokio::spawn(async move {
            scheduler_clone.health_check_loop().await;
        });

        // Start cleanup loop
        let scheduler_clone = self.clone();
        tokio::spawn(async move {
            scheduler_clone.cleanup_loop().await;
        });

        // Restart any deployments that should be running
        self.restart_running_deployments().await?;

        info!("✅ Deployment scheduler started");
        Ok(())
    }

    pub async fn stop(&self) -> NebulaResult<()> {
        info!("Stopping deployment scheduler...");
        
        {
            let mut running = self.is_running.write().await;
            *running = false;
        }

        // Stop all running deployments
        let deployment_ids: Vec<String> = {
            let deployments = self.deployments.read().await;
            deployments.keys().cloned().collect()
        };

        for deployment_id in deployment_ids {
            if let Err(e) = self.stop_deployment(&deployment_id, false).await {
                warn!("Failed to stop deployment {}: {}", deployment_id, e);
            }
        }

        info!("✅ Deployment scheduler stopped");
        Ok(())
    }

    pub async fn create_deployment(
        &self,
        name: String,
        build_path: PathBuf,
        tld: Option<String>,
        config: Option<DeploymentConfig>,
    ) -> NebulaResult<Deployment> {
        // Validate inputs
        if name.is_empty() {
            return Err(NebulaError::validation("Deployment name cannot be empty"));
        }

        if !build_path.exists() {
            return Err(NebulaError::file_not_found(format!("Build path does not exist: {:?}", build_path)));
        }

        // Check concurrent deployment limit
        {
            let deployments = self.deployments.read().await;
            if deployments.len() >= self.config.max_concurrent_deployments {
                return Err(NebulaError::deployment(format!(
                    "Maximum concurrent deployments reached: {}", 
                    self.config.max_concurrent_deployments
                )));
            }
        }

        let id = Uuid::new_v4().to_string();
        let tld = tld.unwrap_or_else(|| self.config.default_tld.clone());
        let domain = format!("{}.{}", name, tld);
        
        // Check if domain is already in use
        if self.is_domain_in_use(&domain).await? {
            return Err(NebulaError::already_exists(format!("Domain already in use: {}", domain)));
        }

        let deployment_config = config.unwrap_or_else(DeploymentConfig::default);
        
        // Assign port if not specified
        let port = if deployment_config.port == 0 {
            self.port_manager.find_free_port().await?
        } else {
            if !self.port_manager.is_port_available(deployment_config.port).await {
                return Err(NebulaError::port_unavailable(deployment_config.port));
            }
            deployment_config.port
        };

        let mut final_config = deployment_config;
        final_config.port = port;

        let deployment = Deployment {
            id: id.clone(),
            name: name.clone(),
            domain: domain.clone(),
            tld,
            build_path,
            status: DeploymentStatus::Created,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            config: final_config,
            metrics: DeploymentMetrics::default(),
            health_status: HealthStatus::default(),
        };

        // Validate build directory
        self.validate_build_directory(&deployment.build_path).await?;

        // Generate SSL certificate if needed
        if deployment.config.auto_ssl {
            self.cert_manager.ensure_certificate(&domain, false).await?;
        }

        // Save deployment
        self.save_deployment(&deployment).await?;
        
        {
            let mut deployments = self.deployments.write().await;
            deployments.insert(id.clone(), deployment.clone());
        }
        
        info!("Created deployment: {} -> {} (ID: {})", name, domain, id);
        Ok(deployment)
    }

    pub async fn start_deployment(&self, deployment_id: &str) -> NebulaResult<()> {
        let mut deployment = {
            let mut deployments = self.deployments.write().await;
            let deployment = deployments.get_mut(deployment_id)
                .ok_or_else(|| NebulaError::not_found(format!("Deployment not found: {}", deployment_id)))?;

            if !matches!(deployment.status, DeploymentStatus::Created | DeploymentStatus::Stopped | DeploymentStatus::Failed) {
                return Err(NebulaError::deployment(format!(
                    "Deployment must be in Created, Stopped, or Failed state to start (current: {:?})", 
                    deployment.status
                )));
            }

            deployment.status = DeploymentStatus::Starting;
            deployment.updated_at = Utc::now();
            deployment.clone()
        };

        info!("Starting deployment: {} ({})", deployment.name, deployment_id);

        // Detect and prepare the application
        let start_command = self.detect_start_command(&deployment).await?;
        
        // Create environment variables
        let mut env_vars = deployment.config.environment_vars.clone();
        env_vars.insert("PORT".to_string(), deployment.config.port.to_string());
        env_vars.insert("NODE_ENV".to_string(), "production".to_string());

        // Create and start the process
        let mut process = DevProcess::new(
            &start_command,
            deployment.build_path.clone(),
            env_vars,
        ).await?;

        process.start().await?;

        // Set up reverse proxy
        let proxy = Arc::new(ReverseProxy::new(
            deployment.config.port + 1000, // HTTPS port
            deployment.config.port,        // HTTP port
            &deployment.domain,
            self.cert_manager.clone(),
        ).await?);

        proxy.start().await?;

        // Store process and proxy
        {
            let mut processes = self.running_processes.write().await;
            processes.insert(deployment_id.to_string(), Arc::new(Mutex::new(process)));
        }

        {
            let mut proxies = self.proxies.write().await;
            proxies.insert(deployment_id.to_string(), proxy);
        }

        // Wait for startup with timeout
        let startup_timeout = Duration::from_secs(deployment.config.startup_timeout as u64);
        let startup_result = tokio::time::timeout(
            startup_timeout,
            self.wait_for_deployment_ready(&deployment)
        ).await;

        match startup_result {
            Ok(Ok(())) => {
                deployment.status = DeploymentStatus::Running;
                deployment.metrics.start_count += 1;
                deployment.updated_at = Utc::now();
                
                {
                    let mut deployments = self.deployments.write().await;
                    deployments.insert(deployment_id.to_string(), deployment.clone());
                }
                
                self.save_deployment(&deployment).await?;
                info!("✅ Deployment started successfully: {}", deployment.name);
            }
            Ok(Err(e)) => {
                deployment.status = DeploymentStatus::Failed;
                deployment.updated_at = Utc::now();
                self.cleanup_failed_deployment(deployment_id).await?;
                return Err(e);
            }
            Err(_) => {
                deployment.status = DeploymentStatus::Failed;
                deployment.updated_at = Utc::now();
                self.cleanup_failed_deployment(deployment_id).await?;
                return Err(NebulaError::timeout(format!("Deployment startup timeout after {} seconds", deployment.config.startup_timeout)));
            }
        }

        Ok(())
    }

    pub async fn stop_deployment(&self, deployment_id: &str, force: bool) -> NebulaResult<()> {
        let mut deployment = {
            let mut deployments = self.deployments.write().await;
            let deployment = deployments.get_mut(deployment_id)
                .ok_or_else(|| NebulaError::not_found(format!("Deployment not found: {}", deployment_id)))?;

            if deployment.status == DeploymentStatus::Stopped {
                return Ok(());
            }

            deployment.status = DeploymentStatus::Stopping;
            deployment.updated_at = Utc::now();
            deployment.clone()
        };

        info!("Stopping deployment: {} ({})", deployment.name, deployment_id);

        // Stop the reverse proxy
        {
            let mut proxies = self.proxies.write().await;
            if let Some(proxy) = proxies.remove(deployment_id) {
                if let Err(e) = proxy.stop().await {
                    warn!("Failed to stop proxy for deployment {}: {}", deployment_id, e);
                }
            }
        }

        // Stop the process
        {
            let mut processes = self.running_processes.write().await;
            if let Some(process_arc) = processes.remove(deployment_id) {
                let mut process = process_arc.lock().await;
                
                if force {
                    if let Err(e) = process.stop().await {
                        warn!("Failed to force stop process for deployment {}: {}", deployment_id, e);
                    }
                } else {
                    // Try graceful shutdown with timeout
                    let shutdown_timeout = Duration::from_secs(deployment.config.shutdown_timeout as u64);
                    let shutdown_result = tokio::time::timeout(shutdown_timeout, process.stop()).await;
                    
                    if let Err(_) = shutdown_result {
                        warn!("Graceful shutdown timeout, force stopping deployment {}", deployment_id);
                        let _ = process.stop().await;
                    }
                }
            }
        }

        deployment.status = DeploymentStatus::Stopped;
        deployment.updated_at = Utc::now();

        {
            let mut deployments = self.deployments.write().await;
            deployments.insert(deployment_id.to_string(), deployment.clone());
        }

        self.save_deployment(&deployment).await?;
        info!("✅ Deployment stopped: {}", deployment.name);
        Ok(())
    }

    pub async fn restart_deployment(&self, deployment_id: &str) -> NebulaResult<()> {
        info!("Restarting deployment: {}", deployment_id);
        
        let deployment = self.get_deployment(deployment_id).await
            .ok_or_else(|| NebulaError::not_found(format!("Deployment not found: {}", deployment_id)))?;

        // Update restart metrics
        {
            let mut deployments = self.deployments.write().await;
            if let Some(dep) = deployments.get_mut(deployment_id) {
                dep.metrics.restart_count += 1;
                dep.metrics.last_restart = Some(Utc::now());
                dep.updated_at = Utc::now();
            }
        }

        if matches!(deployment.status, DeploymentStatus::Running | DeploymentStatus::Unhealthy) {
            self.stop_deployment(deployment_id, false).await?;
        }

        // Wait a moment before restarting
        tokio::time::sleep(Duration::from_millis(1000)).await;

        self.start_deployment(deployment_id).await?;
        Ok(())
    }

    pub async fn scale_deployment(&self, deployment_id: &str, replicas: u32) -> NebulaResult<()> {
        // For now, we only support 0 or 1 replica (stop/start)
        // In a more advanced implementation, you could support multiple instances
        
        if replicas == 0 {
            self.stop_deployment(deployment_id, false).await
        } else if replicas == 1 {
            let deployment = self.get_deployment(deployment_id).await
                .ok_or_else(|| NebulaError::not_found(format!("Deployment not found: {}", deployment_id)))?;
            
            if deployment.status == DeploymentStatus::Stopped {
                self.start_deployment(deployment_id).await
            } else {
                Ok(()) // Already running
            }
        } else {
            Err(NebulaError::validation("Only 0 or 1 replicas are currently supported"))
        }
    }

    pub async fn delete_deployment(&self, deployment_id: &str) -> NebulaResult<()> {
        let deployment = self.get_deployment(deployment_id).await
            .ok_or_else(|| NebulaError::not_found(format!("Deployment not found: {}", deployment_id)))?;

        info!("Deleting deployment: {} ({})", deployment.name, deployment_id);

        // Stop the deployment if it's running
        if !matches!(deployment.status, DeploymentStatus::Stopped) {
            self.stop_deployment(deployment_id, true).await?;
        }

        // Remove from memory
        {
            let mut deployments = self.deployments.write().await;
            deployments.remove(deployment_id);
        }

        // Clean up deployment files
        self.cleanup_deployment(&deployment).await?;

        info!("✅ Deployment deleted: {}", deployment.name);
        Ok(())
    }

    pub async fn update_deployment(&self, deployment_id: &str, updates: HashMap<String, String>) -> NebulaResult<()> {
        let mut deployment = {
            let mut deployments = self.deployments.write().await;
            let deployment = deployments.get_mut(deployment_id)
                .ok_or_else(|| NebulaError::not_found(format!("Deployment not found: {}", deployment_id)))?;
            deployment.clone()
        };

        let mut needs_restart = false;

        for (key, value) in updates {
            match key.as_str() {
                "port" => {
                    let new_port: u16 = value.parse()
                        .map_err(|_| NebulaError::validation(format!("Invalid port: {}", value)))?;
                    
                    if !self.port_manager.is_port_available(new_port).await {
                        return Err(NebulaError::port_unavailable(new_port));
                    }
                    
                    deployment.config.port = new_port;
                    needs_restart = true;
                }
                key if key.starts_with("env.") => {
                    let env_key = key.strip_prefix("env.").unwrap();
                    deployment.config.environment_vars.insert(env_key.to_string(), value);
                    needs_restart = true;
                }
                key if key.starts_with("remove_env.") => {
                    let env_key = key.strip_prefix("remove_env.").unwrap();
                    deployment.config.environment_vars.remove(env_key);
                    needs_restart = true;
                }
                "health_check_path" => {
                    deployment.config.health_check_path = if value.is_empty() { None } else { Some(value) };
                }
                _ => {
                    return Err(NebulaError::validation(format!("Unknown update key: {}", key)));
                }
            }
        }

        deployment.updated_at = Utc::now();

        // Save updated deployment
        {
            let mut deployments = self.deployments.write().await;
            deployments.insert(deployment_id.to_string(), deployment.clone());
        }

        self.save_deployment(&deployment).await?;

        // Restart if necessary
        if needs_restart && matches!(deployment.status, DeploymentStatus::Running) {
            info!("Configuration changed, restarting deployment: {}", deployment.name);
            self.restart_deployment(deployment_id).await?;
        }

        info!("✅ Deployment updated: {}", deployment.name);
        Ok(())
    }

    pub async fn list_deployments(&self, status_filter: Option<&str>) -> NebulaResult<Vec<Deployment>> {
        let deployments = self.deployments.read().await;
        
        let mut result: Vec<Deployment> = if let Some(status) = status_filter {
            let filter_status = match status.to_lowercase().as_str() {
                "created" => DeploymentStatus::Created,
                "building" => DeploymentStatus::Building,
                "built" => DeploymentStatus::Built,
                "starting" => DeploymentStatus::Starting,
                "running" => DeploymentStatus::Running,
                "stopping" => DeploymentStatus::Stopping,
                "stopped" => DeploymentStatus::Stopped,
                "failed" => DeploymentStatus::Failed,
                "unhealthy" => DeploymentStatus::Unhealthy,
                _ => return Err(NebulaError::validation(format!("Invalid status filter: {}", status))),
            };
            
            deployments.values()
                .filter(|d| d.status == filter_status)
                .cloned()
                .collect()
        } else {
            deployments.values().cloned().collect()
        };

        // Sort by creation date (newest first)
        result.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(result)
    }

    pub async fn get_deployment(&self, deployment_id: &str) -> Option<Deployment> {
        let deployments = self.deployments.read().await;
        deployments.get(deployment_id).cloned()
    }

    pub async fn get_deployment_logs(&self, deployment_id: &str, lines: usize) -> NebulaResult<Vec<String>> {
        let log_file = self.config.storage_path
            .join("logs")
            .join(format!("{}.log", deployment_id));

        if !log_file.exists() {
            return Ok(vec![]);
        }

        let content = tokio::fs::read_to_string(&log_file).await?;
        let all_lines: Vec<&str> = content.lines().collect();
        
        let start_index = if all_lines.len() > lines {
            all_lines.len() - lines
        } else {
            0
        };

        Ok(all_lines[start_index..].iter().map(|s| s.to_string()).collect())
    }

    // Private helper methods

    async fn load_deployments(&self) -> NebulaResult<()> {
        let mut deployments = HashMap::new();
        
        let mut entries = tokio::fs::read_dir(&self.config.storage_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_name().to_string_lossy().ends_with(".json") {
                match tokio::fs::read_to_string(entry.path()).await {
                    Ok(content) => {
                        match serde_json::from_str::<Deployment>(&content) {
                            Ok(deployment) => {
                                deployments.insert(deployment.id.clone(), deployment);
                            }
                            Err(e) => {
                                warn!("Failed to parse deployment file {:?}: {}", entry.path(), e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to read deployment file {:?}: {}", entry.path(), e);
                    }
                }
            }
        }
        
        *self.deployments.write().await = deployments;
        info!("Loaded {} deployments", self.deployments.read().await.len());
        Ok(())
    }

    async fn save_deployment(&self, deployment: &Deployment) -> NebulaResult<()> {
        let file_path = self.config.storage_path.join(format!("{}.json", deployment.id));
        let content = serde_json::to_string_pretty(deployment)?;
        tokio::fs::write(file_path, content).await?;
        Ok(())
    }

    async fn cleanup_deployment(&self, deployment: &Deployment) -> NebulaResult<()> {
        let file_path = self.config.storage_path.join(format!("{}.json", deployment.id));
        if file_path.exists() {
            tokio::fs::remove_file(file_path).await?;
        }

        // Clean up log files
        let log_file = self.config.storage_path.join("logs").join(format!("{}.log", deployment.id));
        if log_file.exists() {
            let _ = tokio::fs::remove_file(log_file).await;
        }

        Ok(())
    }

    async fn cleanup_failed_deployment(&self, deployment_id: &str) -> NebulaResult<()> {
        // Stop any running processes
        {
            let mut processes = self.running_processes.write().await;
            if let Some(process_arc) = processes.remove(deployment_id) {
                let mut process = process_arc.lock().await;
                let _ = process.stop().await;
            }
        }

        // Stop any running proxies
        {
            let mut proxies = self.proxies.write().await;
            if let Some(proxy) = proxies.remove(deployment_id) {
                let _ = proxy.stop().await;
            }
        }

        Ok(())
    }

    async fn is_domain_in_use(&self, domain: &str) -> NebulaResult<bool> {
        let deployments = self.deployments.read().await;
        Ok(deployments.values().any(|d| d.domain == domain && d.status != DeploymentStatus::Stopped))
    }

    async fn validate_build_directory(&self, build_path: &PathBuf) -> NebulaResult<()> {
        if !build_path.exists() {
            return Err(NebulaError::file_not_found(format!("Build directory does not exist: {:?}", build_path)));
        }

        if !build_path.is_dir() {
            return Err(NebulaError::validation(format!("Build path is not a directory: {:?}", build_path)));
        }

        // Check if directory contains some files
        let mut entries = tokio::fs::read_dir(build_path).await?;
        if entries.next_entry().await?.is_none() {
            return Err(NebulaError::validation(format!("Build directory is empty: {:?}", build_path)));
        }

        Ok(())
    }

    async fn detect_start_command(&self, deployment: &Deployment) -> NebulaResult<String> {
        let build_path = &deployment.build_path;

        // Check for package.json (Node.js)
        if build_path.join("package.json").exists() {
            return Ok("npm start".to_string());
        }

        // Check for index.html (static site)
        if build_path.join("index.html").exists() {
            return Ok(format!("python -m http.server {}", deployment.config.port));
        }

        // Check for Dockerfile
        if build_path.join("Dockerfile").exists() {
            return Err(NebulaError::validation("Docker deployments not yet supported"));
        }

        // Default to serving static files
        Ok(format!("python -m http.server {}", deployment.config.port))
    }

    async fn wait_for_deployment_ready(&self, deployment: &Deployment) -> NebulaResult<()> {
        let url = format!("http://127.0.0.1:{}", deployment.config.port);
        
        for attempt in 1..=30 {
            match self.health_checker.check_health(&url, None).await {
                Ok(true) => {
                    debug!("Deployment {} is ready after {} attempts", deployment.name, attempt);
                    return Ok(());
                }
                Ok(false) => {
                    debug!("Deployment {} not ready yet (attempt {})", deployment.name, attempt);
                }
                Err(e) => {
                    debug!("Health check failed for deployment {} (attempt {}): {}", deployment.name, attempt, e);
                }
            }
            
            tokio::time::sleep(Duration::from_millis(1000)).await;
        }

        Err(NebulaError::deployment(format!("Deployment {} failed to become ready", deployment.name)))
    }

    async fn restart_running_deployments(&self) -> NebulaResult<()> {
        let deployment_ids: Vec<String> = {
            let deployments = self.deployments.read().await;
            deployments.values()
                .filter(|d| matches!(d.status, DeploymentStatus::Running))
                .map(|d| d.id.clone())
                .collect()
        };

        for deployment_id in deployment_ids {
            info!("Restarting deployment on scheduler startup: {}", deployment_id);
            if let Err(e) = self.start_deployment(&deployment_id).await {
                error!("Failed to restart deployment {}: {}", deployment_id, e);
                
                // Mark as failed
                if let Some(mut deployment) = self.get_deployment(&deployment_id).await {
                    deployment.status = DeploymentStatus::Failed;
                    deployment.updated_at = Utc::now();
                    
                    let mut deployments = self.deployments.write().await;
                    deployments.insert(deployment_id, deployment.clone());
                    let _ = self.save_deployment(&deployment).await;
                }
            }
        }

        Ok(())
    }

    async fn health_check_loop(&self) {
        let mut interval = tokio::time::interval(Duration::from_secs(self.config.health_check_interval as u64));
        
        loop {
            interval.tick().await;
            
            if !*self.is_running.read().await {
                break;
            }

            let deployment_ids: Vec<String> = {
                let deployments = self.deployments.read().await;
                deployments.values()
                    .filter(|d| d.status == DeploymentStatus::Running)
                    .map(|d| d.id.clone())
                    .collect()
            };

            for deployment_id in deployment_ids {
                if let Err(e) = self.perform_health_check(&deployment_id).await {
                    debug!("Health check failed for deployment {}: {}", deployment_id, e);
                }
            }
        }
    }

    async fn perform_health_check(&self, deployment_id: &str) -> NebulaResult<()> {
        let deployment = self.get_deployment(deployment_id).await
            .ok_or_else(|| NebulaError::not_found("Deployment not found"))?;

        if deployment.status != DeploymentStatus::Running {
            return Ok(());
        }

        let url = format!("http://127.0.0.1:{}", deployment.config.port);
        let health_path = deployment.config.health_check_path.as_deref();
        
        let is_healthy = self.health_checker.check_health(&url, health_path).await.unwrap_or(false);
        
        // Update health status
        {
            let mut deployments = self.deployments.write().await;
            if let Some(dep) = deployments.get_mut(deployment_id) {
                dep.health_status.last_check = Some(Utc::now());
                
                if is_healthy {
                    dep.health_status.is_healthy = true;
                    dep.health_status.consecutive_failures = 0;
                    dep.health_status.last_error = None;
                    
                    if dep.status == DeploymentStatus::Unhealthy {
                        dep.status = DeploymentStatus::Running;
                        info!("Deployment {} recovered", dep.name);
                    }
                } else {
                    dep.health_status.consecutive_failures += 1;
                    
                    if dep.health_status.consecutive_failures >= 3 {
                        dep.health_status.is_healthy = false;
                        dep.status = DeploymentStatus::Unhealthy;
                        warn!("Deployment {} marked as unhealthy", dep.name);
                        
                        // Auto-restart if policy allows
                        if matches!(dep.config.restart_policy, RestartPolicy::Always) {
                            if dep.metrics.restart_count < dep.config.max_restarts {
                                info!("Auto-restarting unhealthy deployment: {}", dep.name);
                                let deployment_id = deployment_id.to_string();
                                let scheduler = self.clone();
                                tokio::spawn(async move {
                                    let _ = scheduler.restart_deployment(&deployment_id).await;
                                });
                            }
                        }
                    }
                }
                
                dep.updated_at = Utc::now();
            }
        }

        Ok(())
    }

    async fn cleanup_loop(&self) {
        if !self.config.auto_cleanup {
            return;
        }

        let mut interval = tokio::time::interval(Duration::from_secs(3600)); // Check every hour
        
        loop {
            interval.tick().await;
            
            if !*self.is_running.read().await {
                break;
            }

            if let Err(e) = self.cleanup_old_deployments().await {
                warn!("Cleanup failed: {}", e);
            }
        }
    }

    async fn cleanup_old_deployments(&self) -> NebulaResult<()> {
        let cutoff_date = Utc::now() - chrono::Duration::days(self.config.cleanup_after_days as i64);
        let mut to_remove = Vec::new();
        
        {
            let deployments = self.deployments.read().await;
            for (id, deployment) in deployments.iter() {
                if deployment.updated_at < cutoff_date && 
                   matches!(deployment.status, DeploymentStatus::Stopped | DeploymentStatus::Failed) {
                    to_remove.push(id.clone());
                }
            }
        }
        
        for id in to_remove {
            info!("Auto-cleaning old deployment: {}", id);
            if let Err(e) = self.delete_deployment(&id).await {
                warn!("Failed to auto-cleanup deployment {}: {}", id, e);
            }
        }
        
        Ok(())
    }
}

impl HealthChecker {
    fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        
        Self { client }
    }

    async fn check_health(&self, base_url: &str, health_path: Option<&str>) -> NebulaResult<bool> {
        let url = if let Some(path) = health_path {
            format!("{}{}", base_url, path)
        } else {
            base_url.to_string()
        };

        match self.client.get(&url).send().await {
            Ok(response) => Ok(response.status().is_success()),
            Err(_) => Ok(false),
        }
    }
}

// Default implementations
impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            port: 0, // Will be auto-assigned
            https_enabled: true,
            auto_ssl: true,
            environment_vars: HashMap::new(),
            health_check_path: Some("/health".to_string()),
            health_check_interval: 30,
            health_check_timeout: 10,
            restart_policy: RestartPolicy::Always,
            max_restarts: 5,
            startup_timeout: 60,
            shutdown_timeout: 30,
            resource_limits: ResourceLimits::default(),
        }
    }
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory_mb: Some(512),
            cpu_percent: Some(50),
            disk_mb: Some(1024),
        }
    }
}

impl Default for DeploymentMetrics {
    fn default() -> Self {
        Self {
            start_count: 0,
            restart_count: 0,
            last_restart: None,
            uptime_seconds: 0,
            request_count: 0,
            error_count: 0,
            cpu_usage: 0.0,
            memory_usage: 0.0,
        }
    }
}

impl Default for HealthStatus {
    fn default() -> Self {
        Self {
            is_healthy: true,
            last_check: None,
            consecutive_failures: 0,
            last_error: None,
        }
    }
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            storage_path: dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("nebula")
                .join("scheduler"),
            default_tld: "xyz".to_string(),
            max_concurrent_deployments: 10,
            auto_cleanup: true,
            cleanup_after_days: 30,
            health_check_interval: 30,
            deployment_timeout: 300,
            proxy_config: ProxyConfig::default(),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            enable_compression: true,
            enable_caching: false,
            cache_ttl: 3600,
            max_body_size: 100 * 1024 * 1024, // 100MB
            timeout: 30,
        }
    }
}
