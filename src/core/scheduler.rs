use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deployment {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub tld: String,
    pub build_path: PathBuf,
    pub status: DeploymentStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub config: DeploymentConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DeploymentStatus {
    Building,
    Ready,
    Running,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentConfig {
    pub port: u16,
    pub https_enabled: bool,
    pub auto_ssl: bool,
    pub environment_vars: HashMap<String, String>,
    pub health_check_path: Option<String>,
    pub restart_policy: RestartPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RestartPolicy {
    Always,
    OnFailure,
    Never,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    pub storage_path: PathBuf,
    pub default_tld: String,
    pub max_concurrent_deployments: usize,
    pub auto_cleanup: bool,
    pub cleanup_after_days: u32,
}

#[derive(Clone)]
pub struct NebulaScheduler {
    config: SchedulerConfig,
    deployments: Arc<RwLock<HashMap<String, Deployment>>>,
    running_deployments: Arc<RwLock<HashMap<String, tokio::task::JoinHandle<()>>>>,
}

impl NebulaScheduler {
    pub async fn new(config: SchedulerConfig) -> Result<Self> {
        // Ensure storage directory exists
        tokio::fs::create_dir_all(&config.storage_path).await?;
        
        let scheduler = Self {
            config,
            deployments: Arc::new(RwLock::new(HashMap::new())),
            running_deployments: Arc::new(RwLock::new(HashMap::new())),
        };
        
        // Load existing deployments
        scheduler.load_deployments().await?;
        
        Ok(scheduler)
    }

    pub async fn create_deployment(
        &self,
        name: String,
        build_path: PathBuf,
        tld: Option<String>,
        config: Option<DeploymentConfig>,
    ) -> Result<Deployment> {
        let id = Uuid::new_v4().to_string();
        let tld = tld.unwrap_or_else(|| self.config.default_tld.clone());
        let domain = format!("{}.{}", name, tld);
        
        let deployment = Deployment {
            id: id.clone(),
            name: name.clone(),
            domain,
            tld,
            build_path,
            status: DeploymentStatus::Building,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            config: config.unwrap_or_else(DeploymentConfig::default),
        };

        // Validate build path exists
        if !deployment.build_path.exists() {
            return Err(anyhow::anyhow!("Build path does not exist: {:?}", deployment.build_path));
        }

        // Check if domain is already in use
        if self.is_domain_in_use(&deployment.domain).await? {
            return Err(anyhow::anyhow!("Domain already in use: {}", deployment.domain));
        }

        // Save deployment
        self.save_deployment(&deployment).await?;
        
        let mut deployments = self.deployments.write().await;
        deployments.insert(id.clone(), deployment.clone());
        
        info!("Created deployment: {} -> {}", name, deployment.domain);
        Ok(deployment)
    }

    pub async fn start_deployment(&self, deployment_id: &str) -> Result<()> {
        let mut deployments = self.deployments.write().await;
        
        if let Some(deployment) = deployments.get_mut(deployment_id) {
            if deployment.status != DeploymentStatus::Ready && deployment.status != DeploymentStatus::Stopped {
                return Err(anyhow::anyhow!("Deployment must be in Ready or Stopped state to start"));
            }

            deployment.status = DeploymentStatus::Running;
            deployment.updated_at = chrono::Utc::now();
            
            // Start the deployment process
            let deployment_clone = deployment.clone();
            let deployment_id = deployment.id.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = Self::run_deployment(deployment).await {
                    error!("Deployment {} failed: {}", deployment_id, e);
                }
            });

            let mut running = self.running_deployments.write().await;
            running.insert(deployment_id.to_string(), handle);
            
            self.save_deployment(deployment).await?;
            info!("Started deployment: {}", deployment.name);
            
            Ok(())
        } else {
            Err(anyhow::anyhow!("Deployment not found: {}", deployment_id))
        }
    }

    pub async fn stop_deployment(&self, deployment_id: &str) -> Result<()> {
        let mut deployments = self.deployments.write().await;
        let mut running = self.running_deployments.write().await;
        
        if let Some(deployment) = deployments.get_mut(deployment_id) {
            deployment.status = DeploymentStatus::Stopped;
            deployment.updated_at = chrono::Utc::now();
            
            if let Some(handle) = running.remove(deployment_id) {
                handle.abort();
            }
            
            self.save_deployment(deployment).await?;
            info!("Stopped deployment: {}", deployment.name);
            
            Ok(())
        } else {
            Err(anyhow::anyhow!("Deployment not found: {}", deployment_id))
        }
    }

    pub async fn list_deployments(&self) -> Vec<Deployment> {
        let deployments = self.deployments.read().await;
        deployments.values().cloned().collect()
    }

    pub async fn get_deployment(&self, deployment_id: &str) -> Option<Deployment> {
        let deployments = self.deployments.read().await;
        deployments.get(deployment_id).cloned()
    }

    pub async fn delete_deployment(&self, deployment_id: &str) -> Result<()> {
        let mut deployments = self.deployments.write().await;
        let mut running = self.running_deployments.write().await;
        
        if let Some(deployment) = deployments.remove(deployment_id) {
            // Stop if running
            if deployment.status == DeploymentStatus::Running {
                if let Some(handle) = running.remove(deployment_id) {
                    handle.abort();
                }
            }
            
            // Clean up deployment files
            self.cleanup_deployment(&deployment).await?;
            
            info!("Deleted deployment: {}", deployment.name);
            Ok(())
        } else {
            Err(anyhow::anyhow!("Deployment not found: {}", deployment_id))
        }
    }

    async fn is_domain_in_use(&self, domain: &str) -> Result<bool> {
        let deployments = self.deployments.read().await;
        Ok(deployments.values().any(|d| d.domain == domain && d.status != DeploymentStatus::Stopped))
    }

    async fn save_deployment(&self, deployment: &Deployment) -> Result<()> {
        let file_path = self.config.storage_path.join(format!("{}.json", deployment.id));
        let content = serde_json::to_string_pretty(deployment)?;
        tokio::fs::write(file_path, content).await?;
        Ok(())
    }

    async fn load_deployments(&self) -> Result<()> {
        let mut deployments = HashMap::new();
        
        let mut entries = tokio::fs::read_dir(&self.config.storage_path).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.file_name().to_string_lossy().ends_with(".json") {
                let content = tokio::fs::read_to_string(entry.path()).await?;
                if let Ok(deployment) = serde_json::from_str::<Deployment>(&content) {
                    deployments.insert(deployment.id.clone(), deployment);
                }
            }
        }
        
        *self.deployments.write().await = deployments;
        info!("Loaded {} deployments", self.deployments.read().await.len());
        Ok(())
    }

    async fn cleanup_deployment(&self, deployment: &Deployment) -> Result<()> {
        let file_path = self.config.storage_path.join(format!("{}.json", deployment.id));
        if file_path.exists() {
            tokio::fs::remove_file(file_path).await?;
        }
        Ok(())
    }

    async fn run_deployment(deployment: Deployment) -> Result<()> {
        info!("Running deployment: {}", deployment.name);
        
        // Here you would implement the actual deployment logic:
        // 1. Build the application if needed
        // 2. Start the web server
        // 3. Configure reverse proxy
        // 4. Set up SSL certificates
        // 5. Monitor health checks
        
        // This is a placeholder implementation
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            // Health check logic would go here
        }
    }

    pub async fn cleanup_old_deployments(&self) -> Result<()> {
        if !self.config.auto_cleanup {
            return Ok(());
        }

        let cutoff_date = chrono::Utc::now() - chrono::Duration::days(self.config.cleanup_after_days as i64);
        let mut to_remove = Vec::new();
        
        {
            let deployments = self.deployments.read().await;
            for (id, deployment) in deployments.iter() {
                if deployment.updated_at < cutoff_date && deployment.status == DeploymentStatus::Stopped {
                    to_remove.push(id.clone());
                }
            }
        }
        
        for id in to_remove {
            if let Err(e) = self.delete_deployment(&id).await {
                warn!("Failed to cleanup deployment {}: {}", id, e);
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_scheduler_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = SchedulerConfig {
            storage_path: temp_dir.path().to_path_buf(),
            default_tld: "test".to_string(),
            max_concurrent_deployments: 5,
            auto_cleanup: false,
            cleanup_after_days: 30,
        };

        let scheduler = NebulaScheduler::new(config).await;
        assert!(scheduler.is_ok(), "Scheduler should be created successfully");
    }

    #[tokio::test]
    async fn test_deployment_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = SchedulerConfig {
            storage_path: temp_dir.path().to_path_buf(),
            default_tld: "test".to_string(),
            max_concurrent_deployments: 5,
            auto_cleanup: false,
            cleanup_after_days: 30,
        };

        let scheduler = NebulaScheduler::new(config).await.unwrap();
        
        // Create a temporary directory for build path
        let build_dir = temp_dir.path().join("build");
        std::fs::create_dir_all(&build_dir).unwrap();
        std::fs::write(build_dir.join("index.html"), "<h1>Test</h1>").unwrap();
        
        let deployment = scheduler.create_deployment(
            "test-app".to_string(),
            build_dir.clone(),
            Some("xyz".to_string()),
            None,
        ).await;
        
        assert!(deployment.is_ok(), "Should create deployment successfully");
        let deployment = deployment.unwrap();
        
        assert_eq!(deployment.name, "test-app");
        assert_eq!(deployment.domain, "test-app.xyz");
        assert_eq!(deployment.build_path, build_dir);
        assert_eq!(deployment.status, DeploymentStatus::Building);
    }

    #[tokio::test]
    async fn test_deployment_lifecycle() {
        let temp_dir = TempDir::new().unwrap();
        let config = SchedulerConfig {
            storage_path: temp_dir.path().to_path_buf(),
            default_tld: "test".to_string(),
            max_concurrent_deployments: 5,
            auto_cleanup: false,
            cleanup_after_days: 30,
        };

        let scheduler = NebulaScheduler::new(config).await.unwrap();
        
        let build_dir = temp_dir.path().join("build");
        std::fs::create_dir_all(&build_dir).unwrap();
        std::fs::write(build_dir.join("index.html"), "<h1>Test</h1>").unwrap();
        
        // Create deployment
        let deployment = scheduler.create_deployment(
            "test-app".to_string(),
            build_dir.clone(),
            None, // Use default TLD
            None,
        ).await.unwrap();
        
        assert_eq!(deployment.domain, "test-app.test"); // Default TLD
        
        // List deployments
        let deployments = scheduler.list_deployments().await;
        assert_eq!(deployments.len(), 1);
        assert_eq!(deployments[0].name, "test-app");
        
        // Get deployment by ID
        let retrieved = scheduler.get_deployment(&deployment.id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().name, "test-app");
        
        // Start deployment
        let result = scheduler.start_deployment(&deployment.id).await;
        assert!(result.is_ok(), "Should start deployment successfully");
        
        // Verify status changed
        let updated = scheduler.get_deployment(&deployment.id).await.unwrap();
        assert_eq!(updated.status, DeploymentStatus::Running);
        
        // Stop deployment
        let result = scheduler.stop_deployment(&deployment.id).await;
        assert!(result.is_ok(), "Should stop deployment successfully");
        
        // Verify status changed
        let updated = scheduler.get_deployment(&deployment.id).await.unwrap();
        assert_eq!(updated.status, DeploymentStatus::Stopped);
        
        // Delete deployment
        let result = scheduler.delete_deployment(&deployment.id).await;
        assert!(result.is_ok(), "Should delete deployment successfully");
        
        // Verify deployment is deleted
        let deployments = scheduler.list_deployments().await;
        assert_eq!(deployments.len(), 0);
    }

    #[tokio::test]
    async fn test_deployment_config() {
        let temp_dir = TempDir::new().unwrap();
        let config = SchedulerConfig {
            storage_path: temp_dir.path().to_path_buf(),
            default_tld: "test".to_string(),
            max_concurrent_deployments: 5,
            auto_cleanup: false,
            cleanup_after_days: 30,
        };

        let scheduler = NebulaScheduler::new(config).await.unwrap();
        
        let build_dir = temp_dir.path().join("build");
        std::fs::create_dir_all(&build_dir).unwrap();
        std::fs::write(build_dir.join("index.html"), "<h1>Test</h1>").unwrap();
        
        // Create deployment with custom config
        let deploy_config = DeploymentConfig {
            port: 8080,
            https_enabled: true,
            auto_ssl: true,
            environment_vars: {
                let mut env = std::collections::HashMap::new();
                env.insert("NODE_ENV".to_string(), "production".to_string());
                env
            },
            health_check_path: Some("/health".to_string()),
            restart_policy: RestartPolicy::Always,
        };
        
        let deployment = scheduler.create_deployment(
            "test-app".to_string(),
            build_dir.clone(),
            Some("prod".to_string()),
            Some(deploy_config),
        ).await.unwrap();
        
        assert_eq!(deployment.config.port, 8080);
        assert!(deployment.config.https_enabled);
        assert!(deployment.config.auto_ssl);
        assert_eq!(deployment.config.environment_vars.get("NODE_ENV"), Some(&"production".to_string()));
        assert_eq!(deployment.config.health_check_path, Some("/health".to_string()));
        assert!(matches!(deployment.config.restart_policy, RestartPolicy::Always));
    }

    #[tokio::test]
    async fn test_deployment_validation() {
        let temp_dir = TempDir::new().unwrap();
        let config = SchedulerConfig {
            storage_path: temp_dir.path().to_path_buf(),
            default_tld: "test".to_string(),
            max_concurrent_deployments: 5,
            auto_cleanup: false,
            cleanup_after_days: 30,
        };

        let scheduler = NebulaScheduler::new(config).await.unwrap();
        
        // Test creating deployment with non-existent build path
        let result = scheduler.create_deployment(
            "test-app".to_string(),
            PathBuf::from("/non/existent/path"),
            None,
            None,
        ).await;
        
        assert!(result.is_err(), "Should reject deployment with non-existent build path");
    }

    #[tokio::test]
    async fn test_deployment_domain_conflict() {
        let temp_dir = TempDir::new().unwrap();
        let config = SchedulerConfig {
            storage_path: temp_dir.path().to_path_buf(),
            default_tld: "test".to_string(),
            max_concurrent_deployments: 5,
            auto_cleanup: false,
            cleanup_after_days: 30,
        };

        let scheduler = NebulaScheduler::new(config).await.unwrap();
        
        let build_dir = temp_dir.path().join("build");
        std::fs::create_dir_all(&build_dir).unwrap();
        std::fs::write(build_dir.join("index.html"), "<h1>Test</h1>").unwrap();
        
        // Create first deployment
        let deployment1 = scheduler.create_deployment(
            "test-app".to_string(),
            build_dir.clone(),
            Some("xyz".to_string()),
            None,
        ).await.unwrap();
        
        // Try to create second deployment with same domain
        let result = scheduler.create_deployment(
            "another-app".to_string(),
            build_dir.clone(),
            Some("xyz".to_string()),
            None,
        ).await;
        
        // This should work since we're using different names
        assert!(result.is_ok(), "Should allow different app names with same TLD");
        
        // Try to create deployment with same name and TLD
        let result = scheduler.create_deployment(
            "test-app".to_string(),
            build_dir.clone(),
            Some("xyz".to_string()),
            None,
        ).await;
        
        assert!(result.is_err(), "Should reject deployment with duplicate domain");
    }

    #[tokio::test]
    async fn test_default_configs() {
        let deploy_config = DeploymentConfig::default();
        assert_eq!(deploy_config.port, 3000);
        assert!(deploy_config.https_enabled);
        assert!(deploy_config.auto_ssl);
        assert!(deploy_config.environment_vars.is_empty());
        assert_eq!(deploy_config.health_check_path, Some("/health".to_string()));
        assert!(matches!(deploy_config.restart_policy, RestartPolicy::Always));
        
        let scheduler_config = SchedulerConfig::default();
        assert_eq!(scheduler_config.default_tld, "xyz");
        assert_eq!(scheduler_config.max_concurrent_deployments, 10);
        assert!(scheduler_config.auto_cleanup);
        assert_eq!(scheduler_config.cleanup_after_days, 30);
    }

    #[tokio::test]
    async fn test_concurrent_deployments() {
        let temp_dir = TempDir::new().unwrap();
        let config = SchedulerConfig {
            storage_path: temp_dir.path().to_path_buf(),
            default_tld: "test".to_string(),
            max_concurrent_deployments: 3,
            auto_cleanup: false,
            cleanup_after_days: 30,
        };

        let scheduler = NebulaScheduler::new(config).await.unwrap();
        
        // Create multiple deployments concurrently
        let mut handles = vec![];
        for i in 0..3 {
            let scheduler_clone = scheduler.clone();
            let build_dir = temp_dir.path().join(format!("build{}", i));
            std::fs::create_dir_all(&build_dir).unwrap();
            std::fs::write(build_dir.join("index.html"), format!("<h1>Test {}</h1>", i)).unwrap();
            
            let handle = tokio::spawn(async move {
                scheduler_clone.create_deployment(
                    format!("test-app-{}", i),
                    build_dir,
                    Some("test".to_string()),
                    None,
                ).await
            });
            handles.push(handle);
        }
        
        // Wait for all deployments to complete
        let mut results = vec![];
        for handle in handles {
            let result = handle.await.unwrap();
            assert!(result.is_ok(), "Concurrent deployment creation should work");
            results.push(result.unwrap());
        }
        
        // Verify all deployments were created
        let deployments = scheduler.list_deployments().await;
        assert_eq!(deployments.len(), 3);
        
        // Clean up
        for deployment in results {
            let _ = scheduler.delete_deployment(&deployment.id).await;
        }
    }
}

impl Default for DeploymentConfig {
    fn default() -> Self {
        Self {
            port: 3000,
            https_enabled: true,
            auto_ssl: true,
            environment_vars: HashMap::new(),
            health_check_path: Some("/health".to_string()),
            restart_policy: RestartPolicy::Always,
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
        }
    }
}
