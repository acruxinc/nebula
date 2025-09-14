use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;
use tracing::{info, debug};

use crate::cli::NebulaConfig;
use crate::error::{NebulaError, Result as NebulaResult};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigManager {
    config_path: PathBuf,
    config: NebulaConfig,
    backup_path: Option<PathBuf>,
}

impl ConfigManager {
    pub fn new(config_path: Option<PathBuf>) -> NebulaResult<Self> {
        let config_path = config_path.unwrap_or_else(|| PathBuf::from("nebula.toml"));
        
        let config = if config_path.exists() {
            Self::load_from_file(&config_path)?
        } else {
            NebulaConfig::default()
        };

        Ok(Self {
            config_path: config_path.clone(),
            config,
            backup_path: Some(config_path.with_extension("toml.backup")),
        })
    }

    pub fn load_from_file(path: &PathBuf) -> NebulaResult<NebulaConfig> {
        let content = fs::read_to_string(path)
            .map_err(|e| NebulaError::config(format!("Failed to read config file {:?}: {}", path, e)))?;
        
        let config: NebulaConfig = toml::from_str(&content)
            .map_err(|e| NebulaError::config(format!("Failed to parse config file {:?}: {}", path, e)))?;
        
        // Validate the configuration
        config.validate()?;
        
        debug!("Loaded configuration from {:?}", path);
        Ok(config)
    }

    pub fn save_to_file(&self) -> NebulaResult<()> {
        // Create backup if file exists
        if self.config_path.exists() && self.backup_path.is_some() {
            let backup_path = self.backup_path.as_ref().unwrap();
            if let Err(e) = fs::copy(&self.config_path, backup_path) {
                debug!("Failed to create backup: {}", e);
            }
        }

        // Validate before saving
        self.config.validate()?;

        let content = toml::to_string_pretty(&self.config)
            .map_err(|e| NebulaError::config(format!("Failed to serialize config: {}", e)))?;
        
        // Create parent directory if it doesn't exist
        if let Some(parent) = self.config_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| NebulaError::config(format!("Failed to create config directory: {}", e)))?;
        }
        
        fs::write(&self.config_path, content)
            .map_err(|e| NebulaError::config(format!("Failed to write config file: {}", e)))?;
        
        info!("Configuration saved to {:?}", self.config_path);
        Ok(())
    }

    pub fn get_config(&self) -> &NebulaConfig {
        &self.config
    }

    pub fn get_config_mut(&mut self) -> &mut NebulaConfig {
        &mut self.config
    }

    pub fn update_config<F>(&mut self, updater: F) -> NebulaResult<()>
    where
        F: FnOnce(&mut NebulaConfig),
    {
        updater(&mut self.config);
        self.config.validate()?;
        self.save_to_file()
    }

    pub fn set_domain(&mut self, domain: String) -> NebulaResult<()> {
        self.config.domain = domain;
        self.save_to_file()
    }

    pub fn set_http_port(&mut self, port: u16) -> NebulaResult<()> {
        self.config.http_port = port;
        self.save_to_file()
    }

    pub fn set_https_port(&mut self, port: u16) -> NebulaResult<()> {
        self.config.https_port = port;
        self.save_to_file()
    }

    pub fn set_dev_command(&mut self, command: String) -> NebulaResult<()> {
        self.config.dev_command = command;
        self.save_to_file()
    }

    pub fn enable_dns(&mut self, enabled: bool) -> NebulaResult<()> {
        self.config.dns.enabled = enabled;
        self.save_to_file()
    }

    pub fn enable_dhcp(&mut self, enabled: bool) -> NebulaResult<()> {
        self.config.dhcp.enabled = enabled;
        self.save_to_file()
    }

    pub fn enable_hot_reload(&mut self, enabled: bool) -> NebulaResult<()> {
        self.config.hot_reload = enabled;
        self.save_to_file()
    }

    pub fn add_environment_variable(&mut self, key: String, value: String) -> NebulaResult<()> {
        self.config.environment.insert(key, value);
        self.save_to_file()
    }

    pub fn remove_environment_variable(&mut self, key: &str) -> NebulaResult<()> {
        self.config.environment.remove(key);
        self.save_to_file()
    }

    pub fn set_log_level(&mut self, level: String) -> NebulaResult<()> {
        // Validate log level
        match level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {
                self.config.logging.level = level;
                self.save_to_file()
            }
            _ => Err(NebulaError::validation(format!("Invalid log level: {}", level)))
        }
    }

    pub fn reset_to_defaults(&mut self) -> NebulaResult<()> {
        self.config = NebulaConfig::default();
        self.save_to_file()
    }

    pub fn restore_from_backup(&mut self) -> NebulaResult<()> {
        if let Some(ref backup_path) = self.backup_path {
            if backup_path.exists() {
                self.config = Self::load_from_file(backup_path)?;
                self.save_to_file()?;
                info!("Configuration restored from backup");
                return Ok(());
            }
        }
        Err(NebulaError::not_found("No backup file found"))
    }

    pub fn get_config_path(&self) -> &PathBuf {
        &self.config_path
    }

    pub fn has_backup(&self) -> bool {
        self.backup_path.as_ref().map_or(false, |p| p.exists())
    }

    pub fn export_config(&self, export_path: &PathBuf) -> NebulaResult<()> {
        let content = toml::to_string_pretty(&self.config)
            .map_err(|e| NebulaError::config(format!("Failed to serialize config: {}", e)))?;
        
        fs::write(export_path, content)
            .map_err(|e| NebulaError::config(format!("Failed to export config: {}", e)))?;
        
        info!("Configuration exported to {:?}", export_path);
        Ok(())
    }

    pub fn import_config(&mut self, import_path: &PathBuf) -> NebulaResult<()> {
        self.config = Self::load_from_file(import_path)?;
        self.save_to_file()?;
        info!("Configuration imported from {:?}", import_path);
        Ok(())
    }

    pub fn validate_current_config(&self) -> NebulaResult<()> {
        self.config.validate()
    }

    pub fn merge_config(&mut self, other: NebulaConfig) -> NebulaResult<()> {
        self.config.merge(&other);
        self.config.validate()?;
        self.save_to_file()
    }

    pub fn get_effective_project_dir(&self) -> PathBuf {
        self.config.get_project_dir()
    }

    pub fn is_development_mode(&self) -> bool {
        self.config.is_development()
    }

    pub fn is_production_mode(&self) -> bool {
        self.config.is_production()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_config_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");
        
        let manager = ConfigManager::new(Some(config_path));
        assert!(manager.is_ok(), "Should create config manager");
    }

    #[test]
    fn test_config_save_and_load() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");
        
        let mut manager = ConfigManager::new(Some(config_path.clone())).unwrap();
        manager.set_domain("test.example.com".to_string()).unwrap();
        
        // Create new manager to test loading
        let loaded_manager = ConfigManager::new(Some(config_path)).unwrap();
        assert_eq!(loaded_manager.get_config().domain, "test.example.com");
    }

    #[test]
    fn test_config_validation() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");
        
        let mut manager = ConfigManager::new(Some(config_path)).unwrap();
        
        // Test invalid domain
        let result = manager.set_domain("".to_string());
        assert!(result.is_err(), "Should reject empty domain");
    }

    #[test]
    fn test_environment_variables() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");
        
        let mut manager = ConfigManager::new(Some(config_path)).unwrap();
        
        manager.add_environment_variable("TEST_VAR".to_string(), "test_value".to_string()).unwrap();
        assert_eq!(manager.get_config().environment.get("TEST_VAR"), Some(&"test_value".to_string()));
        
        manager.remove_environment_variable("TEST_VAR").unwrap();
        assert_eq!(manager.get_config().environment.get("TEST_VAR"), None);
    }

    #[test]
    fn test_backup_and_restore() {
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");
        
        let mut manager = ConfigManager::new(Some(config_path)).unwrap();
        manager.set_domain("original.com".to_string()).unwrap();
        
        // Modify config
        manager.set_domain("modified.com".to_string()).unwrap();
        
        // Restore from backup
        if manager.has_backup() {
            manager.restore_from_backup().unwrap();
            assert_eq!(manager.get_config().domain, "original.com");
        }
    }
}
