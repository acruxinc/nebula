use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::fs;

use crate::cli::NebulaConfig;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigManager {
    config_path: PathBuf,
    config: NebulaConfig,
}

impl ConfigManager {
    pub fn new(config_path: Option<PathBuf>) -> Result<Self> {
        let config_path = config_path.unwrap_or_else(|| PathBuf::from("nebula.toml"));
        
        let config = if config_path.exists() {
            Self::load_from_file(&config_path)?
        } else {
            NebulaConfig::default()
        };

        Ok(Self {
            config_path,
            config,
        })
    }

    pub fn load_from_file(path: &PathBuf) -> Result<NebulaConfig> {
        let content = fs::read_to_string(path)?;
        let config: NebulaConfig = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn save_to_file(&self) -> Result<()> {
        let content = toml::to_string_pretty(&self.config)?;
        fs::write(&self.config_path, content)?;
        Ok(())
    }

    pub fn get_config(&self) -> &NebulaConfig {
        &self.config
    }

    pub fn update_config<F>(&mut self, updater: F) -> Result<()>
    where
        F: FnOnce(&mut NebulaConfig),
    {
        updater(&mut self.config);
        self.save_to_file()
    }
}

impl Default for NebulaConfig {
    fn default() -> Self {
        Self {
            domain: "app.dev".to_string(),
            http_port: 3000,
            https_port: 3443,
            dev_command: "npm run dev".to_string(),
            project_dir: None,
            force_certs: false,
            no_dns: false,
            no_dhcp: true, // DHCP disabled by default
            hot_reload: true,
            mode: crate::cli::RunMode::Dev,
            tls: crate::cli::TlsConfig::default(),
            dns: crate::cli::DnsConfig::default(),
            dhcp: crate::cli::DhcpConfig::default(),
            scheduler: crate::cli::SchedulerConfig::default(),
        }
    }
}
