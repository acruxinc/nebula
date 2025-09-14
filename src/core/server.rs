use anyhow::Result;
use serde_json::json;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tracing::{info, error};

use crate::cli::NebulaConfig;

pub struct ServerState {
    pub config: NebulaConfig,
    pub ports: HashMap<String, u16>,
    pub is_running: bool,
    pub pid: Option<u32>,
}

impl ServerState {
    pub fn new(config: NebulaConfig) -> Self {
        Self {
            config,
            ports: HashMap::new(),
            is_running: false,
            pid: None,
        }
    }

    pub fn set_ports(&mut self, http_port: u16, https_port: u16) {
        self.ports.insert("http".to_string(), http_port);
        self.ports.insert("https".to_string(), https_port);
    }

    pub fn set_running(&mut self, running: bool, pid: Option<u32>) {
        self.is_running = running;
        self.pid = pid;
    }

    pub async fn save_state(&self) -> Result<()> {
        let nebula_dir = PathBuf::from(".nebula");
        fs::create_dir_all(&nebula_dir)?;

        // Save port information
        let ports_file = nebula_dir.join("ports.json");
        let ports_json = serde_json::to_string_pretty(&self.ports)?;
        fs::write(ports_file, ports_json)?;

        // Save server info
        let server_info = json!({
            "domain": self.config.domain,
            "ports": self.ports,
            "running": self.is_running,
            "pid": self.pid,
            "started_at": chrono::Utc::now().to_rfc3339()
        });

        let info_file = nebula_dir.join("server.json");
        let info_json = serde_json::to_string_pretty(&server_info)?;
        fs::write(info_file, info_json)?;

        info!("💾 Server state saved");
        Ok(())
    }

    pub async fn load_state() -> Result<Option<ServerState>> {
        let info_file = PathBuf::from(".nebula/server.json");
        
        if !info_file.exists() {
            return Ok(None);
        }

        let content = fs::read_to_string(info_file)?;
        let _server_info: serde_json::Value = serde_json::from_str(&content)?;

        // Basic state loading - you might want to expand this
        info!("📂 Loaded previous server state");
        Ok(None) // Simplified for now
    }

    pub async fn cleanup(&self) -> Result<()> {
        let nebula_dir = PathBuf::from(".nebula");
        
        if nebula_dir.exists() {
            let files_to_remove = vec!["ports.json", "server.json", "nebula.pid"];
            
            for file in files_to_remove {
                let file_path = nebula_dir.join(file);
                if file_path.exists() {
                    if let Err(e) = fs::remove_file(&file_path) {
                        error!("Failed to remove {}: {}", file, e);
                    }
                }
            }
        }

        info!("🧹 Server state cleaned up");
        Ok(())
    }
}
