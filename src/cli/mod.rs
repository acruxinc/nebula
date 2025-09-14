use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::error::{NebulaError, Result};

pub mod commands;
pub mod config;

pub use config::*;

#[derive(Parser)]
#[command(name = "nebula")]
#[command(about = "Cross-platform universal development and production server")]
#[command(version)]
#[command(author)]
pub struct Cli {
    /// Domain to serve (e.g., myapp.dev)
    #[arg(short, long, default_value = "app.nebula.com")]
    pub domain: String,

    /// HTTP port (0 = auto-assign)
    #[arg(long, default_value = "3000")]
    pub http_port: u16,

    /// HTTPS port (0 = auto-assign)
    #[arg(long, default_value = "3443")]
    pub https_port: u16,

    /// Command to run for development server
    #[arg(short, long)]
    pub dev_command: Option<String>,

    /// Project directory
    #[arg(short, long)]
    pub project_dir: Option<PathBuf>,

    /// Configuration file
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Verbose logging
    #[arg(short, long)]
    pub verbose: bool,

    /// Log file path
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Force regenerate certificates
    #[arg(long)]
    pub force_certs: bool,

    /// Disable built-in DNS server
    #[arg(long)]
    pub no_dns: bool,

    /// Disable built-in DHCP server
    #[arg(long)]
    pub no_dhcp: bool,

    /// Enable hot reload
    #[arg(long)]
    pub hot_reload: bool,

    /// Dry run mode (don't actually start services)
    #[arg(long)]
    pub dry_run: bool,

    /// Working directory
    #[arg(long)]
    pub work_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub subcommand: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize Nebula in current directory
    Init {
        /// Template to use
        #[arg(long)]
        template: Option<String>,
        
        /// Skip auto-detection
        #[arg(long)]
        no_detect: bool,
        
        /// Force overwrite existing config
        #[arg(long)]
        force: bool,
    },
    
    /// Install system dependencies and setup
    Setup {
        /// Skip system package installation
        #[arg(long)]
        no_packages: bool,
        
        /// Skip DNS configuration
        #[arg(long)]
        no_dns_setup: bool,
        
        /// Skip firewall setup
        #[arg(long)]
        no_firewall: bool,
    },
    
    /// Start the development server
    Start {
        /// Background mode
        #[arg(short, long)]
        daemon: bool,
        
        /// PID file for daemon mode
        #[arg(long)]
        pid_file: Option<PathBuf>,
    },
    
    /// Stop the development server
    Stop {
        /// PID file location
        #[arg(long)]
        pid_file: Option<PathBuf>,
        
        /// Force kill
        #[arg(long)]
        force: bool,
    },
    
    /// Show server status
    Status {
        /// Output format (text, json)
        #[arg(long, default_value = "text")]
        format: String,
    },
    
    /// Manage certificates
    Cert {
        #[command(subcommand)]
        action: CertCommands,
    },
    
    /// Manage DNS configuration
    Dns {
        #[command(subcommand)]
        action: DnsCommands,
    },
    
    /// Clean up Nebula files
    Clean {
        /// Also remove certificates
        #[arg(long)]
        certs: bool,
        
        /// Also remove logs
        #[arg(long)]
        logs: bool,
        
        /// Remove everything
        #[arg(long)]
        all: bool,
    },
    
    /// Manage production deployments
    Deploy {
        #[command(subcommand)]
        action: DeployCommands,
    },
    
    /// Show configuration
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
    
    /// Health check
    Health {
        /// Check specific component
        #[arg(long)]
        component: Option<String>,
        
        /// Timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,
    },
}

#[derive(Subcommand)]
pub enum CertCommands {
    /// Generate new certificates
    Generate { 
        domain: String,
        
        /// Generate wildcard certificate
        #[arg(long)]
        wildcard: bool,
        
        /// Certificate validity in days
        #[arg(long, default_value = "365")]
        validity_days: u32,
    },
    
    /// List existing certificates
    List {
        /// Show expired certificates
        #[arg(long)]
        show_expired: bool,
        
        /// Output format
        #[arg(long, default_value = "table")]
        format: String,
    },
    
    /// Remove certificates
    Remove { 
        domain: String,
        
        /// Remove all certificates for domain
        #[arg(long)]
        all: bool,
    },
    
    /// Install root CA
    InstallCa {
        /// Trust store to use
        #[arg(long)]
        store: Option<String>,
    },
    
    /// Remove root CA
    RemoveCa,
    
    /// Verify certificate
    Verify { domain: String },
    
    /// Renew certificates
    Renew {
        /// Renew all certificates
        #[arg(long)]
        all: bool,
        
        /// Days before expiry to renew
        #[arg(long, default_value = "30")]
        days_before: u32,
    },
}

#[derive(Subcommand)]
pub enum DnsCommands {
    /// Add DNS entry
    Add { 
        domain: String, 
        ip: String,
        
        /// Record type
        #[arg(long, default_value = "A")]
        record_type: String,
        
        /// TTL in seconds
        #[arg(long, default_value = "300")]
        ttl: u32,
    },
    
    /// Remove DNS entry
    Remove { 
        domain: String,
        
        /// Remove all records for domain
        #[arg(long)]
        all: bool,
    },
    
    /// List DNS entries
    List {
        /// Filter by domain pattern
        #[arg(long)]
        filter: Option<String>,
        
        /// Output format
        #[arg(long, default_value = "table")]
        format: String,
    },
    
    /// Test DNS resolution
    Test { 
        domain: String,
        
        /// Use specific DNS server
        #[arg(long)]
        server: Option<String>,
        
        /// Record type to query
        #[arg(long, default_value = "A")]
        record_type: String,
    },
    
    /// Flush DNS cache
    Flush,
    
    /// DNS server statistics
    Stats,
}

#[derive(Subcommand)]
pub enum DeployCommands {
    /// Create a new deployment
    Create {
        name: String,
        build_path: PathBuf,
        
        #[arg(long)]
        tld: Option<String>,
        
        #[arg(long)]
        port: Option<u16>,
        
        /// Environment variables
        #[arg(long)]
        env: Vec<String>,
        
        /// Health check endpoint
        #[arg(long)]
        health_check: Option<String>,
        
        /// Auto-start after creation
        #[arg(long)]
        start: bool,
    },
    
    /// Start a deployment
    Start { 
        deployment_id: String,
        
        /// Wait for deployment to be ready
        #[arg(long)]
        wait: bool,
        
        /// Timeout for wait
        #[arg(long, default_value = "60")]
        timeout: u64,
    },
    
    /// Stop a deployment
    Stop { 
        deployment_id: String,
        
        /// Force stop
        #[arg(long)]
        force: bool,
    },
    
    /// List all deployments
    List {
        /// Filter by status
        #[arg(long)]
        status: Option<String>,
        
        /// Output format
        #[arg(long, default_value = "table")]
        format: String,
    },
    
    /// Show deployment details
    Show { 
        deployment_id: String,
        
        /// Follow logs
        #[arg(long)]
        follow: bool,
    },
    
    /// Delete a deployment
    Delete { 
        deployment_id: String,
        
        /// Force delete without confirmation
        #[arg(long)]
        force: bool,
    },
    
    /// Update deployment configuration
    Update {
        deployment_id: String,
        
        #[arg(long)]
        port: Option<u16>,
        
        /// Environment variables to add/update
        #[arg(long)]
        env: Vec<String>,
        
        /// Environment variables to remove
        #[arg(long)]
        remove_env: Vec<String>,
    },
    
    /// Restart deployment
    Restart { deployment_id: String },
    
    /// Scale deployment
    Scale { 
        deployment_id: String, 
        replicas: u32,
    },
    
    /// Show deployment logs
    Logs { 
        deployment_id: String,
        
        /// Follow logs
        #[arg(short, long)]
        follow: bool,
        
        /// Number of lines to show
        #[arg(long, default_value = "100")]
        lines: usize,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Show current configuration
    Show {
        /// Configuration section to show
        section: Option<String>,
        
        /// Output format
        #[arg(long, default_value = "toml")]
        format: String,
    },
    
    /// Validate configuration
    Validate {
        /// Configuration file to validate
        file: Option<PathBuf>,
    },
    
    /// Set configuration value
    Set {
        key: String,
        value: String,
    },
    
    /// Get configuration value
    Get {
        key: String,
    },
    
    /// Reset configuration to defaults
    Reset {
        /// Confirm reset
        #[arg(long)]
        confirm: bool,
    },
}

impl Cli {
    /// Convert CLI arguments to NebulaConfig
    pub async fn into_config(self) -> Result<NebulaConfig> {
        let project_dir = self.project_dir
            .or_else(|| self.work_dir.clone())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

        // Change to project directory
        if project_dir != std::env::current_dir().unwrap_or_default() {
            std::env::set_current_dir(&project_dir)
                .map_err(|e| NebulaError::config(format!("Failed to change directory: {}", e)))?;
        }

        // Load configuration from file if it exists
        let config_path = self.config
            .or_else(|| {
                let nebula_config = project_dir.join("nebula.toml");
                if nebula_config.exists() {
                    Some(nebula_config)
                } else {
                    None
                }
            });

        let mut config = if let Some(config_path) = config_path {
            NebulaConfig::load_from_file(&config_path).await?
        } else {
            NebulaConfig::default()
        };

        // Override with CLI arguments
        if self.domain != "app.nebula.com" {
            config.domain = self.domain;
        }
        
        if self.http_port != 3000 {
            config.http_port = self.http_port;
        }
        
        if self.https_port != 3443 {
            config.https_port = self.https_port;
        }

        if let Some(dev_command) = self.dev_command {
            config.dev_command = dev_command;
        }

        config.project_dir = Some(project_dir);
        config.force_certs = self.force_certs;
        config.no_dns = self.no_dns;
        config.no_dhcp = self.no_dhcp;
        config.hot_reload = self.hot_reload;
        config.dry_run = self.dry_run;

        // Validate configuration
        config.validate()?;

        Ok(config)
    }
    
    /// Get the effective project directory
    pub fn get_project_dir(&self) -> PathBuf {
        self.project_dir
            .clone()
            .or_else(|| self.work_dir.clone())
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    }
}
