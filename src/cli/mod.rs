use clap::{Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "nebula")]
#[command(about = "Cross-platform local development server")]
pub struct Cli {
    /// Domain to serve (e.g., myapp.dev)
    #[arg(short, long, default_value = "app.dev")]
    pub domain: String,

    /// HTTP port (0 = auto-assign)
    #[arg(long, default_value = "3000")]
    pub http_port: u16,

    /// HTTPS port (0 = auto-assign)
    #[arg(long, default_value = "3443")]
    pub https_port: u16,

    /// Command to run for development server
    #[arg(short, long, default_value = "npm run dev")]
    pub dev_command: String,

    /// Project directory
    #[arg(short, long)]
    pub project_dir: Option<PathBuf>,

    /// Configuration file
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Verbose logging
    #[arg(short, long)]
    pub verbose: bool,

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

    #[command(subcommand)]
    pub subcommand: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize Nebula in current directory
    Init {
        #[arg(long)]
        template: Option<String>,
    },
    /// Install system dependencies
    Setup,
    /// Start the development server
    Start,
    /// Stop the development server
    Stop,
    /// Show server status
    Status,
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
    Clean,
    /// Manage production deployments
    Deploy {
        #[command(subcommand)]
        action: DeployCommands,
    },
}

#[derive(Subcommand)]
pub enum CertCommands {
    /// Generate new certificates
    Generate { domain: String },
    /// List existing certificates
    List,
    /// Remove certificates
    Remove { domain: String },
    /// Install root CA
    InstallCa,
}

#[derive(Subcommand)]
pub enum DnsCommands {
    /// Add DNS entry
    Add { domain: String, ip: String },
    /// Remove DNS entry
    Remove { domain: String },
    /// List DNS entries
    List,
    /// Test DNS resolution
    Test { domain: String },
}

#[derive(Subcommand)]
pub enum DeployCommands {
    /// Create a new deployment
    Create {
        name: String,
        build_path: String,
        #[arg(long)]
        tld: Option<String>,
        #[arg(long)]
        port: Option<u16>,
    },
    /// Start a deployment
    Start { deployment_id: String },
    /// Stop a deployment
    Stop { deployment_id: String },
    /// List all deployments
    List,
    /// Show deployment details
    Show { deployment_id: String },
    /// Delete a deployment
    Delete { deployment_id: String },
    /// Update deployment configuration
    Update {
        deployment_id: String,
        #[arg(long)]
        port: Option<u16>,
        #[arg(long)]
        env: Vec<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NebulaConfig {
    pub domain: String,
    pub http_port: u16,
    pub https_port: u16,
    pub dev_command: String,
    pub project_dir: Option<PathBuf>,
    pub force_certs: bool,
    pub no_dns: bool,
    pub no_dhcp: bool,
    pub hot_reload: bool,
    pub mode: RunMode,
    pub tls: TlsConfig,
    pub dns: DnsConfig,
    pub dhcp: DhcpConfig,
    pub scheduler: SchedulerConfig,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RunMode {
    Dev,
    Prod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    pub enabled: bool,
    pub default_tld: String,
    pub dev_tld: String,
    pub storage_path: PathBuf,
    pub max_concurrent_deployments: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_dir: PathBuf,
    pub auto_generate: bool,
    pub ca_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enabled: bool,
    pub port: u16,
    pub upstream: Vec<String>,
    pub cache_size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    pub enabled: bool,
    pub range_start: String,
    pub range_end: String,
    pub lease_time: u32,
}

impl From<Cli> for NebulaConfig {
    fn from(cli: Cli) -> Self {
        Self {
            domain: cli.domain,
            http_port: cli.http_port,
            https_port: cli.https_port,
            dev_command: cli.dev_command,
            project_dir: cli.project_dir,
            force_certs: cli.force_certs,
            no_dns: cli.no_dns,
            no_dhcp: cli.no_dhcp,
            hot_reload: cli.hot_reload,
            mode: RunMode::Dev,
            tls: TlsConfig::default(),
            dns: DnsConfig::default(),
            dhcp: DhcpConfig::default(),
            scheduler: SchedulerConfig::default(),
        }
    }
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            cert_dir: dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("nebula")
                .join("certs"),
            auto_generate: true,
            ca_name: "Nebula Development CA".to_string(),
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 53,
            upstream: vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
            cache_size: 1024,
        }
    }
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            range_start: "192.168.100.100".to_string(),
            range_end: "192.168.100.200".to_string(),
            lease_time: 86400, // 24 hours
        }
    }
}

impl Default for SchedulerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_tld: "xyz".to_string(),
            dev_tld: "nebula.com".to_string(),
            storage_path: dirs::data_local_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("nebula")
                .join("scheduler"),
            max_concurrent_deployments: 10,
        }
    }
}

pub mod commands;
