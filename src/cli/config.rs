use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use crate::error::{NebulaError, Result};
use std::net::IpAddr;

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
    pub dry_run: bool,
    pub mode: RunMode,
    
    #[serde(default)]
    pub tls: TlsConfig,
    
    #[serde(default)]
    pub dns: DnsConfig,
    
    #[serde(default)]
    pub dhcp: DhcpConfig,
    
    #[serde(default)]
    pub scheduler: SchedulerConfig,
    
    #[serde(default)]
    pub logging: LoggingConfig,
    
    #[serde(default)]
    pub dev: DevConfig,
    
    #[serde(default)]
    pub server: ServerConfig,
    
    #[serde(default)]
    pub environment: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RunMode {
    #[serde(rename = "dev")]
    Development,
    #[serde(rename = "prod")]
    Production,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub cert_dir: PathBuf,
    pub auto_generate: bool,
    pub ca_name: String,
    pub key_type: KeyType,
    pub validity_days: u32,
    pub auto_renew: bool,
    pub renew_days_before: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum KeyType {
    #[serde(rename = "rsa")]
    Rsa,
    #[serde(rename = "ecdsa")]
    Ecdsa,
    #[serde(rename = "ed25519")]
    Ed25519,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    pub enabled: bool,
    pub port: u16,
    pub bind_address: IpAddr,
    pub upstream: Vec<String>,
    pub cache_size: usize,
    pub cache_ttl: u32,
    pub zones: Vec<DnsZone>,
    pub forwarding: bool,
    pub recursion: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsZone {
    pub name: String,
    pub records: Vec<DnsRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: String,
    pub data: String,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    pub enabled: bool,
    pub interface: Option<String>,
    pub range_start: String,
    pub range_end: String,
    pub lease_time: u32,
    pub renewal_time: u32,
    pub rebinding_time: u32,
    pub subnet_mask: String,
    pub router: Option<String>,
    pub dns_servers: Vec<String>,
    pub domain_name: Option<String>,
    pub static_leases: Vec<StaticLease>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticLease {
    pub mac: String,
    pub ip: String,
    pub hostname: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchedulerConfig {
    pub enabled: bool,
    pub default_tld: String,
    pub dev_tld: String,
    pub storage_path: PathBuf,
    pub max_concurrent_deployments: usize,
    pub auto_cleanup: bool,
    pub cleanup_after_days: u32,
    pub health_check_interval: u32,
    pub restart_policy: RestartPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RestartPolicy {
    #[serde(rename = "always")]
    Always,
    #[serde(rename = "on-failure")]
    OnFailure,
    #[serde(rename = "never")]
    Never,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub file: Option<PathBuf>,
    pub max_size: u64,
    pub max_files: u32,
    pub format: LogFormat,
    pub enable_colors: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LogFormat {
    #[serde(rename = "text")]
    Text,
    #[serde(rename = "json")]
    Json,
    #[serde(rename = "compact")]
    Compact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevConfig {
    pub watch_patterns: Vec<String>,
    pub ignore_patterns: Vec<String>,
    pub restart_delay: u64,
    pub auto_open_browser: bool,
    pub browser_command: Option<String>,
    pub environment: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub request_timeout: u64,
    pub keep_alive_timeout: u64,
    pub max_connections: usize,
    pub worker_threads: Option<usize>,
    pub enable_http2: bool,
    pub compression: bool,
}

impl Default for NebulaConfig {
    fn default() -> Self {
        Self {
            domain: "app.nebula.com".to_string(),
            http_port: 3000,
            https_port: 3443,
            dev_command: "npm run dev".to_string(),
            project_dir: None,
            force_certs: false,
            no_dns: false,
            no_dhcp: true, // DHCP disabled by default
            hot_reload: true,
            dry_run: false,
            mode: RunMode::Development,
            tls: TlsConfig::default(),
            dns: DnsConfig::default(),
            dhcp: DhcpConfig::default(),
            scheduler: SchedulerConfig::default(),
            logging: LoggingConfig::default(),
            dev: DevConfig::default(),
            server: ServerConfig::default(),
            environment: HashMap::new(),
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
            key_type: KeyType::Ecdsa,
            validity_days: 365,
            auto_renew: true,
            renew_days_before: 30,
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 53,
            bind_address: "127.0.0.1".parse().unwrap(),
            upstream: vec!["8.8.8.8:53".to_string(), "1.1.1.1:53".to_string()],
            cache_size: 1024,
            cache_ttl: 300,
            zones: vec![],
            forwarding: true,
            recursion: true,
        }
    }
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: None,
            range_start: "192.168.100.100".to_string(),
            range_end: "192.168.100.200".to_string(),
            lease_time: 86400, // 24 hours
            renewal_time: 43200, // 12 hours
            rebinding_time: 75600, // 21 hours
            subnet_mask: "255.255.255.0".to_string(),
            router: None,
            dns_servers: vec!["127.0.0.1".to_string()],
            domain_name: Some("nebula.local".to_string()),
            static_leases: vec![],
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
            auto_cleanup: true,
            cleanup_after_days: 30,
            health_check_interval: 30,
            restart_policy: RestartPolicy::Always,
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
            file: None,
            max_size: 10 * 1024 * 1024, // 10MB
            max_files: 5,
            format: LogFormat::Text,
            enable_colors: true,
        }
    }
}

impl Default for DevConfig {
    fn default() -> Self {
        Self {
            watch_patterns: vec![
                "src/**/*".to_string(),
                "public/**/*".to_string(),
                "static/**/*".to_string(),
                "assets/**/*".to_string(),
            ],
            ignore_patterns: vec![
                "node_modules/**/*".to_string(),
                ".git/**/*".to_string(),
                "target/**/*".to_string(),
                "dist/**/*".to_string(),
                "build/**/*".to_string(),
                "*.log".to_string(),
                ".DS_Store".to_string(),
                "Thumbs.db".to_string(),
            ],
            restart_delay: 500,
            auto_open_browser: false,
            browser_command: None,
            environment: HashMap::new(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            request_timeout: 30,
            keep_alive_timeout: 60,
            max_connections: 1000,
            worker_threads: None, // Use system default
            enable_http2: true,
            compression: true,
        }
    }
}

impl NebulaConfig {
    /// Load configuration from a TOML file
    pub async fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = tokio::fs::read_to_string(path).await
            .map_err(|e| NebulaError::config(format!("Failed to read config file {:?}: {}", path, e)))?;
        
        let config: Self = toml::from_str(&content)
            .map_err(|e| NebulaError::config(format!("Failed to parse config file {:?}: {}", path, e)))?;
        
        config.validate()?;
        Ok(config)
    }
    
    /// Save configuration to a TOML file
    pub async fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        self.validate()?;
        
        let content = toml::to_string_pretty(self)
            .map_err(|e| NebulaError::config(format!("Failed to serialize config: {}", e)))?;
        
        // Create directory if it doesn't exist
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await
                .map_err(|e| NebulaError::config(format!("Failed to create config directory: {}", e)))?;
        }
        
        tokio::fs::write(path, content).await
            .map_err(|e| NebulaError::config(format!("Failed to write config file: {}", e)))?;
        
        Ok(())
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Validate domain
        if self.domain.is_empty() {
            return Err(NebulaError::config("Domain cannot be empty"));
        }
        
        if !self.domain.contains('.') {
            return Err(NebulaError::config("Domain must contain at least one dot"));
        }
        
        // Validate ports
        if self.http_port == 0 && self.https_port == 0 {
            return Err(NebulaError::config("At least one port must be specified"));
        }
        
        if self.http_port == self.https_port && self.http_port != 0 {
            return Err(NebulaError::config("HTTP and HTTPS ports cannot be the same"));
        }
        
        // Validate dev command
        if self.dev_command.is_empty() {
            return Err(NebulaError::config("Development command cannot be empty"));
        }
        
        // Validate DNS config
        if self.dns.enabled {
            if self.dns.upstream.is_empty() {
                return Err(NebulaError::config("DNS upstream servers cannot be empty when DNS is enabled"));
            }
            
            for upstream in &self.dns.upstream {
                if !upstream.contains(':') {
                    return Err(NebulaError::config(format!("Invalid upstream DNS server format: {}", upstream)));
                }
            }
        }
        
        // Validate DHCP config
        if self.dhcp.enabled {
            use std::net::Ipv4Addr;
            
            let start: Ipv4Addr = self.dhcp.range_start.parse()
                .map_err(|_| NebulaError::config(format!("Invalid DHCP range start IP: {}", self.dhcp.range_start)))?;
            
            let end: Ipv4Addr = self.dhcp.range_end.parse()
                .map_err(|_| NebulaError::config(format!("Invalid DHCP range end IP: {}", self.dhcp.range_end)))?;
            
            if start >= end {
                return Err(NebulaError::config("DHCP range start must be less than range end"));
            }
            
            let _subnet: Ipv4Addr = self.dhcp.subnet_mask.parse()
                .map_err(|_| NebulaError::config(format!("Invalid subnet mask: {}", self.dhcp.subnet_mask)))?;
        }
        
        // Validate logging config
        match self.logging.level.as_str() {
            "trace" | "debug" | "info" | "warn" | "error" => {},
            _ => return Err(NebulaError::config(format!("Invalid log level: {}", self.logging.level))),
        }
        
        Ok(())
    }
    
    /// Get the effective project directory
    pub fn get_project_dir(&self) -> PathBuf {
        self.project_dir.clone()
            .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")))
    }
    
    /// Check if running in development mode
    pub fn is_development(&self) -> bool {
        matches!(self.mode, RunMode::Development)
    }
    
    /// Check if running in production mode
    pub fn is_production(&self) -> bool {
        matches!(self.mode, RunMode::Production)
    }
    
    /// Get all environment variables (config + system)
    pub fn get_environment(&self) -> HashMap<String, String> {
        let mut env = self.environment.clone();
        
        // Add development-specific environment variables
        if self.is_development() {
            env.extend(self.dev.environment.clone());
        }
        
        // Add Nebula-specific variables
        env.insert("NEBULA_DOMAIN".to_string(), self.domain.clone());
        env.insert("NEBULA_HTTP_PORT".to_string(), self.http_port.to_string());
        env.insert("NEBULA_HTTPS_PORT".to_string(), self.https_port.to_string());
        env.insert("NEBULA_MODE".to_string(), match self.mode {
            RunMode::Development => "development".to_string(),
            RunMode::Production => "production".to_string(),
        });
        
        env
    }
    
    /// Merge with another configuration (other takes precedence)
    pub fn merge(&mut self, other: &NebulaConfig) {
        if other.domain != "app.nebula.com" {
            self.domain = other.domain.clone();
        }
        
        if other.http_port != 3000 {
            self.http_port = other.http_port;
        }
        
        if other.https_port != 3443 {
            self.https_port = other.https_port;
        }
        
        if other.dev_command != "npm run dev" {
            self.dev_command = other.dev_command.clone();
        }
        
        if other.project_dir.is_some() {
            self.project_dir = other.project_dir.clone();
        }
        
        // Merge environment variables
        self.environment.extend(other.environment.clone());
        self.dev.environment.extend(other.dev.environment.clone());
    }
}
