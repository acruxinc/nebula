use thiserror::Error;
use std::path::PathBuf;

pub type Result<T> = std::result::Result<T, NebulaError>;

#[derive(Error, Debug)]
pub enum NebulaError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Network error: {message}")]
    Network { message: String },
    
    #[error("DNS error: {0}")]
    Dns(String),
    
    #[error("DHCP error: {0}")]
    Dhcp(String),
    
    #[error("Certificate error: {0}")]
    Certificate(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Project detection failed: {reason}")]
    ProjectDetection { reason: String },
    
    #[error("Command execution failed: {command}")]
    CommandFailed { command: String },
    
    #[error("Port {port} is not available")]
    PortUnavailable { port: u16 },
    
    #[error("File not found: {path}")]
    FileNotFound { path: PathBuf },
    
    #[error("Invalid domain: {domain}")]
    InvalidDomain { domain: String },
    
    #[error("Deployment error: {0}")]
    Deployment(String),
    
    #[error("Platform error: {0}")]
    Platform(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("TOML error: {0}")]
    Toml(#[from] toml::de::Error),
    
    #[error("Join error: {0}")]
    Join(#[from] tokio::task::JoinError),
    
    #[error("Timeout error: {0}")]
    Timeout(String),
    
    #[error("Permission denied: {action}")]
    PermissionDenied { action: String },
    
    #[error("Already exists: {resource}")]
    AlreadyExists { resource: String },
    
    #[error("Not found: {resource}")]
    NotFound { resource: String },
    
    #[error("Validation error: {0}")]
    Validation(String),
}

impl NebulaError {
    pub fn network<S: Into<String>>(message: S) -> Self {
        Self::Network { message: message.into() }
    }
    
    pub fn dns<S: Into<String>>(message: S) -> Self {
        Self::Dns(message.into())
    }
    
    pub fn dhcp<S: Into<String>>(message: S) -> Self {
        Self::Dhcp(message.into())
    }
    
    pub fn certificate<S: Into<String>>(message: S) -> Self {
        Self::Certificate(message.into())
    }
    
    pub fn config<S: Into<String>>(message: S) -> Self {
        Self::Config(message.into())
    }
    
    pub fn project_detection<S: Into<String>>(reason: S) -> Self {
        Self::ProjectDetection { reason: reason.into() }
    }
    
    pub fn command_failed<S: Into<String>>(command: S) -> Self {
        Self::CommandFailed { command: command.into() }
    }
    
    pub fn port_unavailable(port: u16) -> Self {
        Self::PortUnavailable { port }
    }
    
    pub fn file_not_found<P: Into<PathBuf>>(path: P) -> Self {
        Self::FileNotFound { path: path.into() }
    }
    
    pub fn invalid_domain<S: Into<String>>(domain: S) -> Self {
        Self::InvalidDomain { domain: domain.into() }
    }
    
    pub fn deployment<S: Into<String>>(message: S) -> Self {
        Self::Deployment(message.into())
    }
    
    pub fn platform<S: Into<String>>(message: S) -> Self {
        Self::Platform(message.into())
    }
    
    pub fn timeout<S: Into<String>>(message: S) -> Self {
        Self::Timeout(message.into())
    }
    
    pub fn permission_denied<S: Into<String>>(action: S) -> Self {
        Self::PermissionDenied { action: action.into() }
    }
    
    pub fn already_exists<S: Into<String>>(resource: S) -> Self {
        Self::AlreadyExists { resource: resource.into() }
    }
    
    pub fn not_found<S: Into<String>>(resource: S) -> Self {
        Self::NotFound { resource: resource.into() }
    }
    
    pub fn validation<S: Into<String>>(message: S) -> Self {
        Self::Validation(message.into())
    }
    
    /// Check if this error is retryable
    pub fn is_retryable(&self) -> bool {
        matches!(self, 
            NebulaError::Network { .. } |
            NebulaError::Timeout(_) |
            NebulaError::Io(_)
        )
    }
    
    /// Get the error category for metrics/logging
    pub fn category(&self) -> &'static str {
        match self {
            NebulaError::Io(_) => "io",
            NebulaError::Network { .. } => "network",
            NebulaError::Dns(_) => "dns",
            NebulaError::Dhcp(_) => "dhcp",
            NebulaError::Certificate(_) => "certificate",
            NebulaError::Config(_) => "config",
            NebulaError::ProjectDetection { .. } => "project_detection",
            NebulaError::CommandFailed { .. } => "command",
            NebulaError::PortUnavailable { .. } => "port",
            NebulaError::FileNotFound { .. } => "file",
            NebulaError::InvalidDomain { .. } => "domain",
            NebulaError::Deployment(_) => "deployment",
            NebulaError::Platform(_) => "platform",
            NebulaError::Serialization(_) => "serialization",
            NebulaError::Toml(_) => "toml",
            NebulaError::Join(_) => "join",
            NebulaError::Timeout(_) => "timeout",
            NebulaError::PermissionDenied { .. } => "permission",
            NebulaError::AlreadyExists { .. } => "exists",
            NebulaError::NotFound { .. } => "not_found",
            NebulaError::Validation(_) => "validation",
        }
    }
}

// Convert common errors
impl From<hyper::Error> for NebulaError {
    fn from(err: hyper::Error) -> Self {
        NebulaError::network(err.to_string())
    }
}

impl From<trust_dns_client::error::ClientError> for NebulaError {
    fn from(err: trust_dns_client::error::ClientError) -> Self {
        NebulaError::dns(err.to_string())
    }
}

impl From<rcgen::RcgenError> for NebulaError {
    fn from(err: rcgen::RcgenError) -> Self {
        NebulaError::certificate(err.to_string())
    }
}

impl From<rustls::Error> for NebulaError {
    fn from(err: rustls::Error) -> Self {
        NebulaError::certificate(err.to_string())
    }
}

impl From<notify::Error> for NebulaError {
    fn from(err: notify::Error) -> Self {
        NebulaError::Io(std::io::Error::new(std::io::ErrorKind::Other, err))
    }
}

impl From<which::Error> for NebulaError {
    fn from(err: which::Error) -> Self {
        NebulaError::command_failed(err.to_string())
    }
}
