# Core API Reference

This document provides a comprehensive reference for Nebula's core API, including data structures, functions, and interfaces.

## Core Data Structures

### NebulaServer

The main server instance that orchestrates all Nebula services.

```rust
pub struct NebulaServer {
    pub config: Arc<RwLock<NebulaConfig>>,
    pub dns_server: Option<Arc<DnsServer>>,
    pub dhcp_server: Option<Arc<DhcpServer>>,
    pub cert_manager: Arc<CertificateManager>,
    pub scheduler: Option<Arc<NebulaScheduler>>,
    pub shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl NebulaServer {
    pub async fn new(config: NebulaConfig) -> Result<Self>;
    pub async fn run(&self) -> Result<()>;
    pub async fn shutdown(&self) -> Result<()>;
    pub fn is_running(&self) -> bool;
}
```

### NebulaConfig

Configuration structure containing all server settings.

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NebulaConfig {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub dns: DnsConfig,
    pub dhcp: DhcpConfig,
    pub scheduler: SchedulerConfig,
    pub logging: LoggingConfig,
    pub dev: DevConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub domain: String,
    pub http_port: u16,
    pub https_port: u16,
    pub dev_command: String,
    pub hot_reload: bool,
    pub mode: RunMode,
    pub request_timeout: u64,
    pub keep_alive_timeout: u64,
    pub max_connections: usize,
    pub enable_http2: bool,
    pub compression: bool,
}
```

### RunMode

Enumeration of server operation modes.

```rust
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum RunMode {
    Dev,
    Prod,
}
```

## Error Handling

### NebulaError

Main error type for all Nebula operations.

```rust
#[derive(thiserror::Error, Debug)]
pub enum NebulaError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Certificate error: {0}")]
    Certificate(String),
    
    #[error("DNS error: {0}")]
    Dns(String),
    
    #[error("DHCP error: {0}")]
    Dhcp(String),
    
    #[error("Scheduler error: {0}")]
    Scheduler(String),
    
    #[error("Process error: {0}")]
    Process(String),
}

pub type Result<T> = std::result::Result<T, NebulaError>;
```

## Configuration Management

### Configuration Loading

```rust
impl NebulaConfig {
    pub async fn from_file(path: &Path) -> Result<Self>;
    pub async fn from_cli(cli: &Cli) -> Result<Self>;
    pub async fn save_to_file(&self, path: &Path) -> Result<()>;
    pub fn validate(&self) -> Result<()>;
}
```

### Configuration Validation

```rust
impl NebulaConfig {
    fn validate_server_config(&self) -> Result<()>;
    fn validate_tls_config(&self) -> Result<()>;
    fn validate_dns_config(&self) -> Result<()>;
    fn validate_dhcp_config(&self) -> Result<()>;
}
```

## Process Management

### Process Lifecycle

```rust
pub struct ProcessManager {
    processes: HashMap<String, Child>,
    config: Arc<RwLock<NebulaConfig>>,
}

impl ProcessManager {
    pub async fn start_process(&mut self, name: &str, command: &str) -> Result<()>;
    pub async fn stop_process(&mut self, name: &str) -> Result<()>;
    pub async fn restart_process(&mut self, name: &str) -> Result<()>;
    pub fn is_process_running(&self, name: &str) -> bool;
    pub async fn get_process_output(&self, name: &str) -> Result<String>;
}
```

### Hot Reload

```rust
pub struct HotReloadManager {
    watcher: RecommendedWatcher,
    config: Arc<RwLock<NebulaConfig>>,
    restart_tx: tokio::sync::mpsc::UnboundedSender<String>,
}

impl HotReloadManager {
    pub async fn start(&mut self) -> Result<()>;
    pub async fn stop(&mut self) -> Result<()>;
    pub fn add_watch_path(&mut self, path: &Path) -> Result<()>;
    pub fn remove_watch_path(&mut self, path: &Path) -> Result<()>;
}
```

## Utility Functions

### File Operations

```rust
pub mod file_utils {
    pub async fn read_file_to_string(path: &Path) -> Result<String>;
    pub async fn write_string_to_file(path: &Path, content: &str) -> Result<()>;
    pub fn ensure_dir_exists(path: &Path) -> Result<()>;
    pub fn is_file_readable(path: &Path) -> bool;
    pub fn get_file_size(path: &Path) -> Result<u64>;
    pub fn get_file_mtime(path: &Path) -> Result<SystemTime>;
}
```

### Network Utilities

```rust
pub mod network_utils {
    pub fn is_port_available(port: u16) -> bool;
    pub fn find_available_port(start: u16, end: u16) -> Option<u16>;
    pub fn get_local_ip() -> Result<IpAddr>;
    pub fn resolve_hostname(hostname: &str) -> Result<IpAddr>;
    pub fn test_connection(host: &str, port: u16) -> Result<()>;
}
```

### String Utilities

```rust
pub mod string_utils {
    pub fn expand_home_dir(path: &str) -> String;
    pub fn expand_env_vars(s: &str) -> String;
    pub fn sanitize_filename(name: &str) -> String;
    pub fn truncate_string(s: &str, max_len: usize) -> String;
    pub fn join_paths(paths: &[&str]) -> String;
}
```

## Logging and Monitoring

### Logging System

```rust
pub mod logging {
    pub fn init(verbose: bool, log_file: Option<&Path>) -> Result<()>;
    pub fn set_level(level: Level);
    pub fn get_logger(name: &str) -> Logger;
    pub fn flush_logs();
}
```

### Health Monitoring

```rust
pub struct HealthMonitor {
    checks: Vec<Box<dyn HealthCheck>>,
    status: Arc<RwLock<HealthStatus>>,
}

impl HealthMonitor {
    pub fn add_check(&mut self, check: Box<dyn HealthCheck>);
    pub async fn run_checks(&self) -> HealthStatus;
    pub fn get_status(&self) -> HealthStatus;
    pub fn register_callback(&self, callback: Box<dyn Fn(HealthStatus)>);
}

pub trait HealthCheck {
    fn name(&self) -> &str;
    fn check(&self) -> HealthCheckResult;
}

pub enum HealthCheckResult {
    Healthy,
    Warning(String),
    Critical(String),
}
```

## Platform Abstraction

### Platform Traits

```rust
pub trait PlatformInterface {
    fn configure_dns(&self, config: &DnsConfig) -> Result<()>;
    fn configure_firewall(&self, config: &ServerConfig) -> Result<()>;
    fn install_certificate(&self, cert_path: &Path) -> Result<()>;
    fn create_service(&self, config: &NebulaConfig) -> Result<()>;
    fn remove_service(&self) -> Result<()>;
}
```

### Platform Implementations

```rust
pub mod platform {
    pub struct MacOSPlatform;
    pub struct LinuxPlatform;
    pub struct WindowsPlatform;
    
    impl PlatformInterface for MacOSPlatform { /* ... */ }
    impl PlatformInterface for LinuxPlatform { /* ... */ }
    impl PlatformInterface for WindowsPlatform { /* ... */ }
    
    pub fn get_platform() -> Box<dyn PlatformInterface>;
}
```

## Async Runtime

### Task Management

```rust
pub struct TaskManager {
    tasks: HashMap<String, JoinHandle<()>>,
    shutdown_tx: tokio::sync::broadcast::Sender<()>,
}

impl TaskManager {
    pub fn spawn_task<F>(&mut self, name: &str, task: F) -> Result<()>
    where
        F: Future<Output = ()> + Send + 'static;
    
    pub async fn shutdown_all(&mut self) -> Result<()>;
    pub fn is_task_running(&self, name: &str) -> bool;
    pub async fn wait_for_task(&mut self, name: &str) -> Result<()>;
}
```

### Signal Handling

```rust
pub mod signals {
    pub async fn setup_shutdown_handler() -> Result<()>;
    pub fn register_signal_handler<F>(signal: i32, handler: F) -> Result<()>
    where
        F: Fn() + Send + Sync + 'static;
    
    #[cfg(unix)]
    pub async fn wait_for_unix_signals() -> Result<()>;
    
    #[cfg(windows)]
    pub async fn wait_for_windows_signals() -> Result<()>;
}
```

## Resource Management

### Resource Limits

```rust
pub struct ResourceLimits {
    pub max_memory: Option<usize>,
    pub max_cpu: Option<f64>,
    pub max_file_descriptors: Option<usize>,
    pub max_processes: Option<usize>,
}

impl ResourceLimits {
    pub fn new() -> Self;
    pub fn with_memory_limit(mut self, limit: usize) -> Self;
    pub fn with_cpu_limit(mut self, limit: f64) -> Self;
    pub fn apply(&self) -> Result<()>;
}
```

### Resource Monitoring

```rust
pub struct ResourceMonitor {
    limits: ResourceLimits,
    current_usage: Arc<RwLock<ResourceUsage>>,
}

impl ResourceMonitor {
    pub async fn start_monitoring(&self) -> Result<()>;
    pub fn get_current_usage(&self) -> ResourceUsage;
    pub fn is_within_limits(&self) -> bool;
    pub fn register_alert_callback<F>(&self, callback: F)
    where
        F: Fn(ResourceUsage) + Send + Sync + 'static;
}
```

## Security

### Security Context

```rust
pub struct SecurityContext {
    pub user_id: Option<u32>,
    pub group_id: Option<u32>,
    pub capabilities: Vec<String>,
    pub sandbox: bool,
}

impl SecurityContext {
    pub fn new() -> Self;
    pub fn with_user(mut self, uid: u32) -> Self;
    pub fn with_group(mut self, gid: u32) -> Self;
    pub fn with_capabilities(mut self, caps: Vec<String>) -> Self;
    pub fn apply(&self) -> Result<()>;
}
```

### Permission Management

```rust
pub mod permissions {
    pub fn check_file_permission(path: &Path, permission: FilePermission) -> bool;
    pub fn check_network_permission(addr: &SocketAddr) -> bool;
    pub fn check_port_permission(port: u16) -> bool;
    pub fn drop_privileges() -> Result<()>;
    pub fn elevate_privileges() -> Result<()>;
}

pub enum FilePermission {
    Read,
    Write,
    Execute,
}
```

## Configuration Validation

### Validation Rules

```rust
pub struct ValidationRule<T> {
    pub name: String,
    pub validator: Box<dyn Fn(&T) -> Result<()>>,
}

pub struct ConfigValidator {
    rules: Vec<ValidationRule<NebulaConfig>>,
}

impl ConfigValidator {
    pub fn new() -> Self;
    pub fn add_rule(mut self, rule: ValidationRule<NebulaConfig>) -> Self;
    pub fn validate(&self, config: &NebulaConfig) -> Result<()>;
    pub fn validate_field<F>(&self, field: &str, validator: F) -> Result<()>
    where
        F: Fn(&NebulaConfig) -> Result<()>;
}
```

## Performance Metrics

### Metrics Collection

```rust
pub struct MetricsCollector {
    metrics: Arc<RwLock<HashMap<String, MetricValue>>>,
    collectors: Vec<Box<dyn MetricCollector>>,
}

impl MetricsCollector {
    pub fn new() -> Self;
    pub fn add_collector(&mut self, collector: Box<dyn MetricCollector>);
    pub fn collect_metrics(&self) -> HashMap<String, MetricValue>;
    pub fn get_metric(&self, name: &str) -> Option<MetricValue>;
    pub fn export_prometheus(&self) -> String;
}

pub trait MetricCollector {
    fn name(&self) -> &str;
    fn collect(&self) -> MetricValue;
}

pub enum MetricValue {
    Counter(u64),
    Gauge(f64),
    Histogram(Vec<f64>),
    Summary { count: u64, sum: f64 },
}
```

## API Usage Examples

### Basic Server Setup

```rust
use nebula::core::{NebulaServer, NebulaConfig};
use nebula::error::Result;

#[tokio::main]
async fn main() -> Result<()> {
    // Load configuration
    let config = NebulaConfig::from_file("nebula.toml").await?;
    
    // Create server
    let server = NebulaServer::new(config).await?;
    
    // Run server
    server.run().await?;
    
    Ok(())
}
```

### Custom Health Check

```rust
use nebula::core::{HealthCheck, HealthCheckResult};

struct CustomHealthCheck {
    name: String,
}

impl HealthCheck for CustomHealthCheck {
    fn name(&self) -> &str {
        &self.name
    }
    
    fn check(&self) -> HealthCheckResult {
        // Perform custom health check
        if self.is_service_healthy() {
            HealthCheckResult::Healthy
        } else {
            HealthCheckResult::Critical("Service is down".to_string())
        }
    }
}
```

### Resource Monitoring

```rust
use nebula::core::{ResourceMonitor, ResourceLimits};

async fn setup_resource_monitoring() -> Result<()> {
    let limits = ResourceLimits::new()
        .with_memory_limit(512 * 1024 * 1024) // 512MB
        .with_cpu_limit(0.5); // 50% CPU
    
    let monitor = ResourceMonitor::new(limits);
    monitor.start_monitoring().await?;
    
    // Register alert callback
    monitor.register_alert_callback(|usage| {
        eprintln!("Resource usage: {:?}", usage);
    });
    
    Ok(())
}
```

## Next Steps

- **Explore [Network API](network.md)** for DNS and DHCP functionality
- **Read [Certificate API](certificates.md)** for TLS management
- **Check [Scheduler API](scheduler.md)** for production deployment
- **Review [Configuration API](configuration.md)** for config management
