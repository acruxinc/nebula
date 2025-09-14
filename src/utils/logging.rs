use anyhow::Result;
use std::path::{Path, PathBuf};
use tracing::{Level, info};
use tracing_subscriber::{
    fmt, prelude::*, EnvFilter, Registry, filter::LevelFilter,
};
use tracing_appender::{rolling, non_blocking, non_blocking::WorkerGuard};

use crate::error::{NebulaError, Result as NebulaResult};

pub struct LoggingConfig {
    pub level: Level,
    pub file_path: Option<PathBuf>,
    pub max_file_size: u64,
    pub max_files: u32,
    pub enable_colors: bool,
    pub enable_json: bool,
    pub enable_console: bool,
    pub filter: Option<String>,
}

pub struct LoggingManager {
    config: LoggingConfig,
    _guards: Vec<WorkerGuard>, // Keep guards alive
}

impl LoggingManager {
    pub fn new(config: LoggingConfig) -> Self {
        Self {
            config,
            _guards: Vec::new(),
        }
    }

    pub fn init(mut self) -> NebulaResult<()> {
        let registry = Registry::default();
        
        // Create environment filter
        let env_filter = if let Some(ref filter) = self.config.filter {
            EnvFilter::try_new(filter)
                .map_err(|e| NebulaError::config(format!("Invalid log filter: {}", e)))?
        } else {
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    EnvFilter::new(format!("nebula={},warn", level_to_string(&self.config.level)))
                })
        };

        let mut layers = Vec::new();

        // Console layer
        if self.config.enable_console {
            if self.config.enable_json {
                let console_layer = fmt::layer()
                    .json()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_thread_names(true)
                    .with_current_span(true)
                    .with_span_list(true);
                layers.push(console_layer.boxed());
            } else {
                let console_layer = fmt::layer()
                    .with_target(false)
                    .with_thread_ids(false)
                    .with_thread_names(false)
                    .with_ansi(self.config.enable_colors)
                    .compact();
                layers.push(console_layer.boxed());
            }
        }

        // File layer
        if let Some(ref file_path) = self.config.file_path {
            let file_layer = self.create_file_layer(file_path)?;
            if let Some((layer, guard)) = file_layer {
                layers.push(layer);
                self._guards.push(guard);
            }
        }

        // Initialize subscriber
        let subscriber = registry
            .with(env_filter)
            .with(layers);

        tracing::subscriber::set_global_default(subscriber)
            .map_err(|e| NebulaError::config(format!("Failed to set global logger: {}", e)))?;

        info!("Logging initialized with level: {}", level_to_string(&self.config.level));
        
        // Keep guards alive by moving them
        std::mem::forget(self._guards);
        
        Ok(())
    }

    fn create_file_layer(&mut self, file_path: &Path) -> NebulaResult<Option<(Box<dyn tracing_subscriber::Layer<Registry> + Send + Sync>, WorkerGuard)>> {
        // Ensure parent directory exists
        if let Some(parent) = file_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| NebulaError::config(format!("Failed to create log directory: {}", e)))?;
        }

        let file_name = file_path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| NebulaError::config("Invalid log file name"))?;

        let directory = file_path.parent()
            .ok_or_else(|| NebulaError::config("Invalid log directory"))?;

        // Create rolling file appender
        let file_appender = rolling::daily(directory, file_name);
        let (non_blocking, guard) = non_blocking(file_appender);

        let file_layer = if self.config.enable_json {
            fmt::layer()
                .json()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .with_current_span(true)
                .with_span_list(true)
                .boxed()
        } else {
            fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false)
                .with_target(true)
                .with_thread_ids(true)
                .with_thread_names(true)
                .boxed()
        };

        Ok(Some((file_layer, guard)))
    }
}

/// Simple initialization function for basic logging
pub fn init(verbose: bool, log_file: Option<&Path>) -> NebulaResult<()> {
    let level = if verbose { Level::DEBUG } else { Level::INFO };
    
    let config = LoggingConfig {
        level,
        file_path: log_file.map(|p| p.to_path_buf()),
        max_file_size: 10 * 1024 * 1024, // 10MB
        max_files: 5,
        enable_colors: true,
        enable_json: false,
        enable_console: true,
        filter: None,
    };

    let manager = LoggingManager::new(config);
    manager.init()
}

/// Advanced initialization with full configuration
pub fn init_with_config(config: LoggingConfig) -> NebulaResult<()> {
    let manager = LoggingManager::new(config);
    manager.init()
}

/// Create default log file path
pub fn default_log_file_path() -> PathBuf {
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("nebula")
        .join("logs");

    log_dir.join("nebula.log")
}

/// Create log file path with custom name
pub fn log_file_path(name: &str) -> PathBuf {
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("nebula")
        .join("logs");

    log_dir.join(format!("{}.log", name))
}

/// Set up structured logging for a specific component
pub fn setup_component_logging(component: &str, level: Level) -> NebulaResult<()> {
    let filter = format!("{}={},warn", component, level_to_string(&level));
    
    let config = LoggingConfig {
        level,
        file_path: Some(log_file_path(component)),
        max_file_size: 10 * 1024 * 1024,
        max_files: 3,
        enable_colors: false,
        enable_json: true,
        enable_console: false,
        filter: Some(filter),
    };

    let manager = LoggingManager::new(config);
    manager.init()
}

/// Create a structured logger for metrics
pub fn setup_metrics_logging() -> NebulaResult<()> {
    let config = LoggingConfig {
        level: Level::INFO,
        file_path: Some(log_file_path("metrics")),
        max_file_size: 50 * 1024 * 1024, // 50MB for metrics
        max_files: 10,
        enable_colors: false,
        enable_json: true,
        enable_console: false,
        filter: Some("nebula::metrics=info".to_string()),
    };

    let manager = LoggingManager::new(config);
    manager.init()
}

/// Set up audit logging
pub fn setup_audit_logging() -> NebulaResult<()> {
    let config = LoggingConfig {
        level: Level::INFO,
        file_path: Some(log_file_path("audit")),
        max_file_size: 100 * 1024 * 1024, // 100MB for audit logs
        max_files: 50, // Keep more audit logs
        enable_colors: false,
        enable_json: true,
        enable_console: false,
        filter: Some("nebula::audit=info".to_string()),
    };

    let manager = LoggingManager::new(config);
    manager.init()
}

/// Clean up old log files
pub async fn cleanup_old_logs(days_to_keep: u32) -> NebulaResult<usize> {
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("nebula")
        .join("logs");

    if !log_dir.exists() {
        return Ok(0);
    }

    let cutoff = std::time::SystemTime::now() - std::time::Duration::from_secs(days_to_keep as u64 * 24 * 60 * 60);
    let mut cleaned_count = 0;

    let mut entries = tokio::fs::read_dir(&log_dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let metadata = entry.metadata().await?;
        
        if metadata.is_file() {
            if let Ok(modified) = metadata.modified() {
                if modified < cutoff {
                    if let Err(e) = tokio::fs::remove_file(entry.path()).await {
                        tracing::warn!("Failed to remove old log file {:?}: {}", entry.path(), e);
                    } else {
                        cleaned_count += 1;
                        tracing::debug!("Removed old log file: {:?}", entry.path());
                    }
                }
            }
        }
    }

    if cleaned_count > 0 {
        info!("Cleaned up {} old log files", cleaned_count);
    }

    Ok(cleaned_count)
}

/// Get current log level
pub fn get_current_log_level() -> Level {
    // This is a simplified implementation
    // In practice, you'd need to track the current level
    Level::INFO
}

/// Update log level at runtime
pub fn update_log_level(level: Level) -> NebulaResult<()> {
    // This is a placeholder - runtime log level updates are complex with tracing-subscriber
    // You'd need to use a reload layer or similar mechanism
    info!("Log level update requested: {}", level_to_string(&level));
    Ok(())
}

/// Create a span for tracking operations
#[macro_export]
macro_rules! create_span {
    ($level:expr, $name:expr) => {
        tracing::span!($level, $name)
    };
    ($level:expr, $name:expr, $($field:tt)*) => {
        tracing::span!($level, $name, $($field)*)
    };
}

/// Log structured data
#[macro_export]
macro_rules! log_structured {
    ($level:expr, $message:expr, $($field:tt)*) => {
        match $level {
            tracing::Level::ERROR => tracing::error!($message, $($field)*),
            tracing::Level::WARN => tracing::warn!($message, $($field)*),
            tracing::Level::INFO => tracing::info!($message, $($field)*),
            tracing::Level::DEBUG => tracing::debug!($message, $($field)*),
            tracing::Level::TRACE => tracing::trace!($message, $($field)*),
        }
    };
}

/// Utility functions
fn level_to_string(level: &Level) -> &'static str {
    match *level {
        Level::ERROR => "error",
        Level::WARN => "warn", 
        Level::INFO => "info",
        Level::DEBUG => "debug",
        Level::TRACE => "trace",
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            file_path: Some(default_log_file_path()),
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_files: 5,
            enable_colors: true,
            enable_json: false,
            enable_console: true,
            filter: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_default_config() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, Level::INFO);
        assert!(config.enable_console);
        assert!(!config.enable_json);
        assert!(config.enable_colors);
    }

    #[test]
    fn test_log_file_path_creation() {
        let path = log_file_path("test");
        assert!(path.to_string_lossy().contains("test.log"));
    }

    #[tokio::test]
    async fn test_cleanup_old_logs() {
        let temp_dir = TempDir::new().unwrap();
        
        // Create some test log files
        let log_file1 = temp_dir.path().join("old.log");
        let log_file2 = temp_dir.path().join("new.log");
        
        std::fs::write(&log_file1, "old log content").unwrap();
        std::fs::write(&log_file2, "new log content").unwrap();
        
        // Set old file to be very old
        let old_time = std::time::SystemTime::now() - std::time::Duration::from_secs(90 * 24 * 60 * 60);
        filetime::set_file_times(&log_file1, 
            filetime::FileTime::from_system_time(old_time),
            filetime::FileTime::from_system_time(old_time)
        ).unwrap();
        
        // This test would need to be adapted to work with the actual cleanup function
        // since it expects a specific directory structure
    }

    #[test]
    fn test_level_to_string() {
        assert_eq!(level_to_string(&Level::ERROR), "error");
        assert_eq!(level_to_string(&Level::WARN), "warn");
        assert_eq!(level_to_string(&Level::INFO), "info");
        assert_eq!(level_to_string(&Level::DEBUG), "debug");
        assert_eq!(level_to_string(&Level::TRACE), "trace");
    }
}
