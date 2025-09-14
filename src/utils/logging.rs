use anyhow::Result;
use std::path::PathBuf;
use tracing_subscriber::{
    fmt, prelude::*, EnvFilter, Registry,
};

pub fn init(verbose: bool) -> Result<()> {
    let log_level = if verbose { "debug" } else { "info" };
    
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("nebula={},warn", log_level)));

    // Console logging
    let console_layer = fmt::layer()
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .compact();

    // File logging
    let log_dir = dirs::data_local_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("nebula")
        .join("logs");

    std::fs::create_dir_all(&log_dir)?;
    
    let _log_file = log_dir.join("nebula.log");
    let file_appender = tracing_appender::rolling::daily(&log_dir, "nebula.log");
    let file_layer = fmt::layer()
        .with_writer(file_appender)
        .with_ansi(false);

    Registry::default()
        .with(env_filter)
        .with(console_layer)
        .with(file_layer)
        .init();

    Ok(())
}
