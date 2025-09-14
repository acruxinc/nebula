use anyhow::Result;
use clap::Parser;
use nebula::cli::Cli;
use nebula::core::NebulaServer;
use nebula::utils::logging;
use tracing::{info, error};
use std::process;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        error!("Application error: {:#}", e);
        process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging first
    logging::init(cli.verbose, cli.log_file.as_deref())?;
    
    info!("🌌 Nebula Universal Development Server v{}", env!("CARGO_PKG_VERSION"));
    info!("Starting Nebula...");
    
    // Handle subcommands
    match cli.subcommand {
        Some(cmd) => {
            cmd.execute().await?;
        }
        None => {
            // Start the development server
            let config = cli.into_config().await?;
            let server = NebulaServer::new(config).await?;
            
            // Set up graceful shutdown
            let shutdown_signal = setup_shutdown_handler();
            
            // Run server with graceful shutdown
            tokio::select! {
                result = server.run() => {
                    if let Err(e) = result {
                        error!("Server error: {:#}", e);
                        return Err(e);
                    }
                }
                _ = shutdown_signal => {
                    info!("Shutdown signal received, stopping server...");
                    server.shutdown().await?;
                }
            }
        }
    }
    
    Ok(())
}

async fn setup_shutdown_handler() -> Result<()> {
    use tokio::signal;
    
    #[cfg(unix)]
    {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())?;
        let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())?;
        
        tokio::select! {
            _ = sigterm.recv() => info!("Received SIGTERM"),
            _ = sigint.recv() => info!("Received SIGINT"),
        }
    }
    
    #[cfg(windows)]
    {
        signal::ctrl_c().await?;
        info!("Received Ctrl+C");
    }
    
    Ok(())
}
