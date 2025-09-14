use anyhow::Result;
use clap::Parser;
use nebula::cli::Cli;
use nebula::core::NebulaServer;
use nebula::utils::logging;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    logging::init(cli.verbose)?;
    
    info!("🌌 Nebula Local Development Server");
    info!("Version: {}", env!("CARGO_PKG_VERSION"));
    
    match cli.subcommand {
        Some(cmd) => cmd.execute().await,
        None => {
            // Start the development server
            let server = NebulaServer::new(cli.into()).await?;
            server.run().await
        }
    }
}
