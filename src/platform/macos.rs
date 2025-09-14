use anyhow::Result;
use std::process::Command;
use std::io::Write;
use tracing::{info, warn};

pub async fn setup() -> Result<()> {
    info!("🍎 Setting up Nebula for macOS...");
    
    // Check if running as root for privileged operations
    if nix::unistd::geteuid().is_root() {
        warn!("Running as root - some operations may not be necessary");
    }

    // Install Homebrew if not present
    if !is_command_available("brew") {
        info!("📦 Installing Homebrew...");
        install_homebrew().await?;
    }

    // Install system dependencies
    install_system_deps().await?;
    
    // Configure system resolver
    configure_resolver().await?;

    info!("✅ macOS setup completed!");
    Ok(())
}

async fn install_homebrew() -> Result<()> {
    let output = Command::new("bash")
        .arg("-c")
        .arg(r#"/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)""#)
        .output()?;

    if !output.status.success() {
        return Err(anyhow::anyhow!("Failed to install Homebrew"));
    }

    Ok(())
}

async fn install_system_deps() -> Result<()> {
    info!("📦 Installing system dependencies...");
    
    // We don't need external tools since we have built-in DNS/DHCP
    // But we might want some utilities
    let deps = vec!["curl", "jq"];
    
    for dep in deps {
        if !is_command_available(dep) {
            info!("Installing {}...", dep);
            let output = Command::new("brew")
                .args(&["install", dep])
                .output()?;
                
            if !output.status.success() {
                warn!("Failed to install {}: {}", dep, String::from_utf8_lossy(&output.stderr));
            }
        }
    }

    Ok(())
}

async fn configure_resolver() -> Result<()> {
    info!("🌐 Configuring DNS resolver...");
    
    // Create resolver configuration for .dev and .nebula.com domains
    let resolver_dir = "/etc/resolver";
    let resolver_files = vec!["dev", "nebula.com"];
    
    // Create resolver directory if it doesn't exist
    let _ = Command::new("sudo")
        .args(&["mkdir", "-p", resolver_dir])
        .output();
    
    for domain in resolver_files {
        let resolver_file = format!("{}/{}", resolver_dir, domain);
        let resolver_content = "nameserver 127.0.0.1\nport 53\n";
        
        let mut child = Command::new("sudo")
            .args(&["tee", &resolver_file])
            .stdin(std::process::Stdio::piped())
            .spawn()?;
        
        if let Some(stdin) = child.stdin.take() {
            let mut writer = stdin;
            if let Err(e) = writer.write_all(resolver_content.as_bytes()) {
                warn!("Failed to write resolver content for {}: {}", domain, e);
            }
        }
        
        let output = child.wait()?;
        if output.success() {
            info!("✅ System resolver configured for .{} domains", domain);
        } else {
            warn!("Failed to configure system resolver for .{} domains", domain);
        }
    }

    Ok(())
}

pub async fn cleanup() -> Result<()> {
    info!("🧹 Cleaning up macOS configuration...");
    
    let resolver_dir = "/etc/resolver";
    let resolver_files = vec!["dev", "nebula.com"];
    
    for domain in resolver_files {
        let resolver_file = format!("{}/{}", resolver_dir, domain);
        let _ = Command::new("sudo")
            .args(&["rm", "-f", &resolver_file])
            .output();
    }
    
    info!("✅ macOS cleanup completed");
    Ok(())
}

fn is_command_available(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}
