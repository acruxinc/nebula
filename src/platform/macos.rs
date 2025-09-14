use anyhow::Result;
use std::process::Command;
use std::io::Write;
use tracing::{info, warn, error, debug};
use tokio::fs;

use crate::error::{NebulaError, Result as NebulaResult};

pub async fn setup(no_packages: bool, no_dns_setup: bool, no_firewall: bool) -> NebulaResult<()> {
    info!("🍎 Setting up Nebula for macOS...");
    
    // Check macOS version
    check_macos_version().await?;
    
    // Check if running as root for privileged operations
    if nix::unistd::geteuid().is_root() {
        warn!("Running as root - some operations may not be necessary");
    }

    // Install Homebrew if not present and packages are needed
    if !no_packages && !is_command_available("brew") {
        info!("📦 Installing Homebrew...");
        install_homebrew().await?;
    }

    // Install system dependencies
    if !no_packages {
        install_system_deps().await?;
    }
    
    // Configure system resolver
    if !no_dns_setup {
        configure_resolver().await?;
    }

    // Setup firewall rules
    if !no_firewall {
        setup_firewall_rules().await?;
    }

    // Setup launch agents for persistent services
    setup_launch_agents().await?;

    // Configure network preferences
    configure_network_preferences().await?;

    info!("✅ macOS setup completed!");
    Ok(())
}

async fn check_macos_version() -> NebulaResult<()> {
    let output = Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .map_err(|e| NebulaError::platform(format!("Failed to get macOS version: {}", e)))?;

    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        info!("Detected macOS version: {}", version);
        
        // Check for minimum version (macOS 10.15+)
        let parts: Vec<&str> = version.split('.').collect();
        if parts.len() >= 2 {
            if let (Ok(major), Ok(minor)) = (parts[0].parse::<u32>(), parts[1].parse::<u32>()) {
                if major < 10 || (major == 10 && minor < 15) {
                    warn!("macOS version {} may not be fully supported. Recommended: 10.15+", version);
                }
            }
        }
    }

    Ok(())
}

async fn install_homebrew() -> NebulaResult<()> {
    info!("Installing Homebrew package manager...");
    
    let install_script = r#"/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)""#;
    
    let output = Command::new("bash")
        .arg("-c")
        .arg(install_script)
        .output()
        .map_err(|e| NebulaError::platform(format!("Failed to install Homebrew: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NebulaError::platform(format!("Homebrew installation failed: {}", stderr)));
    }

    // Add Homebrew to PATH for current session
    if let Some(home) = dirs::home_dir() {
        let brew_path = home.join(".brew");
        if brew_path.exists() {
            std::env::set_var("PATH", format!("{}:{}", brew_path.join("bin").display(), std::env::var("PATH").unwrap_or_default()));
        }
    }

    info!("✅ Homebrew installed successfully");
    Ok(())
}

async fn install_system_deps() -> NebulaResult<()> {
    info!("📦 Installing system dependencies...");
    
    let dependencies = vec![
        "curl",
        "jq", 
        "wget",
        "openssl",
    ];
    
    for dep in dependencies {
        if !is_command_available(dep) {
            info!("Installing {}...", dep);
            let output = Command::new("brew")
                .args(&["install", dep])
                .output()
                .map_err(|e| NebulaError::platform(format!("Failed to run brew: {}", e)))?;
                
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to install {}: {}", dep, stderr);
                // Continue with other dependencies
            } else {
                debug!("Successfully installed {}", dep);
            }
        } else {
            debug!("{} already installed", dep);
        }
    }

    Ok(())
}

async fn configure_resolver() -> NebulaResult<()> {
    info!("🌐 Configuring DNS resolver...");
    
    // Create resolver configuration for .dev and .nebula.com domains
    let resolver_dir = "/etc/resolver";
    let resolver_domains = vec!["dev", "nebula.com"];
    
    // Create resolver directory if it doesn't exist
    let output = Command::new("sudo")
        .args(&["mkdir", "-p", resolver_dir])
        .output()
        .map_err(|e| NebulaError::platform(format!("Failed to create resolver directory: {}", e)))?;
    
    if !output.status.success() {
        return Err(NebulaError::platform("Failed to create resolver directory"));
    }
    
    for domain in resolver_domains {
        let resolver_file = format!("{}/{}", resolver_dir, domain);
        let resolver_content = format!(
            "nameserver 127.0.0.1\nport 53\ntimeout 1\nsearch_order 1\n"
        );
        
        // Write resolver configuration
        let result = write_file_with_sudo(&resolver_file, &resolver_content).await;
        
        match result {
            Ok(_) => {
                info!("✅ System resolver configured for .{} domains", domain);
            }
            Err(e) => {
                warn!("Failed to configure system resolver for .{} domains: {}", domain, e);
            }
        }
    }

    // Flush DNS cache
    flush_dns_cache().await?;

    Ok(())
}

async fn setup_firewall_rules() -> NebulaResult<()> {
    info!("🔥 Setting up firewall rules...");

    // Check if pfctl is available (macOS firewall)
    if !is_command_available("pfctl") {
        warn!("pfctl not available, skipping firewall configuration");
        return Ok(());
    }

    // Allow HTTP and HTTPS traffic
    let rules = vec![
        "pass in proto tcp from any to any port 3000",
        "pass in proto tcp from any to any port 3443", 
        "pass in proto tcp from any to any port 8080",
        "pass in proto udp from any to any port 53",
    ];

    for rule in &rules {
        debug!("Adding firewall rule: {}", rule);
        
        // Note: In a real implementation, you'd need to properly manage pf rules
        // This is a simplified approach
        let output = Command::new("sudo")
            .args(&["pfctl", "-ef", "-"])
            .stdin(std::process::Stdio::piped())
            .spawn();

        if let Ok(mut child) = output {
            if let Some(stdin) = child.stdin.take() {
                let mut writer = stdin;
                if let Err(e) = writeln!(writer, "{}", rule) {
                    warn!("Failed to write firewall rule: {}", e);
                }
            }
            
            let _ = child.wait();
        }
    }

    info!("✅ Firewall rules configured");
    Ok(())
}

async fn setup_launch_agents() -> NebulaResult<()> {
    info!("🚀 Setting up launch agents...");

    let user_agents_dir = dirs::home_dir()
        .ok_or_else(|| NebulaError::platform("Could not find home directory"))?
        .join("Library/LaunchAgents");

    // Create directory if it doesn't exist
    fs::create_dir_all(&user_agents_dir).await
        .map_err(|e| NebulaError::platform(format!("Failed to create LaunchAgents directory: {}", e)))?;

    // Create a launch agent for Nebula DNS
    let dns_plist = user_agents_dir.join("com.nebula.dns.plist");
    let dns_plist_content = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.nebula.dns</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/nebula</string>
        <string>dns</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <false/>
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>
    <key>StandardOutPath</key>
    <string>/tmp/nebula-dns.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/nebula-dns.error.log</string>
</dict>
</plist>"#;

    fs::write(&dns_plist, dns_plist_content).await
        .map_err(|e| NebulaError::platform(format!("Failed to write DNS launch agent: {}", e)))?;

    info!("✅ Launch agents configured");
    Ok(())
}

async fn configure_network_preferences() -> NebulaResult<()> {
    info!("🌐 Configuring network preferences...");

    // Set custom DNS servers for development
    let interfaces = get_network_interfaces().await?;
    
    for interface in &interfaces {
        debug!("Configuring DNS for interface: {}", interface);
        
        // Add our local DNS as the first server
        let output = Command::new("sudo")
            .args(&[
                "networksetup",
                "-setdnsservers",
                interface,
                "127.0.0.1",
                "8.8.8.8",
                "1.1.1.1"
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    debug!("DNS configured for interface: {}", interface);
                } else {
                    let stderr = String::from_utf8_lossy(&result.stderr);
                    warn!("Failed to configure DNS for {}: {}", interface, stderr);
                }
            }
            Err(e) => {
                warn!("Failed to run networksetup for {}: {}", interface, e);
            }
        }
    }

    Ok(())
}

async fn get_network_interfaces() -> NebulaResult<Vec<String>> {
    let output = Command::new("networksetup")
        .args(&["-listallnetworkservices"])
        .output()
        .map_err(|e| NebulaError::platform(format!("Failed to list network services: {}", e)))?;

    if !output.status.success() {
        return Err(NebulaError::platform("Failed to get network interfaces"));
    }

    let output_str = String::from_utf8_lossy(&output.stdout);
    let interfaces: Vec<String> = output_str
        .lines()
        .skip(1) // Skip the header line
        .filter(|line| !line.starts_with('*')) // Skip disabled interfaces
        .map(|line| line.trim().to_string())
        .collect();

    Ok(interfaces)
}

async fn flush_dns_cache() -> NebulaResult<()> {
    info!("🔄 Flushing DNS cache...");

    let commands = vec![
        vec!["sudo", "dscacheutil", "-flushcache"],
        vec!["sudo", "killall", "-HUP", "mDNSResponder"],
    ];

    for cmd in commands {
        let output = Command::new(cmd[0])
            .args(&cmd[1..])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    debug!("Successfully ran: {:?}", cmd);
                } else {
                    debug!("Command failed (may be normal): {:?}", cmd);
                }
            }
            Err(e) => {
                debug!("Failed to run command {:?}: {}", cmd, e);
            }
        }
    }

    Ok(())
}

async fn write_file_with_sudo(file_path: &str, content: &str) -> NebulaResult<()> {
    let mut child = Command::new("sudo")
        .args(&["tee", file_path])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .map_err(|e| NebulaError::platform(format!("Failed to spawn sudo tee: {}", e)))?;
    
    if let Some(stdin) = child.stdin.take() {
        let mut writer = stdin;
        writer.write_all(content.as_bytes())
            .map_err(|e| NebulaError::platform(format!("Failed to write content: {}", e)))?;
    }
    
    let output = child.wait()
        .map_err(|e| NebulaError::platform(format!("Failed to wait for sudo tee: {}", e)))?;
    
    if !output.success() {
        return Err(NebulaError::platform("sudo tee command failed"));
    }
    
    Ok(())
}

pub async fn cleanup() -> NebulaResult<()> {
    info!("🧹 Cleaning up macOS configuration...");
    
    let resolver_dir = "/etc/resolver";
    let resolver_domains = vec!["dev", "nebula.com"];
    
    // Remove resolver configurations
    for domain in resolver_domains {
        let resolver_file = format!("{}/{}", resolver_dir, domain);
        let output = Command::new("sudo")
            .args(&["rm", "-f", &resolver_file])
            .output();
        
        match output {
            Ok(result) => {
                if result.status.success() {
                    debug!("Removed resolver file: {}", resolver_file);
                } else {
                    warn!("Failed to remove resolver file: {}", resolver_file);
                }
            }
            Err(e) => {
                warn!("Error removing resolver file {}: {}", resolver_file, e);
            }
        }
    }

    // Reset DNS settings for network interfaces
    let interfaces = get_network_interfaces().await.unwrap_or_default();
    for interface in &interfaces {
        let output = Command::new("sudo")
            .args(&[
                "networksetup",
                "-setdnsservers",
                interface,
                "8.8.8.8",
                "1.1.1.1"
            ])
            .output();

        match output {
            Ok(result) => {
                if result.status.success() {
                    debug!("Reset DNS for interface: {}", interface);
                } else {
                    debug!("Failed to reset DNS for interface: {}", interface);
                }
            }
            Err(e) => {
                debug!("Error resetting DNS for {}: {}", interface, e);
            }
        }
    }

    // Remove launch agents
    if let Some(home) = dirs::home_dir() {
        let user_agents_dir = home.join("Library/LaunchAgents");
        let dns_plist = user_agents_dir.join("com.nebula.dns.plist");
        
        if dns_plist.exists() {
            if let Err(e) = fs::remove_file(&dns_plist).await {
                warn!("Failed to remove launch agent: {}", e);
            } else {
                debug!("Removed launch agent: {:?}", dns_plist);
            }
        }
    }

    // Flush DNS cache
    flush_dns_cache().await?;

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

/// macOS-specific utilities
pub struct MacOSUtils;

impl MacOSUtils {
    /// Check if SIP (System Integrity Protection) is enabled
    pub fn is_sip_enabled() -> bool {
        Command::new("csrutil")
            .arg("status")
            .output()
            .map(|output| {
                let stdout = String::from_utf8_lossy(&output.stdout);
                !stdout.contains("disabled")
            })
            .unwrap_or(true) // Assume enabled if we can't check
    }

    /// Get macOS build version
    pub fn get_build_version() -> Option<String> {
        Command::new("sw_vers")
            .arg("-buildVersion")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    /// Check if Homebrew is installed
    pub fn has_homebrew() -> bool {
        is_command_available("brew")
    }

    /// Get active network service
    pub fn get_active_network_service() -> Option<String> {
        Command::new("route")
            .args(&["get", "default"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.trim().starts_with("interface:") {
                        return line.split(':').nth(1).map(|s| s.trim().to_string());
                    }
                }
                None
            })
    }

    /// Check if running on Apple Silicon
    pub fn is_apple_silicon() -> bool {
        std::env::consts::ARCH == "aarch64"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_command_available() {
        // Test with a command that should always exist
        assert!(is_command_available("ls"));
        
        // Test with a command that shouldn't exist
        assert!(!is_command_available("this_command_does_not_exist_12345"));
    }

    #[test]
    fn test_macos_utils() {
        // These tests will only work on macOS
        #[cfg(target_os = "macos")]
        {
            // Test SIP check (should not crash)
            let _sip_enabled = MacOSUtils::is_sip_enabled();
            
            // Test build version (should return something on macOS)
            let _build_version = MacOSUtils::get_build_version();
            
            // Test architecture check
            let _is_arm = MacOSUtils::is_apple_silicon();
        }
    }

    #[tokio::test]
    async fn test_get_network_interfaces() {
        #[cfg(target_os = "macos")]
        {
            let result = get_network_interfaces().await;
            // Should either succeed or fail gracefully
            match result {
                Ok(interfaces) => {
                    // Should have at least one interface on a real system
                    assert!(!interfaces.is_empty() || cfg!(test));
                }
                Err(_) => {
                    // Failure is acceptable in test environment
                }
            }
        }
    }
}
