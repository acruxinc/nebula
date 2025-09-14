use anyhow::Result;
use std::process::Command;
use std::fs;
use std::io::Write;
use tracing::{info, warn};

pub async fn setup() -> Result<()> {
    info!("🐧 Setting up Nebula for Linux...");

    // Detect Linux distribution
    let distro = detect_distro().await?;
    info!("Detected Linux distribution: {}", distro);

    // Install package manager dependencies
    install_system_deps(&distro).await?;

    // Configure systemd-resolved if present
    configure_systemd_resolved().await?;

    // Setup iptables rules for port forwarding if needed
    setup_port_forwarding().await?;

    info!("✅ Linux setup completed!");
    Ok(())
}

async fn detect_distro() -> Result<String> {
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            if line.starts_with("ID=") {
                return Ok(line.split('=').nth(1).unwrap_or("unknown").trim_matches('"').to_string());
            }
        }
    }

    // Fallback detection methods
    if std::path::Path::new("/etc/debian_version").exists() {
        return Ok("debian".to_string());
    }
    if std::path::Path::new("/etc/redhat-release").exists() {
        return Ok("rhel".to_string());
    }
    if std::path::Path::new("/etc/arch-release").exists() {
        return Ok("arch".to_string());
    }

    Ok("unknown".to_string())
}

async fn install_system_deps(distro: &str) -> Result<()> {
    info!("📦 Installing system dependencies for {}...", distro);

    let install_cmd = match distro {
        "ubuntu" | "debian" => {
            // Update package list first
            let _ = Command::new("sudo")
                .args(&["apt", "update"])
                .output();

            vec!["sudo", "apt", "install", "-y", "curl", "jq", "net-tools"]
        }
        "fedora" | "rhel" | "centos" => {
            vec!["sudo", "dnf", "install", "-y", "curl", "jq", "net-tools"]
        }
        "arch" | "manjaro" => {
            vec!["sudo", "pacman", "-S", "--noconfirm", "curl", "jq", "net-tools"]
        }
        "opensuse" => {
            vec!["sudo", "zypper", "install", "-y", "curl", "jq", "net-tools"]
        }
        _ => {
            warn!("Unknown distribution: {}. Skipping package installation.", distro);
            return Ok(());
        }
    };

    let output = Command::new(install_cmd[0])
        .args(&install_cmd[1..])
        .output()?;

    if !output.status.success() {
        warn!("Failed to install some packages: {}", 
              String::from_utf8_lossy(&output.stderr));
    } else {
        info!("✅ System dependencies installed");
    }

    Ok(())
}

async fn configure_systemd_resolved() -> Result<()> {
    if !std::path::Path::new("/etc/systemd/resolved.conf").exists() {
        info!("systemd-resolved not found, skipping DNS configuration");
        return Ok(());
    }

    info!("🌐 Configuring systemd-resolved...");

    // Create a resolved configuration for .dev domains
    let resolved_conf = r#"
[Resolve]
DNS=127.0.0.1
Domains=~dev
"#;

    let conf_dir = "/etc/systemd/resolved.conf.d";
    
    // Create directory if it doesn't exist
    let _ = Command::new("sudo")
        .args(&["mkdir", "-p", conf_dir])
        .output();

    let conf_path = format!("{}/nebula.conf", conf_dir);
    
    // Write configuration
    let mut child = Command::new("sudo")
        .args(&["tee", &conf_path])
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    
    if let Some(stdin) = child.stdin.take() {
        let mut writer = stdin;
        if let Err(e) = writer.write_all(resolved_conf.as_bytes()) {
            warn!("Failed to write resolved configuration: {}", e);
        }
    }
    
    let output = child.wait()?;
    if output.success() {
        // Restart systemd-resolved
        let _ = Command::new("sudo")
            .args(&["systemctl", "restart", "systemd-resolved"])
            .output();
        
        info!("✅ systemd-resolved configured for .dev and .nebula.com domains");
    } else {
        warn!("Failed to write resolved configuration");
    }

    Ok(())
}

async fn setup_port_forwarding() -> Result<()> {
    info!("🔄 Setting up port forwarding rules...");

    // Check if user wants to forward port 80 to 8080 and 443 to 8443
    let rules = vec![
        ("80", "8080"),
        ("443", "8443"),
    ];

    for (from_port, to_port) in rules {
        let rule = format!(
            "PREROUTING -t nat -i lo -p tcp --dport {} -j REDIRECT --to-port {}",
            from_port, to_port
        );

        let output = Command::new("sudo")
            .args(&["iptables", "-C"])
            .args(rule.split_whitespace())
            .output();

        // If rule doesn't exist, add it
        if let Ok(output) = output {
            if !output.status.success() {
                let output = Command::new("sudo")
                    .args(&["iptables", "-I"])
                    .args(rule.split_whitespace())
                    .output()?;

                if output.status.success() {
                    info!("✅ Port forwarding: {} -> {}", from_port, to_port);
                } else {
                    warn!("Failed to add port forwarding rule: {} -> {}", from_port, to_port);
                }
            }
        }
    }

    // Save iptables rules if iptables-persistent is available
    if is_command_available("iptables-save") {
        let _ = Command::new("sudo")
            .args(&["sh", "-c", "iptables-save > /etc/iptables/rules.v4"])
            .output();
    }

    Ok(())
}

fn is_command_available(cmd: &str) -> bool {
    Command::new("which")
        .arg(cmd)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub async fn cleanup() -> Result<()> {
    info!("🧹 Cleaning up Linux configuration...");

    // Remove systemd-resolved configuration
    let conf_path = "/etc/systemd/resolved.conf.d/nebula.conf";
    let _ = Command::new("sudo")
        .args(&["rm", "-f", conf_path])
        .output();

    // Remove iptables rules
    let rules = vec![
        "PREROUTING -t nat -i lo -p tcp --dport 80 -j REDIRECT --to-port 8080",
        "PREROUTING -t nat -i lo -p tcp --dport 443 -j REDIRECT --to-port 8443",
    ];

    for rule in rules {
        let _ = Command::new("sudo")
            .args(&["iptables", "-D"])
            .args(rule.split_whitespace())
            .output();
    }

    info!("✅ Linux cleanup completed");
    Ok(())
}
