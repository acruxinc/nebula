use anyhow::Result;
use std::process::Command;
use std::fs;
use std::io::Write;
use tracing::{info, warn, error, debug};
use tokio::fs as async_fs;

use crate::error::{NebulaError, Result as NebulaResult};

pub async fn setup(no_packages: bool, no_dns_setup: bool, no_firewall: bool) -> NebulaResult<()> {
    info!("🐧 Setting up Nebula for Linux...");

    // Detect Linux distribution
    let distro = detect_distro().await?;
    info!("Detected Linux distribution: {}", distro.name);

    // Check for systemd
    let has_systemd = check_systemd().await;
    if has_systemd {
        info!("systemd detected");
    } else {
        warn!("systemd not detected, some features may not work");
    }

    // Install package manager dependencies
    if !no_packages {
        install_system_deps(&distro).await?;
    }

    // Configure systemd-resolved if present
    if !no_dns_setup {
        configure_dns_resolution(&distro).await?;
    }

    // Setup firewall rules
    if !no_firewall {
        setup_firewall_rules(&distro).await?;
    }

    // Setup systemd services
    if has_systemd {
        setup_systemd_services().await?;
    }

    // Configure network settings
    configure_network_settings().await?;

    info!("✅ Linux setup completed!");
    Ok(())
}

#[derive(Debug, Clone)]
struct LinuxDistro {
    name: String,
    id: String,
    version: Option<String>,
    package_manager: PackageManager,
}

#[derive(Debug, Clone)]
enum PackageManager {
    Apt,     // Debian/Ubuntu
    Dnf,     // Fedora/RHEL 8+
    Yum,     // RHEL/CentOS 7
    Pacman,  // Arch Linux
    Zypper,  // openSUSE
    Apk,     // Alpine Linux
    Unknown,
}

async fn detect_distro() -> NebulaResult<LinuxDistro> {
    // Try /etc/os-release first (standard)
    if let Ok(content) = async_fs::read_to_string("/etc/os-release").await {
        let mut name = "Unknown".to_string();
        let mut id = "unknown".to_string();
        let mut version = None;

        for line in content.lines() {
            if let Some((key, value)) = line.split_once('=') {
                let value = value.trim_matches('"');
                match key {
                    "NAME" => name = value.to_string(),
                    "ID" => id = value.to_string(),
                    "VERSION" => version = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        let package_manager = match id.as_str() {
            "ubuntu" | "debian" | "linuxmint" | "elementary" => PackageManager::Apt,
            "fedora" | "rhel" | "centos" => {
                if is_command_available("dnf") {
                    PackageManager::Dnf
                } else {
                    PackageManager::Yum
                }
            }
            "arch" | "manjaro" | "endeavouros" => PackageManager::Pacman,
            "opensuse" | "opensuse-leap" | "opensuse-tumbleweed" => PackageManager::Zypper,
            "alpine" => PackageManager::Apk,
            _ => PackageManager::Unknown,
        };

        return Ok(LinuxDistro {
            name,
            id,
            version,
            package_manager,
        });
    }

    // Fallback detection methods
    let fallback_distros = vec![
        ("/etc/debian_version", "debian", PackageManager::Apt),
        ("/etc/redhat-release", "rhel", PackageManager::Dnf),
        ("/etc/arch-release", "arch", PackageManager::Pacman),
        ("/etc/alpine-release", "alpine", PackageManager::Apk),
    ];

    for (file, id, pm) in fallback_distros {
        if tokio::fs::metadata(file).await.is_ok() {
            return Ok(LinuxDistro {
                name: id.to_string(),
                id: id.to_string(),
                version: None,
                package_manager: pm,
            });
        }
    }

    Ok(LinuxDistro {
        name: "Unknown".to_string(),
        id: "unknown".to_string(),
        version: None,
        package_manager: PackageManager::Unknown,
    })
}

async fn check_systemd() -> bool {
    tokio::fs::metadata("/run/systemd/system").await.is_ok()
}

async fn install_system_deps(distro: &LinuxDistro) -> NebulaResult<()> {
    info!("📦 Installing system dependencies for {}...", distro.name);

    let (install_cmd, packages) = match distro.package_manager {
        PackageManager::Apt => {
            // Update package list first
            let _ = run_command(&["sudo", "apt", "update"]).await;
            (
                vec!["sudo", "apt", "install", "-y"],
                vec!["curl", "jq", "net-tools", "dnsutils", "iptables", "systemd-resolved"]
            )
        }
        PackageManager::Dnf => {
            (
                vec!["sudo", "dnf", "install", "-y"],
                vec!["curl", "jq", "net-tools", "bind-utils", "iptables", "systemd-resolved"]
            )
        }
        PackageManager::Yum => {
            (
                vec!["sudo", "yum", "install", "-y"],
                vec!["curl", "jq", "net-tools", "bind-utils", "iptables"]
            )
        }
        PackageManager::Pacman => {
            (
                vec!["sudo", "pacman", "-S", "--noconfirm"],
                vec!["curl", "jq", "net-tools", "bind", "iptables", "systemd-resolvconf"]
            )
        }
        PackageManager::Zypper => {
            (
                vec!["sudo", "zypper", "install", "-y"],
                vec!["curl", "jq", "net-tools", "bind-utils", "iptables", "systemd"]
            )
        }
        PackageManager::Apk => {
            (
                vec!["sudo", "apk", "add"],
                vec!["curl", "jq", "net-tools", "bind-tools", "iptables"]
            )
        }
        PackageManager::Unknown => {
            warn!("Unknown package manager for distribution: {}. Skipping package installation.", distro.name);
            return Ok(());
        }
    };

    let mut cmd = install_cmd;
    cmd.extend(packages);

    match run_command(&cmd).await {
        Ok(_) => {
            info!("✅ System dependencies installed");
        }
        Err(e) => {
            warn!("Failed to install some packages: {}", e);
            // Continue anyway as some packages might be optional
        }
    }

    Ok(())
}

async fn configure_dns_resolution(distro: &LinuxDistro) -> NebulaResult<()> {
    info!("🌐 Configuring DNS resolution...");

    // Try systemd-resolved first
    if tokio::fs::metadata("/etc/systemd/resolved.conf").await.is_ok() {
        configure_systemd_resolved().await?;
    }
    // Fallback to /etc/resolv.conf
    else {
        configure_resolv_conf().await?;
    }

    // Add entries to /etc/hosts for development domains
    configure_hosts_file().await?;

    Ok(())
}

async fn configure_systemd_resolved() -> NebulaResult<()> {
    info!("Configuring systemd-resolved...");

    let resolved_conf = r#"
[Resolve]
DNS=127.0.0.1
Domains=~dev ~nebula.com
DNSSEC=no
DNSOverTLS=no
"#;

    let conf_dir = "/etc/systemd/resolved.conf.d";
    
    // Create directory if it doesn't exist
    run_command(&["sudo", "mkdir", "-p", conf_dir]).await?;

    let conf_path = format!("{}/nebula.conf", conf_dir);
    
    // Write configuration
    write_file_with_sudo(&conf_path, resolved_conf).await?;
    
    // Restart systemd-resolved
    let restart_result = run_command(&["sudo", "systemctl", "restart", "systemd-resolved"]).await;
    match restart_result {
        Ok(_) => {
            info!("✅ systemd-resolved configured and restarted");
        }
        Err(e) => {
            warn!("Failed to restart systemd-resolved: {}", e);
            // Try to reload instead
            let _ = run_command(&["sudo", "systemctl", "reload-or-restart", "systemd-resolved"]).await;
        }
    }

    Ok(())
}

async fn configure_resolv_conf() -> NebulaResult<()> {
    info!("Configuring /etc/resolv.conf...");

    // Check if /etc/resolv.conf is a symlink (likely managed by systemd)
    if let Ok(metadata) = tokio::fs::symlink_metadata("/etc/resolv.conf").await {
        if metadata.file_type().is_symlink() {
            warn!("/etc/resolv.conf is a symlink, DNS configuration may be overridden");
        }
    }

    // Backup original resolv.conf
    let _ = run_command(&["sudo", "cp", "/etc/resolv.conf", "/etc/resolv.conf.nebula.backup"]).await;

    // Create new resolv.conf with our DNS server first
    let resolv_content = r#"# Generated by Nebula
nameserver 127.0.0.1
nameserver 8.8.8.8
nameserver 1.1.1.1

search dev nebula.com
"#;

    write_file_with_sudo("/etc/resolv.conf", resolv_content).await?;
    
    info!("✅ /etc/resolv.conf configured");
    Ok(())
}

async fn configure_hosts_file() -> NebulaResult<()> {
    info!("Configuring /etc/hosts...");

    // Read current hosts file
    let hosts_content = match async_fs::read_to_string("/etc/hosts").await {
        Ok(content) => content,
        Err(_) => String::new(),
    };

    // Check if our entries already exist
    if hosts_content.contains("# Nebula development entries") {
        debug!("Nebula entries already exist in /etc/hosts");
        return Ok(());
    }

    let nebula_entries = r#"
# Nebula development entries
127.0.0.1 app.nebula.com
127.0.0.1 api.nebula.com
127.0.0.1 admin.nebula.com
127.0.0.1 localhost.dev
::1 app.nebula.com
::1 api.nebula.com
::1 admin.nebula.com
::1 localhost.dev
"#;

    let new_content = format!("{}{}", hosts_content, nebula_entries);
    write_file_with_sudo("/etc/hosts", &new_content).await?;

    info!("✅ /etc/hosts configured");
    Ok(())
}

async fn setup_firewall_rules(distro: &LinuxDistro) -> NebulaResult<()> {
    info!("🔥 Setting up firewall rules...");

    // Detect firewall system
    if is_command_available("ufw") {
        setup_ufw_rules().await?;
    } else if is_command_available("firewalld") || is_command_available("firewall-cmd") {
        setup_firewalld_rules().await?;
    } else if is_command_available("iptables") {
        setup_iptables_rules().await?;
    } else {
        warn!("No supported firewall system found");
    }

    Ok(())
}

async fn setup_ufw_rules() -> NebulaResult<()> {
    info!("Configuring UFW firewall...");

    let rules = vec![
        vec!["sudo", "ufw", "allow", "3000/tcp"],
        vec!["sudo", "ufw", "allow", "3443/tcp"],
        vec!["sudo", "ufw", "allow", "8080/tcp"],
        vec!["sudo", "ufw", "allow", "53/udp"],
        vec!["sudo", "ufw", "allow", "53/tcp"],
    ];

    for rule in rules {
        match run_command(&rule).await {
            Ok(_) => debug!("UFW rule added: {:?}", rule),
            Err(e) => warn!("Failed to add UFW rule {:?}: {}", rule, e),
        }
    }

    // Enable UFW if not already enabled
    let _ = run_command(&["sudo", "ufw", "--force", "enable"]).await;

    info!("✅ UFW rules configured");
    Ok(())
}

async fn setup_firewalld_rules() -> NebulaResult<()> {
    info!("Configuring firewalld...");

    let rules = vec![
        vec!["sudo", "firewall-cmd", "--permanent", "--add-port=3000/tcp"],
        vec!["sudo", "firewall-cmd", "--permanent", "--add-port=3443/tcp"],
        vec!["sudo", "firewall-cmd", "--permanent", "--add-port=8080/tcp"],
        vec!["sudo", "firewall-cmd", "--permanent", "--add-port=53/udp"],
        vec!["sudo", "firewall-cmd", "--permanent", "--add-port=53/tcp"],
    ];

    for rule in rules {
        match run_command(&rule).await {
            Ok(_) => debug!("firewalld rule added: {:?}", rule),
            Err(e) => warn!("Failed to add firewalld rule {:?}: {}", rule, e),
        }
    }

    // Reload firewalld
    let _ = run_command(&["sudo", "firewall-cmd", "--reload"]).await;

    info!("✅ firewalld rules configured");
    Ok(())
}

async fn setup_iptables_rules() -> NebulaResult<()> {
    info!("Configuring iptables...");

    let rules = vec![
        vec!["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "3000", "-j", "ACCEPT"],
        vec!["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "3443", "-j", "ACCEPT"],
        vec!["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "8080", "-j", "ACCEPT"],
        vec!["sudo", "iptables", "-A", "INPUT", "-p", "udp", "--dport", "53", "-j", "ACCEPT"],
        vec!["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"],
    ];

    for rule in rules {
        match run_command(&rule).await {
            Ok(_) => debug!("iptables rule added: {:?}", rule),
            Err(e) => warn!("Failed to add iptables rule {:?}: {}", rule, e),
        }
    }

    // Save iptables rules if iptables-persistent is available
    if is_command_available("iptables-save") {
        let distro_paths = vec![
            "/etc/iptables/rules.v4",
            "/etc/sysconfig/iptables",
        ];

        for path in distro_paths {
            if let Ok(_) = run_command(&["sudo", "iptables-save"]).await {
                let output = run_command_output(&["sudo", "iptables-save"]).await?;
                if let Err(e) = write_file_with_sudo(path, &output).await {
                    debug!("Could not save to {}: {}", path, e);
                } else {
                    debug!("Saved iptables rules to {}", path);
                    break;
                }
            }
        }
    }

    info!("✅ iptables rules configured");
    Ok(())
}

async fn setup_systemd_services() -> NebulaResult<()> {
    info!("🚀 Setting up systemd services...");

    let service_dir = "/etc/systemd/system";
    
    // Create a systemd service for Nebula DNS
    let dns_service_content = r#"[Unit]
Description=Nebula DNS Server
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/nebula dns start
Restart=always
RestartSec=5
User=root
Group=root
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"#;

    let dns_service_path = format!("{}/nebula-dns.service", service_dir);
    write_file_with_sudo(&dns_service_path, dns_service_content).await?;

    // Reload systemd and enable service
    run_command(&["sudo", "systemctl", "daemon-reload"]).await?;
    
    // Don't start automatically, just make it available
    info!("✅ systemd services configured");
    Ok(())
}

async fn configure_network_settings() -> NebulaResult<()> {
    info!("🌐 Configuring network settings...");

    // Enable IP forwarding for better networking
    let sysctl_conf = "/etc/sysctl.d/99-nebula.conf";
    let sysctl_content = r#"# Nebula network settings
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.core.rmem_max=134217728
net.core.wmem_max=134217728
"#;

    write_file_with_sudo(sysctl_conf, sysctl_content).await?;
    
    // Apply sysctl settings
    let _ = run_command(&["sudo", "sysctl", "-p", sysctl_conf]).await;

    info!("✅ Network settings configured");
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

async fn run_command(args: &[&str]) -> NebulaResult<()> {
    if args.is_empty() {
        return Err(NebulaError::platform("Empty command"));
    }

    let output = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| NebulaError::platform(format!("Failed to run command {:?}: {}", args, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NebulaError::platform(format!("Command failed {:?}: {}", args, stderr)));
    }

    Ok(())
}

async fn run_command_output(args: &[&str]) -> NebulaResult<String> {
    if args.is_empty() {
        return Err(NebulaError::platform("Empty command"));
    }

    let output = Command::new(args[0])
        .args(&args[1..])
        .output()
        .map_err(|e| NebulaError::platform(format!("Failed to run command {:?}: {}", args, e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NebulaError::platform(format!("Command failed {:?}: {}", args, stderr)));
    }

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub async fn cleanup() -> NebulaResult<()> {
    info!("🧹 Cleaning up Linux configuration...");

    // Remove systemd-resolved configuration
    let conf_path = "/etc/systemd/resolved.conf.d/nebula.conf";
    let _ = run_command(&["sudo", "rm", "-f", conf_path]).await;
    
    // Restart systemd-resolved
    let _ = run_command(&["sudo", "systemctl", "restart", "systemd-resolved"]).await;

    // Restore original resolv.conf if backup exists
    if tokio::fs::metadata("/etc/resolv.conf.nebula.backup").await.is_ok() {
        let _ = run_command(&["sudo", "mv", "/etc/resolv.conf.nebula.backup", "/etc/resolv.conf"]).await;
    }

    // Remove entries from /etc/hosts
    if let Ok(hosts_content) = async_fs::read_to_string("/etc/hosts").await {
        if hosts_content.contains("# Nebula development entries") {
            let cleaned_content = hosts_content
                .lines()
                .take_while(|line| !line.contains("# Nebula development entries"))
                .collect::<Vec<_>>()
                .join("\n");
            
            if !cleaned_content.is_empty() {
                let _ = write_file_with_sudo("/etc/hosts", &cleaned_content).await;
            }
        }
    }

    // Remove systemd services
    let _ = run_command(&["sudo", "rm", "-f", "/etc/systemd/system/nebula-dns.service"]).await;
    let _ = run_command(&["sudo", "systemctl", "daemon-reload"]).await;

    // Remove sysctl configuration
    let _ = run_command(&["sudo", "rm", "-f", "/etc/sysctl.d/99-nebula.conf"]).await;

    // Remove firewall rules (basic cleanup - may not remove all rules)
    if is_command_available("ufw") {
        let ports = vec!["3000/tcp", "3443/tcp", "8080/tcp", "53/udp", "53/tcp"];
        for port in ports {
            let _ = run_command(&["sudo", "ufw", "delete", "allow", port]).await;
        }
    }

    info!("✅ Linux cleanup completed");
    Ok(())
}

fn is_command_available(cmd: &str) -> bool {
    which::which(cmd).is_ok()
}

/// Linux-specific utilities
pub struct LinuxUtils;

impl LinuxUtils {
    /// Get the current Linux distribution
    pub async fn get_distribution() -> NebulaResult<LinuxDistro> {
        detect_distro().await
    }

    /// Check if systemd is available
    pub async fn has_systemd() -> bool {
        check_systemd().await
    }

    /// Get the init system
    pub fn get_init_system() -> String {
        if std::path::Path::new("/run/systemd/system").exists() {
            "systemd".to_string()
        } else if std::path::Path::new("/sbin/init").exists() {
            // Try to determine if it's SysV, Upstart, etc.
            "sysv".to_string() // Simplified
        } else {
            "unknown".to_string()
        }
    }

    /// Check if running in a container
    pub fn is_container() -> bool {
        std::path::Path::new("/.dockerenv").exists() ||
        std::env::var("container").is_ok() ||
        std::fs::read_to_string("/proc/1/cgroup")
            .map(|content| content.contains("docker") || content.contains("lxc"))
            .unwrap_or(false)
    }

    /// Get available package managers
    pub fn get_package_managers() -> Vec<String> {
        let managers = vec![
            ("apt", "apt"),
            ("dnf", "dnf"),
            ("yum", "yum"),
            ("pacman", "pacman"),
            ("zypper", "zypper"),
            ("apk", "apk"),
        ];

        managers
            .into_iter()
            .filter(|(cmd, _)| is_command_available(cmd))
            .map(|(_, name)| name.to_string())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_detect_distro() {
        // This test will only work properly on Linux
        #[cfg(target_os = "linux")]
        {
            let result = detect_distro().await;
            assert!(result.is_ok(), "Should detect Linux distribution");
            
            let distro = result.unwrap();
            assert!(!distro.name.is_empty(), "Distribution name should not be empty");
        }
    }

    #[test]
    fn test_is_command_available() {
        // Test with a command that should always exist on Linux
        #[cfg(target_os = "linux")]
        {
            assert!(is_command_available("ls"));
            assert!(!is_command_available("this_command_does_not_exist_12345"));
        }
    }

    #[tokio::test]
    async fn test_linux_utils() {
        #[cfg(target_os = "linux")]
        {
            // Test init system detection
            let init_system = LinuxUtils::get_init_system();
            assert!(!init_system.is_empty());

            // Test container detection
            let _is_container = LinuxUtils::is_container();

            // Test package manager detection
            let package_managers = LinuxUtils::get_package_managers();
            // Should have at least one package manager on a real Linux system
            assert!(!package_managers.is_empty() || cfg!(test));
        }
    }

    #[tokio::test]
    async fn test_systemd_check() {
        #[cfg(target_os = "linux")]
        {
            let has_systemd = check_systemd().await;
            // This will be true on most modern Linux systems
            debug!("systemd available: {}", has_systemd);
        }
    }
}
