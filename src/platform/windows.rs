use anyhow::Result;
use std::process::Command;
use tracing::{info, warn};

pub async fn setup() -> Result<()> {
    info!("🪟 Setting up Nebula for Windows...");

    // Check if running as administrator
    if !is_admin() {
        warn!("⚠️  Not running as administrator. Some features may not work properly.");
        warn!("Consider running PowerShell as Administrator for full functionality.");
    }

    // Install chocolatey if not present
    ensure_chocolatey().await?;

    // Install system dependencies
    install_system_deps().await?;

    // Configure Windows DNS
    configure_dns().await?;

    // Setup Windows Firewall rules
    setup_firewall_rules().await?;

    info!("✅ Windows setup completed!");
    Ok(())
}

fn is_admin() -> bool {
    #[cfg(windows)]
    {
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::processthreadsapi::{GetCurrentProcess, OpenProcessToken};
        use winapi::um::securitybaseapi::GetTokenInformation;
        use winapi::um::winnt::{TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};

        unsafe {
            let mut token = std::ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return false;
            }

            let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
            let mut size = 0;
            let result = GetTokenInformation(
                token,
                TokenElevation,
                &mut elevation as *mut _ as *mut _,
                std::mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut size,
            );

            CloseHandle(token);

            if result == 0 {
                return false;
            }

            elevation.TokenIsElevated != 0
        }
    }

    #[cfg(not(windows))]
    false
}

async fn ensure_chocolatey() -> Result<()> {
    if is_command_available("choco") {
        info!("Chocolatey already installed");
        return Ok(());
    }

    info!("📦 Installing Chocolatey package manager...");

    let install_script = r#"
        Set-ExecutionPolicy Bypass -Scope Process -Force;
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
        iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
    "#;

    let output = Command::new("powershell")
        .args(&["-Command", install_script])
        .output()?;

    if output.status.success() {
        info!("✅ Chocolatey installed successfully");
    } else {
        warn!("Failed to install Chocolatey: {}", 
              String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}

async fn install_system_deps() -> Result<()> {
    info!("📦 Installing system dependencies...");

    let packages = vec!["curl", "jq"];

    for package in packages {
        if !is_command_available(package) {
            info!("Installing {}...", package);
            
            let output = Command::new("choco")
                .args(&["install", package, "-y"])
                .output()?;

            if output.status.success() {
                info!("✅ {} installed", package);
            } else {
                warn!("Failed to install {}: {}", package, 
                      String::from_utf8_lossy(&output.stderr));
            }
        }
    }

    Ok(())
}

async fn configure_dns() -> Result<()> {
    info!("🌐 Configuring Windows DNS...");

    // Add DNS server for .dev domains
    let powershell_script = r#"
        # Add DNS client rule for .dev domains
        try {
            $rule = Get-DnsClientNrptRule -Namespace ".dev" -ErrorAction SilentlyContinue
            if (-not $rule) {
                Add-DnsClientNrptRule -Namespace ".dev" -NameServers "127.0.0.1"
                Write-Host "DNS rule added for .dev domains"
            } else {
                Write-Host "DNS rule already exists for .dev domains"
            }
        } catch {
            Write-Warning "Failed to configure DNS rule: $($_.Exception.Message)"
        }
    "#;

    let output = Command::new("powershell")
        .args(&["-Command", powershell_script])
        .output()?;

    if output.status.success() {
        info!("✅ DNS configured for .dev domains");
    } else {
        warn!("Failed to configure DNS: {}", 
              String::from_utf8_lossy(&output.stderr));
    }

    Ok(())
}

async fn setup_firewall_rules() -> Result<()> {
    info!("🔥 Setting up Windows Firewall rules...");

    let rules = vec![
        ("Nebula HTTP", "3000"),
        ("Nebula HTTPS", "3443"),
        ("Nebula DNS", "53"),
    ];

    for (rule_name, port) in rules {
        let command = format!(
            "New-NetFirewallRule -DisplayName '{}' -Direction Inbound -Protocol TCP -LocalPort {} -Action Allow -ErrorAction SilentlyContinue",
            rule_name, port
        );

        let output = Command::new("powershell")
            .args(&["-Command", &command])
            .output()?;

        if output.status.success() {
            info!("✅ Firewall rule added: {} (port {})", rule_name, port);
        } else {
            // Rule might already exist, which is fine
            info!("Firewall rule for {} may already exist", rule_name);
        }
    }

    Ok(())
}

fn is_command_available(cmd: &str) -> bool {
    Command::new("where")
        .arg(cmd)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub async fn cleanup() -> Result<()> {
    info!("🧹 Cleaning up Windows configuration...");

    // Remove DNS client rule
    let powershell_script = r#"
        try {
            Remove-DnsClientNrptRule -Namespace ".dev" -Force -ErrorAction SilentlyContinue
            Write-Host "DNS rule removed for .dev domains"
        } catch {
            Write-Warning "Failed to remove DNS rule: $($_.Exception.Message)"
        }
    "#;

    let _ = Command::new("powershell")
        .args(&["-Command", powershell_script])
        .output();

    // Remove firewall rules
    let rules = vec!["Nebula HTTP", "Nebula HTTPS", "Nebula DNS"];
    
    for rule_name in rules {
        let command = format!(
            "Remove-NetFirewallRule -DisplayName '{}' -ErrorAction SilentlyContinue",
            rule_name
        );

        let _ = Command::new("powershell")
            .args(&["-Command", &command])
            .output();
    }

    info!("✅ Windows cleanup completed");
    Ok(())
}
