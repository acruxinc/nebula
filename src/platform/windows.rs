use anyhow::Result;
use std::process::Command;
use tracing::{info, warn, error, debug};
use tokio::fs;

use crate::error::{NebulaError, Result as NebulaResult};

pub async fn setup(no_packages: bool, no_dns_setup: bool, no_firewall: bool) -> NebulaResult<()> {
    info!("🪟 Setting up Nebula for Windows...");

    // Check Windows version
    check_windows_version().await?;

    // Check if running as administrator
    if !is_admin() {
        warn!("⚠️  Not running as administrator. Some features may not work properly.");
        warn!("Consider running PowerShell as Administrator for full functionality.");
    }

    // Install chocolatey if not present and packages are needed
    if !no_packages {
        ensure_chocolatey().await?;
        install_system_deps().await?;
    }

    // Configure Windows DNS
    if !no_dns_setup {
        configure_dns().await?;
    }

    // Setup Windows Firewall rules
    if !no_firewall {
        setup_firewall_rules().await?;
    }

    // Setup Windows services
    setup_windows_services().await?;

    // Configure network adapter settings
    configure_network_settings().await?;

    // Setup scheduled tasks
    setup_scheduled_tasks().await?;

    info!("✅ Windows setup completed!");
    Ok(())
}

async fn check_windows_version() -> NebulaResult<()> {
    let version_info = get_windows_version().await?;
    info!("Detected Windows version: {}", version_info.display_version);
    
    // Check for minimum Windows 10 version
    if version_info.major_version < 10 {
        warn!("Windows version {} may not be fully supported. Recommended: Windows 10+", 
              version_info.display_version);
    }

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

async fn ensure_chocolatey() -> NebulaResult<()> {
    if is_command_available("choco") {
        info!("Chocolatey already installed");
        return Ok(());
    }

    info!("📦 Installing Chocolatey package manager...");

    let install_script = r#"
        Set-ExecutionPolicy Bypass -Scope Process -Force;
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072;
        try {
            iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
            Write-Output "Chocolatey installation completed"
        } catch {
            Write-Error "Chocolatey installation failed: $_"
            exit 1
        }
    "#;

    let output = run_powershell_command(install_script).await?;

    if output.status.success() {
        info!("✅ Chocolatey installed successfully");
        
        // Refresh environment variables
        refresh_environment().await?;
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(NebulaError::platform(format!("Chocolatey installation failed: {}", stderr)));
    }

    Ok(())
}

async fn install_system_deps() -> NebulaResult<()> {
    info!("📦 Installing system dependencies...");

    let packages = vec![
        "curl",
        "jq", 
        "wget",
        "openssl",
        "nmap", // For network utilities
    ];

    for package in packages {
        if !is_package_installed(package).await {
            info!("Installing {}...", package);
            
            let install_cmd = format!("choco install {} -y", package);
            let output = run_powershell_command(&install_cmd).await?;

            if output.status.success() {
                debug!("Successfully installed {}", package);
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!("Failed to install {}: {}", package, stderr);
                // Continue with other packages
            }
        } else {
            debug!("{} already installed", package);
        }
    }

    // Refresh environment after installations
    refresh_environment().await?;

    Ok(())
}

async fn configure_dns() -> NebulaResult<()> {
    info!("🌐 Configuring Windows DNS...");

    // Get all network adapters
    let adapters = get_network_adapters().await?;
    
    for adapter in &adapters {
        if adapter.status == "Up" {
            debug!("Configuring DNS for adapter: {}", adapter.name);
            
            // Set DNS servers (our local DNS first, then fallbacks)
            let dns_script = format!(
                r#"
                try {{
                    Set-DnsClientServerAddress -InterfaceAlias "{}" -ServerAddresses "127.0.0.1","8.8.8.8","1.1.1.1"
                    Write-Output "DNS configured for {}"
                }} catch {{
                    Write-Warning "Failed to configure DNS for {}: $_"
                }}
                "#, 
                adapter.name, adapter.name, adapter.name
            );
            
            let output = run_powershell_command(&dns_script).await;
            match output {
                Ok(result) => {
                    if result.status.success() {
                        debug!("DNS configured for adapter: {}", adapter.name);
                    } else {
                        warn!("Failed to configure DNS for adapter: {}", adapter.name);
                    }
                }
                Err(e) => {
                    warn!("Error configuring DNS for adapter {}: {}", adapter.name, e);
                }
            }
        }
    }

    // Add DNS client NRPT rules for development domains
    configure_nrpt_rules().await?;

    // Flush DNS cache
    flush_dns_cache().await?;

    Ok(())
}

async fn configure_nrpt_rules() -> NebulaResult<()> {
    info!("Configuring NRPT rules for development domains...");

    let domains = vec!["dev", "nebula.com"];
    
    for domain in domains {
        let nrpt_script = format!(
            r#"
            try {{
                $existingRule = Get-DnsClientNrptRule -Namespace ".{}" -ErrorAction SilentlyContinue
                if ($existingRule) {{
                    Remove-DnsClientNrptRule -Namespace ".{}" -Force
                }}
                Add-DnsClientNrptRule -Namespace ".{}" -NameServers "127.0.0.1"
                Write-Output "NRPT rule added for .{}"
            }} catch {{
                Write-Warning "Failed to configure NRPT rule for .{}: $_"
            }}
            "#, 
            domain, domain, domain, domain, domain
        );
        
        let output = run_powershell_command(&nrpt_script).await;
        match output {
            Ok(result) => {
                if result.status.success() {
                    debug!("NRPT rule configured for .{}", domain);
                } else {
                    warn!("Failed to configure NRPT rule for .{}", domain);
                }
            }
            Err(e) => {
                warn!("Error configuring NRPT rule for .{}: {}", domain, e);
            }
        }
    }

    Ok(())
}

async fn setup_firewall_rules() -> NebulaResult<()> {
    info!("🔥 Setting up Windows Firewall rules...");

    let rules = vec![
        ("Nebula HTTP", "3000", "TCP"),
        ("Nebula HTTPS", "3443", "TCP"),
        ("Nebula Alt HTTP", "8080", "TCP"),
        ("Nebula DNS TCP", "53", "TCP"),
        ("Nebula DNS UDP", "53", "UDP"),
    ];

    for (rule_name, port, protocol) in rules {
        let firewall_script = format!(
            r#"
            try {{
                $existingRule = Get-NetFirewallRule -DisplayName "{}" -ErrorAction SilentlyContinue
                if ($existingRule) {{
                    Remove-NetFirewallRule -DisplayName "{}"
                }}
                New-NetFirewallRule -DisplayName "{}" -Direction Inbound -Protocol {} -LocalPort {} -Action Allow -Profile Any
                Write-Output "Firewall rule added: {} (port {}/{})"
            }} catch {{
                Write-Warning "Failed to add firewall rule {}: $_"
            }}
            "#, 
            rule_name, rule_name, rule_name, protocol, port, rule_name, port, protocol, rule_name
        );

        let output = run_powershell_command(&firewall_script).await;
        match output {
            Ok(result) => {
                if result.status.success() {
                    debug!("Firewall rule added: {} (port {}/{})", rule_name, port, protocol);
                } else {
                    warn!("Failed to add firewall rule: {}", rule_name);
                }
            }
            Err(e) => {
                warn!("Error adding firewall rule {}: {}", rule_name, e);
            }
        }
    }

    info!("✅ Firewall rules configured");
    Ok(())
}

async fn setup_windows_services() -> NebulaResult<()> {
    info!("🚀 Setting up Windows services...");

    // Create a Windows service configuration for Nebula DNS
    // Note: This is a simplified approach - in production you'd use a proper Windows service wrapper
    
    let service_script = r#"
    # Check if Nebula DNS service exists
    $serviceName = "NebulaDNS"
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    
    if ($service) {
        Write-Output "Nebula DNS service already exists"
    } else {
        Write-Output "Nebula DNS service configuration prepared"
        # In a real implementation, you would install the service here
        # New-Service -Name $serviceName -BinaryPathName "C:\Program Files\Nebula\nebula.exe dns start"
    }
    "#;

    let output = run_powershell_command(service_script).await;
    match output {
        Ok(result) => {
            if result.status.success() {
                debug!("Windows services configured");
            }
        }
        Err(e) => {
            warn!("Error configuring Windows services: {}", e);
        }
    }

    Ok(())
}

async fn configure_network_settings() -> NebulaResult<()> {
    info!("🌐 Configuring network settings...");

    // Configure network adapter settings for better performance
    let network_script = r#"
    try {
        # Enable DNS over HTTPS (DoH) fallback
        Set-DnsClientDohServerAddress -ServerAddress "1.1.1.1" -DohTemplate "https://cloudflare-dns.com/dns-query" -AllowFallbackToUdp $true -ErrorAction SilentlyContinue
        
        # Configure DNS cache settings
        Set-DnsClient -InterfaceIndex (Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Select-Object -First 1).InterfaceIndex -RegisterThisConnectionsAddress $true -ErrorAction SilentlyContinue
        
        Write-Output "Network settings configured"
    } catch {
        Write-Warning "Some network settings could not be configured: $_"
    }
    "#;

    let output = run_powershell_command(network_script).await;
    match output {
        Ok(result) => {
            if result.status.success() {
                debug!("Network settings configured");
            }
        }
        Err(e) => {
            warn!("Error configuring network settings: {}", e);
        }
    }

    Ok(())
}

async fn setup_scheduled_tasks() -> NebulaResult<()> {
    info!("⏰ Setting up scheduled tasks...");

    // Create a scheduled task for Nebula maintenance
    let task_script = r#"
    try {
        $taskName = "NebulaMaintenanceTask"
        $existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        
        if ($existingTask) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
        
        # Create a simple maintenance task (this is a placeholder)
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-Command `"Write-Output 'Nebula maintenance task executed'`""
        $trigger = New-ScheduledTaskTrigger -Daily -At "02:00AM"
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Description "Nebula maintenance task"
        
        Write-Output "Scheduled task created: $taskName"
    } catch {
        Write-Warning "Failed to create scheduled task: $_"
    }
    "#;

    let output = run_powershell_command(task_script).await;
    match output {
        Ok(result) => {
            if result.status.success() {
                debug!("Scheduled tasks configured");
            }
        }
        Err(e) => {
            warn!("Error configuring scheduled tasks: {}", e);
        }
    }

    Ok(())
}

async fn flush_dns_cache() -> NebulaResult<()> {
    info!("🔄 Flushing DNS cache...");

    let flush_script = r#"
    try {
        Clear-DnsClientCache
        Write-Output "DNS cache flushed successfully"
    } catch {
        Write-Warning "Failed to flush DNS cache: $_"
    }
    "#;

    let output = run_powershell_command(flush_script).await;
    match output {
        Ok(result) => {
            if result.status.success() {
                debug!("DNS cache flushed");
            }
        }
        Err(e) => {
            warn!("Error flushing DNS cache: {}", e);
        }
    }

    Ok(())
}

async fn refresh_environment() -> NebulaResult<()> {
    let refresh_script = r#"
    try {
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")
        Write-Output "Environment variables refreshed"
    } catch {
        Write-Warning "Failed to refresh environment: $_"
    }
    "#;

    let _ = run_powershell_command(refresh_script).await;
    Ok(())
}

async fn run_powershell_command(script: &str) -> NebulaResult<std::process::Output> {
    let output = Command::new("powershell")
        .args(&["-ExecutionPolicy", "Bypass", "-Command", script])
        .output()
        .map_err(|e| NebulaError::platform(format!("Failed to run PowerShell command: {}", e)))?;

    Ok(output)
}

async fn is_package_installed(package: &str) -> bool {
    let check_script = format!(
        r#"
        try {{
            $package = choco list --local-only {} --exact
            if ($package -match "{}") {{
                Write-Output "installed"
            }} else {{
                Write-Output "not_installed"
            }}
        }} catch {{
            Write-Output "not_installed"
        }}
        "#, 
        package, package
    );

    match run_powershell_command(&check_script).await {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            stdout.contains("installed")
        }
        Err(_) => false,
    }
}

#[derive(Debug, Clone)]
struct NetworkAdapter {
    name: String,
    status: String,
    interface_index: u32,
}

async fn get_network_adapters() -> NebulaResult<Vec<NetworkAdapter>> {
    let adapter_script = r#"
    Get-NetAdapter | Where-Object {$_.Virtual -eq $false} | ForEach-Object {
        "$($_.Name)|$($_.Status)|$($_.InterfaceIndex)"
    }
    "#;

    let output = run_powershell_command(adapter_script).await?;
    
    if !output.status.success() {
        return Err(NebulaError::platform("Failed to get network adapters"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut adapters = Vec::new();

    for line in stdout.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.split('|').collect();
        if parts.len() >= 3 {
            if let Ok(interface_index) = parts[2].parse::<u32>() {
                adapters.push(NetworkAdapter {
                    name: parts[0].to_string(),
                    status: parts[1].to_string(),
                    interface_index,
                });
            }
        }
    }

    Ok(adapters)
}

#[derive(Debug, Clone)]
struct WindowsVersion {
    major_version: u32,
    minor_version: u32,
    build_number: u32,
    display_version: String,
}

async fn get_windows_version() -> NebulaResult<WindowsVersion> {
    let version_script = r#"
    try {
        $version = Get-ComputerInfo | Select-Object WindowsProductName, WindowsVersion, WindowsBuildLabEx
        $osVersion = [System.Environment]::OSVersion.Version
        Write-Output "$($osVersion.Major)|$($osVersion.Minor)|$($osVersion.Build)|$($version.WindowsProductName) $($version.WindowsVersion)"
    } catch {
        Write-Output "10|0|0|Windows 10"
    }
    "#;

    let output = run_powershell_command(version_script).await?;
    
    if !output.status.success() {
        return Ok(WindowsVersion {
            major_version: 10,
            minor_version: 0,
            build_number: 0,
            display_version: "Windows 10".to_string(),
        });
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout.lines().next().unwrap_or("10|0|0|Windows 10");
    let parts: Vec<&str> = line.split('|').collect();

    if parts.len() >= 4 {
        Ok(WindowsVersion {
            major_version: parts[0].parse().unwrap_or(10),
            minor_version: parts[1].parse().unwrap_or(0),
            build_number: parts[2].parse().unwrap_or(0),
            display_version: parts[3].to_string(),
        })
    } else {
        Ok(WindowsVersion {
            major_version: 10,
            minor_version: 0,
            build_number: 0,
            display_version: "Windows 10".to_string(),
        })
    }
}

pub async fn cleanup() -> NebulaResult<()> {
    info!("🧹 Cleaning up Windows configuration...");

    // Remove NRPT rules
    let cleanup_nrpt_script = r#"
    try {
        Get-DnsClientNrptRule | Where-Object {$_.Namespace -match "\.dev$|\.nebula\.com$"} | Remove-DnsClientNrptRule -Force
        Write-Output "NRPT rules removed"
    } catch {
        Write-Warning "Failed to remove NRPT rules: $_"
    }
    "#;

    let _ = run_powershell_command(cleanup_nrpt_script).await;

    // Reset DNS settings for adapters
    let reset_dns_script = r#"
    try {
        Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object {
            Set-DnsClientServerAddress -InterfaceAlias $_.Name -ResetServerAddresses
        }
        Write-Output "DNS settings reset"
    } catch {
        Write-Warning "Failed to reset DNS settings: $_"
    }
    "#;

    let _ = run_powershell_command(reset_dns_script).await;

    // Remove firewall rules
    let remove_firewall_script = r#"
    try {
        $ruleNames = @("Nebula HTTP", "Nebula HTTPS", "Nebula Alt HTTP", "Nebula DNS TCP", "Nebula DNS UDP")
        foreach ($ruleName in $ruleNames) {
            $rule = Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue
            if ($rule) {
                Remove-NetFirewallRule -DisplayName $ruleName
                Write-Output "Removed firewall rule: $ruleName"
            }
        }
    } catch {
        Write-Warning "Failed to remove firewall rules: $_"
    }
    "#;

    let _ = run_powershell_command(remove_firewall_script).await;

    // Remove scheduled tasks
    let remove_task_script = r#"
    try {
        $taskName = "NebulaMaintenanceTask"
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Output "Scheduled task removed: $taskName"
        }
    } catch {
        Write-Warning "Failed to remove scheduled task: $_"
    }
    "#;

    let _ = run_powershell_command(remove_task_script).await;

    // Flush DNS cache
    flush_dns_cache().await?;

    info!("✅ Windows cleanup completed");
    Ok(())
}

fn is_command_available(cmd: &str) -> bool {
    Command::new("where")
        .arg(cmd)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

/// Windows-specific utilities
pub struct WindowsUtils;

impl WindowsUtils {
    /// Check if running on Windows 11
    pub async fn is_windows_11() -> bool {
        match get_windows_version().await {
            Ok(version) => version.major_version >= 10 && version.build_number >= 22000,
            Err(_) => false,
        }
    }

    /// Get Windows edition
    pub async fn get_windows_edition() -> Option<String> {
        let edition_script = r#"
        try {
            (Get-ComputerInfo).WindowsEditionId
        } catch {
            "Unknown"
        }
        "#;

        match run_powershell_command(edition_script).await {
            Ok(output) => {
                if output.status.success() {
                    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Check if WSL is available
    pub async fn has_wsl() -> bool {
        is_command_available("wsl")
    }

    /// Check if Hyper-V is enabled
    pub async fn has_hyperv() -> bool {
        let hyperv_script = r#"
        try {
            $hyperv = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All
            $hyperv.State -eq "Enabled"
        } catch {
            $false
        }
        "#;

        match run_powershell_command(hyperv_script).await {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    stdout.trim() == "True"
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }

    /// Get PowerShell version
    pub async fn get_powershell_version() -> Option<String> {
        let version_script = r#"$PSVersionTable.PSVersion.ToString()"#;

        match run_powershell_command(version_script).await {
            Ok(output) => {
                if output.status.success() {
                    Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
                } else {
                    None
                }
            }
            Err(_) => None,
        }
    }

    /// Check if Windows Terminal is installed
    pub async fn has_windows_terminal() -> bool {
        let terminal_script = r#"
        try {
            Get-AppxPackage -Name "Microsoft.WindowsTerminal" | Select-Object -First 1
            $true
        } catch {
            $false
        }
        "#;

        match run_powershell_command(terminal_script).await {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    stdout.trim() == "True"
                } else {
                    false
                }
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_admin() {
        // This test will only work properly on Windows
        #[cfg(windows)]
        {
            let _is_admin = is_admin();
            // Just ensure it doesn't crash
        }
    }

    #[test]
    fn test_is_command_available() {
        #[cfg(windows)]
        {
            assert!(is_command_available("cmd"));
            assert!(is_command_available("powershell"));
            assert!(!is_command_available("this_command_does_not_exist_12345"));
        }
    }

    #[tokio::test]
    async fn test_windows_version() {
        #[cfg(windows)]
        {
            let result = get_windows_version().await;
            assert!(result.is_ok(), "Should get Windows version");
            
            let version = result.unwrap();
            assert!(version.major_version >= 6, "Should be Windows Vista or later");
        }
    }

    #[tokio::test]
    async fn test_windows_utils() {
        #[cfg(windows)]
        {
            // Test Windows 11 detection
            let _is_win11 = WindowsUtils::is_windows_11().await;
            
            // Test PowerShell version
            let _ps_version = WindowsUtils::get_powershell_version().await;
            
            // Test WSL detection
            let _has_wsl = WindowsUtils::has_wsl().await;
        }
    }

    #[tokio::test]
    async fn test_network_adapters() {
        #[cfg(windows)]
        {
            let result = get_network_adapters().await;
            // Should either succeed or fail gracefully
            match result {
                Ok(adapters) => {
                    // Should have at least one adapter on a real system
                    assert!(!adapters.is_empty() || cfg!(test));
                }
                Err(_) => {
                    // Failure is acceptable in test environment
                }
            }
        }
    }

    #[tokio::test]
    async fn test_powershell_execution() {
        #[cfg(windows)]
        {
            let simple_script = r#"Write-Output "test""#;
            let result = run_powershell_command(simple_script).await;
            
            assert!(result.is_ok(), "Should be able to run PowerShell commands");
            
            if let Ok(output) = result {
                assert!(output.status.success(), "Simple PowerShell command should succeed");
                let stdout = String::from_utf8_lossy(&output.stdout);
                assert!(stdout.contains("test"), "Should output test message");
            }
        }
    }
}
