# Nebula Installation Script for Windows
# Requires PowerShell 5.1 or later

param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:ProgramFiles\Nebula",
    [switch]$Uninstall,
    [switch]$Help
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Constants
$RepoUrl = "https://github.com/your-org/nebula"
$ReleasesUrl = "$RepoUrl/releases"
$TempDir = [System.IO.Path]::GetTempPath() + "nebula-install-$(Get-Random)"

# Colors for output (PowerShell 5.1 compatible)
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    switch ($Level) {
        "INFO" { 
            Write-Host "[$timestamp] [INFO] $Message" -ForegroundColor Cyan
        }
        "SUCCESS" { 
            Write-Host "[$timestamp] [SUCCESS] $Message" -ForegroundColor Green
        }
        "WARN" { 
            Write-Host "[$timestamp] [WARN] $Message" -ForegroundColor Yellow
        }
        "ERROR" { 
            Write-Host "[$timestamp] [ERROR] $Message" -ForegroundColor Red
        }
        default {
            Write-Host "[$timestamp] $Message"
        }
    }
}

# Logging functions
function Log-Info { param($Message) Write-ColorOutput $Message "INFO" }
function Log-Success { param($Message) Write-ColorOutput $Message "SUCCESS" }
function Log-Warn { param($Message) Write-ColorOutput $Message "WARN" }
function Log-Error { param($Message) Write-ColorOutput $Message "ERROR" }

# Check PowerShell version
function Test-PowerShellVersion {
    $psVersion = $PSVersionTable.PSVersion.Major
    if ($psVersion -lt 5) {
        Log-Error "PowerShell 5.1 or later is required. Current version: $($PSVersionTable.PSVersion)"
        exit 1
    }
    Log-Info "PowerShell version: $($PSVersionTable.PSVersion)"
}

# Check if running as administrator
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Check system dependencies
function Test-Dependencies {
    Log-Info "Checking system dependencies..."
    
    $missingDeps = @()
    
    # Check for required commands
    $requiredCommands = @("curl", "tar")
    foreach ($cmd in $requiredCommands) {
        if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
            $missingDeps += $cmd
        }
    }
    
    if ($missingDeps.Count -gt 0) {
        Log-Error "Missing required dependencies: $($missingDeps -join ', ')"
        Log-Info "Please install missing dependencies and try again"
        Log-Info "You can install curl and tar using:"
        Log-Info "  - Chocolatey: choco install curl tar"
        Log-Info "  - Scoop: scoop install curl tar"
        Log-Info "  - Manual download from: https://curl.se/download.html"
        exit 1
    }
    
    Log-Success "All dependencies satisfied"
}

# Detect system architecture
function Get-SystemArchitecture {
    $arch = $env:PROCESSOR_ARCHITECTURE
    
    switch ($arch) {
        "AMD64" { return "amd64" }
        "ARM64" { return "arm64" }
        default { 
            Log-Error "Unsupported architecture: $arch"
            exit 1
        }
    }
}

# Get the latest version if not specified
function Get-LatestVersion {
    if ($Version -eq "latest") {
        Log-Info "Fetching latest version..."
        try {
            $response = Invoke-RestMethod -Uri "$ReleasesUrl/latest" -Method Get
            $Version = $response.tag_name
            if (-not $Version) {
                # Fallback method using GitHub API
                $apiResponse = Invoke-RestMethod -Uri "https://api.github.com/repos/your-org/nebula/releases/latest"
                $Version = $apiResponse.tag_name
            }
            Log-Info "Latest version: $Version"
        }
        catch {
            Log-Error "Failed to fetch latest version: $($_.Exception.Message)"
            exit 1
        }
    }
}

# Download and verify nebula binary
function Install-Nebula {
    $arch = Get-SystemArchitecture
    $downloadUrl = "$ReleasesUrl/download/$Version/nebula-windows-$arch.zip"
    
    # Create temp directory
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    
    Log-Info "Downloading Nebula $Version for windows-$arch..."
    Log-Info "Download URL: $downloadUrl"
    
    try {
        $zipPath = "$TempDir\nebula.zip"
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing
        
        Log-Info "Extracting archive..."
        Expand-Archive -Path $zipPath -DestinationPath $TempDir -Force
        
        # Find the nebula executable
        $nebulaExe = Get-ChildItem -Path $TempDir -Name "nebula.exe" -Recurse | Select-Object -First 1
        if (-not $nebulaExe) {
            Log-Error "Nebula executable not found in archive"
            exit 1
        }
        
        $nebulaPath = Join-Path $TempDir $nebulaExe
        
        # Create install directory if it doesn't exist
        if (-not (Test-Path $InstallDir)) {
            Log-Info "Creating install directory: $InstallDir"
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }
        
        # Install binary
        Log-Info "Installing to $InstallDir..."
        Copy-Item -Path $nebulaPath -Destination "$InstallDir\nebula.exe" -Force
        
        # Create start menu shortcut
        New-StartMenuShortcut -InstallDir $InstallDir
        
        # Cleanup
        Remove-Item -Path $TempDir -Recurse -Force
        
        Log-Success "Nebula installed successfully!"
    }
    catch {
        Log-Error "Failed to install Nebula: $($_.Exception.Message)"
        if (Test-Path $TempDir) {
            Remove-Item -Path $TempDir -Recurse -Force
        }
        exit 1
    }
}

# Create start menu shortcut
function New-StartMenuShortcut {
    param($InstallDir)
    
    try {
        $startMenuPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs"
        $shortcutPath = "$startMenuPath\Nebula.lnk"
        
        $WshShell = New-Object -comObject WScript.Shell
        $Shortcut = $WshShell.CreateShortcut($shortcutPath)
        $Shortcut.TargetPath = "$InstallDir\nebula.exe"
        $Shortcut.Arguments = "server"
        $Shortcut.WorkingDirectory = $InstallDir
        $Shortcut.Description = "Nebula Universal Development Server"
        $Shortcut.Save()
        
        Log-Success "Start menu shortcut created"
    }
    catch {
        Log-Warn "Failed to create start menu shortcut: $($_.Exception.Message)"
    }
}

# Setup PowerShell profile integration
function Set-PowerShellProfile {
    Log-Info "Setting up PowerShell profile integration..."
    
    $profilePath = $PROFILE
    $profileDir = Split-Path $profilePath -Parent
    
    # Create profile directory if it doesn't exist
    if (-not (Test-Path $profileDir)) {
        New-Item -ItemType Directory -Path $profileDir -Force | Out-Null
    }
    
    # Add Nebula to PATH and create alias
    $nebulaPath = "$InstallDir\nebula.exe"
    $profileContent = @"

# Nebula Universal Development Server
`$env:PATH += ";$InstallDir"
Set-Alias -Name nebula -Value "$nebulaPath"

# Nebula completion function
function NebulaCompletion {
    param(`$commandName, `$parameterName, `$wordToComplete, `$commandAst, `$fakeBoundParameters)
    
    if (`$wordToComplete -match '^init|dev|build|scheduler|dns|dhcp|setup|cleanup$') {
        return `$wordToComplete
    }
    
    # Add more completion logic as needed
    return @()
}

Register-ArgumentCompleter -CommandName nebula -ParameterName Command -ScriptBlock `$function:NebulaCompletion
"@
    
    # Check if profile already has Nebula configuration
    if (Test-Path $profilePath) {
        $existingContent = Get-Content $profilePath -Raw
        if ($existingContent -notmatch "Nebula Universal Development Server") {
            Add-Content -Path $profilePath -Value $profileContent
            Log-Success "PowerShell profile updated"
        } else {
            Log-Info "PowerShell profile already contains Nebula configuration"
        }
    } else {
        Set-Content -Path $profilePath -Value $profileContent
        Log-Success "PowerShell profile created"
    }
}

# Create Windows service
function New-NebulaService {
    Log-Info "Setting up Windows service..."
    
    $serviceName = "NebulaServer"
    $serviceExists = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    
    if (-not $serviceExists) {
        try {
            $binaryPath = "$InstallDir\nebula.exe"
            
            # Create service using sc.exe
            $result = & sc.exe create $serviceName binPath= "$binaryPath server" start= auto DisplayName= "Nebula Universal Development Server"
            
            if ($LASTEXITCODE -eq 0) {
                Log-Success "Windows service created"
                
                # Set service description
                & sc.exe description $serviceName "Universal development and production server for any programming language and framework"
            } else {
                Log-Warn "Failed to create Windows service: $result"
            }
        }
        catch {
            Log-Warn "Failed to create Windows service: $($_.Exception.Message)"
        }
    } else {
        Log-Info "Windows service already exists"
    }
}

# Verify installation
function Test-Installation {
    Log-Info "Verifying installation..."
    
    $nebulaPath = "$InstallDir\nebula.exe"
    
    if (Test-Path $nebulaPath) {
        try {
            $version = & $nebulaPath --version 2>$null
            if ($LASTEXITCODE -eq 0) {
                Log-Success "Nebula installed successfully!"
                Log-Info "Version: $version"
                Log-Info "Location: $nebulaPath"
                
                # Test basic functionality
                $helpResult = & $nebulaPath --help 2>$null
                if ($LASTEXITCODE -eq 0) {
                    Log-Success "Installation verification passed"
                    return $true
                } else {
                    Log-Warn "Installation verification failed - nebula --help returned error"
                    return $false
                }
            } else {
                Log-Error "Failed to get Nebula version"
                return $false
            }
        }
        catch {
            Log-Error "Failed to verify installation: $($_.Exception.Message)"
            return $false
        }
    } else {
        Log-Error "Nebula executable not found at: $nebulaPath"
        return $false
    }
}

# Display post-installation instructions
function Show-PostInstallInfo {
    Log-Info "Post-installation setup:"
    Write-Host ""
    Write-Host "1. Reload PowerShell profile:" -ForegroundColor Cyan
    Write-Host "   . `$PROFILE"
    Write-Host ""
    Write-Host "2. Or restart PowerShell to load new configuration"
    Write-Host ""
    Write-Host "3. Initialize Nebula in your project:" -ForegroundColor Cyan
    Write-Host "   cd your-project-directory"
    Write-Host "   nebula init"
    Write-Host ""
    Write-Host "4. Start development server:" -ForegroundColor Cyan
    Write-Host "   nebula dev"
    Write-Host ""
    Write-Host "5. For production deployment:" -ForegroundColor Cyan
    Write-Host "   nebula scheduler start"
    Write-Host ""
    Write-Host "6. Manage Windows service:" -ForegroundColor Cyan
    Write-Host "   Start-Service NebulaServer"
    Write-Host "   Stop-Service NebulaServer"
    Write-Host ""
    Write-Host "🎉 Installation complete! Happy coding with Nebula!" -ForegroundColor Green
}

# Uninstall function
function Remove-Nebula {
    Log-Info "Uninstalling Nebula..."
    
    # Remove binary
    $nebulaPath = "$InstallDir\nebula.exe"
    if (Test-Path $nebulaPath) {
        Remove-Item -Path $nebulaPath -Force
        Log-Success "Removed nebula executable"
    }
    
    # Remove install directory if empty
    if ((Get-ChildItem $InstallDir -ErrorAction SilentlyContinue).Count -eq 0) {
        Remove-Item -Path $InstallDir -Force
        Log-Success "Removed install directory"
    }
    
    # Remove Windows service
    $serviceName = "NebulaServer"
    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Stop-Service -Name $serviceName -Force
        }
        & sc.exe delete $serviceName
        Log-Success "Removed Windows service"
    }
    
    # Remove start menu shortcut
    $shortcutPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Nebula.lnk"
    if (Test-Path $shortcutPath) {
        Remove-Item -Path $shortcutPath -Force
        Log-Success "Removed start menu shortcut"
    }
    
    # Clean PowerShell profile
    if (Test-Path $PROFILE) {
        $profileContent = Get-Content $PROFILE -Raw
        if ($profileContent -match "Nebula Universal Development Server") {
            # Remove Nebula section from profile
            $lines = Get-Content $PROFILE
            $newLines = @()
            $skipSection = $false
            
            foreach ($line in $lines) {
                if ($line -match "Nebula Universal Development Server") {
                    $skipSection = $true
                }
                elseif ($skipSection -and $line -match "^$") {
                    $skipSection = $false
                    continue
                }
                elseif (-not $skipSection) {
                    $newLines += $line
                }
            }
            
            Set-Content -Path $PROFILE -Value $newLines
            Log-Success "Cleaned PowerShell profile"
        }
    }
    
    # Remove config directory
    $configDir = "$env:APPDATA\Nebula"
    if (Test-Path $configDir) {
        Remove-Item -Path $configDir -Recurse -Force
        Log-Success "Removed configuration directory"
    }
    
    Log-Success "Nebula uninstalled successfully!"
}

# Show usage information
function Show-Usage {
    Write-Host "Nebula Installation Script for Windows"
    Write-Host ""
    Write-Host "Usage: .\install.ps1 [OPTIONS]"
    Write-Host ""
    Write-Host "Options:"
    Write-Host "  -Version VERSION     Install specific version (default: latest)"
    Write-Host "  -InstallDir PATH     Installation directory (default: `$env:ProgramFiles\Nebula)"
    Write-Host "  -Uninstall          Uninstall Nebula"
    Write-Host "  -Help               Show this help message"
    Write-Host ""
    Write-Host "Environment variables:"
    Write-Host "  `$env:NEBULA_VERSION    Version to install"
    Write-Host "  `$env:NEBULA_INSTALL_DIR Installation directory"
    Write-Host ""
    Write-Host "Examples:"
    Write-Host "  .\install.ps1                           # Install latest version"
    Write-Host "  .\install.ps1 -Version v1.0.0          # Install specific version"
    Write-Host "  .\install.ps1 -InstallDir C:\Tools     # Install to custom directory"
    Write-Host "  .\install.ps1 -Uninstall               # Uninstall Nebula"
    Write-Host ""
    Write-Host "Note: Administrator privileges may be required for service installation."
}

# Main function
function Main {
    # Handle help
    if ($Help) {
        Show-Usage
        exit 0
    }
    
    # Handle uninstall
    if ($Uninstall) {
        Remove-Nebula
        exit 0
    }
    
    # Check if running as administrator for service creation
    $isAdmin = Test-Administrator
    if (-not $isAdmin) {
        Log-Warn "Not running as administrator. Some features may not be available."
    }
    
    # Installation process
    Log-Info "Starting Nebula installation..."
    Log-Info "Version: $Version"
    Log-Info "Install directory: $InstallDir"
    Write-Host ""
    
    Test-PowerShellVersion
    Test-Dependencies
    Get-LatestVersion
    Install-Nebula
    Set-PowerShellProfile
    
    if ($isAdmin) {
        New-NebulaService
    } else {
        Log-Info "Skipping service creation (not running as administrator)"
    }
    
    if (Test-Installation) {
        Show-PostInstallInfo
    } else {
        Log-Error "Installation verification failed"
        exit 1
    }
}

# Run main function
try {
    Main
}
catch {
    Log-Error "Installation failed: $($_.Exception.Message)"
    exit 1
}
finally {
    # Cleanup temp directory if it exists
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
