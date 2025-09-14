# Installation Guide

This guide will help you install Nebula on your system. Nebula supports macOS, Linux, and Windows.

## System Requirements

### Minimum Requirements
- **CPU**: 1 core, 2GHz
- **RAM**: 512MB
- **Storage**: 100MB free space
- **Network**: Internet connection for initial setup

### Supported Operating Systems
- **macOS**: 10.15+ (Catalina and later)
- **Linux**: Ubuntu 18.04+, CentOS 7+, Fedora 32+, Arch Linux
- **Windows**: Windows 10 version 1903+, Windows 11

### Dependencies
- **Rust**: 1.70+ (for building from source)
- **OpenSSL**: Latest version (for TLS support)
- **Git**: For version control (optional)

## Installation Methods

### Method 1: Quick Install (Recommended)

The quickest way to install Nebula is using our installation scripts:

#### Unix-like Systems (macOS, Linux)

```bash
# Download and run the installation script
curl -fsSL https://raw.githubusercontent.com/acruxinc/nebula/main/scripts/install.sh | bash

# Or with specific version
curl -fsSL https://raw.githubusercontent.com/acruxinc/nebula/main/scripts/install.sh | bash -s -- --version v1.0.0
```

#### Windows (PowerShell)

```powershell
# Download and run the installation script
iwr -useb https://raw.githubusercontent.com/acruxinc/nebula/main/scripts/install.ps1 | iex

# Or with specific version
iwr -useb https://raw.githubusercontent.com/acruxinc/nebula/main/scripts/install.ps1 | iex -ArgumentList "-Version", "v1.0.0"
```

### Method 2: Manual Installation

#### Step 1: Download Binary

1. Go to the [GitHub Releases](https://github.com/acruxinc/nebula/releases) page
2. Download the appropriate binary for your system:
   - **macOS**: `nebula-macos-amd64.tar.gz` or `nebula-macos-arm64.tar.gz`
   - **Linux**: `nebula-linux-amd64.tar.gz` or `nebula-linux-arm64.tar.gz`
   - **Windows**: `nebula-windows-amd64.zip` or `nebula-windows-arm64.zip`

#### Step 2: Extract and Install

**macOS/Linux:**
```bash
# Extract the archive
tar -xzf nebula-linux-amd64.tar.gz

# Move to system PATH
sudo mv nebula /usr/local/bin/

# Make executable
sudo chmod +x /usr/local/bin/nebula
```

**Windows:**
```powershell
# Extract the archive
Expand-Archive -Path nebula-windows-amd64.zip -DestinationPath C:\Program Files\Nebula

# Add to PATH (optional)
$env:PATH += ";C:\Program Files\Nebula"
```

### Method 3: Package Managers

#### Homebrew (macOS)
```bash
# Add the tap (when available)
brew tap acruxinc/nebula

# Install Nebula
brew install nebula
```

#### Chocolatey (Windows)
```powershell
# Install via Chocolatey (when available)
choco install nebula
```

#### Snap (Linux)
```bash
# Install via Snap (when available)
sudo snap install nebula
```

### Method 4: Build from Source

#### Prerequisites
```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Install platform-specific dependencies
# macOS
brew install openssl pkg-config

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install libssl-dev pkg-config

# CentOS/RHEL/Fedora
sudo dnf install openssl-devel pkg-config
```

#### Build and Install
```bash
# Clone the repository
git clone https://github.com/acruxinc/nebula.git
cd nebula

# Build in release mode
cargo build --release

# Install to system
sudo cp target/release/nebula /usr/local/bin/
sudo chmod +x /usr/local/bin/nebula
```

## Post-Installation Setup

### 1. Verify Installation

```bash
# Check version
nebula --version

# Check help
nebula --help

# Run health check
nebula health
```

### 2. System Setup

Run the setup command to configure system dependencies:

```bash
# Run system setup
nebula setup

# This will:
# - Configure DNS settings
# - Set up firewall rules
# - Install system certificates
# - Create necessary directories
```

### 3. Configuration

Create your first configuration:

```bash
# Initialize in a project directory
mkdir my-project
cd my-project
nebula init

# This creates nebula.toml with default settings
```

## Platform-Specific Notes

### macOS

The installation script will:
- Configure DNS resolver in `/etc/resolver/`
- Add firewall rules via `pfctl`
- Install certificates in the system keychain
- Create launchd service (optional)

**Manual DNS Setup:**
```bash
# Create resolver configuration
sudo mkdir -p /etc/resolver
echo "nameserver 127.0.0.1" | sudo tee /etc/resolver/nebula.com
echo "nameserver 127.0.0.1" | sudo tee /etc/resolver/dev
```

### Linux

The installation script will:
- Configure `systemd-resolved` (if available)
- Set up `iptables` rules
- Install CA certificates
- Create systemd service (optional)

**Manual DNS Setup:**
```bash
# For systemd-resolved
sudo mkdir -p /etc/systemd/resolved.conf.d
sudo tee /etc/systemd/resolved.conf.d/nebula.conf << EOF
[Resolve]
DNS=127.0.0.1
Domains=~dev ~nebula.com
EOF
sudo systemctl restart systemd-resolved
```

### Windows

The installation script will:
- Configure DNS client rules
- Add firewall rules via PowerShell
- Install certificates in the certificate store
- Create Windows service (optional)

**Manual DNS Setup:**
```powershell
# Configure DNS client rules
Add-DnsClientNrptRule -Namespace ".dev" -NameServers "127.0.0.1"
Add-DnsClientNrptRule -Namespace ".nebula.com" -NameServers "127.0.0.1"
```

## Troubleshooting Installation

### Common Issues

**Permission Denied:**
```bash
# Fix permissions
sudo chmod +x /usr/local/bin/nebula
sudo chown root:root /usr/local/bin/nebula
```

**Command Not Found:**
```bash
# Check if nebula is in PATH
which nebula
echo $PATH

# Add to PATH if needed
export PATH="/usr/local/bin:$PATH"
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc
```

**Port Conflicts:**
```bash
# Check what's using port 53 (DNS)
sudo lsof -i :53

# Check other ports
sudo lsof -i :3000  # HTTP
sudo lsof -i :3443  # HTTPS
```

**Certificate Issues:**
```bash
# Regenerate certificates
nebula cert generate --force

# Check certificate status
nebula cert list
```

### Getting Help

If you encounter issues during installation:

1. **Check the logs**: `nebula logs`
2. **Run health check**: `nebula health`
3. **Search existing issues**: [GitHub Issues](https://github.com/acruxinc/nebula/issues)
4. **Ask for help**: [GitHub Discussions](https://github.com/acruxinc/nebula/discussions)

## Uninstallation

### Quick Uninstall

**macOS/Linux:**
```bash
# Run the uninstall script (if available)
curl -fsSL https://raw.githubusercontent.com/acruxinc/nebula/main/scripts/uninstall.sh | bash
```

**Windows:**
```powershell
# Run the uninstall script (if available)
iwr -useb https://raw.githubusercontent.com/acruxinc/nebula/main/scripts/uninstall.ps1 | iex
```

### Manual Uninstall

**Remove Binary:**
```bash
# Remove the binary
sudo rm -f /usr/local/bin/nebula
```

**Clean Configuration:**
```bash
# Remove configuration directory
rm -rf ~/.config/nebula
rm -rf ~/.local/share/nebula

# Remove certificates
rm -rf ~/.local/share/nebula/certs
```

**Restore System Settings:**
```bash
# macOS - Remove DNS resolver
sudo rm -f /etc/resolver/nebula.com
sudo rm -f /etc/resolver/dev

# Linux - Remove systemd-resolved config
sudo rm -f /etc/systemd/resolved.conf.d/nebula.conf
sudo systemctl restart systemd-resolved

# Windows - Remove DNS client rules
Remove-DnsClientNrptRule -Namespace ".dev"
Remove-DnsClientNrptRule -Namespace ".nebula.com"
```

## Next Steps

After successful installation:

1. **Follow the [Quick Start Guide](quick-start.md)** to create your first project
2. **Read the [Configuration Guide](../configuration/overview.md)** to customize settings
3. **Explore [CLI Commands](../cli/overview.md)** for advanced usage
4. **Check [Troubleshooting](../troubleshooting/common-issues.md)** if you encounter issues

---

**Ready to get started?** Continue to the [Quick Start Guide](quick-start.md)!
