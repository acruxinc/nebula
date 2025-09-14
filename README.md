# 🌌 Nebula - Cross-Platform Development & Production Server

A powerful cross-platform development and production server with built-in DNS, DHCP, TLS certificate management, and deployment scheduling.

## Features

### Development Mode
- 🔒 **Automatic HTTPS** - Self-signed certificates with proper CA
- 🌐 **Built-in DNS Server** - No external dependencies like dnsmasq
- 🔄 **Hot Reload** - Automatic restart on file changes  
- 🖥️ **Cross-Platform** - Works on macOS, Linux, and Windows
- ⚡ **Zero Configuration** - Works out of the box
- 🎯 **Framework Agnostic** - Works with any development server
- 🏠 **Custom Dev Domains** - Automatic `*.nebula.com` resolution

### Production Mode
- 🚀 **Built-in Scheduler** - Deploy and manage production applications
- 🌍 **Custom TLD Support** - Deploy to your own domain (e.g., `app.xyz`)
- 🔄 **Auto-scaling** - Manage multiple deployments simultaneously
- 📊 **Health Monitoring** - Built-in health checks and monitoring
- 🔐 **Production TLS** - Automatic SSL certificate management

## Quick Start

### Installation

```bash
# macOS/Linux
curl -fsSL https://get.nebula.dev | sh

# Windows (PowerShell)
iwr https://get.nebula.dev/install.ps1 | iex
```

### Usage

```bash
# Initialize in your project
nebula init

# Start development server (uses *.nebula.com domains)
nebula start

# Or run directly with custom domain
nebula --domain myapp.nebula.com --command "npm run dev"
```

## Commands

### Development Commands
- `nebula init` - Initialize Nebula in current directory
- `nebula start` - Start the development server
- `nebula stop` - Stop the development server
- `nebula status` - Show server status
- `nebula setup` - Install system dependencies

### DNS Management
- `nebula dns add <domain> <ip>` - Add DNS record
- `nebula dns remove <domain>` - Remove DNS record
- `nebula dns list` - List DNS records
- `nebula dns test <domain>` - Test DNS resolution

### Certificate Management
- `nebula cert generate <domain>` - Generate certificate
- `nebula cert list` - List certificates
- `nebula cert install-ca` - Install root CA
- `nebula cert remove <domain>` - Remove certificate

### Production Deployment
- `nebula deploy create <name> <build_path> --tld xyz` - Create deployment
- `nebula deploy start <deployment_id>` - Start deployment
- `nebula deploy stop <deployment_id>` - Stop deployment
- `nebula deploy list` - List all deployments
- `nebula deploy show <deployment_id>` - Show deployment details
- `nebula deploy delete <deployment_id>` - Delete deployment

### Utility Commands
- `nebula clean` - Clean up Nebula files

## Configuration

Nebula supports both development and production modes through configuration:

### Development Mode
```toml
[server]
domain = "app.nebula.com"
mode = "dev"
command = "npm run dev"

[dns]
enabled = true
port = 53

[scheduler]
dev_tld = "nebula.com"
```

### Production Mode
```toml
[server]
mode = "prod"

[scheduler]
enabled = true
default_tld = "xyz"
max_concurrent_deployments = 10
```

## Architecture

Nebula provides a complete solution without external dependencies:

- **DNS Server**: Built-in DNS server with zone management
- **DHCP Server**: Full DHCP protocol implementation
- **TLS Manager**: Automatic certificate generation and management
- **Scheduler**: Production deployment management
- **Reverse Proxy**: HTTPS termination and routing
- **Cross-Platform**: Native implementations for macOS, Linux, and Windows

## Development Workflow

1. **Initialize**: `nebula init` in your project
2. **Develop**: `nebula start` - your app runs on `projectname.nebula.com`
3. **Deploy**: `nebula deploy create myapp ./dist --tld xyz`
4. **Production**: Your app runs on `myapp.xyz` with automatic HTTPS