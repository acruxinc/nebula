# 🌌 Nebula - Cross-Platform Universal Development & Production Server

A powerful cross-platform universal development and production server that supports **any programming language and framework**. Nebula automatically detects your project type and provides built-in DNS, DHCP, TLS certificate management, and deployment scheduling with optimal configuration for your specific tech stack.

## 🚀 Supported Languages & Frameworks

Nebula automatically detects and supports a wide range of programming languages and frameworks:

### Frontend Frameworks
- **React** - Next.js, Create React App, Vite
- **Vue** - Nuxt.js, Vue CLI, Vite  
- **Angular** - Angular CLI, Nx
- **Svelte** - SvelteKit, Vite
- **JavaScript/TypeScript** - Node.js, Express, Fastify

### Backend Languages
- **Python** - Flask, Django, FastAPI, Streamlit
- **Go** - Gin, Echo, Gorilla Mux
- **Rust** - Actix-web, Axum, Warp, Rocket
- **Java** - Spring Boot, Quarkus, Micronaut
- **C#** - ASP.NET Core, Blazor
- **PHP** - Laravel, Symfony, CodeIgniter
- **Ruby** - Rails, Sinatra

### Other Technologies
- **Docker** - Docker Compose
- **Scripts** - Bash, PowerShell
- **Infrastructure** - Terraform, Ansible

## 🎯 Smart Auto-Detection

Simply run `nebula init` in any project directory and Nebula will:
1. **Detect your project type** automatically
2. **Configure optimal settings** for your language/framework
3. **Set up environment variables** specific to your stack
4. **Choose the right ports** and commands
5. **Generate appropriate configuration** files

## Features

### Development Mode
- 🔒 **Automatic HTTPS** - Self-signed certificates with proper CA
- 🌐 **Built-in DNS Server** - No external dependencies like dnsmasq
- 🔄 **Hot Reload** - Automatic restart on file changes  
- 🖥️ **Cross-Platform** - Works on macOS, Linux, and Windows
- ⚡ **Zero Configuration** - Works out of the box
- 🎯 **Universal Language Support** - Auto-detects and supports Python, Go, Rust, Java, C#, PHP, Ruby, JavaScript, TypeScript, React, Vue, Angular, and more
- 🧠 **Smart Auto-Detection** - Automatically configures optimal settings for your specific language/framework
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

#### Universal Language Support

Nebula works with any programming language or framework. Simply run `nebula init` in your project directory:

```bash
# For a Python Flask project
cd my-flask-app
nebula init  # Auto-detects Python/Flask and configures accordingly

# For a Go web service  
cd my-go-service
nebula init  # Auto-detects Go and configures Gin/Echo/etc.

# For a React application
cd my-react-app  
nebula init  # Auto-detects React and configures npm/yarn

# For a Rust web server
cd my-rust-api
nebula init  # Auto-detects Rust and configures Actix-web/Axum

# For a Java Spring Boot app
cd my-spring-app
nebula init  # Auto-detects Java and configures Spring Boot

# For any other language/framework
nebula init  # Works with PHP, Ruby, C#, Vue, Angular, Svelte, etc.
```

#### Development Mode

```bash
# Initialize Nebula (auto-detects your project type)
nebula init

# Start development server (uses optimal settings for your language/framework)
nebula start

# Your app will be available at:
# HTTP:  http://app.nebula.com:[detected-port]
# HTTPS: https://app.nebula.com:[https-port]
```

#### Production Deployment

```bash
# Create a deployment (works with any built application)
nebula deploy create my-app ./dist --tld xyz

# Start the deployment
nebula deploy start my-app

# Your app will be available at:
# HTTPS: https://my-app.xyz
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