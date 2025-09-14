# 🌌 Nebula

**Universal Development & Production Server for Any Programming Language and Framework**

[![CI/CD](https://github.com/acruxinc/nebula/actions/workflows/ci.yml/badge.svg)](https://github.com/acruxinc/nebula/actions/workflows/ci.yml)
[![Security](https://github.com/acruxinc/nebula/actions/workflows/security.yml/badge.svg)](https://github.com/acruxinc/nebula/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org)

Nebula is a cross-platform universal development and production server that works with **any programming language and framework**. It provides built-in DNS, DHCP, and TLS management, making local development seamless and production deployment effortless.

## ✨ Features

### 🚀 **Universal Language Support**
- **Auto-detection** of 15+ programming languages and frameworks
- **Smart configuration** generation based on project type
- **Framework-specific templates** with optimized settings
- **No external dependencies** - works out of the box

### 🌐 **Built-in Network Services**
- **Custom DNS server** with `.nebula.com` and `.dev` domain support
- **DHCP server** with full protocol implementation and lease management
- **Automatic TLS certificate generation** with wildcard support
- **Cross-platform DNS configuration** (macOS, Linux, Windows)

### 🎯 **Development Mode**
- **Hot reload** with intelligent file watching
- **Automatic browser opening** (optional)
- **Process management** with graceful shutdown
- **Environment variable injection**
- **Port conflict resolution**

### 🏭 **Production Mode**
- **Built-in scheduler** for deployment management
- **Custom TLD support** for production domains
- **Concurrent deployment handling**
- **Health monitoring** and auto-restart
- **Resource management** and cleanup

### 🔧 **Advanced Features**
- **Cross-platform compatibility** (macOS, Linux, Windows)
- **Zero-configuration setup** with smart defaults
- **Comprehensive CLI** with subcommands
- **Configuration management** with TOML files
- **Logging and monitoring** with structured output
- **Security-first design** with certificate management

## 🚀 Supported Languages & Frameworks

| Language | Frameworks | Auto-Detected |
|----------|------------|---------------|
| **JavaScript/TypeScript** | React, Vue, Svelte, Next.js, Nuxt.js, Angular | ✅ |
| **Python** | Flask, Django, FastAPI, Streamlit | ✅ |
| **Go** | Gin, Echo, Fiber, Beego | ✅ |
| **Rust** | Actix-web, Axum, Warp, Rocket | ✅ |
| **Java** | Spring Boot, Quarkus, Micronaut | ✅ |
| **C#** | ASP.NET Core, Blazor | ✅ |
| **PHP** | Laravel, Symfony, CodeIgniter | ✅ |
| **Ruby** | Rails, Sinatra, Hanami | ✅ |
| **C/C++** | Custom build systems | ✅ |
| **Shell/Bash** | Scripts and automation | ✅ |
| **Docker** | Containerized applications | ✅ |

## 🎯 Smart Auto-Detection

Nebula automatically detects your project type by analyzing:
- **Package managers** (`package.json`, `pyproject.toml`, `go.mod`, `Cargo.toml`)
- **Framework files** (`next.config.js`, `vue.config.js`, `angular.json`)
- **Build systems** (`Makefile`, `CMakeLists.txt`, `gradle.build`)
- **Language indicators** (file extensions, directory structure)

## 📦 Installation

### Quick Install (Recommended)

```bash
# Unix-like systems (macOS, Linux)
curl -fsSL https://raw.githubusercontent.com/acruxinc/nebula/main/scripts/install.sh | bash

# Windows (PowerShell)
iwr -useb https://raw.githubusercontent.com/acruxinc/nebula/main/scripts/install.ps1 | iex
```

### Manual Installation

1. **Download the latest release** from [GitHub Releases](https://github.com/acruxinc/nebula/releases)
2. **Extract the binary** to your PATH
3. **Run setup** to configure system dependencies:

```bash
nebula setup
```

### From Source

```bash
git clone https://github.com/acruxinc/nebula.git
cd nebula
cargo build --release
sudo cp target/release/nebula /usr/local/bin/
```

## 🚀 Quick Start

### 1. Initialize Your Project

```bash
# Auto-detect project type and create configuration
nebula init

# Or specify a template
nebula init --template python
nebula init --template react
nebula init --template rust
```

### 2. Start Development Server

```bash
# Start with auto-detected settings
nebula

# Or specify custom domain and ports
nebula --domain myapp.nebula.com --http-port 8080
```

### 3. Access Your Application

- **HTTP**: `http://myapp.nebula.com:3000`
- **HTTPS**: `https://myapp.nebula.com:3443` (auto-generated certificates)
- **Custom domains**: `http://myapp.dev` (with DNS configuration)

## 🎯 Universal Language Support

Nebula works with any programming language or framework. Simply run `nebula init` in your project directory:

### Frontend Frameworks
```bash
# React application
cd my-react-app
nebula init  # Auto-detects React and configures npm/yarn

# Vue.js application  
cd my-vue-app
nebula init  # Auto-detects Vue and configures dev server

# Next.js application
cd my-nextjs-app
nebula init  # Auto-detects Next.js and configures accordingly
```

### Backend Services
```bash
# Python Flask/Django
cd my-python-api
nebula init  # Auto-detects Python and configures appropriate server

# Go web service
cd my-go-service
nebula init  # Auto-detects Go and configures Gin/Echo/etc.

# Rust web server
cd my-rust-api
nebula init  # Auto-detects Rust and configures Actix-web/Axum

# Java Spring Boot
cd my-spring-app
nebula init  # Auto-detects Java and configures Spring Boot
```

### Other Languages
```bash
# PHP Laravel/Symfony
cd my-php-app
nebula init  # Auto-detects PHP and configures web server

# Ruby on Rails
cd my-rails-app
nebula init  # Auto-detects Ruby and configures Rails server

# C# ASP.NET Core
cd my-dotnet-app
nebula init  # Auto-detects C# and configures ASP.NET Core
```

## 🏭 Production Deployment

### 1. Build Your Application

```bash
# Build your project (language-specific)
npm run build          # Node.js
go build              # Go
cargo build --release # Rust
# ... etc
```

### 2. Deploy with Nebula Scheduler

```bash
# Start the production scheduler
nebula scheduler start

# Deploy your application
nebula deploy create myapp --path ./dist --tld mycompany.com

# Your app is now live at: https://myapp.mycompany.com
```

### 3. Manage Deployments

```bash
# List all deployments
nebula deploy list

# Check deployment status
nebula deploy status myapp

# Update deployment
nebula deploy update myapp --path ./new-dist

# Remove deployment
nebula deploy remove myapp
```

## ⚙️ Configuration

Nebula uses TOML configuration files. The default `nebula.toml` is created during initialization:

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "npm run dev"
hot_reload = true

[tls]
auto_generate = true
ca_name = "Nebula Development CA"

[dns]
enabled = true
port = 53
upstream = ["8.8.8.8:53", "1.1.1.1:53"]

[dhcp]
enabled = false

[scheduler]
enabled = true
default_tld = "xyz"
dev_tld = "nebula.com"

[dev]
watch_patterns = ["src/**/*", "public/**/*"]
ignore_patterns = ["node_modules/**/*", ".git/**/*"]
restart_delay = 500
```

### Configuration Commands

```bash
# Show current configuration
nebula config show

# Set configuration values
nebula config set server.http_port 8080
nebula config set tls.auto_generate true

# Get configuration values
nebula config get server.domain
nebula config get dns.enabled
```

## 🛠️ CLI Commands

### Core Commands
```bash
nebula                    # Start development server
nebula init               # Initialize project configuration
nebula setup              # Setup system dependencies
nebula start              # Start as daemon
nebula stop               # Stop daemon
nebula status             # Show server status
```

### Certificate Management
```bash
nebula cert generate      # Generate certificates
nebula cert list          # List certificates
nebula cert remove <name> # Remove certificate
nebula cert info <name>   # Show certificate info
```

### DNS Management
```bash
nebula dns start          # Start DNS server
nebula dns stop           # Stop DNS server
nebula dns add <name> <ip> # Add DNS record
nebula dns list           # List DNS records
nebula dns remove <name>  # Remove DNS record
```

### Deployment Management
```bash
nebula scheduler start    # Start production scheduler
nebula scheduler stop     # Stop scheduler
nebula deploy create <name> --path <path> --tld <domain>
nebula deploy list        # List deployments
nebula deploy status <name>
nebula deploy remove <name>
```

### Utility Commands
```bash
nebula clean              # Clean temporary files
nebula health             # Check system health
nebula logs               # Show server logs
nebula version            # Show version info
```

## 🔧 Advanced Usage

### Custom Domains

```bash
# Use custom domain
nebula --domain myapp.local

# Configure custom TLD for production
nebula deploy create myapp --path ./build --tld mycompany.com
```

### Environment Variables

```bash
# Set environment variables
export NEBULA_DOMAIN=myapp.nebula.com
export NEBULA_HTTP_PORT=8080
nebula

# Or use .env file
echo "NEBULA_DOMAIN=myapp.nebula.com" > .env
nebula
```

### Docker Integration

```bash
# Run Nebula in Docker
docker run -p 3000:3000 -p 3443:3443 -p 53:53/udp \
  -v $(pwd):/workspace acruxinc/nebula

# Docker Compose
version: '3.8'
services:
  nebula:
    image: acruxinc/nebula
    ports:
      - "3000:3000"
      - "3443:3443"
      - "53:53/udp"
    volumes:
      - .:/workspace
```

### CI/CD Integration

```yaml
# GitHub Actions example
name: Deploy with Nebula
on:
  push:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup Nebula
        run: |
          curl -fsSL https://raw.githubusercontent.com/acruxinc/nebula/main/scripts/install.sh | bash
          nebula setup
      - name: Build and Deploy
        run: |
          npm run build
          nebula deploy create ${{ github.event.repository.name }} \
            --path ./dist \
            --tld mycompany.com
```

## 🔒 Security Features

- **Automatic TLS certificate generation** with self-signed CA
- **Wildcard certificate support** for subdomains
- **Certificate validation** and expiration monitoring
- **Secure default configurations**
- **DNS over HTTPS** support
- **Firewall rule management** (platform-specific)

## 🐛 Troubleshooting

### Common Issues

**Port conflicts:**
```bash
# Check what's using a port
nebula status --ports
# Use different port
nebula --http-port 8080
```

**Certificate issues:**
```bash
# Regenerate certificates
nebula cert generate --force
# Check certificate status
nebula cert info app.nebula.com
```

**DNS resolution problems:**
```bash
# Check DNS configuration
nebula dns status
# Test DNS resolution
dig @127.0.0.1 app.nebula.com
```

**Permission issues:**
```bash
# Run setup to fix permissions
nebula setup
# Check system requirements
nebula health
```

### Getting Help

- **Documentation**: [docs/](docs/)
- **Issues**: [GitHub Issues](https://github.com/acruxinc/nebula/issues)
- **Discussions**: [GitHub Discussions](https://github.com/acruxinc/nebula/discussions)
- **Discord**: [Join our community](https://discord.gg/nebula)

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](.github/CONTRIBUTING.md) for details.

### Development Setup

```bash
git clone https://github.com/acruxinc/nebula.git
cd nebula
cargo build
cargo test
```

### Running Tests

```bash
# Run all tests
cargo test

# Run specific test categories
cargo test --lib                    # Unit tests
cargo test --test integration_tests # Integration tests

# Run with coverage
cargo tarpaulin --out Html
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with [Rust](https://www.rust-lang.org/) for performance and reliability
- Uses [Tokio](https://tokio.rs/) for async runtime
- DNS implementation powered by [trust-dns](https://github.com/bluejekyll/trust-dns)
- TLS support via [rustls](https://github.com/rustls/rustls)
- HTTP server built on [Hyper](https://hyper.rs/)

## 📊 Project Status

- ✅ **Core functionality** - Complete
- ✅ **Cross-platform support** - Complete  
- ✅ **Universal language detection** - Complete
- ✅ **Production scheduler** - Complete
- ✅ **Security features** - Complete
- ✅ **Documentation** - Complete
- ✅ **CI/CD pipeline** - Complete
- 🚧 **Plugin system** - In development
- 🚧 **Web dashboard** - Planned
- 🚧 **Metrics collection** - Planned

---

<div align="center">
  <strong>Made with ❤️ by the Nebula Team</strong>
  <br>
  <a href="https://github.com/acruxinc/nebula">⭐ Star us on GitHub</a> |
  <a href="https://discord.gg/nebula">💬 Join our Discord</a> |
  <a href="https://twitter.com/nebuladev">🐦 Follow us on Twitter</a>
</div>