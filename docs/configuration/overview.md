# Configuration Overview

Nebula uses TOML configuration files to manage all aspects of the development and production environment. This guide explains the configuration system and how to customize Nebula for your needs.

## Configuration File Locations

Nebula looks for configuration files in the following order:

1. **Command-line specified**: `nebula --config /path/to/config.toml`
2. **Project directory**: `./nebula.toml`
3. **User directory**: `~/.config/nebula/config.toml`
4. **System directory**: `/etc/nebula/config.toml`
5. **Default configuration**: Built-in defaults

## Configuration Structure

The main configuration file (`nebula.toml`) is organized into sections:

```toml
[server]      # Server settings and behavior
[tls]         # TLS certificate configuration
[dns]         # DNS server settings
[dhcp]        # DHCP server settings (optional)
[scheduler]   # Production scheduler settings
[logging]     # Logging configuration
[dev]         # Development-specific settings
[dev.env]     # Development environment variables
```

## Server Configuration

The `[server]` section controls the core server behavior:

```toml
[server]
# Domain to serve your application
domain = "app.nebula.com"

# HTTP and HTTPS ports
http_port = 3000
https_port = 3443

# Command to run for development
command = "npm run dev"

# Enable hot reload (restart on file changes)
hot_reload = true

# Server mode: "dev" or "prod"
mode = "dev"

# Request timeout in seconds
request_timeout = 30

# Keep-alive timeout in seconds
keep_alive_timeout = 60

# Maximum concurrent connections
max_connections = 1000

# Enable HTTP/2 support
enable_http2 = true

# Enable response compression
compression = true
```

### Domain Configuration

Nebula supports multiple domain patterns:

```toml
[server]
# Standard nebula.com subdomain
domain = "myapp.nebula.com"

# Custom .dev domain (requires DNS setup)
domain = "myapp.dev"

# Local domain
domain = "myapp.local"

# Custom TLD (for production)
domain = "myapp.mycompany.com"
```

## TLS Configuration

The `[tls]` section manages SSL/TLS certificates:

```toml
[tls]
# Directory to store certificates
cert_dir = "~/.local/share/nebula/certs"

# Automatically generate certificates
auto_generate = true

# CA certificate name
ca_name = "Nebula Development CA"

# Certificate key type: "rsa" or "ecdsa"
key_type = "ecdsa"

# Certificate validity in days
validity_days = 365

# Auto-renew certificates before expiration
auto_renew = true

# Days before expiration to renew
renew_days_before = 30

# Additional domains for wildcard certificates
additional_domains = [
    "*.nebula.com",
    "*.dev",
    "localhost"
]
```

### Certificate Management

Nebula automatically generates and manages certificates:

- **Self-signed CA**: Creates a local Certificate Authority
- **Wildcard certificates**: Supports `*.nebula.com` and `*.dev`
- **Auto-renewal**: Automatically renews certificates before expiration
- **Cross-platform**: Works on macOS, Linux, and Windows

## DNS Configuration

The `[dns]` section configures the built-in DNS server:

```toml
[dns]
# Enable DNS server
enabled = true

# DNS server port
port = 53

# Bind address
bind_address = "127.0.0.1"

# Cache settings
cache_size = 1024
cache_ttl = 300

# Upstream DNS servers
upstream = [
    "8.8.8.8:53",
    "1.1.1.1:53"
]

# Enable DNS forwarding
forwarding = true

# Enable DNS recursion
recursion = true

# Custom DNS records
[custom_records]
"api.nebula.com" = "127.0.0.1"
"db.nebula.com" = "127.0.0.1"
```

### DNS Features

- **Local resolution**: Resolves `.nebula.com` and `.dev` domains
- **Upstream forwarding**: Forwards other queries to public DNS
- **Caching**: Improves performance with intelligent caching
- **Custom records**: Define custom A records for services

## DHCP Configuration (Optional)

The `[dhcp]` section configures the built-in DHCP server:

```toml
[dhcp]
# Enable DHCP server
enabled = false

# IP address range
range_start = "192.168.100.100"
range_end = "192.168.100.200"

# Lease time in seconds
lease_time = 86400

# Renewal time in seconds
renewal_time = 43200

# Rebinding time in seconds
rebinding_time = 75600

# Subnet mask
subnet_mask = "255.255.255.0"

# DNS servers to provide to clients
dns_servers = ["127.0.0.1"]

# Domain name to provide to clients
domain_name = "nebula.local"

# Router/gateway IP
router = "192.168.100.1"
```

## Scheduler Configuration

The `[scheduler]` section manages production deployments:

```toml
[scheduler]
# Enable production scheduler
enabled = true

# Default TLD for production deployments
default_tld = "xyz"

# Development TLD
dev_tld = "nebula.com"

# Storage path for scheduler data
storage_path = "~/.local/share/nebula/scheduler"

# Maximum concurrent deployments
max_concurrent_deployments = 10

# Auto-cleanup old deployments
auto_cleanup = true

# Days to keep deployments before cleanup
cleanup_after_days = 30

# Health check interval in seconds
health_check_interval = 30

# Restart policy: "always", "on-failure", "never"
restart_policy = "always"

# Resource limits per deployment
[resource_limits]
max_memory = "512Mi"
max_cpu = "500m"
```

## Logging Configuration

The `[logging]` section controls logging behavior:

```toml
[logging]
# Log level: "trace", "debug", "info", "warn", "error"
level = "info"

# Maximum log file size in bytes
max_size = 10485760  # 10MB

# Maximum number of log files to keep
max_files = 5

# Log format: "text" or "json"
format = "text"

# Enable colored output
enable_colors = true

# Log file path (if not specified, logs to stdout)
file_path = "~/.local/share/nebula/logs/nebula.log"

# Enable structured logging
structured = true
```

## Development Configuration

The `[dev]` section contains development-specific settings:

```toml
[dev]
# File patterns to watch for changes
watch_patterns = [
    "src/**/*",
    "public/**/*",
    "static/**/*",
    "assets/**/*"
]

# File patterns to ignore
ignore_patterns = [
    "node_modules/**/*",
    ".git/**/*",
    "target/**/*",
    "dist/**/*",
    "build/**/*",
    "*.log",
    ".DS_Store",
    "Thumbs.db"
]

# Delay before restarting after file change (milliseconds)
restart_delay = 500

# Automatically open browser on startup
auto_open_browser = false

# Browser to open (if auto_open_browser is true)
browser = "default"

# Additional arguments for the development command
command_args = ["--watch", "--hot"]

# Working directory for the development command
working_directory = "."
```

## Environment Variables

The `[dev.env]` section sets environment variables for development:

```toml
[dev.env]
# Node.js environment
NODE_ENV = "development"

# Debug mode
DEBUG = "true"

# API endpoints
API_URL = "http://localhost:8000"
DATABASE_URL = "sqlite:///dev.db"

# Custom variables
MY_CUSTOM_VAR = "development_value"
```

## Configuration Management Commands

### View Configuration

```bash
# Show current configuration
nebula config show

# Show specific section
nebula config show server
nebula config show tls
```

### Modify Configuration

```bash
# Set configuration values
nebula config set server.http_port 8080
nebula config set tls.auto_generate true
nebula config set dns.enabled false

# Get configuration values
nebula config get server.domain
nebula config get tls.cert_dir
```

### Validate Configuration

```bash
# Check configuration syntax
nebula config validate

# Test configuration
nebula config test
```

## Environment-Specific Configuration

### Development Configuration

```toml
# nebula.toml (development)
[server]
domain = "app.nebula.com"
http_port = 3000
command = "npm run dev"
hot_reload = true

[tls]
auto_generate = true

[dns]
enabled = true
```

### Production Configuration

```toml
# nebula.prod.toml (production)
[server]
domain = "myapp.mycompany.com"
http_port = 80
https_port = 443
command = "npm start"
hot_reload = false

[tls]
auto_generate = false
cert_dir = "/etc/ssl/nebula"

[scheduler]
enabled = true
default_tld = "mycompany.com"
```

### Staging Configuration

```toml
# nebula.staging.toml (staging)
[server]
domain = "myapp-staging.mycompany.com"
http_port = 8080
command = "npm run start:staging"
hot_reload = false

[tls]
auto_generate = true
validity_days = 30
```

## Configuration Templates

Nebula provides templates for different project types:

### React Template

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "npm run dev"
hot_reload = true

[dev]
watch_patterns = ["src/**/*", "public/**/*"]
ignore_patterns = ["node_modules/**/*", "build/**/*"]

[dev.env]
NODE_ENV = "development"
REACT_APP_API_URL = "http://localhost:8000"
```

### Python Template

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "python manage.py runserver 0.0.0.0:5000"
hot_reload = true

[dev]
watch_patterns = ["*.py", "templates/**/*", "static/**/*"]
ignore_patterns = ["__pycache__/**/*", "*.pyc", "venv/**/*"]

[dev.env]
DEBUG = "True"
DATABASE_URL = "sqlite:///dev.db"
```

### Go Template

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "go run ."
hot_reload = true

[dev]
watch_patterns = ["*.go", "templates/**/*", "static/**/*"]
ignore_patterns = ["vendor/**/*", "*.exe"]

[dev.env]
GO_ENV = "development"
PORT = "8080"
```

## Best Practices

### 1. Use Environment-Specific Configs

```bash
# Development
nebula --config nebula.dev.toml

# Staging
nebula --config nebula.staging.toml

# Production
nebula --config nebula.prod.toml
```

### 2. Secure Sensitive Information

```toml
# Use environment variables for sensitive data
[dev.env]
DATABASE_URL = "${DATABASE_URL}"
API_KEY = "${API_KEY}"
```

### 3. Optimize File Watching

```toml
[dev]
# Be specific about what to watch
watch_patterns = [
    "src/**/*.js",
    "src/**/*.ts",
    "src/**/*.jsx",
    "src/**/*.tsx"
]

# Ignore unnecessary files
ignore_patterns = [
    "node_modules/**/*",
    "dist/**/*",
    "coverage/**/*",
    "*.log"
]
```

### 4. Use Appropriate Log Levels

```toml
[logging]
# Development: verbose logging
level = "debug"

# Production: minimal logging
level = "warn"
```

## Troubleshooting Configuration

### Common Issues

**Invalid TOML syntax:**
```bash
# Validate configuration
nebula config validate
```

**Missing required fields:**
```bash
# Check configuration completeness
nebula config test
```

**Port conflicts:**
```bash
# Check available ports
nebula status --ports
```

**Certificate issues:**
```bash
# Regenerate certificates
nebula cert generate --force
```

## Next Steps

- **Learn about [Server Configuration](server.md)** for detailed server settings
- **Explore [TLS Configuration](tls.md)** for certificate management
- **Read [DNS Configuration](dns.md)** for DNS server setup
- **Check [Environment Variables](environment.md)** for environment configuration
