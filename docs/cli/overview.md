# CLI Overview

Nebula provides a comprehensive command-line interface for managing development and production environments. This guide covers all available commands and their usage.

## Command Structure

Nebula uses a hierarchical command structure:

```bash
nebula [OPTIONS] [SUBCOMMAND]
```

### Global Options

```bash
nebula [OPTIONS] [SUBCOMMAND]

OPTIONS:
    -d, --domain <DOMAIN>        Domain to serve (e.g., myapp.dev)
        --http-port <PORT>       HTTP port (default: 3000)
        --https-port <PORT>      HTTPS port (default: 3443)
    -c, --config <CONFIG>        Configuration file path
    -v, --verbose               Enable verbose logging
        --log-file <FILE>        Log file path
        --force-certs           Force regenerate certificates
        --no-dns                Disable built-in DNS server
        --no-dhcp               Disable built-in DHCP server
        --hot-reload            Enable hot reload
        --dry-run               Dry run mode
    -w, --work-dir <DIR>        Working directory
    -h, --help                  Print help information
    -V, --version               Print version information
```

## Core Commands

### `nebula` - Start Development Server

Start the Nebula development server with the current configuration:

```bash
# Start with default settings
nebula

# Start with custom domain
nebula --domain myapp.nebula.com

# Start with custom ports
nebula --http-port 8080 --https-port 8443

# Start with custom command
nebula --dev-command "yarn dev"

# Start with configuration file
nebula --config custom.toml

# Start with verbose logging
nebula --verbose
```

### `nebula init` - Initialize Project

Initialize Nebula configuration in the current directory:

```bash
# Auto-detect project type and create configuration
nebula init

# Use specific template
nebula init --template react
nebula init --template python
nebula init --template rust

# Skip auto-detection
nebula init --no-detect

# Force overwrite existing configuration
nebula init --force
```

### `nebula setup` - System Setup

Configure system dependencies and settings:

```bash
# Full system setup
nebula setup

# Skip package installation
nebula setup --no-packages

# Skip DNS configuration
nebula setup --no-dns-setup

# Skip firewall configuration
nebula setup --no-firewall
```

### `nebula start` - Start as Daemon

Start Nebula as a background daemon:

```bash
# Start daemon
nebula start

# Start with PID file
nebula start --pid-file /var/run/nebula.pid

# Start daemon with custom config
nebula start --config production.toml
```

### `nebula stop` - Stop Daemon

Stop the Nebula daemon:

```bash
# Stop daemon
nebula stop

# Stop with specific PID file
nebula stop --pid-file /var/run/nebula.pid

# Force stop
nebula stop --force
```

### `nebula status` - Show Status

Display current Nebula status:

```bash
# Show general status
nebula status

# Show status in JSON format
nebula status --format json

# Show status in YAML format
nebula status --format yaml
```

## Certificate Management Commands

### `nebula cert generate` - Generate Certificates

Generate TLS certificates:

```bash
# Generate default certificates
nebula cert generate

# Generate certificate for specific domain
nebula cert generate --domain myapp.nebula.com

# Force regenerate existing certificates
nebula cert generate --force

# Generate wildcard certificate
nebula cert generate --domain "*.nebula.com"

# Generate with custom CA name
nebula cert generate --ca-name "My Custom CA"
```

### `nebula cert list` - List Certificates

List all certificates:

```bash
# List all certificates
nebula cert list

# List with details
nebula cert list --verbose

# List expired certificates
nebula cert list --expired

# List certificates expiring soon
nebula cert list --expiring 30
```

### `nebula cert info` - Certificate Information

Show detailed certificate information:

```bash
# Show certificate info
nebula cert info myapp.nebula.com

# Show with full details
nebula cert info myapp.nebula.com --verbose

# Show certificate chain
nebula cert info myapp.nebula.com --chain
```

### `nebula cert remove` - Remove Certificate

Remove a certificate:

```bash
# Remove certificate
nebula cert remove myapp.nebula.com

# Remove with confirmation
nebula cert remove myapp.nebula.com --confirm
```

## DNS Management Commands

### `nebula dns start` - Start DNS Server

Start the built-in DNS server:

```bash
# Start DNS server
nebula dns start

# Start with custom port
nebula dns start --port 5353

# Start with custom bind address
nebula dns start --bind 0.0.0.0
```

### `nebula dns stop` - Stop DNS Server

Stop the DNS server:

```bash
# Stop DNS server
nebula dns stop
```

### `nebula dns status` - DNS Status

Show DNS server status:

```bash
# Show DNS status
nebula dns status

# Show with statistics
nebula dns status --stats
```

### `nebula dns add` - Add DNS Record

Add a DNS record:

```bash
# Add A record
nebula dns add myapp.nebula.com 127.0.0.1

# Add CNAME record
nebula dns add api.myapp.nebula.com myapp.nebula.com --type CNAME

# Add MX record
nebula dns add nebula.com mail.nebula.com --type MX --priority 10
```

### `nebula dns list` - List DNS Records

List DNS records:

```bash
# List all records
nebula dns list

# List records for specific domain
nebula dns list --domain nebula.com

# List specific record type
nebula dns list --type A
```

### `nebula dns remove` - Remove DNS Record

Remove a DNS record:

```bash
# Remove record
nebula dns remove myapp.nebula.com

# Remove specific record type
nebula dns remove myapp.nebula.com --type A
```

## Deployment Commands

### `nebula scheduler start` - Start Scheduler

Start the production scheduler:

```bash
# Start scheduler
nebula scheduler start

# Start with custom configuration
nebula scheduler start --config production.toml
```

### `nebula scheduler stop` - Stop Scheduler

Stop the scheduler:

```bash
# Stop scheduler
nebula scheduler stop
```

### `nebula scheduler status` - Scheduler Status

Show scheduler status:

```bash
# Show scheduler status
nebula scheduler status

# Show with statistics
nebula scheduler status --stats
```

### `nebula deploy create` - Create Deployment

Create a new deployment:

```bash
# Create deployment
nebula deploy create myapp --path ./dist --tld mycompany.com

# Create with custom domain
nebula deploy create myapp --path ./dist --domain myapp.mycompany.com

# Create with environment variables
nebula deploy create myapp --path ./dist --env NODE_ENV=production

# Create with resource limits
nebula deploy create myapp --path ./dist --memory 512Mi --cpu 500m
```

### `nebula deploy list` - List Deployments

List all deployments:

```bash
# List deployments
nebula deploy list

# List with details
nebula deploy list --verbose

# List by status
nebula deploy list --status running
```

### `nebula deploy status` - Deployment Status

Show deployment status:

```bash
# Show deployment status
nebula deploy status myapp

# Show with logs
nebula deploy status myapp --logs

# Show with metrics
nebula deploy status myapp --metrics
```

### `nebula deploy update` - Update Deployment

Update an existing deployment:

```bash
# Update deployment
nebula deploy update myapp --path ./new-dist

# Update with new environment
nebula deploy update myapp --env NODE_ENV=staging
```

### `nebula deploy remove` - Remove Deployment

Remove a deployment:

```bash
# Remove deployment
nebula deploy remove myapp

# Remove with confirmation
nebula deploy remove myapp --confirm
```

## Configuration Commands

### `nebula config show` - Show Configuration

Display current configuration:

```bash
# Show all configuration
nebula config show

# Show specific section
nebula config show server
nebula config show tls
nebula config show dns
```

### `nebula config set` - Set Configuration

Set configuration values:

```bash
# Set server port
nebula config set server.http_port 8080

# Set TLS settings
nebula config set tls.auto_generate true

# Set DNS settings
nebula config set dns.enabled false
```

### `nebula config get` - Get Configuration

Get configuration values:

```bash
# Get server domain
nebula config get server.domain

# Get TLS certificate directory
nebula config get tls.cert_dir

# Get DNS port
nebula config get dns.port
```

### `nebula config validate` - Validate Configuration

Validate configuration file:

```bash
# Validate current configuration
nebula config validate

# Validate specific file
nebula config validate --config custom.toml
```

## Utility Commands

### `nebula clean` - Clean Temporary Files

Clean temporary files and caches:

```bash
# Clean all temporary files
nebula clean

# Clean certificates only
nebula clean --certs

# Clean logs only
nebula clean --logs

# Clean everything
nebula clean --all
```

### `nebula health` - Health Check

Check system health:

```bash
# Check overall health
nebula health

# Check specific component
nebula health --component dns
nebula health --component tls
nebula health --component scheduler

# Check with timeout
nebula health --timeout 30
```

### `nebula logs` - Show Logs

Display server logs:

```bash
# Show recent logs
nebula logs

# Show logs with tail
nebula logs --tail 100

# Show logs in real-time
nebula logs --follow

# Show logs with specific level
nebula logs --level error
```

### `nebula version` - Version Information

Show version information:

```bash
# Show version
nebula version

# Show version with details
nebula version --verbose
```

## Command Aliases

Nebula provides convenient aliases for common commands:

```bash
# Short aliases
nebula s          # nebula status
nebula c          # nebula config show
nebula h          # nebula health
nebula v          # nebula version

# Certificate aliases
nebula cert g     # nebula cert generate
nebula cert l     # nebula cert list
nebula cert i     # nebula cert info
nebula cert r     # nebula cert remove

# DNS aliases
nebula dns s      # nebula dns status
nebula dns a      # nebula dns add
nebula dns l      # nebula dns list
nebula dns r      # nebula dns remove

# Deployment aliases
nebula deploy c   # nebula deploy create
nebula deploy l   # nebula deploy list
nebula deploy s   # nebula deploy status
nebula deploy u   # nebula deploy update
nebula deploy r   # nebula deploy remove
```

## Environment Variables

Nebula respects the following environment variables:

```bash
# Configuration
NEBULA_CONFIG=/path/to/config.toml
NEBULA_DOMAIN=myapp.nebula.com
NEBULA_HTTP_PORT=3000
NEBULA_HTTPS_PORT=3443

# Logging
NEBULA_LOG_LEVEL=info
NEBULA_LOG_FILE=/path/to/logfile.log

# Certificates
NEBULA_CERT_DIR=/path/to/certs
NEBULA_FORCE_CERTS=true

# DNS
NEBULA_DNS_ENABLED=true
NEBULA_DNS_PORT=53

# Development
NEBULA_HOT_RELOAD=true
NEBULA_VERBOSE=true
```

## Shell Completion

Nebula provides shell completion for Bash, Zsh, and Fish:

### Enable Completion

```bash
# Bash
source <(nebula completions bash)
echo 'source <(nebula completions bash)' >> ~/.bashrc

# Zsh
source <(nebula completions zsh)
echo 'source <(nebula completions zsh)' >> ~/.zshrc

# Fish
source <(nebula completions fish)
echo 'source <(nebula completions fish)' >> ~/.config/fish/config.fish
```

### Completion Features

- **Command completion**: Complete subcommands and options
- **File completion**: Complete file paths for config options
- **Domain completion**: Complete common domain patterns
- **Port completion**: Complete common port numbers

## Interactive Mode

Nebula provides an interactive mode for complex operations:

```bash
# Start interactive mode
nebula interactive

# Or use the short alias
nebula i
```

Interactive mode provides:
- **Command history**: Navigate through previous commands
- **Tab completion**: Complete commands and options
- **Help system**: Built-in help for all commands
- **Context awareness**: Suggestions based on current state

## Batch Operations

For multiple operations, use batch mode:

```bash
# Execute multiple commands
nebula batch << EOF
cert generate --force
dns start
scheduler start
EOF

# Or from file
nebula batch --file commands.txt
```

## Scripting Integration

Nebula integrates well with shell scripts:

```bash
#!/bin/bash
# Deploy script example

# Check if Nebula is running
if ! nebula status >/dev/null 2>&1; then
    echo "Starting Nebula..."
    nebula start
fi

# Generate certificates
nebula cert generate --force

# Start DNS
nebula dns start

# Deploy application
nebula deploy create myapp --path ./dist --tld mycompany.com

echo "Deployment complete!"
```

## Troubleshooting CLI Issues

### Common Issues

**Command not found:**
```bash
# Check installation
which nebula
nebula version

# Reinstall if needed
curl -fsSL https://raw.githubusercontent.com/acruxinc/nebula/main/scripts/install.sh | bash
```

**Permission denied:**
```bash
# Fix permissions
sudo chmod +x /usr/local/bin/nebula
sudo chown root:root /usr/local/bin/nebula
```

**Configuration errors:**
```bash
# Validate configuration
nebula config validate

# Show current configuration
nebula config show
```

**Port conflicts:**
```bash
# Check port usage
nebula status --ports

# Use different ports
nebula --http-port 8080 --https-port 8443
```

## Next Steps

- **Learn about [Core Commands](core-commands.md)** for essential operations
- **Explore [Certificate Commands](certificate-commands.md)** for TLS management
- **Read [DNS Commands](dns-commands.md)** for DNS server management
- **Check [Deployment Commands](deployment-commands.md)** for production deployment
