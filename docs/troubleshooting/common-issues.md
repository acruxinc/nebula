# Common Issues and Troubleshooting

This guide covers the most common issues you might encounter when using Nebula and how to resolve them.

## Installation Issues

### Command Not Found

**Problem**: `nebula: command not found`

**Solutions**:

```bash
# Check if nebula is in PATH
which nebula
echo $PATH

# Add nebula to PATH
export PATH="/usr/local/bin:$PATH"
echo 'export PATH="/usr/local/bin:$PATH"' >> ~/.bashrc

# Reinstall nebula
curl -fsSL https://raw.githubusercontent.com/acruxinc/nebula/main/scripts/install.sh | bash
```

### Permission Denied

**Problem**: `Permission denied` when running nebula

**Solutions**:

```bash
# Fix permissions
sudo chmod +x /usr/local/bin/nebula
sudo chown root:root /usr/local/bin/nebula

# Or run with sudo (temporary)
sudo nebula --help
```

### Installation Script Fails

**Problem**: Installation script fails with errors

**Solutions**:

```bash
# Check system requirements
uname -a
which curl
which tar

# Install dependencies
# macOS
brew install curl

# Ubuntu/Debian
sudo apt-get update
sudo apt-get install curl tar

# CentOS/RHEL
sudo yum install curl tar

# Try manual installation
wget https://github.com/acruxinc/nebula/releases/latest/download/nebula-linux-amd64.tar.gz
tar -xzf nebula-linux-amd64.tar.gz
sudo mv nebula /usr/local/bin/
```

## Port Conflicts

### Port Already in Use

**Problem**: `Address already in use` or `Port 3000 is already in use`

**Solutions**:

```bash
# Check what's using the port
sudo lsof -i :3000
sudo lsof -i :3443
sudo lsof -i :53

# Kill the process using the port
sudo kill -9 <PID>

# Use different ports
nebula --http-port 8080 --https-port 8443

# Check available ports
nebula status --ports
```

### DNS Port 53 Conflict

**Problem**: Cannot bind to port 53 (DNS)

**Solutions**:

```bash
# Check what's using port 53
sudo lsof -i :53

# Stop system DNS resolver (temporary)
# macOS
sudo launchctl unload /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist

# Linux (systemd-resolved)
sudo systemctl stop systemd-resolved

# Use different DNS port
nebula --dns-port 5353

# Configure system to use custom DNS port
# Add to /etc/resolver/nebula.com (macOS)
echo "nameserver 127.0.0.1" | sudo tee /etc/resolver/nebula.com
echo "port 5353" | sudo tee -a /etc/resolver/nebula.com
```

## Certificate Issues

### SSL Certificate Errors

**Problem**: Browser shows "Your connection is not private" or certificate errors

**Solutions**:

```bash
# Regenerate certificates
nebula cert generate --force

# Check certificate status
nebula cert info app.nebula.com

# Install CA certificate manually
# macOS
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.local/share/nebula/certs/nebula-ca.crt

# Linux
sudo cp ~/.local/share/nebula/certs/nebula-ca.crt /usr/local/share/ca-certificates/
sudo update-ca-certificates

# Windows
certutil -addstore -user Root ~/.local/share/nebula/certs/nebula-ca.crt
```

### Certificate Not Found

**Problem**: `Certificate not found` error

**Solutions**:

```bash
# List available certificates
nebula cert list

# Generate missing certificate
nebula cert generate --domain app.nebula.com

# Check certificate directory
ls -la ~/.local/share/nebula/certs/

# Recreate certificate directory
rm -rf ~/.local/share/nebula/certs/
nebula cert generate
```

### Certificate Expired

**Problem**: Certificate has expired

**Solutions**:

```bash
# Check certificate expiration
nebula cert info app.nebula.com

# Regenerate expired certificate
nebula cert generate --domain app.nebula.com --force

# Enable auto-renewal
nebula config set tls.auto_renew true
```

## DNS Resolution Issues

### Domain Not Resolving

**Problem**: Cannot access `app.nebula.com` or `*.dev` domains

**Solutions**:

```bash
# Check DNS server status
nebula dns status

# Test DNS resolution
dig @127.0.0.1 app.nebula.com
nslookup app.nebula.com 127.0.0.1

# Restart DNS server
nebula dns stop
nebula dns start

# Check DNS configuration
# macOS
cat /etc/resolver/nebula.com
cat /etc/resolver/dev

# Linux
cat /etc/systemd/resolved.conf.d/nebula.conf

# Windows
Get-DnsClientNrptRule | Where-Object {$_.Namespace -like "*.nebula.com"}
```

### DNS Server Not Starting

**Problem**: DNS server fails to start

**Solutions**:

```bash
# Check if port 53 is available
sudo lsof -i :53

# Use different port
nebula dns start --port 5353

# Check permissions
sudo nebula dns start

# Check logs
nebula logs --component dns
```

### System DNS Override

**Problem**: System DNS settings override Nebula DNS

**Solutions**:

```bash
# macOS - Check resolver order
scutil --dns

# Linux - Check systemd-resolved
systemd-resolve --status

# Windows - Check DNS client rules
Get-DnsClientNrptRule

# Flush DNS cache
# macOS
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# Linux
sudo systemctl flush-dns

# Windows
ipconfig /flushdns
```

## Application Issues

### Hot Reload Not Working

**Problem**: File changes don't trigger application restart

**Solutions**:

```bash
# Check file watching patterns
nebula config show dev.watch_patterns

# Add more patterns
nebula config set dev.watch_patterns '["src/**/*", "public/**/*", "*.js", "*.ts"]'

# Check ignore patterns
nebula config show dev.ignore_patterns

# Reduce ignore patterns
nebula config set dev.ignore_patterns '["node_modules/**/*", ".git/**/*"]'

# Increase restart delay
nebula config set dev.restart_delay 1000

# Enable verbose logging
nebula --verbose
```

### Application Not Starting

**Problem**: Development server fails to start

**Solutions**:

```bash
# Check the command being run
nebula config show server.command

# Test the command manually
npm run dev
python manage.py runserver
go run .

# Check working directory
nebula config show dev.working_directory

# Set correct working directory
nebula config set dev.working_directory "."

# Check environment variables
nebula config show dev.env

# Add missing environment variables
nebula config set dev.env.NODE_ENV "development"
```

### Process Management Issues

**Problem**: Application processes not being managed correctly

**Solutions**:

```bash
# Check running processes
ps aux | grep nebula

# Kill orphaned processes
pkill -f "nebula"

# Restart Nebula
nebula stop
nebula start

# Check process limits
ulimit -a

# Increase file descriptor limit
ulimit -n 65536
```

## Configuration Issues

### Invalid Configuration

**Problem**: `Invalid configuration` or TOML parsing errors

**Solutions**:

```bash
# Validate configuration
nebula config validate

# Check TOML syntax
cat nebula.toml

# Use online TOML validator
# https://www.tomllint.com/

# Reset to default configuration
rm nebula.toml
nebula init
```

### Configuration Not Loading

**Problem**: Configuration changes not taking effect

**Solutions**:

```bash
# Check configuration file location
nebula config show --source

# Reload configuration
nebula stop
nebula start

# Use explicit config file
nebula --config nebula.toml

# Check configuration precedence
nebula config show --all
```

### Environment Variables Not Set

**Problem**: Environment variables not available to application

**Solutions**:

```bash
# Check environment variables
nebula config show dev.env

# Set environment variables
nebula config set dev.env.NODE_ENV "development"
nebula config set dev.env.DATABASE_URL "sqlite:///dev.db"

# Restart to apply changes
nebula restart

# Test environment variables
nebula exec -- env | grep NODE_ENV
```

## Performance Issues

### High CPU Usage

**Problem**: Nebula or applications using excessive CPU

**Solutions**:

```bash
# Check resource usage
nebula status --resources

# Limit file watching
nebula config set dev.watch_patterns '["src/**/*"]'

# Increase restart delay
nebula config set dev.restart_delay 2000

# Check for infinite loops in applications
nebula logs --level error
```

### High Memory Usage

**Problem**: Nebula using too much memory

**Solutions**:

```bash
# Check memory usage
nebula status --memory

# Limit concurrent connections
nebula config set server.max_connections 100

# Reduce cache sizes
nebula config set dns.cache_size 512

# Restart to free memory
nebula restart
```

### Slow Startup

**Problem**: Nebula takes too long to start

**Solutions**:

```bash
# Check startup time
time nebula --dry-run

# Disable unnecessary services
nebula config set dhcp.enabled false

# Use faster DNS upstream
nebula config set dns.upstream '["1.1.1.1:53"]'

# Skip certificate generation if not needed
nebula config set tls.auto_generate false
```

## Platform-Specific Issues

### macOS Issues

**Problem**: macOS-specific DNS or permission issues

**Solutions**:

```bash
# Check macOS version
sw_vers

# Reset DNS settings
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder

# Check firewall
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Reset network settings
sudo networksetup -setdnsservers Wi-Fi 127.0.0.1
```

### Linux Issues

**Problem**: Linux-specific systemd or permission issues

**Solutions**:

```bash
# Check systemd-resolved status
sudo systemctl status systemd-resolved

# Restart systemd-resolved
sudo systemctl restart systemd-resolved

# Check SELinux (if enabled)
sestatus
sudo setsebool -P httpd_can_network_connect 1

# Check AppArmor
sudo aa-status
```

### Windows Issues

**Problem**: Windows-specific DNS or firewall issues

**Solutions**:

```powershell
# Check Windows version
Get-ComputerInfo | Select-Object WindowsProductName

# Reset DNS client
Clear-DnsClientCache
Restart-Service Dnscache

# Check Windows Firewall
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Nebula*"}

# Run as Administrator
Start-Process powershell -Verb RunAs
```

## Network Issues

### Firewall Blocking

**Problem**: Firewall blocking Nebula ports

**Solutions**:

```bash
# Check firewall status
# macOS
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# Linux (ufw)
sudo ufw status

# Linux (iptables)
sudo iptables -L

# Windows
Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Nebula*"}

# Add firewall rules
# macOS
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/local/bin/nebula

# Linux (ufw)
sudo ufw allow 3000
sudo ufw allow 3443
sudo ufw allow 53

# Windows
New-NetFirewallRule -DisplayName "Nebula HTTP" -Direction Inbound -Protocol TCP -LocalPort 3000 -Action Allow
```

### Proxy Issues

**Problem**: Corporate proxy blocking Nebula

**Solutions**:

```bash
# Set proxy environment variables
export HTTP_PROXY=http://proxy.company.com:8080
export HTTPS_PROXY=http://proxy.company.com:8080

# Configure proxy in Nebula
nebula config set network.proxy "http://proxy.company.com:8080"

# Bypass proxy for local addresses
nebula config set network.no_proxy "localhost,127.0.0.1,*.nebula.com"
```

## Getting Help

### Debug Information

When reporting issues, include:

```bash
# System information
nebula version --verbose
uname -a
cat /etc/os-release  # Linux
sw_vers  # macOS
Get-ComputerInfo  # Windows

# Configuration
nebula config show --all

# Logs
nebula logs --tail 100

# Status
nebula status --verbose
```

### Log Analysis

```bash
# View recent logs
nebula logs --tail 50

# Filter by level
nebula logs --level error

# Follow logs in real-time
nebula logs --follow

# Export logs
nebula logs --export logs.txt
```

### Health Check

```bash
# Run comprehensive health check
nebula health --verbose

# Check specific components
nebula health --component dns
nebula health --component tls
nebula health --component scheduler
```

## Community Support

### GitHub Issues

- **Bug reports**: [GitHub Issues](https://github.com/acruxinc/nebula/issues)
- **Feature requests**: [GitHub Discussions](https://github.com/acruxinc/nebula/discussions)
- **Documentation**: [GitHub Wiki](https://github.com/acruxinc/nebula/wiki)

### Community Channels

- **Discord**: [Join our Discord](https://discord.gg/nebula)
- **Twitter**: [@nebuladev](https://twitter.com/nebuladev)
- **Stack Overflow**: Tag questions with `nebula`

### Professional Support

For enterprise support and consulting:
- **Email**: support@nebula.dev
- **Website**: https://nebula.dev/support

## Next Steps

If you've resolved your issue:

1. **Document the solution** for future reference
2. **Share your experience** in the community
3. **Contribute improvements** to the documentation
4. **Report any bugs** you discovered

If you're still having issues:

1. **Search existing issues** on GitHub
2. **Create a new issue** with detailed information
3. **Join the Discord community** for real-time help
4. **Check the [full documentation](../README.md)** for advanced topics
