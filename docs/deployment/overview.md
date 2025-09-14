# Production Deployment Overview

Nebula provides a comprehensive production deployment system through its built-in scheduler. This guide covers the concepts, architecture, and workflow for deploying applications to production.

## Production Architecture

Nebula's production system consists of several key components:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Nebula CLI    │    │  Nebula Server  │    │  Scheduler      │
│                 │    │                 │    │                 │
│ • Deploy        │───▶│ • HTTP/HTTPS    │───▶│ • Process Mgmt  │
│ • Manage        │    │ • TLS Proxy     │    │ • Health Check  │
│ • Monitor       │    │ • Load Balance  │    │ • Auto-restart  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Applications  │    │     DNS         │    │   Monitoring    │
│                 │    │                 │    │                 │
│ • Static Sites  │    │ • Domain Mgmt   │    │ • Logs          │
│ • APIs          │    │ • SSL Certs     │    │ • Metrics       │
│ • Services      │    │ • Load Balance  │    │ • Alerts        │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Key Concepts

### Applications
Applications are the services you deploy to production. They can be:
- **Static websites** (React, Vue, Angular builds)
- **Web APIs** (Node.js, Python, Go, Rust services)
- **Microservices** (Containerized applications)
- **Full-stack applications** (Frontend + Backend)

### Domains
Each application gets a unique domain:
- **Development**: `myapp.nebula.com`
- **Production**: `myapp.yourcompany.com`
- **Staging**: `myapp-staging.yourcompany.com`

### Deployments
A deployment represents a specific version of an application running in production:
- **Versioned**: Each deployment has a unique version
- **Isolated**: Deployments run in separate processes
- **Scalable**: Multiple instances can run simultaneously
- **Monitored**: Health checks and logging included

### Scheduler
The scheduler manages all deployments:
- **Process management**: Starts, stops, and monitors applications
- **Health monitoring**: Checks application health and restarts if needed
- **Resource management**: Limits CPU and memory usage
- **Auto-cleanup**: Removes old deployments automatically

## Deployment Workflow

### 1. Build Your Application

First, build your application for production:

```bash
# React/Next.js
npm run build

# Vue.js
npm run build

# Python Django
python manage.py collectstatic

# Go
go build -o myapp

# Rust
cargo build --release
```

### 2. Start the Scheduler

Start the production scheduler:

```bash
# Start scheduler
nebula scheduler start

# Check scheduler status
nebula scheduler status
```

### 3. Deploy Your Application

Deploy your built application:

```bash
# Deploy static site
nebula deploy create myapp \
  --path ./dist \
  --tld mycompany.com

# Deploy API service
nebula deploy create myapi \
  --path ./build \
  --tld mycompany.com \
  --env NODE_ENV=production

# Deploy with resource limits
nebula deploy create myapp \
  --path ./dist \
  --tld mycompany.com \
  --memory 512Mi \
  --cpu 500m
```

### 4. Access Your Application

Your application is now live at:
- **Production URL**: `https://myapp.mycompany.com`
- **Health Check**: `https://myapp.mycompany.com/health`

### 5. Monitor and Manage

Monitor your deployment:

```bash
# Check deployment status
nebula deploy status myapp

# View logs
nebula deploy logs myapp

# Update deployment
nebula deploy update myapp --path ./new-dist

# Remove deployment
nebula deploy remove myapp
```

## Deployment Types

### Static Site Deployment

Deploy static websites (React, Vue, Angular builds):

```bash
# Build your static site
npm run build

# Deploy the build directory
nebula deploy create mywebsite \
  --path ./dist \
  --tld mycompany.com \
  --type static
```

**Features:**
- **Automatic serving**: Static files served directly
- **Gzip compression**: Automatic compression for better performance
- **Caching headers**: Optimized caching for static assets
- **SPA support**: Single Page Application routing support

### API Service Deployment

Deploy web APIs and services:

```bash
# Deploy Node.js API
nebula deploy create myapi \
  --path ./build \
  --tld mycompany.com \
  --command "node server.js" \
  --env NODE_ENV=production

# Deploy Python API
nebula deploy create myapi \
  --path ./src \
  --tld mycompany.com \
  --command "python app.py" \
  --env FLASK_ENV=production
```

**Features:**
- **Process management**: Automatic process monitoring and restart
- **Health checks**: Built-in health check endpoints
- **Load balancing**: Multiple instances supported
- **Environment variables**: Secure environment variable management

### Container Deployment

Deploy containerized applications:

```bash
# Deploy Docker container
nebula deploy create myapp \
  --image myapp:latest \
  --tld mycompany.com \
  --port 8080

# Deploy with custom configuration
nebula deploy create myapp \
  --image myapp:latest \
  --tld mycompany.com \
  --port 8080 \
  --env DATABASE_URL=postgresql://...
```

**Features:**
- **Docker support**: Run any Docker container
- **Port mapping**: Automatic port management
- **Volume mounting**: Persistent storage support
- **Network isolation**: Secure container networking

## Domain Management

### Custom TLD Setup

Configure your custom top-level domain:

```bash
# Set default TLD for deployments
nebula config set scheduler.default_tld mycompany.com

# Deploy with custom TLD
nebula deploy create myapp \
  --path ./dist \
  --tld mycompany.com
```

### Subdomain Management

Nebula automatically creates subdomains for your applications:

```bash
# These will be automatically available:
# https://myapp.mycompany.com
# https://api.mycompany.com
# https://admin.mycompany.com
# https://staging-myapp.mycompany.com
```

### SSL Certificate Management

Automatic SSL certificate generation and management:

```bash
# Generate wildcard certificate for your domain
nebula cert generate --domain "*.mycompany.com"

# Check certificate status
nebula cert info "*.mycompany.com"
```

## Environment Management

### Environment Variables

Set environment variables for your deployments:

```bash
# Deploy with environment variables
nebula deploy create myapp \
  --path ./dist \
  --tld mycompany.com \
  --env NODE_ENV=production \
  --env DATABASE_URL=postgresql://... \
  --env API_KEY=secret-key
```

### Environment Files

Use environment files for complex configurations:

```bash
# Create environment file
cat > .env.production << EOF
NODE_ENV=production
DATABASE_URL=postgresql://user:pass@localhost:5432/mydb
API_KEY=your-secret-key
DEBUG=false
EOF

# Deploy with environment file
nebula deploy create myapp \
  --path ./dist \
  --tld mycompany.com \
  --env-file .env.production
```

### Secrets Management

For sensitive data, use Nebula's secrets management:

```bash
# Set secret
nebula secrets set database_password "super-secret-password"

# Use secret in deployment
nebula deploy create myapp \
  --path ./dist \
  --tld mycompany.com \
  --secret database_password
```

## Scaling and Performance

### Horizontal Scaling

Run multiple instances of your application:

```bash
# Deploy with multiple instances
nebula deploy create myapp \
  --path ./dist \
  --tld mycompany.com \
  --instances 3
```

### Resource Limits

Set resource limits for your deployments:

```bash
# Deploy with resource limits
nebula deploy create myapp \
  --path ./dist \
  --tld mycompany.com \
  --memory 1Gi \
  --cpu 1000m \
  --instances 2
```

### Load Balancing

Nebula automatically load balances between instances:

- **Round-robin**: Distributes requests evenly
- **Health-aware**: Skips unhealthy instances
- **Sticky sessions**: Optional session affinity
- **Circuit breaker**: Automatic failure handling

## Monitoring and Observability

### Health Checks

Built-in health monitoring:

```bash
# Check deployment health
nebula deploy health myapp

# View health history
nebula deploy health myapp --history
```

### Logging

Centralized logging for all deployments:

```bash
# View deployment logs
nebula deploy logs myapp

# Follow logs in real-time
nebula deploy logs myapp --follow

# Filter logs by level
nebula deploy logs myapp --level error
```

### Metrics

Built-in metrics collection:

```bash
# View deployment metrics
nebula deploy metrics myapp

# Export metrics
nebula deploy metrics myapp --export prometheus
```

### Alerts

Configure alerts for deployment issues:

```bash
# Set up alerts
nebula alerts create \
  --deployment myapp \
  --condition "health_check_failed" \
  --action "restart_deployment"

# List alerts
nebula alerts list
```

## Backup and Recovery

### Deployment Backups

Backup your deployments:

```bash
# Backup deployment
nebula backup create myapp --output myapp-backup.tar.gz

# List backups
nebula backup list

# Restore from backup
nebula backup restore myapp-backup.tar.gz
```

### Configuration Backups

Backup scheduler configuration:

```bash
# Backup scheduler config
nebula scheduler backup --output scheduler-backup.tar.gz

# Restore scheduler config
nebula scheduler restore scheduler-backup.tar.gz
```

## Security Considerations

### Network Security

- **TLS encryption**: All traffic encrypted with TLS
- **Firewall rules**: Automatic firewall configuration
- **Network isolation**: Deployments isolated from each other
- **Access control**: Role-based access control

### Application Security

- **Process isolation**: Each deployment runs in isolated process
- **Resource limits**: Prevent resource exhaustion
- **Health monitoring**: Automatic detection of compromised applications
- **Secret management**: Secure handling of sensitive data

### Certificate Security

- **Automatic renewal**: Certificates renewed automatically
- **Strong cryptography**: ECDSA keys with strong curves
- **Certificate transparency**: Optional CT logging
- **HSTS headers**: HTTP Strict Transport Security

## Troubleshooting

### Common Issues

**Deployment fails to start:**
```bash
# Check deployment logs
nebula deploy logs myapp

# Check health status
nebula deploy health myapp

# Restart deployment
nebula deploy restart myapp
```

**SSL certificate issues:**
```bash
# Regenerate certificates
nebula cert generate --force

# Check certificate status
nebula cert info "*.mycompany.com"
```

**DNS resolution problems:**
```bash
# Check DNS configuration
nebula dns status

# Test DNS resolution
dig myapp.mycompany.com
```

**Performance issues:**
```bash
# Check resource usage
nebula deploy metrics myapp

# Scale deployment
nebula deploy scale myapp --instances 3
```

### Debug Mode

Enable debug mode for detailed logging:

```bash
# Start scheduler with debug logging
nebula scheduler start --debug

# Deploy with debug logging
nebula deploy create myapp \
  --path ./dist \
  --tld mycompany.com \
  --debug
```

## Best Practices

### 1. Use Version Control

```bash
# Tag your deployments
nebula deploy create myapp-v1.0.0 \
  --path ./dist \
  --tld mycompany.com

# Keep deployment history
nebula deploy list --all
```

### 2. Environment Separation

```bash
# Production
nebula deploy create myapp \
  --path ./dist \
  --tld mycompany.com

# Staging
nebula deploy create myapp-staging \
  --path ./dist \
  --tld mycompany.com \
  --env NODE_ENV=staging
```

### 3. Resource Planning

```bash
# Set appropriate resource limits
nebula deploy create myapp \
  --path ./dist \
  --tld mycompany.com \
  --memory 512Mi \
  --cpu 500m
```

### 4. Monitoring Setup

```bash
# Set up comprehensive monitoring
nebula alerts create \
  --deployment myapp \
  --condition "cpu_usage > 80%" \
  --action "scale_up"

nebula alerts create \
  --deployment myapp \
  --condition "health_check_failed" \
  --action "restart_deployment"
```

## Next Steps

- **Set up [Scheduler](scheduler.md)** for production deployment
- **Deploy [Applications](applications.md)** to production
- **Manage [Domains](domains.md)** and SSL certificates
- **Configure [Monitoring](monitoring.md)** and alerts
- **Learn about [Scaling](scaling.md)** your deployments
