# Quick Start Guide

Get up and running with Nebula in under 5 minutes! This guide will walk you through creating your first project and starting the development server.

## Prerequisites

- Nebula installed (see [Installation Guide](installation.md))
- A project directory (any programming language/framework)

## Step 1: Initialize Your Project

Navigate to your project directory and initialize Nebula:

```bash
cd my-awesome-project
nebula init
```

Nebula will automatically detect your project type and create an optimized configuration:

```
🌌 Initializing Nebula in current directory...
🔍 Auto-detecting project type...
✅ Detected project type: JavaScript with framework: React
📝 Generating nebula.toml configuration...
✅ Nebula configuration created for react
🎉 Ready to start development!
```

## Step 2: Start the Development Server

Start Nebula with the auto-detected configuration:

```bash
nebula
```

You'll see output similar to:

```
🌌 Nebula Universal Development Server v0.1.0
🔧 Loading configuration from nebula.toml
🌐 Starting DNS server on 127.0.0.1:53
🔐 Generating TLS certificates...
✅ Certificate generated for app.nebula.com
🚀 Starting development server...
📡 HTTP server running on http://app.nebula.com:3000
🔒 HTTPS server running on https://app.nebula.com:3443
🔄 Hot reload enabled - watching for changes
```

## Step 3: Access Your Application

Your application is now accessible at:

- **HTTP**: `http://app.nebula.com:3000`
- **HTTPS**: `https://app.nebula.com:3443` (with auto-generated certificates)

### Browser Setup

**First time setup**: You may need to accept the self-signed certificate:

1. Visit `https://app.nebula.com:3443`
2. Click "Advanced" → "Proceed to app.nebula.com (unsafe)"
3. The certificate will be automatically trusted for future visits

## Step 4: Start Developing

Nebula automatically:
- ✅ **Watches for file changes** and reloads your application
- ✅ **Manages your development process** (npm run dev, python manage.py runserver, etc.)
- ✅ **Provides HTTPS** with valid certificates
- ✅ **Handles DNS resolution** for your domain
- ✅ **Monitors logs** and shows real-time output

### Example Workflows

**React/Next.js:**
```bash
# Your npm run dev will run automatically
# Edit src/App.js and see changes instantly
```

**Python Flask/Django:**
```bash
# Your python manage.py runserver will run automatically
# Edit your Python files and see changes instantly
```

**Go:**
```bash
# Your go run . will run automatically
# Edit your Go files and see changes instantly
```

## Customizing Your Setup

### Different Domain

```bash
nebula --domain myapp.nebula.com
```

### Different Ports

```bash
nebula --http-port 8080 --https-port 8443
```

### Custom Development Command

```bash
nebula --dev-command "yarn dev"
```

### Configuration File

Edit `nebula.toml` to customize settings:

```toml
[server]
domain = "myapp.nebula.com"
http_port = 8080
https_port = 8443
command = "yarn dev"
hot_reload = true

[tls]
auto_generate = true
ca_name = "My Custom CA"

[dns]
enabled = true
port = 53

[dev]
watch_patterns = ["src/**/*", "public/**/*"]
ignore_patterns = ["node_modules/**/*", ".git/**/*"]
```

## Language-Specific Examples

### React Application

```bash
# Create new React app
npx create-react-app my-react-app
cd my-react-app

# Initialize Nebula
nebula init

# Start development (runs npm start automatically)
nebula
# Access at: http://my-react-app.nebula.com:3000
```

### Vue.js Application

```bash
# Create new Vue app
npm create vue@latest my-vue-app
cd my-vue-app

# Install dependencies
npm install

# Initialize Nebula
nebula init

# Start development (runs npm run dev automatically)
nebula
# Access at: http://my-vue-app.nebula.com:3000
```

### Python Flask

```bash
# Create Flask app
mkdir my-flask-app
cd my-flask-app

# Create app.py
cat > app.py << EOF
from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello():
    return 'Hello from Flask!'

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
EOF

# Initialize Nebula
nebula init

# Start development (runs python app.py automatically)
nebula
# Access at: http://my-flask-app.nebula.com:3000
```

### Go Web Server

```bash
# Create Go app
mkdir my-go-app
cd my-go-app

# Create main.go
cat > main.go << EOF
package main

import (
    "fmt"
    "net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello from Go!")
}

func main() {
    http.HandleFunc("/", handler)
    http.ListenAndServe(":8080", nil)
}
EOF

# Initialize Go module
go mod init my-go-app

# Initialize Nebula
nebula init

# Start development (runs go run . automatically)
nebula
# Access at: http://my-go-app.nebula.com:3000
```

### Rust Web Server

```bash
# Create Rust app
cargo new my-rust-app
cd my-rust-app

# Add dependencies to Cargo.toml
cat >> Cargo.toml << EOF

[dependencies]
tokio = { version = "1.0", features = ["full"] }
warp = "0.3"
EOF

# Create src/main.rs
cat > src/main.rs << EOF
use warp::Filter;

#[tokio::main]
async fn main() {
    let hello = warp::path::end()
        .map(|| "Hello from Rust!");

    warp::serve(hello)
        .run(([0, 0, 0, 0], 8080))
        .await;
}
EOF

# Initialize Nebula
nebula init

# Start development (runs cargo run automatically)
nebula
# Access at: http://my-rust-app.nebula.com:3000
```

## Advanced Features

### Hot Reload Customization

Configure file watching patterns in `nebula.toml`:

```toml
[dev]
watch_patterns = [
    "src/**/*",
    "public/**/*", 
    "static/**/*",
    "assets/**/*",
    "*.html",
    "*.css",
    "*.js"
]
ignore_patterns = [
    "node_modules/**/*",
    ".git/**/*",
    "target/**/*",
    "dist/**/*",
    "*.log"
]
restart_delay = 500  # milliseconds
```

### Environment Variables

Set environment variables for your development environment:

```toml
[dev.env]
NODE_ENV = "development"
DEBUG = "true"
API_URL = "http://localhost:8000"
DATABASE_URL = "sqlite:///dev.db"
```

### Multiple Projects

Run multiple projects simultaneously:

```bash
# Terminal 1: Project A
cd project-a
nebula --http-port 3000

# Terminal 2: Project B  
cd project-b
nebula --http-port 3001
```

## Stopping Nebula

Stop the development server:

```bash
# Press Ctrl+C in the terminal running nebula
# Or send SIGTERM
kill $(pgrep nebula)
```

## Troubleshooting

### Port Already in Use

```bash
# Check what's using the port
lsof -i :3000

# Use a different port
nebula --http-port 8080
```

### DNS Not Working

```bash
# Test DNS resolution
dig @127.0.0.1 app.nebula.com

# Restart DNS server
nebula dns restart
```

### Certificate Issues

```bash
# Regenerate certificates
nebula cert generate --force

# Check certificate status
nebula cert info app.nebula.com
```

### Project Not Detected

```bash
# Force specific template
nebula init --template python
nebula init --template react
nebula init --template default
```

## Next Steps

Now that you have Nebula running:

1. **Explore [Configuration Options](../configuration/overview.md)** to customize your setup
2. **Learn about [CLI Commands](../cli/overview.md)** for advanced usage
3. **Set up [Production Deployment](../deployment/overview.md)** for your applications
4. **Check [Language-Specific Guides](../development/languages.md)** for detailed examples

## Getting Help

- **Documentation**: Browse the [full documentation](../README.md)
- **Issues**: [GitHub Issues](https://github.com/acruxinc/nebula/issues)
- **Discussions**: [GitHub Discussions](https://github.com/acruxinc/nebula/discussions)
- **Discord**: [Join our community](https://discord.gg/nebula)

---

**Congratulations!** You've successfully set up Nebula and are ready to start developing! 🎉
