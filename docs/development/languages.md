# Language and Framework Support

Nebula provides universal support for any programming language and framework. This guide covers the supported languages, auto-detection capabilities, and framework-specific configurations.

## Supported Languages

Nebula automatically detects and configures support for the following programming languages:

### Frontend Frameworks

#### JavaScript/TypeScript
- **React** - Create React App, Next.js, Gatsby
- **Vue.js** - Vue CLI, Nuxt.js, Quasar
- **Angular** - Angular CLI, Angular Universal
- **Svelte** - SvelteKit, Sapper
- **Alpine.js** - Lightweight reactive framework
- **Lit** - Web Components library

#### CSS Frameworks
- **Tailwind CSS** - Utility-first CSS framework
- **Bootstrap** - Popular CSS framework
- **Bulma** - Modern CSS framework
- **Foundation** - Responsive front-end framework

### Backend Languages

#### Python
- **Flask** - Lightweight web framework
- **Django** - Full-featured web framework
- **FastAPI** - Modern async web framework
- **Streamlit** - Data science web apps
- **Tornado** - Async web framework
- **Bottle** - Micro web framework

#### Go
- **Gin** - HTTP web framework
- **Echo** - High performance web framework
- **Fiber** - Express-inspired web framework
- **Beego** - Full-stack web framework
- **Iris** - Fast web framework
- **Chi** - Lightweight router

#### Rust
- **Actix-web** - Actor-based web framework
- **Axum** - Ergonomic web framework
- **Warp** - Super-fast web framework
- **Rocket** - Web framework with type safety
- **Tide** - Modular web framework
- **Poem** - Full-featured web framework

#### Java
- **Spring Boot** - Enterprise Java framework
- **Quarkus** - Supersonic Java framework
- **Micronaut** - Modern JVM framework
- **Vert.x** - Reactive toolkit
- **Play Framework** - Web application framework
- **Spark** - Micro framework

#### C#
- **ASP.NET Core** - Cross-platform web framework
- **Blazor** - Web UI framework
- **Nancy** - Lightweight web framework
- **ServiceStack** - Web services framework

#### PHP
- **Laravel** - Elegant PHP framework
- **Symfony** - PHP framework and components
- **CodeIgniter** - Lightweight PHP framework
- **CakePHP** - Rapid development framework
- **Yii** - High-performance PHP framework
- **Zend Framework** - Enterprise PHP framework

#### Ruby
- **Ruby on Rails** - Web application framework
- **Sinatra** - DSL for web applications
- **Hanami** - Modern Ruby web framework
- **Grape** - REST-like API framework
- **Padrino** - Ruby web framework
- **Camping** - Micro web framework

### Other Languages

#### C/C++
- **Custom build systems** - Make, CMake, Autotools
- **HTTP servers** - Custom implementations
- **CGI applications** - Common Gateway Interface

#### Shell/Bash
- **Shell scripts** - Bash, Zsh, Fish
- **Automation scripts** - CI/CD, deployment scripts
- **System utilities** - Command-line tools

#### Docker
- **Containerized applications** - Docker, Podman
- **Multi-stage builds** - Development and production containers
- **Docker Compose** - Multi-container applications

## Auto-Detection System

Nebula automatically detects your project type by analyzing:

### Package Managers
- **Node.js**: `package.json`, `yarn.lock`, `package-lock.json`
- **Python**: `requirements.txt`, `pyproject.toml`, `Pipfile`
- **Go**: `go.mod`, `go.sum`
- **Rust**: `Cargo.toml`, `Cargo.lock`
- **Java**: `pom.xml`, `build.gradle`, `gradle.properties`
- **C#**: `*.csproj`, `*.sln`, `packages.config`
- **PHP**: `composer.json`, `composer.lock`
- **Ruby**: `Gemfile`, `Gemfile.lock`

### Framework Indicators
- **React**: `react`, `react-dom` in package.json, JSX files
- **Vue**: `vue` in package.json, `.vue` files
- **Angular**: `@angular/core` in package.json, `.component.ts` files
- **Next.js**: `next` in package.json, `pages/` directory
- **Nuxt.js**: `nuxt` in package.json, `nuxt.config.js`
- **Django**: `manage.py`, `settings.py`, `wsgi.py`
- **Flask**: `app.py`, `application.py`, Flask imports
- **Spring Boot**: `@SpringBootApplication` annotations
- **Laravel**: `artisan`, `app/` directory structure

### Build Systems
- **Make**: `Makefile`
- **CMake**: `CMakeLists.txt`
- **Autotools**: `configure.ac`, `Makefile.am`
- **Gradle**: `build.gradle`, `gradle/wrapper/`
- **Maven**: `pom.xml`
- **Webpack**: `webpack.config.js`
- **Vite**: `vite.config.js`
- **Rollup**: `rollup.config.js`

## Framework-Specific Configurations

### React Applications

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "npm run dev"
hot_reload = true

[dev]
watch_patterns = [
    "src/**/*.js",
    "src/**/*.jsx", 
    "src/**/*.ts",
    "src/**/*.tsx",
    "public/**/*"
]
ignore_patterns = [
    "node_modules/**/*",
    "build/**/*",
    "coverage/**/*"
]

[dev.env]
NODE_ENV = "development"
REACT_APP_API_URL = "http://localhost:8000"
REACT_APP_DEBUG = "true"
```

### Vue.js Applications

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "npm run serve"
hot_reload = true

[dev]
watch_patterns = [
    "src/**/*.vue",
    "src/**/*.js",
    "src/**/*.ts",
    "public/**/*"
]
ignore_patterns = [
    "node_modules/**/*",
    "dist/**/*"
]

[dev.env]
NODE_ENV = "development"
VUE_APP_API_URL = "http://localhost:8000"
```

### Next.js Applications

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "npm run dev"
hot_reload = true

[dev]
watch_patterns = [
    "pages/**/*",
    "components/**/*",
    "lib/**/*",
    "styles/**/*",
    "public/**/*"
]
ignore_patterns = [
    "node_modules/**/*",
    ".next/**/*"
]

[dev.env]
NODE_ENV = "development"
NEXT_PUBLIC_API_URL = "http://localhost:8000"
```

### Python Flask Applications

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "python app.py"
hot_reload = true

[dev]
watch_patterns = [
    "*.py",
    "templates/**/*",
    "static/**/*",
    "app/**/*"
]
ignore_patterns = [
    "__pycache__/**/*",
    "*.pyc",
    "venv/**/*",
    ".pytest_cache/**/*"
]

[dev.env]
FLASK_ENV = "development"
FLASK_DEBUG = "1"
DATABASE_URL = "sqlite:///dev.db"
```

### Python Django Applications

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "python manage.py runserver 0.0.0.0:8000"
hot_reload = true

[dev]
watch_patterns = [
    "*.py",
    "templates/**/*",
    "static/**/*",
    "media/**/*",
    "**/migrations/**/*"
]
ignore_patterns = [
    "__pycache__/**/*",
    "*.pyc",
    "venv/**/*",
    "migrations/__pycache__/**/*"
]

[dev.env]
DEBUG = "True"
DATABASE_URL = "sqlite:///dev.db"
SECRET_KEY = "dev-secret-key"
```

### Go Web Applications

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "go run ."
hot_reload = true

[dev]
watch_patterns = [
    "*.go",
    "templates/**/*",
    "static/**/*",
    "configs/**/*"
]
ignore_patterns = [
    "vendor/**/*",
    "*.exe",
    "*.test"
]

[dev.env]
GO_ENV = "development"
PORT = "8080"
DATABASE_URL = "sqlite://dev.db"
```

### Rust Web Applications

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "cargo run"
hot_reload = true

[dev]
watch_patterns = [
    "src/**/*.rs",
    "templates/**/*",
    "static/**/*",
    "Cargo.toml"
]
ignore_patterns = [
    "target/**/*",
    "*.pdb"
]

[dev.env]
RUST_LOG = "debug"
DATABASE_URL = "sqlite://dev.db"
```

### Java Spring Boot Applications

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "mvn spring-boot:run"
hot_reload = true

[dev]
watch_patterns = [
    "src/**/*.java",
    "src/**/*.xml",
    "src/**/*.properties",
    "src/**/*.yml"
]
ignore_patterns = [
    "target/**/*",
    "*.class"
]

[dev.env]
SPRING_PROFILES_ACTIVE = "development"
SERVER_PORT = "8080"
```

### PHP Laravel Applications

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "php artisan serve --host=0.0.0.0 --port=8000"
hot_reload = true

[dev]
watch_patterns = [
    "app/**/*.php",
    "resources/**/*",
    "routes/**/*.php",
    "config/**/*.php"
]
ignore_patterns = [
    "vendor/**/*",
    "storage/**/*",
    "bootstrap/cache/**/*"
]

[dev.env]
APP_ENV = "local"
APP_DEBUG = "true"
DB_CONNECTION = "sqlite"
```

### Ruby on Rails Applications

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "rails server -b 0.0.0.0 -p 3000"
hot_reload = true

[dev]
watch_patterns = [
    "app/**/*.rb",
    "app/**/*.erb",
    "config/**/*.rb",
    "lib/**/*.rb"
]
ignore_patterns = [
    "vendor/**/*",
    "log/**/*",
    "tmp/**/*"
]

[dev.env]
RAILS_ENV = "development"
DATABASE_URL = "sqlite://dev.db"
```

## Custom Language Support

### Adding Custom Detection

You can extend Nebula's detection by creating a custom configuration:

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "my-custom-command"
hot_reload = true

[dev]
watch_patterns = [
    "src/**/*.myext",
    "config/**/*.conf"
]
ignore_patterns = [
    "build/**/*",
    "cache/**/*"
]

[dev.env]
MY_CUSTOM_VAR = "value"
```

### Custom Build Commands

For languages not automatically detected, specify custom commands:

```toml
[server]
# Custom build and run commands
command = "make build && ./bin/myapp"

# Or separate build and run
build_command = "make build"
run_command = "./bin/myapp"

# Custom working directory
working_directory = "build"
```

## Language-Specific Tips

### JavaScript/TypeScript

- **Package managers**: Supports npm, yarn, pnpm
- **Build tools**: Webpack, Vite, Rollup, Parcel
- **Testing**: Jest, Vitest, Mocha, Cypress
- **Linting**: ESLint, Prettier

### Python

- **Virtual environments**: venv, virtualenv, conda
- **Package managers**: pip, poetry, pipenv
- **Testing**: pytest, unittest, nose
- **Linting**: flake8, black, isort

### Go

- **Modules**: Go modules (go.mod)
- **Testing**: go test
- **Linting**: golangci-lint, gofmt
- **Build**: go build, go install

### Rust

- **Package manager**: Cargo
- **Testing**: cargo test
- **Linting**: clippy, rustfmt
- **Build**: cargo build, cargo run

### Java

- **Build tools**: Maven, Gradle
- **Testing**: JUnit, TestNG
- **Linting**: Checkstyle, SpotBugs
- **IDE**: IntelliJ, Eclipse, VS Code

## Troubleshooting Language Detection

### Force Template Selection

```bash
# Override auto-detection
nebula init --template python
nebula init --template react
nebula init --template default
```

### Debug Detection

```bash
# Show detection details
nebula init --verbose

# Skip auto-detection
nebula init --no-detect
```

### Manual Configuration

If auto-detection fails, create a manual configuration:

```toml
[server]
domain = "app.nebula.com"
http_port = 3000
https_port = 3443
command = "your-custom-command"
hot_reload = true

[dev]
watch_patterns = ["**/*"]
ignore_patterns = ["node_modules/**/*", ".git/**/*"]
```

## Best Practices

### 1. Use Appropriate File Watching

```toml
[dev]
# Be specific about file patterns
watch_patterns = [
    "src/**/*.js",
    "src/**/*.ts",
    "templates/**/*"
]

# Ignore unnecessary files
ignore_patterns = [
    "node_modules/**/*",
    "dist/**/*",
    "*.log",
    "coverage/**/*"
]
```

### 2. Set Environment Variables

```toml
[dev.env]
# Language-specific variables
NODE_ENV = "development"
DEBUG = "true"
API_URL = "http://localhost:8000"
```

### 3. Optimize Restart Behavior

```toml
[dev]
# Adjust restart delay for your language
restart_delay = 500  # milliseconds

# Use appropriate command arguments
command = "npm run dev --watch"
```

### 4. Handle Dependencies

```toml
[dev]
# Watch dependency files
watch_patterns = [
    "package.json",
    "requirements.txt",
    "go.mod",
    "Cargo.toml"
]
```

## Next Steps

- **Learn about [Hot Reload](hot-reload.md)** for file watching
- **Explore [Configuration Options](../configuration/overview.md)** for customization
- **Check [Development Workflow](workflow.md)** for best practices
- **Read [Troubleshooting](../troubleshooting/common-issues.md)** for common issues
