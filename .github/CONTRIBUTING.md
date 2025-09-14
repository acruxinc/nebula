# Contributing to Nebula

Thank you for your interest in contributing to Nebula! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Contributing Process](#contributing-process)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Guidelines](#testing-guidelines)
- [Documentation Guidelines](#documentation-guidelines)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Release Process](#release-process)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code.

## Getting Started

### Prerequisites

- Rust 1.70+ (latest stable recommended)
- Git
- Platform-specific dependencies:
  - **macOS**: Xcode Command Line Tools
  - **Linux**: `libssl-dev`, `pkg-config`
  - **Windows**: Visual Studio Build Tools

### Development Setup

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/your-username/nebula.git
   cd nebula
   ```

3. Add the upstream remote:
   ```bash
   git remote add upstream https://github.com/your-org/nebula.git
   ```

4. Install dependencies:
   ```bash
   cargo build
   ```

5. Run tests:
   ```bash
   cargo test
   ```

## Contributing Process

### 1. Create an Issue

Before starting work, please:
- Check existing issues to avoid duplicates
- Create an issue describing your proposed change
- Wait for maintainer approval before starting work

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 3. Make Changes

- Follow the code style guidelines
- Write tests for new functionality
- Update documentation as needed
- Ensure all tests pass

### 4. Test Your Changes

```bash
# Run all tests
cargo test

# Run specific test categories
cargo test --lib                    # Unit tests
cargo test --test integration_tests # Integration tests

# Run with verbose output
cargo test -- --nocapture

# Run benchmarks
cargo bench

# Check code formatting
cargo fmt --all -- --check

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings
```

### 5. Submit a Pull Request

- Push your branch to your fork
- Create a pull request with a clear description
- Reference any related issues
- Ensure CI checks pass

## Code Style Guidelines

### Rust Code Style

We follow standard Rust conventions:

- Use `rustfmt` for formatting (run `cargo fmt`)
- Use `clippy` for linting (run `cargo clippy`)
- Follow the Rust API Guidelines
- Use meaningful variable and function names
- Add documentation for public APIs

### Code Organization

```
src/
├── cli/           # Command-line interface
├── core/          # Core application logic
├── network/       # Network components (DNS, DHCP, TLS)
├── platform/      # Platform-specific implementations
├── utils/         # Utility functions
└── main.rs        # Application entry point
```

### Error Handling

- Use `anyhow::Result<T>` for application errors
- Use `thiserror` for custom error types
- Provide meaningful error messages
- Include context in error chains

Example:
```rust
use anyhow::{Context, Result};

pub fn load_config(path: &Path) -> Result<Config> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read config from {}", path.display()))?;
    
    toml::from_str(&content)
        .context("Failed to parse configuration file")
}
```

### Logging

- Use the `tracing` crate for logging
- Use appropriate log levels:
  - `error!` for errors that need attention
  - `warn!` for warnings
  - `info!` for important information
  - `debug!` for debugging information
  - `trace!` for very verbose debugging

Example:
```rust
use tracing::{info, warn, error};

pub fn start_server(config: &Config) -> Result<()> {
    info!("Starting Nebula server on port {}", config.port);
    
    if config.debug_mode {
        warn!("Debug mode is enabled - this should not be used in production");
    }
    
    // ... server logic
}
```

## Testing Guidelines

### Test Structure

- Unit tests go in the same file as the code they test
- Integration tests go in the `tests/` directory
- Use descriptive test names that explain what is being tested

### Test Categories

1. **Unit Tests**: Test individual functions and methods
2. **Integration Tests**: Test component interactions
3. **Performance Tests**: Benchmark critical paths
4. **Security Tests**: Verify security properties

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_config_loading_success() {
        // Arrange
        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("test.toml");
        
        // Act
        let result = load_config(&config_path);
        
        // Assert
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_loading_invalid_path() {
        // Arrange
        let invalid_path = Path::new("/nonexistent/config.toml");
        
        // Act
        let result = load_config(invalid_path);
        
        // Assert
        assert!(result.is_err());
    }
}
```

### Test Data

- Use `tempfile::TempDir` for temporary files
- Create minimal test data
- Clean up resources after tests

## Documentation Guidelines

### Code Documentation

- Document all public APIs with doc comments
- Use examples in documentation when helpful
- Follow Rust documentation conventions

```rust
/// Loads configuration from a TOML file.
///
/// # Arguments
///
/// * `path` - Path to the configuration file
///
/// # Returns
///
/// Returns a `Result` containing the parsed configuration or an error.
///
/// # Examples
///
/// ```rust
/// use std::path::Path;
/// 
/// let config = load_config(Path::new("config.toml"))?;
/// println!("Server port: {}", config.port);
/// ```
pub fn load_config(path: &Path) -> Result<Config> {
    // Implementation
}
```

### README Updates

- Keep the README up to date with new features
- Include usage examples
- Update installation instructions if needed

### API Documentation

- Document breaking changes
- Provide migration guides
- Include deprecation notices

## Commit Message Guidelines

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Types

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Changes that do not affect the meaning of the code
- `refactor`: A code change that neither fixes a bug nor adds a feature
- `perf`: A code change that improves performance
- `test`: Adding missing tests or correcting existing tests
- `chore`: Changes to the build process or auxiliary tools

### Examples

```
feat(dns): add support for custom DNS servers

Add ability to configure custom upstream DNS servers in nebula.toml.
This allows users to use their preferred DNS providers.

Closes #123
```

```
fix(tls): resolve certificate validation issue

Fix issue where self-signed certificates were not being properly
validated, causing connection failures.

Fixes #456
```

## Release Process

### Version Numbering

We follow [Semantic Versioning](https://semver.org/):
- `MAJOR`: Incompatible API changes
- `MINOR`: Backward-compatible functionality additions
- `PATCH`: Backward-compatible bug fixes

### Release Checklist

- [ ] All tests pass
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated
- [ ] Version numbers are bumped
- [ ] Security audit is completed
- [ ] Performance benchmarks are acceptable

### Creating a Release

1. Update version in `Cargo.toml`
2. Update `CHANGELOG.md`
3. Create a release branch
4. Submit PR for review
5. Merge and tag release
6. Publish to crates.io (if applicable)

## Getting Help

- **Documentation**: Check the [README](README.md) and inline documentation
- **Issues**: Search existing issues or create a new one
- **Discussions**: Use GitHub Discussions for questions
- **Discord**: Join our community Discord server

## Recognition

Contributors will be recognized in:
- Release notes
- CONTRIBUTORS.md file
- GitHub contributor graphs

Thank you for contributing to Nebula! 🚀
