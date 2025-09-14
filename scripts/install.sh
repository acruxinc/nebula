#!/bin/bash
set -euo pipefail

# Nebula Installation Script for Unix-like systems
# Supports macOS and Linux

NEBULA_VERSION="${NEBULA_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
REPO_URL="https://github.com/your-org/nebula"
RELEASES_URL="$REPO_URL/releases"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        log_warn "Running as root. Some operations may require non-root access."
    fi
}

# Detect operating system and architecture
detect_platform() {
    local os
    local arch
    
    case "$(uname -s)" in
        Darwin*)
            os="darwin"
            ;;
        Linux*)
            os="linux"
            ;;
        *)
            log_error "Unsupported operating system: $(uname -s)"
            exit 1
            ;;
    esac
    
    case "$(uname -m)" in
        x86_64)
            arch="amd64"
            ;;
        arm64|aarch64)
            arch="arm64"
            ;;
        *)
            log_error "Unsupported architecture: $(uname -m)"
            exit 1
            ;;
    esac
    
    echo "${os}-${arch}"
}

# Check system dependencies
check_dependencies() {
    log_info "Checking system dependencies..."
    
    local missing_deps=()
    
    # Check for required commands
    local required_commands=("curl" "tar")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_deps+=("$cmd")
        fi
    done
    
    if [[ ${#missing_deps[@]} -ne 0 ]]; then
        log_error "Missing required dependencies: ${missing_deps[*]}"
        log_info "Please install missing dependencies and try again"
        
        # Provide installation hints
        case "$(uname -s)" in
            Darwin*)
                log_info "On macOS, install with: brew install ${missing_deps[*]}"
                ;;
            Linux*)
                log_info "On Ubuntu/Debian: sudo apt update && sudo apt install ${missing_deps[*]}"
                log_info "On RHEL/CentOS/Fedora: sudo dnf install ${missing_deps[*]}"
                log_info "On Arch Linux: sudo pacman -S ${missing_deps[*]}"
                ;;
        esac
        exit 1
    fi
    
    log_success "All dependencies satisfied"
}

# Get the latest version if not specified
get_latest_version() {
    if [[ "$NEBULA_VERSION" == "latest" ]]; then
        log_info "Fetching latest version..."
        NEBULA_VERSION=$(curl -s "${RELEASES_URL}/latest" | grep -o 'tag/[v.0-9]*' | head -n1 | cut -d/ -f2)
        if [[ -z "$NEBULA_VERSION" ]]; then
            log_error "Failed to fetch latest version"
            exit 1
        fi
        log_info "Latest version: $NEBULA_VERSION"
    fi
}

# Download and verify nebula binary
download_nebula() {
    local platform
    platform=$(detect_platform)
    
    local download_url="${RELEASES_URL}/download/${NEBULA_VERSION}/nebula-${platform}.tar.gz"
    local tmp_dir
    tmp_dir=$(mktemp -d)
    local archive_path="${tmp_dir}/nebula.tar.gz"
    
    log_info "Downloading Nebula ${NEBULA_VERSION} for ${platform}..."
    log_info "Download URL: ${download_url}"
    
    if ! curl -sL -o "$archive_path" "$download_url"; then
        log_error "Failed to download Nebula"
        rm -rf "$tmp_dir"
        exit 1
    fi
    
    log_info "Extracting archive..."
    if ! tar -xzf "$archive_path" -C "$tmp_dir"; then
        log_error "Failed to extract archive"
        rm -rf "$tmp_dir"
        exit 1
    fi
    
    # Find the nebula binary
    local nebula_binary
    nebula_binary=$(find "$tmp_dir" -name "nebula" -type f | head -n1)
    
    if [[ ! -f "$nebula_binary" ]]; then
        log_error "Nebula binary not found in archive"
        rm -rf "$tmp_dir"
        exit 1
    fi
    
    # Make it executable
    chmod +x "$nebula_binary"
    
    # Install to destination
    log_info "Installing to ${INSTALL_DIR}..."
    
    # Create install directory if it doesn't exist
    if [[ ! -d "$INSTALL_DIR" ]]; then
        if ! sudo mkdir -p "$INSTALL_DIR"; then
            log_error "Failed to create install directory: $INSTALL_DIR"
            rm -rf "$tmp_dir"
            exit 1
        fi
    fi
    
    # Copy binary
    if ! sudo cp "$nebula_binary" "$INSTALL_DIR/nebula"; then
        log_error "Failed to install nebula to $INSTALL_DIR"
        rm -rf "$tmp_dir"
        exit 1
    fi
    
    # Cleanup
    rm -rf "$tmp_dir"
    
    log_success "Nebula installed successfully!"
}

# Setup shell completion
setup_completion() {
    log_info "Setting up shell completion..."
    
    local completion_dir
    local shell_config
    
    # Detect shell and set completion directory
    case "$SHELL" in
        */bash)
            if [[ -d "/usr/local/etc/bash_completion.d" ]]; then
                completion_dir="/usr/local/etc/bash_completion.d"
            elif [[ -d "/etc/bash_completion.d" ]]; then
                completion_dir="/etc/bash_completion.d"
            else
                completion_dir="$HOME/.local/share/bash-completion/completions"
                mkdir -p "$completion_dir"
            fi
            shell_config="$HOME/.bashrc"
            ;;
        */zsh)
            completion_dir="$HOME/.zsh/completions"
            mkdir -p "$completion_dir"
            shell_config="$HOME/.zshrc"
            ;;
        */fish)
            completion_dir="$HOME/.config/fish/completions"
            mkdir -p "$completion_dir"
            shell_config="$HOME/.config/fish/config.fish"
            ;;
        *)
            log_warn "Unsupported shell: $SHELL"
            return 0
            ;;
    esac
    
    # Generate completion script
    if command -v nebula >/dev/null 2>&1; then
        log_info "Generating completion script for $SHELL..."
        if nebula completions "$SHELL" > "${completion_dir}/nebula" 2>/dev/null; then
            log_success "Shell completion installed"
            
            # Add completion to shell config if needed
            if [[ -n "$shell_config" && -f "$shell_config" ]]; then
                local completion_line
                case "$SHELL" in
                    */bash)
                        completion_line="source ${completion_dir}/nebula"
                        ;;
                    */zsh)
                        completion_line="fpath=(${completion_dir} \$fpath)"
                        ;;
                    */fish)
                        # Fish completion is automatically loaded
                        completion_line=""
                        ;;
                esac
                
                if [[ -n "$completion_line" ]] && ! grep -q "nebula" "$shell_config" 2>/dev/null; then
                    echo "" >> "$shell_config"
                    echo "# Nebula completion" >> "$shell_config"
                    echo "$completion_line" >> "$shell_config"
                    log_info "Added completion to $shell_config"
                fi
            fi
        else
            log_warn "Failed to generate completion script"
        fi
    else
        log_warn "Nebula not found in PATH, skipping completion setup"
    fi
}

# Setup system integration
setup_system_integration() {
    log_info "Setting up system integration..."
    
    # Create systemd service (Linux only)
    if [[ "$(uname -s)" == "Linux" ]] && command -v systemctl >/dev/null 2>&1; then
        local service_file="/etc/systemd/system/nebula.service"
        if [[ ! -f "$service_file" ]]; then
            log_info "Creating systemd service..."
            sudo tee "$service_file" > /dev/null << EOF
[Unit]
Description=Nebula Universal Development Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=$INSTALL_DIR/nebula server
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
            sudo systemctl daemon-reload
            log_success "Systemd service created"
        fi
    fi
    
    # Create launchd plist (macOS only)
    if [[ "$(uname -s)" == "Darwin" ]]; then
        local plist_dir="$HOME/Library/LaunchAgents"
        local plist_file="$plist_dir/com.nebula.server.plist"
        
        if [[ ! -f "$plist_file" ]]; then
            log_info "Creating launchd plist..."
            mkdir -p "$plist_dir"
            tee "$plist_file" > /dev/null << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.nebula.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>$INSTALL_DIR/nebula</string>
        <string>server</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/nebula.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/nebula.error.log</string>
</dict>
</plist>
EOF
            log_success "Launchd plist created"
        fi
    fi
}

# Verify installation
verify_installation() {
    log_info "Verifying installation..."
    
    if command -v nebula >/dev/null 2>&1; then
        local version
        version=$(nebula --version 2>/dev/null || echo "unknown")
        log_success "Nebula installed successfully!"
        log_info "Version: $version"
        log_info "Location: $(which nebula)"
        
        # Test basic functionality
        if nebula --help >/dev/null 2>&1; then
            log_success "Installation verification passed"
        else
            log_warn "Installation verification failed - nebula --help returned error"
        fi
    else
        log_error "Nebula not found in PATH"
        log_info "Please ensure $INSTALL_DIR is in your PATH"
        return 1
    fi
}

# Display post-installation instructions
show_post_install_info() {
    log_info "Post-installation setup:"
    echo ""
    echo -e "${BLUE}1. Add to PATH (if not already):${NC}"
    echo "   export PATH=\"$INSTALL_DIR:\$PATH\""
    echo ""
    echo -e "${BLUE}2. Reload shell configuration:${NC}"
    case "$SHELL" in
        */bash)
            echo "   source ~/.bashrc"
            ;;
        */zsh)
            echo "   source ~/.zshrc"
            ;;
        */fish)
            echo "   # Fish configuration is automatically loaded"
            ;;
    esac
    echo ""
    echo -e "${BLUE}3. Initialize Nebula in your project:${NC}"
    echo "   cd your-project-directory"
    echo "   nebula init"
    echo ""
    echo -e "${BLUE}4. Start development server:${NC}"
    echo "   nebula dev"
    echo ""
    echo -e "${BLUE}5. For production deployment:${NC}"
    echo "   nebula scheduler start"
    echo ""
    echo -e "${GREEN}🎉 Installation complete! Happy coding with Nebula!${NC}"
}

# Uninstall function
uninstall() {
    log_info "Uninstalling Nebula..."
    
    # Remove binary
    if [[ -f "$INSTALL_DIR/nebula" ]]; then
        sudo rm -f "$INSTALL_DIR/nebula"
        log_success "Removed nebula binary"
    fi
    
    # Remove completion scripts
    local completion_files=(
        "/usr/local/etc/bash_completion.d/nebula"
        "/etc/bash_completion.d/nebula"
        "$HOME/.local/share/bash-completion/completions/nebula"
        "$HOME/.zsh/completions/nebula"
        "$HOME/.config/fish/completions/nebula"
    )
    
    for file in "${completion_files[@]}"; do
        if [[ -f "$file" ]]; then
            rm -f "$file"
            log_info "Removed completion script: $file"
        fi
    done
    
    # Remove system services
    if [[ "$(uname -s)" == "Linux" ]] && [[ -f "/etc/systemd/system/nebula.service" ]]; then
        sudo systemctl stop nebula 2>/dev/null || true
        sudo systemctl disable nebula 2>/dev/null || true
        sudo rm -f "/etc/systemd/system/nebula.service"
        sudo systemctl daemon-reload
        log_success "Removed systemd service"
    fi
    
    if [[ "$(uname -s)" == "Darwin" ]] && [[ -f "$HOME/Library/LaunchAgents/com.nebula.server.plist" ]]; then
        launchctl unload "$HOME/Library/LaunchAgents/com.nebula.server.plist" 2>/dev/null || true
        rm -f "$HOME/Library/LaunchAgents/com.nebula.server.plist"
        log_success "Removed launchd plist"
    fi
    
    # Remove config directory
    if [[ -d "$HOME/.config/nebula" ]]; then
        rm -rf "$HOME/.config/nebula"
        log_success "Removed configuration directory"
    fi
    
    log_success "Nebula uninstalled successfully!"
}

# Show usage information
show_usage() {
    echo "Nebula Installation Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -v, --version VERSION    Install specific version (default: latest)"
    echo "  -d, --dir DIRECTORY      Installation directory (default: /usr/local/bin)"
    echo "  -u, --uninstall         Uninstall Nebula"
    echo "  -h, --help              Show this help message"
    echo ""
    echo "Environment variables:"
    echo "  NEBULA_VERSION          Version to install"
    echo "  INSTALL_DIR             Installation directory"
    echo ""
    echo "Examples:"
    echo "  $0                      # Install latest version"
    echo "  $0 -v v1.0.0           # Install specific version"
    echo "  $0 -d ~/.local/bin     # Install to custom directory"
    echo "  $0 --uninstall         # Uninstall Nebula"
}

# Main function
main() {
    local uninstall_flag=false
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -v|--version)
                NEBULA_VERSION="$2"
                shift 2
                ;;
            -d|--dir)
                INSTALL_DIR="$2"
                shift 2
                ;;
            -u|--uninstall)
                uninstall_flag=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
    
    # Handle uninstall
    if [[ "$uninstall_flag" == true ]]; then
        uninstall
        exit 0
    fi
    
    # Installation process
    log_info "Starting Nebula installation..."
    log_info "Version: $NEBULA_VERSION"
    log_info "Install directory: $INSTALL_DIR"
    echo ""
    
    check_root
    check_dependencies
    get_latest_version
    download_nebula
    setup_completion
    setup_system_integration
    
    if verify_installation; then
        show_post_install_info
    else
        log_error "Installation verification failed"
        exit 1
    fi
}

# Run main function
main "$@"
