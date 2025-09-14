#!/bin/bash

set -e

NEBULA_VERSION="latest"
INSTALL_DIR="$HOME/.local/bin"
REPO_URL="https://github.com/yourusername/nebula"

echo "🌌 Installing Nebula Local Development Server..."

# Detect architecture and OS
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

case $ARCH in
    x86_64) ARCH="x86_64" ;;
    arm64|aarch64) ARCH="aarch64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

# Create install directory
mkdir -p "$INSTALL_DIR"

# Download and install
DOWNLOAD_URL="$REPO_URL/releases/download/$NEBULA_VERSION/nebula-$OS-$ARCH"
echo "Downloading from: $DOWNLOAD_URL"

if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$DOWNLOAD_URL" -o "$INSTALL_DIR/nebula"
elif command -v wget >/dev/null 2>&1; then
    wget -q "$DOWNLOAD_URL" -O "$INSTALL_DIR/nebula"
else
    echo "Error: curl or wget is required"
    exit 1
fi

chmod +x "$INSTALL_DIR/nebula"

# Add to PATH if not already there
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> ~/.bashrc
    echo "export PATH=\"$INSTALL_DIR:\$PATH\"" >> ~/.zshrc 2>/dev/null || true
fi

echo "✅ Nebula installed successfully!"
echo "🚀 Run 'nebula setup' to install system dependencies"
echo "💡 Then run 'nebula --domain myapp.dev --command \"npm run dev\"'"
