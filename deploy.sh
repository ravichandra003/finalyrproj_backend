#!/bin/bash
set -eux  # Exit on error and print commands

echo "🔍 Checking system dependencies..."

# Ensure running in a non-root environment
if [ "$(id -u)" -eq 0 ]; then
    echo "❌ Do not run this script as root."
    exit 1
fi

echo "📦 Installing YARA locally..."
YARA_VERSION="4.4.0"
YARA_BIN="/usr/local/bin/yara"

if ! command -v yara &> /dev/null; then
    wget -q "https://github.com/VirusTotal/yara/releases/latest/download/yara-${YARA_VERSION}-linux.tar.gz" -O yara.tar.gz
    tar -xzf yara.tar.gz
    mv yara "$YARA_BIN"
    chmod +x "$YARA_BIN"
else
    echo "✅ YARA is already installed."
fi

echo "✅ Verifying YARA installation..."
which yara
yara --version

echo "📦 Installing Python dependencies..."
if [ -f "requirements.txt" ]; then
    pip install --no-cache-dir -r requirements.txt
else
    echo "❌ requirements.txt not found!"
    exit 1
fi

echo "🚀 Deployment complete!"
