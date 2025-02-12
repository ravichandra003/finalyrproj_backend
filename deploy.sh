#!/bin/bash
set -eux

echo "🔍 Updating system..."
apt-get update

echo "📦 Installing YARA..."
apt-get install -y yara

echo "✅ Verifying YARA installation..."
which yara
yara --version

echo "📦 Installing Python dependencies..."
pip install -r requirements.txt

echo "🚀 Deployment complete!"
