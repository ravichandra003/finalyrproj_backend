#!/bin/bash
set -eux

echo "Updating package lists..."
apt-get update && apt-get install -y yara
echo "YARA installed successfully."

echo "Installing Python dependencies..."
pip install flask flask-cors yara-python
echo "Python dependencies installed successfully."

echo "Deployment script executed successfully."
