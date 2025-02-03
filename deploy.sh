#!/bin/bash

# Install Python dependencies (Render runs in a virtualized environment)
echo "Installing required Python packages..."
pip install --no-cache-dir yara-python Flask flask-cors pydeep os-sys

# Define the deployment folder (if applicable)
DEPLOY_DIR="yara-master"  # Change this to the folder where you want to run the build commands 

# Navigate to the deployment folder
echo "Navigating to deployment directory: $DEPLOY_DIR"
cd "$DEPLOY_DIR" || { echo "Error: Directory $DEPLOY_DIR not found!"; exit 1; }

# Run build commands inside the deployment folder
echo "Running bootstrap script..."
./bootstrap.sh

echo "Configuring the build..."
./configure

echo "Building the project..."
make

echo "Deployment script completed successfully!"
