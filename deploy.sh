#!/bin/bash

# Install Python dependencies
echo "Installing required Python packages..."
apt-get update && apt-get install -y libfuzzy-dev
pip install --no-cache-dir -r requirements.txt

# Define the build directory (change if needed)
BUILD_DIR="yara-master"

# Navigate to the build directory
if [ -d "$BUILD_DIR" ]; then
    echo "Navigating to build directory: $BUILD_DIR"
    cd "$BUILD_DIR" || { echo "Error: Failed to navigate to $BUILD_DIR"; exit 1; }
fi

# Run build commands
echo "Running bootstrap script..."
./bootstrap.sh

echo "Configuring the build..."
./configure

echo "Building the project..."
make

echo "Deployment script completed successfully!"
