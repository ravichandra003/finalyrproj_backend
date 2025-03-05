#!/bin/bash

# Navigate to the yara-master directory
echo "Navigating to yara-master directory..."
cd yara-master
echo "Successfully entered yara-master directory."

# Update and install system dependencies
echo "Updating package list and installing dependencies..."
sudo apt-get update
sudo apt-get install -y \
    autoconf \
    automake \
    libtool \
    pkg-config \
    flex \
    bison \
    libssl-dev \
    libyara-dev \
    python3-pip  # Install pip for Python 3
echo "Dependencies installed successfully."

# Run the bootstrap script
echo "Running bootstrap script..."
./bootstrap.sh
echo "Bootstrap script completed successfully."

# Configure the build system
echo "Configuring the build system..."
./configure
echo "Build system configured successfully."

# Build the project
echo "Building the project..."
make
echo "Project built successfully."

# Install YARA
echo "Installing YARA..."
sudo make install
echo "YARA installed successfully."

# Return to the project root directory
echo "Returning to the project root directory..."
cd ..
echo "Successfully returned to the project root directory."

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --no-cache-dir flask flask-cors yara-python ppdeep
echo "Python dependencies installed successfully."

echo "All steps completed successfully!"
