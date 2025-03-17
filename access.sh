#!/bin/bash

# Install Python dependencies first
echo "Installing Python dependencies..."
pip install --no-cache-dir flask flask-cors yara-python ppdeep
echo "Python dependencies installed successfully."

# Install Git if not present
if ! command -v git &> /dev/null; then
    echo "Git is not installed. Installing Git..."
    sudo apt-get update
    sudo apt-get install -y git
    echo "Git installed successfully."
else
    echo "Git is already installed."
fi

# Clone the repository
echo "Cloning the repository..."
git clone https://github.com/chapl1n03/YARA-with-Similarity_Matching.git
cd YARA-with-Similarity_Matching/Embedded_yara-master/yara-master

# Run the bootstrap script
echo "Running bootstrap script..."
./bootstrap.sh

# Configure the build system
echo "Configuring the build system..."
./configure

# Build the project
echo "Building the project..."
make
