#!/bin/bash

# Upgrade pip to the latest version
echo "Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
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

# Make bootstrap.sh executable and run it
if [ -f "./bootstrap.sh" ]; then
    echo "Making bootstrap.sh executable..."
    chmod +x ./bootstrap.sh
    echo "Running bootstrap script..."
    ./bootstrap.sh
else
    echo "Error: bootstrap.sh not found in the current directory."
    exit 1
fi

# Make configure executable and run it
if [ -f "./configure" ]; then
    echo "Making configure executable..."
    chmod +x ./configure
    echo "Configuring the build system..."
    ./configure
else
    echo "Error: configure not found in the current directory."
    exit 1
fi

# Build the project
echo "Building the project..."
make

# Run the YARA tool
echo "Running the YARA tool..."
./yara

echo "All steps completed successfully!"
