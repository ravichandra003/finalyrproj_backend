#!/bin/bash


# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo "Installing Python dependencies..."
pip install --no-cache-dir flask flask-cors yara-python ppdeep
echo "Python dependencies installed successfully."

# Install Git if not present
if ! command -v git &> /dev/null; then
    echo "Git is not installed. Installing Git..."
    apt-get update
    apt-get install -y git
    echo "Git installed successfully."
else
    echo "Git is already installed."
fi

# Install build dependencies (flex, bison, autotools, etc.)
echo "Installing build dependencies..."
apt-get update
apt-get install -y autoconf automake libtool flex bison

# Clone the repository
echo "Cloning the repository..."
git clone https://github.com/chapl1n03/YARA-with-Similarity_Matching.git
cd YARA-with-Similarity_Matching/Embedded_yara-master/yara-master

# Create the 'm4' directory if it doesn't exist
echo "Creating 'm4' directory..."
mkdir -p m4

# Download the ACX_PTHREAD macro manually
echo "Downloading ACX_PTHREAD macro..."
curl -o m4/ax_pthread.m4 https://raw.githubusercontent.com/autoconf-archive/autoconf-archive/master/m4/ax_pthread.m4

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

# Configure the build system
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

# Check if yara executable was built
if [ -f "./yara" ]; then
    echo "yara executable built successfully."
else
    echo "Error: yara executable not found. Build may have failed."
    exit 1
fi

echo "All steps completed successfully!"
