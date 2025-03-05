#!/bin/bash

# Navigate to the yara-master directory
echo "Navigating to yara-master directory..."
cd yara-master
echo "Successfully entered yara-master directory."

# Update and install system dependencies
echo "Updating package list and installing dependencies..."
apt-get update
apt-get install -y \
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

# Create the m4 directory
echo "Creating m4 directory..."
mkdir -p m4
echo "m4 directory created successfully."

# Update configure.ac
echo "Updating configure.ac..."
autoupdate
echo "configure.ac updated successfully."

# Regenerate auxiliary files
echo "Regenerating auxiliary files..."
autoreconf -f -i
echo "Auxiliary files regenerated successfully."

# Manually add missing auxiliary files
echo "Downloading missing auxiliary files..."
wget https://git.savannah.gnu.org/cgit/config.git/plain/config.guess
wget https://git.savannah.gnu.org/cgit/config.git/plain/config.sub
wget https://git.savannah.gnu.org/cgit/config.git/plain/compile
wget https://git.savannah.gnu.org/cgit/config.git/plain/ar-lib
wget https://git.savannah.gnu.org/cgit/config.git/plain/missing
wget https://git.savannah.gnu.org/cgit/config.git/plain/install-sh
mkdir -p build-aux
mv config.guess config.sub compile ar-lib missing install-sh build-aux/
echo "Missing auxiliary files added successfully."

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
make install
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
