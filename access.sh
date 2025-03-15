#!/bin/bash





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
./bootstrap.sh
./configure
echo "Build system configured successfully."

# Build the project
echo "Building the project..."
make
echo "Project built successfully."



# Install Python dependencies
echo "Installing Python dependencies..."
pip install --no-cache-dir flask flask-cors yara-python ppdeep
echo "Python dependencies installed successfully."

echo "All steps completed successfully!"
