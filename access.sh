#!/bin/bash




# Configure the build system
#echo "Configuring the build system..."
#./bootstrap.sh
#./configure
#echo "Build system configured successfully."

# Build the project
#echo "Building the project..."
#make
#echo "Project built successfully."



# Install Python dependencies
echo "Installing Python dependencies..."
pip install --no-cache-dir flask flask-cors yara-python ppdeep
echo "Python dependencies installed successfully."

echo "All steps completed successfully!"
