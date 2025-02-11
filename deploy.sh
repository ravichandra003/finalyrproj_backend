#!/bin/bash

echo "Installing required system dependencies..."
if [ -f "apt.txt" ]; then
    echo "Using apt.txt for package installation..."
else
    echo "apt.txt not found! Creating one..."
    echo "libfuzzy-dev" > apt.txt
fi

echo "Installing required Python packages..."
pip install -r requirements.txt
pip install ssdeep  # Alternative to libfuzzy-dev for Python
