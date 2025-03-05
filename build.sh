#!/bin/bash

cd yara-master

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


./bootstrap.sh


./configure

make

sudo make install

# Return to the project root directory
cd ..

# Install Python dependencies
pip install --no-cache-dir flask flask-cors yara-python ppdeep