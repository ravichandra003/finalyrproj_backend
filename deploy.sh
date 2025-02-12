#!/bin/bash
set -eux

# Install dependencies via a Docker-like environment
if ! command -v yara &> /dev/null; then
    echo "YARA is missing, installing..."
    curl -L -o /tmp/yara.deb http://ftp.us.debian.org/debian/pool/main/y/yara/yara_4.3.1-1_amd64.deb
    dpkg -i /tmp/yara.deb || apt-get install -f -y
    rm /tmp/yara.deb
fi

# Install Python packages
pip install --no-cache-dir flask flask-cors yara-python
