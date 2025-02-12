#!/bin/bash
set -eux

# Install YARA
apt-get update && apt-get install -y yara
pip install flask flask-cors yara-python 
