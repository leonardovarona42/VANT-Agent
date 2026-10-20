#!/bin/bash
# VANT-SIEM Agent Packaging Script
# This script must be run on a Linux machine (Ubuntu/Debian recommended)

set -e

# 1. Setup build environment
echo "[*] Setting up build environment..."
apt-get update
apt-get install -y python3-pip python3-dev build-essential binutils

# 2. Install Python dependencies
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt
pip3 install pyinstaller

# 3. Build Binary with PyInstaller
echo "[*] Building binary with PyInstaller..."
# We assume the script is run from the root of VANT-Agent
# We need to make sure the 'vant' package is importable
export PYTHONPATH=$PYTHONPATH:$(pwd)
pyinstaller --onefile vant/main.py -n vant-agent --clean

# 4. Prepare Debian structure
echo "[*] Preparing Debian package structure..."
PKG_ROOT="build_deb"
rm -rf "$PKG_ROOT"
mkdir -p "$PKG_ROOT/DEBIAN"
mkdir -p "$PKG_ROOT/opt/vant-agent/bin"
mkdir -p "$PKG_ROOT/opt/vant-agent/etc"
mkdir -p "$PKG_ROOT/etc/systemd/system"

# Copy files from packaging/ folder
cp -r packaging/DEBIAN/* "$PKG_ROOT/DEBIAN/"
cp packaging/etc/systemd/system/vant-agent.service "$PKG_ROOT/etc/systemd/system/"

# Copy the PyInstaller binary
cp dist/vant-agent "$PKG_ROOT/opt/vant-agent/bin/"

# Create a default example config
cat <<EOF > "$PKG_ROOT/opt/vant-agent/etc/config.example.yaml"
server:
  url: "https://192.168.12.46"
  service_secret: "your-secret-here"
agent:
  check_interval: 60
collectors:
  syslog: {enabled: true, path: /var/log/syslog}
inventory: {enabled: true}
EOF

# 5. Build the .deb package
echo "[*] Building .deb package..."
chmod 755 "$PKG_ROOT/DEBIAN/postinst"
dpkg-deb --build "$PKG_ROOT" vant-agent_2.0.0_amd64.deb

echo "--------------------------------------------------"
echo " SUCCESS: vant-agent_2.0.0_amd64.deb created!"
echo "--------------------------------------------------"
