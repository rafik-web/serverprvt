#!/bin/bash

set -e

echo "🚀 Starting InfluxDB + Grafana setup..."

# Update and install dependencies
echo "🔄 Updating system packages..."
sudo apt update && sudo apt upgrade -y

echo "📦 Installing dependencies..."
sudo apt install -y curl gnupg apt-transport-https software-properties-common wget

# -----------------------------
# Install InfluxDB
# -----------------------------
echo "📥 Installing InfluxDB..."

curl -s https://repos.influxdata.com/influxdata-archive.key | sudo gpg --dearmor -o /etc/apt/keyrings/influxdata-archive-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/influxdata-archive-keyring.gpg] https://repos.influxdata.com/debian stable main' | sudo tee /etc/apt/sources.list.d/influxdata.list

sudo apt update
sudo apt install -y influxdb2

echo "✅ Enabling and starting InfluxDB..."
sudo systemctl enable influxdb
sudo systemctl start influxdb

# -----------------------------
# Install Grafana
# -----------------------------
echo "📥 Installing Grafana..."

wget -q -O - https://packages.grafana.com/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/grafana-archive-keyrings.gpg
echo "deb [signed-by=/usr/share/keyrings/grafana-archive-keyrings.gpg] https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list

sudo apt update
sudo apt install -y grafana

echo "✅ Enabling and starting Grafana..."
sudo systemctl enable grafana-server
sudo systemctl start grafana-server

# -----------------------------
# Firewall (Optional)
# -----------------------------
echo "🔥 Allowing ports in firewall (if ufw is active)..."
if sudo ufw status | grep -q "Status: active"; then
  sudo ufw allow 8086    # InfluxDB
  sudo ufw allow 3000    # Grafana
  echo "✅ UFW ports allowed."
else
  echo "⚠️ UFW not active, skipping firewall config."
fi

# -----------------------------
# Status Check
# -----------------------------
echo "📊 Checking service status..."
sudo systemctl status influxdb | grep Active
sudo systemctl status grafana-server | grep Active

echo "✅ All done!"
echo "InfluxDB running on: http://localhost:8086"
echo "Grafana running on: http://localhost:3000"
