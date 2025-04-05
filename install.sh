#!/bin/bash

set -e

echo "🚀 Starting Full Setup: InfluxDB + Grafana + Cloudflare DNS + SSL"

# -----------------------------
# USER CONFIG INPUT
# -----------------------------
read -p "🌐 Enter your root domain (e.g. rafik.cloud): " DOMAIN
read -p "🔤 Enter your subdomain (e.g. monitor): " SUBDOMAIN
read -p "🔐 Enter your Cloudflare API Token: " CF_API_TOKEN
read -p "📧 Enter your Cloudflare Account Email: " CF_EMAIL

RECORD_NAME="$SUBDOMAIN.$DOMAIN"
SERVER_IP=$(curl -s ifconfig.me)

# -----------------------------
# INSTALL DEPENDENCIES
# -----------------------------
echo "📦 Installing dependencies..."
sudo apt update && sudo apt install -y curl wget gnupg apt-transport-https software-properties-common jq nginx

# -----------------------------
# INSTALL INFLUXDB
# -----------------------------
echo "📥 Installing InfluxDB..."
curl -s https://repos.influxdata.com/influxdata-archive.key | sudo gpg --dearmor -o /etc/apt/keyrings/influxdata-archive-keyring.gpg
echo 'deb [signed-by=/etc/apt/keyrings/influxdata-archive-keyring.gpg] https://repos.influxdata.com/debian stable main' | sudo tee /etc/apt/sources.list.d/influxdata.list
sudo apt update && sudo apt install -y influxdb2
sudo systemctl enable influxdb && sudo systemctl start influxdb

# -----------------------------
# INSTALL GRAFANA
# -----------------------------
echo "📥 Installing Grafana..."
wget -q -O - https://packages.grafana.com/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/grafana-archive-keyrings.gpg
echo "deb [signed-by=/usr/share/keyrings/grafana-archive-keyrings.gpg] https://packages.grafana.com/oss/deb stable main" | sudo tee /etc/apt/sources.list.d/grafana.list
sudo apt update && sudo apt install -y grafana
sudo systemctl enable grafana-server && sudo systemctl start grafana-server

# -----------------------------
# CLOUDFLARE DNS SETUP
# -----------------------------
echo "🌐 Setting up DNS record in Cloudflare..."
ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
    -H "Authorization: Bearer $CF_API_TOKEN" \
    -H "Content-Type: application/json" | jq -r '.result[0].id')

DNS_RECORD=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?name=$RECORD_NAME" \
    -H "Authorization: Bearer $CF_API_TOKEN" \
    -H "Content-Type: application/json")

RECORD_ID=$(echo "$DNS_RECORD" | jq -r '.result[0].id')

if [[ "$RECORD_ID" == "null" ]]; then
  echo "📌 Creating DNS record..."
  curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
    -H "Authorization: Bearer $CF_API_TOKEN" \
    -H "Content-Type: application/json" \
    --data '{"type":"A","name":"'"$RECORD_NAME"'","content":"'"$SERVER_IP"'","ttl":120,"proxied":true}'
else
  echo "🔁 Updating DNS record..."
  curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
    -H "Authorization: Bearer $CF_API_TOKEN" \
    -H "Content-Type: application/json" \
    --data '{"type":"A","name":"'"$RECORD_NAME"'","content":"'"$SERVER_IP"'","ttl":120,"proxied":true}'
fi

# -----------------------------
# CLOUDFLARE ORIGIN CERT SETUP
# -----------------------------
echo "🔐 Generating Cloudflare Origin SSL Certificate..."
CERT_DATA=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/origin_certificates" \
  -H "Authorization: Bearer $CF_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{"hostnames":["'"$RECORD_NAME"'"],"requested_validity":5475,"request_type":"origin-rsa"}')

CERT=$(echo "$CERT_DATA" | jq -r '.result.certificate')
KEY=$(echo "$CERT_DATA" | jq -r '.result.private_key')

sudo mkdir -p /etc/ssl/rafik/
echo "$CERT" | sudo tee /etc/ssl/rafik/origin.crt >/dev/null
echo "$KEY" | sudo tee /etc/ssl/rafik/origin.key >/dev/null
sudo chmod 600 /etc/ssl/rafik/*

# -----------------------------
# NGINX REVERSE PROXY SETUP
# -----------------------------
echo "🔁 Setting up Nginx reverse proxy..."

cat <<EOF | sudo tee /etc/nginx/sites-available/monitoring
server {
    listen 443 ssl;
    server_name $RECORD_NAME;

    ssl_certificate /etc/ssl/rafik/origin.crt;
    ssl_certificate_key /etc/ssl/rafik/origin.key;

    location /influxdb/ {
        proxy_pass http://localhost:8086/;
        proxy_set_header Host \$host;
    }

    location /grafana/ {
        proxy_pass http://localhost:3000/;
        proxy_set_header Host \$host;
    }
}

server {
    listen 80;
    server_name $RECORD_NAME;
    return 301 https://\$host\$request_uri;
}
EOF

sudo ln -sf /etc/nginx/sites-available/monitoring /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# -----------------------------
# DONE
# -----------------------------
echo "✅ Setup complete!"
echo "Access InfluxDB at: https://$RECORD_NAME/influxdb/"
echo "Access Grafana at: https://$RECORD_NAME/grafana/"
