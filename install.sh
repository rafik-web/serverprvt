#!/bin/bash

# InfluxDB and Grafana Setup Script with Domain Configuration and HTTPS
# Usage: bash <(curl -Ls https://raw.githubusercontent.com/yourusername/yourrepo/main/install.sh)

# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Header
echo -e "${BOLD}${CYAN}"
echo "┌──────────────────────────────────────────────────┐"
echo "│            InfluxDB + Grafana Setup              │"
echo "│        with Cloudflare + HTTPS Support           │"
echo "│                   By Rafik                       │"
echo "└─────────────────────────────────────────────-────┘"
echo -e "${NC}"

set -e

if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root or with sudo${NC}"
  exit 1
fi

# Domain prompt
echo -e "${YELLOW}Enter your domain (e.g. example.com):${NC}"
read -p "> " DOMAIN

if [ -z "$DOMAIN" ]; then
  echo -e "${RED}Domain cannot be empty.${NC}"
  exit 1
fi

DATABASE_SUBDOMAIN="database.${DOMAIN}"
DASHBOARD_SUBDOMAIN="dashboard.${DOMAIN}"
SERVER_IP=$(curl -s https://ipv4.icanhazip.com)

echo -e "\n${GREEN}Configuration:${NC}"
echo -e "  ${BLUE}Domain:${NC} ${DOMAIN}"
echo -e "  ${BLUE}Database URL:${NC} https://${DATABASE_SUBDOMAIN}"
echo -e "  ${BLUE}Dashboard URL:${NC} https://${DASHBOARD_SUBDOMAIN}"
echo -e "  ${BLUE}Server IP (IPv4):${NC} ${SERVER_IP}\n"

read -p "${YELLOW}Proceed with installation? (y/n): ${NC}" confirm
[[ $confirm =~ ^[yY](es)?$ ]] || { echo -e "${RED}Cancelled.${NC}"; exit 1; }

show_progress() {
  echo -e "\n${BOLD}${BLUE}$1...${NC}"
}

show_progress "Updating system"
apt update && apt upgrade -y

show_progress "Installing dependencies"
apt install -y wget curl gnupg2 apt-transport-https software-properties-common ufw nginx certbot python3-certbot-nginx

show_progress "Installing InfluxDB"
wget -q https://repos.influxdata.com/influxdata-archive_compat.key
cat influxdata-archive_compat.key | gpg --dearmor > /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg
echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' > /etc/apt/sources.list.d/influxdata.list
apt update && apt install -y influxdb
systemctl enable --now influxdb

show_progress "Installing Grafana"
wget -q -O - https://packages.grafana.com/gpg.key | apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" > /etc/apt/sources.list.d/grafana.list
apt update && apt install -y grafana
systemctl enable --now grafana-server

show_progress "Configuring Nginx"

for SUBDOMAIN in "$DATABASE_SUBDOMAIN" "$DASHBOARD_SUBDOMAIN"; do
cat > "/etc/nginx/sites-available/$SUBDOMAIN" <<EOF
server {
    listen 80;
    server_name $SUBDOMAIN;
    return 301 https://\$host\$request_uri;
}
EOF
done

cat >> "/etc/nginx/sites-available/$DATABASE_SUBDOMAIN" <<EOF

server {
    listen 443 ssl;
    server_name $DATABASE_SUBDOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DATABASE_SUBDOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DATABASE_SUBDOMAIN/privkey.pem;

    location / {
        proxy_pass http://localhost:8086;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

cat >> "/etc/nginx/sites-available/$DASHBOARD_SUBDOMAIN" <<EOF

server {
    listen 443 ssl;
    server_name $DASHBOARD_SUBDOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DASHBOARD_SUBDOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DASHBOARD_SUBDOMAIN/privkey.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
EOF

ln -sf /etc/nginx/sites-available/$DATABASE_SUBDOMAIN /etc/nginx/sites-enabled/
ln -sf /etc/nginx/sites-available/$DASHBOARD_SUBDOMAIN /etc/nginx/sites-enabled/

nginx -t && systemctl reload nginx

show_progress "Obtaining SSL certificates from Let's Encrypt"
echo -e "${YELLOW}Make sure Cloudflare proxy is OFF (DNS only) for now.${NC}"
certbot --nginx -d $DATABASE_SUBDOMAIN -d $DASHBOARD_SUBDOMAIN

show_progress "Configuring firewall"
ufw allow OpenSSH
ufw allow 'Nginx Full'
echo "y" | ufw enable

show_progress "Final notes"
echo -e "\n${BOLD}${GREEN}Setup Complete!${NC}"
echo -e "\n${CYAN}Access your services securely at:${NC}"
echo -e " - InfluxDB: https://${DATABASE_SUBDOMAIN}"
echo -e " - Grafana: https://${DASHBOARD_SUBDOMAIN} (default login: admin / admin)"
echo -e "\n${YELLOW}Switch Cloudflare proxy back ON and set SSL mode to 'Full (strict)'${NC}"
echo -e "\n${GREEN}Enjoy your secure monitoring stack!${NC}"
