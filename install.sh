#!/bin/bash

# InfluxDB and Grafana Setup Script with Domain Configuration (IPv4 only)
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
echo "┌─────────────────────────────────────────────────┐"
echo "│            InfluxDB + Grafana Setup             │"
echo "│          with Cloudflare SSL Integration        │"
echo "│                     By Rafik                    │"
echo "└─────────────────────────────────────────────────┘"
echo -e "${NC}"

# Exit on any error
set -e

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}Please run as root or with sudo${NC}"
  exit 1
fi

# Get domain information
echo -e "${YELLOW}Please enter your domain (without subdomains, e.g. rafik.cloud):${NC}"
read -p "> " DOMAIN

if [ -z "$DOMAIN" ]; then
  echo -e "${RED}Domain cannot be empty. Exiting.${NC}"
  exit 1
fi

DATABASE_SUBDOMAIN="database.${DOMAIN}"
DASHBOARD_SUBDOMAIN="dashboard.${DOMAIN}"
SERVER_IP=$(curl -s https://ipv4.icanhazip.com)

echo -e "\n${GREEN}Setting up with the following configuration:${NC}"
echo -e "  ${BLUE}Domain:${NC} ${DOMAIN}"
echo -e "  ${BLUE}Database URL:${NC} ${DATABASE_SUBDOMAIN}"
echo -e "  ${BLUE}Dashboard URL:${NC} ${DASHBOARD_SUBDOMAIN}"
echo -e "  ${BLUE}Server IPv4:${NC} ${SERVER_IP}\n"

echo -ne "${YELLOW}Proceed with installation? (y/n):${NC} "
read -p "" confirm
if [[ $confirm != [yY] && $confirm != [yY][eE][sS] ]]; then
  echo -e "${RED}Installation cancelled.${NC}"
  exit 1
fi

# Progress function
show_progress() {
  echo -e "\n${BOLD}${BLUE}$1...${NC}"
}

# Update system
show_progress "Updating system packages"
apt update && apt upgrade -y

# Install necessary tools
show_progress "Installing necessary tools"
apt install -y wget curl gnupg2 apt-transport-https software-properties-common ufw

# Install InfluxDB
show_progress "Installing InfluxDB"
wget -q https://repos.influxdata.com/influxdata-archive_compat.key
echo '393e8779c89ac8d958f81f942f9ad7fb82a25e133faddaf92e15b16e6ac9ce4c influxdata-archive_compat.key' | sha256sum -c && cat influxdata-archive_compat.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg > /dev/null
echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' | tee /etc/apt/sources.list.d/influxdata.list
apt update
apt install -y influxdb
systemctl start influxdb
systemctl enable influxdb

# Install Grafana
show_progress "Installing Grafana"
wget -q -O - https://packages.grafana.com/gpg.key | apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | tee /etc/apt/sources.list.d/grafana.list
apt update
apt install -y grafana
systemctl start grafana-server
systemctl enable grafana-server

# Install Nginx
show_progress "Installing Nginx"
apt install -y nginx
systemctl start nginx
systemctl enable nginx

# Configure Nginx for database subdomain
show_progress "Creating Nginx configuration for ${DATABASE_SUBDOMAIN}"
cat > /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} << EOF
server {
    listen 80;
    server_name ${DATABASE_SUBDOMAIN};

    location / {
        proxy_pass http://localhost:8086;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Configure Nginx for dashboard subdomain
show_progress "Creating Nginx configuration for ${DASHBOARD_SUBDOMAIN}"
cat > /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN} << EOF
server {
    listen 80;
    server_name ${DASHBOARD_SUBDOMAIN};

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

# Enable Nginx configurations
show_progress "Enabling Nginx configurations"
ln -sf /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} /etc/nginx/sites-enabled/
ln -sf /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN} /etc/nginx/sites-enabled/

# Test Nginx configuration
nginx -t

# Restart Nginx
show_progress "Restarting Nginx"
systemctl restart nginx

# Install Certbot (optional but prepared)
show_progress "Installing Certbot for potential SSL setup"
apt install -y certbot python3-certbot-nginx

# Configure firewall
show_progress "Configuring firewall"
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
echo "y" | ufw enable

# Create a convenient helper script for SSL setup
cat > /root/setup-ssl.sh << 'EOF'
#!/bin/bash
if [ -z "$1" ]; then
  echo "Please provide your domain name"
  echo "Usage: $0 yourdomain.com"
  exit 1
fi

DOMAIN=$1
DATABASE_SUBDOMAIN="database.${DOMAIN}"
DASHBOARD_SUBDOMAIN="dashboard.${DOMAIN}"

echo "Setting up SSL certificates for ${DATABASE_SUBDOMAIN} and ${DASHBOARD_SUBDOMAIN}"
echo "IMPORTANT: Before continuing, set your Cloudflare DNS records to 'DNS only' (grey cloud)"
echo ""
read -p "Press Enter when ready..."

certbot --nginx -d ${DATABASE_SUBDOMAIN} -d ${DASHBOARD_SUBDOMAIN}

echo ""
echo "SSL certificates installed. You can now:"
echo "1. Switch back to 'Proxied' in Cloudflare"
echo "2. Set Cloudflare SSL/TLS mode to 'Full (strict)'"
EOF

chmod +x /root/setup-ssl.sh

# Success message
echo -e "\n${BOLD}${GREEN}"
echo "┌─────────────────────────────────────────────────┐"
echo "│             INSTALLATION COMPLETE!              │"
echo "└─────────────────────────────────────────────────┘"
echo -e "${NC}"

echo -e "${CYAN}NEXT STEPS:${NC}\n"
echo -e "${BOLD}1. Log in to your Cloudflare account and add these DNS records:${NC}"
echo -e "   - Type: A, Name: database, Content: ${SERVER_IP}, Proxy status: Proxied"
echo -e "   - Type: A, Name: dashboard, Content: ${SERVER_IP}, Proxy status: Proxied"
echo -e "   - Optional: Add AAAA records if you want IPv6 support\n"

echo -e "${BOLD}2. In Cloudflare, go to SSL/TLS section and set encryption mode to 'Full'${NC}\n"

echo -e "${BOLD}3. After DNS propagation (might take a few minutes to hours), you can access:${NC}"
echo -e "   - InfluxDB: http://${DATABASE_SUBDOMAIN}"
echo -e "   - Grafana: http://${DASHBOARD_SUBDOMAIN}"
echo -e "     Default Grafana login: admin / admin\n"

echo -e "${BOLD}4. Optional: To set up SSL with Let's Encrypt, run:${NC}"
echo -e "   sudo /root/setup-ssl.sh ${DOMAIN}\n"

echo -e "${BOLD}5. Optional: To secure InfluxDB, run:${NC}"
echo -e "   influx"
echo -e "   CREATE USER admin WITH PASSWORD 'your_secure_password' WITH ALL PRIVILEGES"
echo -e "   EXIT"
echo -e ""
echo -e "   Then edit /etc/influxdb/influxdb.conf, find the [http] section,"
echo -e "   set auth-enabled = true, and restart InfluxDB with:"
echo -e "   sudo systemctl restart influxdb\n"

echo -e "${GREEN}Enjoy your new InfluxDB and Grafana setup with Cloudflare integration!${NC}"
