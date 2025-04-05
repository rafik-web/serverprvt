#!/bin/bash

# Enhanced InfluxDB and Grafana Setup Script for Amazon Lightsail
# AUTOMATICALLY generates/deploys Cloudflare Origin Certificate via API
# !! USES GLOBAL API KEY - READ SECURITY WARNINGS !!
# Usage: sudo bash <(curl -Ls https://your-raw-script-url.com/install-cf-origin-auto.sh) # Replace with your URL

# --- Configuration ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Exit on any error and handle errors in pipelines
set -eo pipefail

# --- Helper Functions ---
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}${BOLD}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}${BOLD}[ERROR]${NC} $1" >&2
}

show_progress() {
  echo -e "\n${BOLD}${CYAN}==> $1...${NC}"
}

# --- Header ---
echo -e "${BOLD}${MAGENTA}"
echo "┌────────────────────────────────────────────────────────┐"
echo "│     InfluxDB + Grafana + Nginx Setup (Lightsail)     │"
echo "│    Automatic Cloudflare Origin Certificate via API     │"
echo "│         + Manual IP Fallback Support                 │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"
echo -e "${RED}${BOLD}!!!!!!!!!!!!!!!!!!!!! SECURITY WARNING !!!!!!!!!!!!!!!!!!!!!"
echo -e "This script requires your Cloudflare Global API Key."
echo -e "Entering it below may store it in your shell history."
echo -e "Consider using environment variables or Cloudflare API Tokens"
echo -e "for better security in production environments."
echo -e "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!${NC}"

# --- Pre-flight Checks ---
if [ "$EUID" -ne 0 ]; then
  log_error "Please run this script as root or using sudo."
  exit 1
fi

# Check essential commands early, Nginx & jq will be installed later.
for cmd in curl wget gpg apt ufw systemctl; do
    if ! command -v $cmd &> /dev/null; then
        log_error "$cmd command not found. Please install it or ensure it's in the PATH."
        exit 1
    fi
done

# --- User Input ---
log_info "Gathering required information..."

while [ -z "$DOMAIN" ]; do
    read -p "$(echo -e "${YELLOW}Enter your main domain (e.g., rafik.cloud):${NC} ")" DOMAIN
    if [[ ! "$DOMAIN" == *"."* ]]; then
        log_warning "Invalid domain format. Please enter a valid domain (e.g., example.com)."
        DOMAIN=""
    fi
done

# Cloudflare Credentials
while [ -z "$CF_EMAIL" ]; do
    read -p "$(echo -e "${YELLOW}Enter your Cloudflare Account Email Address:${NC} ")" CF_EMAIL
     # Basic email validation
    if [[ ! "$CF_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_warning "Invalid email format. Please enter a valid email address."
        CF_EMAIL=""
    fi
done

while [ -z "$CF_API_KEY" ]; do
    # Use -s for silent input to hide the key visually
    read -sp "$(echo -e "${YELLOW}Enter your Cloudflare Global API Key:${NC} ")" CF_API_KEY
    echo "" # Add a newline after silent input
    if [ -z "$CF_API_KEY" ]; then
       log_warning "Cloudflare Global API Key cannot be empty."
    fi
done


DATABASE_SUBDOMAIN="database.${DOMAIN}"
DASHBOARD_SUBDOMAIN="dashboard.${DOMAIN}"
# Use a single cert valid for both subdomains, named after the main domain
SSL_CERT_DIR="/etc/nginx/ssl"
CERT_NAME="${DOMAIN}" # Base name for cert/key files
CERT_FILE="${SSL_CERT_DIR}/${CERT_NAME}.pem"
KEY_FILE="${SSL_CERT_DIR}/${CERT_NAME}.key"


# Get Server Public IPv4 Address (with manual fallback)
show_progress "Fetching Server Public IPv4 Address"
SERVER_IP=$(curl -s --connect-timeout 5 http://169.254.169.254/latest/meta-data/public-ipv4 || curl -4s --connect-timeout 5 ifconfig.me || curl -4s --connect-timeout 5 icanhazip.com || echo "")

if [ -z "$SERVER_IP" ]; then
    log_error "Could not automatically determine the server's public IPv4 address."
    log_warning "This might be due to network restrictions or the metadata service being unavailable."
    log_warning "Please find your server's Public IPv4 address manually (e.g., in your Lightsail console)."
    while [ -z "$SERVER_IP" ]; do
        read -p "$(echo -e "${YELLOW}Please manually enter the server's public IPv4 address:${NC} ")" SERVER_IP
        if [ -z "$SERVER_IP" ]; then log_warning "Server IP address cannot be empty. Please try again."; fi
        elif [[ ! "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then log_warning "Input '$SERVER_IP' invalid. Please check."; SERVER_IP=""; fi
    done
    log_success "Using manually entered Server IPv4: ${SERVER_IP}"
else
    log_success "Detected Server IPv4: ${SERVER_IP}"
fi


# --- Confirmation ---
echo -e "\n${GREEN}Setup will proceed with the following details:${NC}"
echo -e "  ${BLUE}Domain:${NC} ${DOMAIN}"
echo -e "  ${BLUE}Database URL:${NC} https://${DATABASE_SUBDOMAIN}"
echo -e "  ${BLUE}Dashboard URL:${NC} https://${DASHBOARD_SUBDOMAIN}"
echo -e "  ${BLUE}Server IPv4:${NC} ${SERVER_IP}"
echo -e "  ${BLUE}Cloudflare Email:${NC} ${CF_EMAIL}"
echo -e "  ${BLUE}Cloudflare API Key:${NC} ************ (Hidden)"
echo -e "  ${BLUE}SSL Cert Location:${NC} ${CERT_FILE}"
echo -e "  ${BLUE}SSL Key Location:${NC} ${KEY_FILE}"
echo -e "  ${GREEN}${BOLD}Note:${NC} An Origin Certificate for *.${DOMAIN} and ${DOMAIN} will be automatically generated via Cloudflare API.\n"

read -p "$(echo -e "${YELLOW}Proceed with installation? (y/n):${NC} ")" confirm
if [[ ! $confirm =~ ^[yY]([eE][sS])?$ ]]; then
  log_warning "Installation cancelled by user."
  exit 1
fi

# --- Installation and Configuration ---

# Update System
show_progress "Updating system packages"
apt update && apt upgrade -y

# Install Essential Tools & Nginx & JQ
show_progress "Installing Nginx, JQ, and other essential tools"
apt install -y wget curl gnupg2 apt-transport-https software-properties-common ufw nginx jq

# Install InfluxDB
show_progress "Installing InfluxDB"
wget -qO- https://repos.influxdata.com/influxdata-archive_compat.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg > /dev/null
echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' | tee /etc/apt/sources.list.d/influxdata.list
apt update
apt install -y influxdb
systemctl start influxdb
systemctl enable influxdb
log_success "InfluxDB installed and started."

# Install Grafana
show_progress "Installing Grafana"
wget -q -O /usr/share/keyrings/grafana.key https://packages.grafana.com/gpg.key
echo "deb [signed-by=/usr/share/keyrings/grafana.key] https://packages.grafana.com/oss/deb stable main" | tee /etc/apt/sources.list.d/grafana.list
apt update
apt install -y grafana
systemctl start grafana-server
systemctl enable grafana-server
log_success "Grafana installed and started."

# Prepare SSL Directory
show_progress "Creating SSL certificate directory: ${SSL_CERT_DIR}"
mkdir -p "${SSL_CERT_DIR}"
chmod 700 "${SSL_CERT_DIR}" # Secure directory permissions

# --- Cloudflare API: Generate and Deploy Origin Certificate ---
show_progress "Attempting to generate Cloudflare Origin Certificate via API"

# Prepare JSON payload for API request (includes wildcard and root domain for flexibility)
# Alternatively, list specific subdomains: "\"${DATABASE_SUBDOMAIN}\", \"${DASHBOARD_SUBDOMAIN}\""
# Using wildcard + root is often easier. Cloudflare might auto-include root if wildcard is used. Check their behavior.
JSON_PAYLOAD=$(cat <<EOF
{
  "hostnames": ["*.${DOMAIN}", "${DOMAIN}"],
  "requested_validity": 5475,
  "request_type": "origin-rsa"
}
EOF
)

# Make the API call
API_RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/certificates" \
     -H "X-Auth-Email: ${CF_EMAIL}" \
     -H "X-Auth-Key: ${CF_API_KEY}" \
     -H "Content-Type: application/json" \
     --data "${JSON_PAYLOAD}")

# Check if the API call was successful and extract data using jq
if echo "${API_RESPONSE}" | jq -e '.success == true' > /dev/null; then
    log_success "Cloudflare API call successful."

    CERTIFICATE=$(echo "${API_RESPONSE}" | jq -r '.result.certificate')
    PRIVATE_KEY=$(echo "${API_RESPONSE}" | jq -r '.result.private_key')
    CERT_ID=$(echo "${API_RESPONSE}" | jq -r '.result.id') # Optional: store ID if needed later

    if [ -z "$CERTIFICATE" ] || [ "$CERTIFICATE" == "null" ] || [ -z "$PRIVATE_KEY" ] || [ "$PRIVATE_KEY" == "null" ]; then
         log_error "Failed to extract certificate or private key from API response."
         log_error "Response: ${API_RESPONSE}"
         exit 1
    fi

    log_info "Saving Origin Certificate to ${CERT_FILE}"
    echo "${CERTIFICATE}" > "${CERT_FILE}"

    log_info "Saving Private Key to ${KEY_FILE}"
    echo "${PRIVATE_KEY}" > "${KEY_FILE}"

    log_info "Setting secure permissions for certificate and key"
    chmod 644 "${CERT_FILE}"
    chmod 600 "${KEY_FILE}"
    chown root:root "${SSL_CERT_DIR}"/*

    log_success "Cloudflare Origin Certificate and Key deployed successfully."
else
    log_error "Cloudflare API call failed."
    log_error "Please check your Cloudflare Email/API Key and domain settings."
    log_error "API Response: ${API_RESPONSE}"
    # Clean up potentially created directory if API failed early
    rm -rf "${SSL_CERT_DIR}"
    exit 1
fi
# Clear sensitive variable from memory (basic measure)
unset CF_API_KEY CF_EMAIL

# --- Configure Nginx for HTTPS (using the generated certs) ---
show_progress "Creating Nginx configurations using generated certificates"

# Nginx config for database subdomain (HTTPS)
cat > /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} << EOF
server {
    listen 80;
    server_name ${DATABASE_SUBDOMAIN};
    return 301 https://\$host\$request_uri; # Redirect HTTP to HTTPS
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DATABASE_SUBDOMAIN};

    ssl_certificate ${CERT_FILE};       # Use the generated cert
    ssl_certificate_key ${KEY_FILE};    # Use the generated key

    # Recommended SSL settings (unchanged)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    location / {
        proxy_pass http://localhost:8086;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

# Nginx config for dashboard subdomain (HTTPS)
cat > /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN} << EOF
server {
    listen 80;
    server_name ${DASHBOARD_SUBDOMAIN};
    return 301 https://\$host\$request_uri; # Redirect HTTP to HTTPS
}
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DASHBOARD_SUBDOMAIN};

    ssl_certificate ${CERT_FILE};       # Use the generated cert
    ssl_certificate_key ${KEY_FILE};    # Use the generated key

    # Recommended SSL settings (unchanged)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host;
    }
}
EOF

# Enable Nginx configurations
show_progress "Enabling Nginx configurations"
ln -sf /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} /etc/nginx/sites-enabled/
ln -sf /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN} /etc/nginx/sites-enabled/

# Remove default Nginx site if it exists
rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration (SHOULD PASS NOW)
show_progress "Testing Nginx configuration"
if nginx -t; then
    log_success "Nginx configuration test successful."
else
    log_error "Nginx configuration test failed. Please check logs and configs."
    log_error "Files: /etc/nginx/sites-available/${DATABASE_SUBDOMAIN}, /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN}"
    log_error "Check if certificate files exist and have correct permissions: ${CERT_FILE}, ${KEY_FILE}"
    exit 1
fi

# Restart/Enable Nginx
show_progress "Restarting and enabling Nginx service"
systemctl restart nginx
systemctl enable nginx

# Configure Firewall
show_progress "Configuring firewall (UFW)"
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP (for redirection)
ufw allow 443/tcp  # HTTPS
ufw --force enable # Enable UFW non-interactively
log_success "Firewall configured and enabled."

# --- Final Instructions ---
echo -e "\n${BOLD}${GREEN}"
echo "┌─────────────────────────────────────────────────┐"
echo "│         SETUP SCRIPT FINISHED (Automated)         │"
echo "└─────────────────────────────────────────────────┘"
echo -e "${NC}"

echo -e "${CYAN}SUMMARY & NEXT STEPS:${NC}\n"
echo -e "${BOLD}1. Cloudflare Configuration:${NC}"
echo -e "   - Log in to your Cloudflare account for the domain '${BOLD}${DOMAIN}${NC}'."
echo -e "   - Ensure these DNS A records exist and are set to ${BOLD}Proxied (Orange Cloud)${NC}:"
echo -e "     - Type: ${BOLD}A${NC}, Name: ${BOLD}database${NC}, Content: ${BOLD}${SERVER_IP}${NC}"
echo -e "     - Type: ${BOLD}A${NC}, Name: ${BOLD}dashboard${NC}, Content: ${BOLD}${SERVER_IP}${NC}"
echo -e "   - Navigate to the ${BOLD}SSL/TLS -> Overview${NC} section."
echo -e "   - Ensure the encryption mode is set to: ${BOLD}Full (strict)${NC}."
echo -e "   - (Optional) Verify the new Origin Certificate under ${BOLD}SSL/TLS -> Origin Server${NC}."
echo -e ""

echo -e "${BOLD}2. Access Your Services (after DNS propagation):${NC}"
echo -e "   - InfluxDB API: ${GREEN}https://${DATABASE_SUBDOMAIN}${NC}"
echo -e "   - Grafana UI:   ${GREEN}https://${DASHBOARD_SUBDOMAIN}${NC}"
echo -e "     ${YELLOW}Default Grafana login: admin / admin (CHANGE THIS IMMEDIATELY!)${NC}"
echo -e ""

echo -e "${BOLD}3. Secure InfluxDB:${NC} (Recommended)"
echo -e "   - Run: ${CYAN}influx${NC}"
echo -e "   - Inside influx shell: ${CYAN}CREATE USER myadmin WITH PASSWORD 'YourVerySecurePassword' WITH ALL PRIVILEGES${NC}"
echo -e "   - Then type: ${CYAN}exit${NC}"
echo -e "   - Edit config: ${CYAN}sudo nano /etc/influxdb/influxdb.conf${NC} -> Find [http] -> Set ${BOLD}auth-enabled = true${NC}"
echo -e "   - Restart: ${CYAN}sudo systemctl restart influxdb${NC}"
echo -e "   - ${YELLOW}Update Grafana datasource with credentials.${NC}"
echo -e ""

echo -e "${BOLD}4. Secure Grafana:${NC}"
echo -e "   - Log in to Grafana at ${GREEN}https://${DASHBOARD_SUBDOMAIN}${NC} with ${YELLOW}admin / admin${NC}."
echo -e "   - ${RED}IMMEDIATELY change the admin password${NC}."
echo -e "   - Consider disabling anonymous access/sign-up in ${CYAN}sudo nano /etc/grafana/grafana.ini${NC}."
echo -e ""

echo -e "${GREEN}Automated setup complete. Enjoy your secured InfluxDB and Grafana!${NC}"
