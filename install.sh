#!/bin/bash

# Enhanced InfluxDB and Grafana Setup Script for Amazon Lightsail
# Automatically generates Cloudflare Origin Certificates via Cloudflare API
# Includes improved IPv4 detection methods
# Usage: sudo bash <(curl -Ls https://your-raw-script-url.com/install-cf-auto.sh) # Replace with your URL

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

get_server_ip() {
    # Try multiple IP detection methods in sequence
    local ip=""
    # Methods in order of preference:
    
    # 1. AWS Metadata service (for Lightsail/EC2)
    ip=$(curl -s --connect-timeout 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "")
    
    # 2. Multiple external IP detection services with short timeouts
    if [ -z "$ip" ]; then
        ip=$(curl -4s --connect-timeout 3 https://ifconfig.me 2>/dev/null || echo "")
    fi
    
    if [ -z "$ip" ]; then
        ip=$(curl -4s --connect-timeout 3 https://icanhazip.com 2>/dev/null || echo "")
    fi
    
    if [ -z "$ip" ]; then
        ip=$(curl -4s --connect-timeout 3 https://api.ipify.org 2>/dev/null || echo "")
    fi
    
    if [ -z "$ip" ]; then
        ip=$(curl -4s --connect-timeout 3 https://ipinfo.io/ip 2>/dev/null || echo "")
    fi
    
    # 3. Try to extract from 'ip' command if available
    if [ -z "$ip" ] && command -v ip &>/dev/null; then
        # Get the default route interface
        local interface=$(ip route | grep default | awk '{print $5}' | head -n1)
        if [ -n "$interface" ]; then
            # Get the IP from that interface (non-loopback, IPv4)
            ip=$(ip addr show dev "$interface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1)
        fi
    fi
    
    # 4. Try ifconfig as last resort if installed
    if [ -z "$ip" ] && command -v ifconfig &>/dev/null; then
        # Extract first non-localhost IPv4 address
        ip=$(ifconfig | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1)
    fi
    
    echo "$ip"
}

# --- Header ---
echo -e "${BOLD}${MAGENTA}"
echo "┌────────────────────────────────────────────────────────┐"
echo "│     InfluxDB + Grafana + Nginx Setup (Lightsail)       │"
echo "│         Automatic Cloudflare Certificate Setup         │"
echo "│          & Improved IP Address Detection               │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# --- Pre-flight Checks ---
if [ "$EUID" -ne 0 ]; then
  log_error "Please run this script as root or using sudo."
  exit 1
fi

# Check essential commands early
for cmd in curl wget gpg apt ufw systemctl; do
    if ! command -v $cmd &> /dev/null; then
        log_error "$cmd command not found. Please install it or ensure it's in the PATH."
        exit 1
    fi
done

# --- User Input ---
log_info "Gathering required information..."

while [ -z "$DOMAIN" ]; do
    read -p "$(echo -e "${YELLOW}Enter your main domain (e.g., example.com):${NC} ")" DOMAIN
    if [[ ! "$DOMAIN" == *"."* ]]; then
        log_warning "Invalid domain format. Please enter a valid domain (e.g., example.com)."
        DOMAIN=""
    fi
done

# Cloudflare API credentials
while [ -z "$CF_EMAIL" ]; do
    read -p "$(echo -e "${YELLOW}Enter your Cloudflare account email:${NC} ")" CF_EMAIL
    if [[ ! "$CF_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_warning "Invalid email format. Please enter a valid email address."
        CF_EMAIL=""
    fi
done

while [ -z "$CF_API_KEY" ]; do
    read -p "$(echo -e "${YELLOW}Enter your Cloudflare Global API Key:${NC} ")" CF_API_KEY
    if [ -z "$CF_API_KEY" ]; then
        log_warning "API Key cannot be empty."
    fi
done

# Get Zone ID for the domain
show_progress "Fetching Cloudflare Zone ID for $DOMAIN"
CF_ZONE_ID=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json" | grep -Po '(?<="id":")[^"]*' | head -1)

if [ -z "$CF_ZONE_ID" ]; then
    log_error "Could not fetch Zone ID for $DOMAIN. Please verify your domain is registered with Cloudflare and your API credentials are correct."
    exit 1
fi

log_success "Found Cloudflare Zone ID: $CF_ZONE_ID"

DATABASE_SUBDOMAIN="database.${DOMAIN}"
DASHBOARD_SUBDOMAIN="dashboard.${DOMAIN}"
SSL_CERT_DIR="/etc/nginx/ssl" # Directory to store certificates
DB_CERT_FILE="${SSL_CERT_DIR}/${DATABASE_SUBDOMAIN}.pem"
DB_KEY_FILE="${SSL_CERT_DIR}/${DATABASE_SUBDOMAIN}.key"
DASH_CERT_FILE="${SSL_CERT_DIR}/${DASHBOARD_SUBDOMAIN}.pem"
DASH_KEY_FILE="${SSL_CERT_DIR}/${DASHBOARD_SUBDOMAIN}.key"

# Get Server Public IPv4 Address with improved detection
show_progress "Detecting Server Public IPv4 Address"
SERVER_IP=$(get_server_ip)

# Check if all detection methods failed
if [ -z "$SERVER_IP" ]; then
    log_error "All automatic IP detection methods failed."
    log_warning "Please find your server's Public IPv4 address manually (e.g., in your Lightsail console)."

    # Loop until a non-empty IP is entered
    while [ -z "$SERVER_IP" ]; do
        read -p "$(echo -e "${YELLOW}Please manually enter the server's public IPv4 address:${NC} ")" SERVER_IP
        if [ -z "$SERVER_IP" ]; then
            log_warning "Server IP address cannot be empty. Please try again."
        # Basic sanity check for IP format
        elif [[ ! "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            log_warning "The input '$SERVER_IP' doesn't look like a valid IPv4 address. Please check and re-enter."
            SERVER_IP="" # Clear invalid input
        fi
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
echo -e "  ${BLUE}Cloudflare Zone ID:${NC} ${CF_ZONE_ID}"
echo -e "  ${BLUE}SSL Certificate Dir:${NC} ${SSL_CERT_DIR}\n"

read -p "$(echo -e "${YELLOW}Proceed with installation? (y/n):${NC} ")" confirm
if [[ ! $confirm =~ ^[yY]([eE][sS])?$ ]]; then
  log_warning "Installation cancelled by user."
  exit 1
fi

# --- Installation and Configuration ---

# Update System
show_progress "Updating system packages"
apt update && apt upgrade -y

# Install Essential Tools & Nginx
show_progress "Installing Nginx and other essential tools"
apt install -y wget curl gnupg2 apt-transport-https software-properties-common ufw nginx jq openssl

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

# Create Cloudflare DNS A records
show_progress "Creating/Updating Cloudflare DNS Records"

# Function to create or update DNS record
create_or_update_dns_record() {
    local name=$1
    local content=$2
    
    # Check if record exists
    local record_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?type=A&name=$name.$DOMAIN" \
         -H "X-Auth-Email: $CF_EMAIL" \
         -H "X-Auth-Key: $CF_API_KEY" \
         -H "Content-Type: application/json" | jq -r '.result[0].id')
    
    if [ "$record_id" != "null" ] && [ -n "$record_id" ]; then
        # Update existing record
        curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$record_id" \
             -H "X-Auth-Email: $CF_EMAIL" \
             -H "X-Auth-Key: $CF_API_KEY" \
             -H "Content-Type: application/json" \
             --data "{\"type\":\"A\",\"name\":\"$name\",\"content\":\"$content\",\"ttl\":1,\"proxied\":true}" | jq .
        log_success "Updated DNS A record for $name.$DOMAIN"
    else
        # Create new record
        curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
             -H "X-Auth-Email: $CF_EMAIL" \
             -H "X-Auth-Key: $CF_API_KEY" \
             -H "Content-Type: application/json" \
             --data "{\"type\":\"A\",\"name\":\"$name\",\"content\":\"$content\",\"ttl\":1,\"proxied\":true}" | jq .
        log_success "Created DNS A record for $name.$DOMAIN"
    fi
}

# Create/Update database and dashboard DNS A records
create_or_update_dns_record "database" "$SERVER_IP"
create_or_update_dns_record "dashboard" "$SERVER_IP"

# Set Cloudflare SSL/TLS mode to Full (Strict)
show_progress "Setting Cloudflare SSL/TLS mode to Full (Strict)"
curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/settings/ssl" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"value":"strict"}' | jq .
log_success "Set SSL/TLS mode to Full (Strict)"

# Prepare SSL Directory
show_progress "Creating SSL certificate directory: ${SSL_CERT_DIR}"
mkdir -p "${SSL_CERT_DIR}"
chmod 700 "${SSL_CERT_DIR}" # Secure directory permissions

# Generate CSR and Private Key for Origin Certificate
show_progress "Generating private key and CSR for Origin Certificate"

# Generate private key
openssl genrsa -out "${SSL_CERT_DIR}/origin_private.key" 2048
log_success "Generated private key"

# Create CSR configuration file
cat > "${SSL_CERT_DIR}/csr.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${DOMAIN}

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = ${DOMAIN}
DNS.2 = *.${DOMAIN}
DNS.3 = ${DATABASE_SUBDOMAIN}
DNS.4 = ${DASHBOARD_SUBDOMAIN}
EOF

# Generate CSR
openssl req -new -key "${SSL_CERT_DIR}/origin_private.key" -out "${SSL_CERT_DIR}/origin.csr" -config "${SSL_CERT_DIR}/csr.conf"

# Properly format CSR for Cloudflare API (this is the fixed part)
CSR=$(cat "${SSL_CERT_DIR}/origin.csr" | grep -v "BEGIN CERTIFICATE REQUEST" | grep -v "END CERTIFICATE REQUEST" | tr -d '\n\r')

log_success "Generated CSR"

# Request Origin Certificate from Cloudflare
show_progress "Requesting Origin Certificate from Cloudflare API"
CERT_RESPONSE=$(curl -s -X POST "https://api.cloudflare.com/client/v4/certificates" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json" \
     --data "{\"hostnames\":[\"${DOMAIN}\",\"*.${DOMAIN}\",\"${DATABASE_SUBDOMAIN}\",\"${DASHBOARD_SUBDOMAIN}\"],\"requested_validity\":5475,\"request_type\":\"origin-rsa\",\"csr\":\"${CSR}\"}")

# Check if certificate creation was successful
if echo "$CERT_RESPONSE" | jq -e '.success == true' > /dev/null; then
    log_success "Origin Certificate successfully created"
    
    # Extract and save the certificate
    echo "$CERT_RESPONSE" | jq -r '.result.certificate' > "${SSL_CERT_DIR}/origin_certificate.pem"
    
    # Copy the certificate and key to the required locations
    cp "${SSL_CERT_DIR}/origin_certificate.pem" "$DB_CERT_FILE"
    cp "${SSL_CERT_DIR}/origin_certificate.pem" "$DASH_CERT_FILE"
    cp "${SSL_CERT_DIR}/origin_private.key" "$DB_KEY_FILE"
    cp "${SSL_CERT_DIR}/origin_private.key" "$DASH_KEY_FILE"
    
    # Set secure permissions
    chmod 644 "$DB_CERT_FILE" "$DASH_CERT_FILE"
    chmod 600 "$DB_KEY_FILE" "$DASH_KEY_FILE"
    
    log_success "Origin Certificate and Private Key deployed to required locations"
else
    log_error "Failed to create Origin Certificate. Response: $(echo "$CERT_RESPONSE" | jq -r '.errors')"
    
    # Debug output - this can help diagnose the issue further if it still fails
    echo "DEBUG: CSR contents (should not be empty):"
    echo "$CSR" | head -c 50
    echo "... (truncated for display)"
    echo "DEBUG: Full error response:"
    echo "$CERT_RESPONSE"
    
    # Fallback procedure suggestion
    echo ""
    log_warning "FALLBACK OPTION: Create Origin Certificate manually from Cloudflare dashboard:"
    echo "1. Go to Cloudflare dashboard → SSL/TLS → Origin Server"
    echo "2. Click 'Create Certificate'"
    echo "3. Add hostnames: ${DOMAIN}, *.${DOMAIN}, ${DATABASE_SUBDOMAIN}, ${DASHBOARD_SUBDOMAIN}"
    echo "4. Download certificate and key, then place them in ${SSL_CERT_DIR}/"
    echo "5. Continue setup manually by configuring Nginx"
    
    exit 1
fi

# Configure Nginx for HTTPS
show_progress "Creating Nginx configurations for ${DATABASE_SUBDOMAIN} and ${DASHBOARD_SUBDOMAIN}"

# Nginx config for database subdomain (HTTPS)
cat > /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} << EOF
server {
    listen 80;
    server_name ${DATABASE_SUBDOMAIN};
    # Redirect all HTTP traffic to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DATABASE_SUBDOMAIN};

    # --- SSL Configuration ---
    ssl_certificate ${DB_CERT_FILE};
    ssl_certificate_key ${DB_KEY_FILE};

    # Recommended SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    location / {
        proxy_pass http://localhost:8086; # InfluxDB default port
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
    # Redirect all HTTP traffic to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${DASHBOARD_SUBDOMAIN};

    # --- SSL Configuration ---
    ssl_certificate ${DASH_CERT_FILE};
    ssl_certificate_key ${DASH_KEY_FILE};

    # Recommended SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    location / {
        proxy_pass http://localhost:3000; # Grafana default port
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

# Test Nginx configuration 
show_progress "Testing Nginx configuration"
if ! nginx -t; then
    log_error "Nginx configuration test failed. Please check the error messages above."
    exit 1
else
    log_success "Nginx configuration test successful."
fi

# Start and Enable Nginx
show_progress "Starting and enabling Nginx service"
systemctl restart nginx
systemctl enable nginx

# Configure Firewall
show_progress "Configuring firewall (UFW)"
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP (for redirection)
ufw allow 443/tcp  # HTTPS
ufw --force enable # Enable UFW non-interactively
log_success "Firewall configured and enabled."

# --- Final Configuration ---
echo -e "\n${BOLD}${GREEN}"
echo "┌─────────────────────────────────────────────────┐"
echo "│        SETUP SCRIPT COMPLETED SUCCESSFULLY        │"
echo "└─────────────────────────────────────────────────┘"
echo -e "${NC}"

echo -e "${CYAN}SUMMARY & NEXT STEPS:${NC}\n"
echo -e "${BOLD}1. Access Your Services:${NC}"
echo -e "   - InfluxDB API: ${GREEN}https://${DATABASE_SUBDOMAIN}${NC}"
echo -e "   - Grafana UI:   ${GREEN}https://${DASHBOARD_SUBDOMAIN}${NC}"
echo -e "     ${YELLOW}Default Grafana login: admin / admin (CHANGE THIS IMMEDIATELY!)${NC}"
echo -e ""

echo -e "${BOLD}2. Secure InfluxDB:${NC} (Recommended)"
echo -e "   - Run: ${CYAN}influx${NC}"
echo -e "   - Inside influx shell: ${CYAN}CREATE USER myadmin WITH PASSWORD 'YourVerySecurePassword' WITH ALL PRIVILEGES${NC}"
echo -e "   - Then type: ${CYAN}exit${NC}"
echo -e "   - Edit config: ${CYAN}sudo nano /etc/influxdb/influxdb.conf${NC} -> Find [http] -> Set ${BOLD}auth-enabled = true${NC}"
echo -e "   - Restart: ${CYAN}sudo systemctl restart influxdb${NC}"
echo -e "   - ${YELLOW}Update Grafana datasource with credentials.${NC}"
echo -e ""

echo -e "${BOLD}3. Secure Grafana:${NC}"
echo -e "   - Log in to Grafana at ${GREEN}https://${DASHBOARD_SUBDOMAIN}${NC} with ${YELLOW}admin / admin${NC}."
echo -e "   - ${RED}IMMEDIATELY change the admin password${NC}."
echo -e "   - Consider disabling anonymous access/sign-up in ${CYAN}sudo nano /etc/grafana/grafana.ini${NC}."
echo -e ""

echo -e "${GREEN}Your setup is complete and ready to use! Everything has been configured automatically.${NC}"
echo -e "${YELLOW}NOTE: If you encounter any SSL/TLS issues, you may need to wait a few minutes for Cloudflare to fully propagate your DNS and certificate changes.${NC}"
