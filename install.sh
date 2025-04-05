#!/bin/bash

# Enhanced InfluxDB and Grafana Setup Script for Amazon Lightsail
# Uses Cloudflare Origin Certificates for HTTPS (Manual Cert Installation Required)
# Includes fallback for manual IPv4 input if auto-detection fails.
# Usage: sudo bash <(curl -Ls https://your-raw-script-url.com/install-cf-origin-manual-ip.sh) # Replace with your URL

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
echo "│      Using Cloudflare Origin Certificates (Manual)     │"
echo "│         + Manual IP Fallback Support                 │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# --- Pre-flight Checks ---
if [ "$EUID" -ne 0 ]; then
  log_error "Please run this script as root or using sudo."
  exit 1
fi

# Check essential commands early, Nginx will be installed later.
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

DATABASE_SUBDOMAIN="database.${DOMAIN}"
DASHBOARD_SUBDOMAIN="dashboard.${DOMAIN}"
SSL_CERT_DIR="/etc/nginx/ssl" # Directory to store certificates
DB_CERT_FILE="${SSL_CERT_DIR}/${DATABASE_SUBDOMAIN}.pem"
DB_KEY_FILE="${SSL_CERT_DIR}/${DATABASE_SUBDOMAIN}.key"
DASH_CERT_FILE="${SSL_CERT_DIR}/${DASHBOARD_SUBDOMAIN}.pem"
DASH_KEY_FILE="${SSL_CERT_DIR}/${DASHBOARD_SUBDOMAIN}.key"

# Get Server Public IPv4 Address (with manual fallback)
show_progress "Fetching Server Public IPv4 Address"
SERVER_IP=$(curl -s --connect-timeout 5 http://169.254.169.254/latest/meta-data/public-ipv4 || curl -4s --connect-timeout 5 ifconfig.me || curl -4s --connect-timeout 5 icanhazip.com || echo "")

# Check if auto-detection failed
if [ -z "$SERVER_IP" ]; then
    log_error "Could not automatically determine the server's public IPv4 address."
    log_warning "This might be due to network restrictions or the metadata service being unavailable."
    log_warning "Please find your server's Public IPv4 address manually (e.g., in your Lightsail console)."

    # Loop until a non-empty IP is entered
    while [ -z "$SERVER_IP" ]; do
        read -p "$(echo -e "${YELLOW}Please manually enter the server's public IPv4 address:${NC} ")" SERVER_IP
        if [ -z "$SERVER_IP" ]; then
            log_warning "Server IP address cannot be empty. Please try again."
        # Basic sanity check for IP format (optional but helpful)
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
echo -e "  ${BLUE}SSL Certificate Dir:${NC} ${SSL_CERT_DIR}"
echo -e "  ${RED}${BOLD}Note:${NC} You will need to MANUALLY generate Cloudflare Origin Certificates and place them in ${SSL_CERT_DIR}.\n"

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
# Note: certbot is NOT installed in this version
apt install -y wget curl gnupg2 apt-transport-https software-properties-common ufw nginx

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

# Configure Nginx for HTTPS (using placeholders for Cloudflare Origin Certs)
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
    # IMPORTANT: You MUST place the Cloudflare Origin Certificate & Key here!
    ssl_certificate ${DB_CERT_FILE};
    ssl_certificate_key ${DB_KEY_FILE};

    # Recommended SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    # Consider adding HSTS header after confirming everything works:
    # add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    location / {
        proxy_pass http://localhost:8086; # Assuming InfluxDB runs on default port
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
    # IMPORTANT: You MUST place the Cloudflare Origin Certificate & Key here!
    ssl_certificate ${DASH_CERT_FILE};
    ssl_certificate_key ${DASH_KEY_FILE};

    # Recommended SSL settings (same as above)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    # Consider adding HSTS header after confirming everything works:
    # add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;

    location / {
        proxy_pass http://localhost:3000; # Assuming Grafana runs on default port
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

# Test Nginx configuration (EXPECTED TO FAIL INITIALLY)
show_progress "Testing Nginx configuration (will likely fail until certificates are placed)"
if ! nginx -t; then
    log_warning "Nginx configuration test failed, which is *expected* at this stage because the SSL certificates are missing."
    log_warning "You will need to place the Cloudflare Origin certificates in ${SSL_CERT_DIR} and then run 'sudo nginx -t' and 'sudo systemctl restart nginx' manually."
else
    # This shouldn't happen unless dummy certs exist, but handle it just in case
    log_success "Nginx configuration test successful (unexpected - did you pre-place certs?)."
fi

# Start and Enable Nginx (even if test fails, we need it running for later restart)
show_progress "Starting and enabling Nginx service"
systemctl start nginx
systemctl enable nginx

# Configure Firewall
show_progress "Configuring firewall (UFW)"
ufw allow 22/tcp   # SSH
ufw allow 80/tcp   # HTTP (for redirection)
ufw allow 443/tcp  # HTTPS
ufw --force enable # Enable UFW non-interactively
log_success "Firewall configured and enabled."

# --- MANUAL STEPS REQUIRED ---
echo -e "\n${BOLD}${YELLOW}!!!!!!!!!!!!!!!!!! IMPORTANT MANUAL STEPS REQUIRED !!!!!!!!!!!!!!!!!!${NC}"
echo -e "${YELLOW}The basic setup is complete, but Nginx requires Cloudflare Origin Certificates to serve HTTPS.${NC}\n"

echo -e "${BOLD}1. Configure Cloudflare DNS:${NC}"
echo -e "   - Log in to your Cloudflare account for the domain '${BOLD}${DOMAIN}${NC}'."
echo -e "   - Add/Update these DNS A records:"
echo -e "     - Type: ${BOLD}A${NC}, Name: ${BOLD}database${NC}, Content: ${BOLD}${SERVER_IP}${NC}, Proxy status: ${BOLD}Proxied (Orange Cloud)${NC}"
echo -e "     - Type: ${BOLD}A${NC}, Name: ${BOLD}dashboard${NC}, Content: ${BOLD}${SERVER_IP}${NC}, Proxy status: ${BOLD}Proxied (Orange Cloud)${NC}"
echo -e "   - Navigate to the ${BOLD}SSL/TLS -> Overview${NC} section."
echo -e "   - Set the encryption mode to: ${BOLD}Full (strict)${NC}. This is crucial for security."
echo -e ""

echo -e "${BOLD}2. Generate Cloudflare Origin Certificates:${NC}"
echo -e "   - In Cloudflare, go to ${BOLD}SSL/TLS -> Origin Server${NC}."
echo -e "   - Click ${BOLD}Create Certificate${NC}."
echo -e "   - Choose '${BOLD}Let Cloudflare generate a private key and a CSR${NC}' (unless you have specific needs)."
echo -e "   - Ensure the hostnames ${BOLD}${DATABASE_SUBDOMAIN}${NC} and ${BOLD}${DASHBOARD_SUBDOMAIN}${NC} are listed (or use a wildcard like *.${DOMAIN} if appropriate)."
echo -e "   - Choose a validity period (e.g., 15 years)."
echo -e "   - Click ${BOLD}Create${NC}."
echo -e ""

echo -e "${BOLD}3. Install Certificates on Your Server:${NC}"
echo -e "   - ${RED}CRITICAL:${NC} Cloudflare will show you the ${BOLD}Origin Certificate${NC} and the ${BOLD}Private Key${NC}. Copy each one."
echo -e "   - ${YELLOW}You MUST save the Private Key now, Cloudflare will not show it again.${NC}"
echo -e "   - Connect to your Lightsail server via SSH."
echo -e "   - Create/Edit the certificate file for the database:"
echo -e "     ${CYAN}sudo nano ${DB_CERT_FILE}${NC}"
echo -e "     Paste the entire ${BOLD}Origin Certificate${NC} (including -----BEGIN/END CERTIFICATE----- lines) into this file. Save and close (Ctrl+X, Y, Enter)."
echo -e "   - Create/Edit the key file for the database:"
echo -e "     ${CYAN}sudo nano ${DB_KEY_FILE}${NC}"
echo -e "     Paste the entire ${BOLD}Private Key${NC} (including -----BEGIN/END PRIVATE KEY----- lines) into this file. Save and close."
echo -e "   - Create/Edit the certificate file for the dashboard (paste the SAME Origin Certificate):"
echo -e "     ${CYAN}sudo nano ${DASH_CERT_FILE}${NC}"
echo -e "     Paste the same ${BOLD}Origin Certificate${NC} again. Save and close."
echo -e "   - Create/Edit the key file for the dashboard (paste the SAME Private Key):"
echo -e "     ${CYAN}sudo nano ${DASH_KEY_FILE}${NC}"
echo -e "     Paste the same ${BOLD}Private Key${NC} again. Save and close."
echo -e ""
echo -e "   - ${BOLD}Set Secure Permissions:${NC}"
echo -e "     ${CYAN}sudo chmod 644 ${DB_CERT_FILE} ${DASH_CERT_FILE}${NC}"
echo -e "     ${CYAN}sudo chmod 600 ${DB_KEY_FILE} ${DASH_KEY_FILE}${NC}"
echo -e "     ${CYAN}sudo chown root:root ${SSL_CERT_DIR}/*${NC} (Ensure ownership is root)"
echo -e ""

echo -e "${BOLD}4. Test and Restart Nginx:${NC}"
echo -e "   - After placing the certificate and key files, test the Nginx configuration:"
echo -e "     ${CYAN}sudo nginx -t${NC}"
echo -e "   - If the test is successful, restart Nginx to apply the changes:"
echo -e "     ${CYAN}sudo systemctl restart nginx${NC}"
echo -e "   - If the test fails, review the error message and double-check the certificate/key files and Nginx configuration."
echo -e ""

# --- Final Instructions ---
echo -e "\n${BOLD}${GREEN}"
echo "┌─────────────────────────────────────────────────┐"
echo "│      SETUP SCRIPT FINISHED (Manual Steps Req.)    │"
echo "└─────────────────────────────────────────────────┘"
echo -e "${NC}"

echo -e "${CYAN}SUMMARY & NEXT STEPS (After Manual Cert Installation & Nginx Restart):${NC}\n"
echo -e "${BOLD}1. Cloudflare Settings:${NC}"
echo -e "   - Ensure DNS A records for '${BOLD}database${NC}' and '${BOLD}dashboard${NC}' point to ${BOLD}${SERVER_IP}${NC}."
echo -e "   - Ensure Proxy status is ${BOLD}Proxied (Orange Cloud)${NC}."
echo -e "   - Ensure SSL/TLS Encryption mode is ${BOLD}Full (strict)${NC}."
echo -e ""

echo -e "${BOLD}2. Access Your Services:${NC}"
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

echo -e "${GREEN}Once you complete the manual certificate steps, enjoy your secured setup!${NC}"
