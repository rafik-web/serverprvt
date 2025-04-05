#!/bin/bash

# Enhanced InfluxDB and Grafana Setup Script for Amazon Lightsail
# Automatically generates Cloudflare Origin Certificates via Cloudflare API
# Includes improved IPv4 detection methods
# *** ALTERNATIVE APPROACH 2: Using temporary file for curl --data ***
# *** SECURITY WARNING: API Key input is VISIBLE as requested ***
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

# --- Cleanup Function ---
# This function will be called on script exit to remove temporary files
cleanup() {
    if [[ -n "$TMP_PAYLOAD_FILE" && -f "$TMP_PAYLOAD_FILE" ]]; then
        log_info "Cleaning up temporary payload file: $TMP_PAYLOAD_FILE"
        rm -f "$TMP_PAYLOAD_FILE"
    fi
}
# Register the cleanup function to run on EXIT signal
trap cleanup EXIT

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
    local ip=""
    ip=$(curl -s --connect-timeout 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "")
    if [ -z "$ip" ]; then ip=$(curl -4s --connect-timeout 3 https://ifconfig.me 2>/dev/null || echo ""); fi
    if [ -z "$ip" ]; then ip=$(curl -4s --connect-timeout 3 https://icanhazip.com 2>/dev/null || echo ""); fi
    if [ -z "$ip" ]; then ip=$(curl -4s --connect-timeout 3 https://api.ipify.org 2>/dev/null || echo ""); fi
    if [ -z "$ip" ]; then ip=$(curl -4s --connect-timeout 3 https://ipinfo.io/ip 2>/dev/null || echo ""); fi
    if [ -z "$ip" ] && command -v ip &>/dev/null; then
        local interface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -n1)
        if [ -n "$interface" ]; then ip=$(ip -4 addr show dev "$interface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1); fi
    fi
    if [ -z "$ip" ] && command -v ifconfig &>/dev/null; then ip=$(ifconfig | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1); fi
    echo "$ip"
}

# --- Header ---
echo -e "${BOLD}${MAGENTA}"
echo "┌────────────────────────────────────────────────────────┐"
echo "│     InfluxDB + Grafana + Nginx Setup (Lightsail)       │"
echo "│         Automatic Cloudflare Certificate Setup         │"
echo "│    *** Using Temp File for API + Visible API Key ***   │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# --- Pre-flight Checks ---
if [ "$EUID" -ne 0 ]; then log_error "Please run this script as root or using sudo."; exit 1; fi
for cmd in curl wget gpg apt ufw systemctl openssl jq mktemp; do
    if ! command -v $cmd &>/dev/null; then
        log_error "$cmd command not found. Trying to install..."
        apt update && apt install -y $cmd || { log_error "Failed to install $cmd. Please install it manually and rerun."; exit 1; }
        log_success "$cmd installed."
    fi
done

# --- User Input ---
log_info "Gathering required information..."
while [ -z "$DOMAIN" ]; do
    read -p "$(echo -e "${YELLOW}Enter your main domain (e.g., example.com):${NC} ")" DOMAIN
    if [[ ! "$DOMAIN" == *"."* ]]; then log_warning "Invalid domain format."; DOMAIN=""; fi
done
while [ -z "$CF_EMAIL" ]; do
    read -p "$(echo -e "${YELLOW}Enter your Cloudflare account email:${NC} ")" CF_EMAIL
    if [[ ! "$CF_EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then log_warning "Invalid email format."; CF_EMAIL=""; fi
done
while [ -z "$CF_API_KEY" ]; do
    # *** MODIFICATION: Removed -s to make API key visible during input ***
    # *** SECURITY RISK: Only use this in a secure, private environment! ***
    read -p "$(echo -e "${YELLOW}${BOLD}Enter Cloudflare Global API Key (VISIBLE INPUT):${NC} ")" CF_API_KEY
    echo # Add a newline
    if [ -z "$CF_API_KEY" ]; then log_warning "API Key cannot be empty."; fi
done

# Get Zone ID
show_progress "Fetching Cloudflare Zone ID for $DOMAIN"
CF_ZONE_ID_JSON=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN&status=active" \
     -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_API_KEY" -H "Content-Type: application/json")
CF_ZONE_ID=$(echo "$CF_ZONE_ID_JSON" | jq -r '.result[0].id // empty')
if [ -z "$CF_ZONE_ID" ]; then
    log_error "Could not fetch Zone ID for $DOMAIN. Verify domain/credentials."
    API_ERRORS=$(echo "$CF_ZONE_ID_JSON" | jq -r '.errors // [] | .[] | "\(.code): \(.message)"' 2>/dev/null)
    if [ -n "$API_ERRORS" ]; then log_error "Cloudflare API Errors:\n${RED}${API_ERRORS}${NC}"; fi
    exit 1
fi
log_success "Found Cloudflare Zone ID: $CF_ZONE_ID"

DATABASE_SUBDOMAIN="database.${DOMAIN}"
DASHBOARD_SUBDOMAIN="dashboard.${DOMAIN}"
SSL_CERT_DIR="/etc/nginx/ssl"
DB_CERT_FILE="${SSL_CERT_DIR}/${DATABASE_SUBDOMAIN}.pem"
DB_KEY_FILE="${SSL_CERT_DIR}/${DATABASE_SUBDOMAIN}.key"
DASH_CERT_FILE="${SSL_CERT_DIR}/${DASHBOARD_SUBDOMAIN}.pem"
DASH_KEY_FILE="${SSL_CERT_DIR}/${DASHBOARD_SUBDOMAIN}.key}"

# Get Server IP
show_progress "Detecting Server Public IPv4 Address"
SERVER_IP=$(get_server_ip)
if [ -z "$SERVER_IP" ]; then
    log_error "Automatic IP detection failed."
    while [ -z "$SERVER_IP" ]; do
        read -p "$(echo -e "${YELLOW}Please manually enter the server's public IPv4 address:${NC} ")" SERVER_IP
        if [[ ! "$SERVER_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then log_warning "Invalid IPv4 format."; SERVER_IP=""; fi
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
echo -e "  ${BLUE}SSL Certificate Dir:${NC} ${SSL_CERT_DIR}"
echo -e "  ${RED}${BOLD}API Key input was visible (Security Warning)${NC}\n"
read -p "$(echo -e "${YELLOW}Proceed with installation? (y/n):${NC} ")" confirm
if [[ ! $confirm =~ ^[yY]([eE][sS])?$ ]]; then log_warning "Installation cancelled."; exit 1; fi

# --- Installation ---
show_progress "Updating system and installing tools"
apt update && apt upgrade -y
apt install -y wget curl gnupg2 apt-transport-https software-properties-common ufw nginx jq openssl mktemp influxdb grafana

show_progress "Starting InfluxDB & Grafana"
systemctl enable --now influxdb
systemctl enable --now grafana-server
log_success "InfluxDB & Grafana installed and started."

# --- Cloudflare DNS & SSL Settings ---
show_progress "Configuring Cloudflare DNS and SSL settings"
create_or_update_dns_record() {
    local name=$1 content=$2 full_hostname="${name}.${DOMAIN}" record_id current_ip
    log_info "Checking DNS record for ${full_hostname}..."
    local get_record_response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?type=A&name=$full_hostname" \
         -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_API_KEY" -H "Content-Type: application/json")
    record_id=$(echo "$get_record_response" | jq -r '.result[0].id // empty')
    current_ip=$(echo "$get_record_response" | jq -r '.result[0].content // empty')
    if [ -n "$record_id" ]; then
        if [ "$current_ip" == "$content" ]; then log_success "DNS A record for ${full_hostname} OK (${content})."; else
            log_info "Updating DNS A record for ${full_hostname} -> ${content}..."
            local update_response=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$record_id" \
                 -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_API_KEY" -H "Content-Type: application/json" \
                 --data "{\"type\":\"A\",\"name\":\"$full_hostname\",\"content\":\"$content\",\"ttl\":1,\"proxied\":true}")
            if echo "$update_response" | jq -e '.success == true' > /dev/null; then log_success "Updated DNS A record for ${full_hostname}"; else log_error "Failed to update DNS record for ${full_hostname}:\n$(echo "$update_response" | jq .)"; fi
        fi
    else
        log_info "Creating new DNS A record for ${full_hostname} -> ${content}..."
        local create_response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
             -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_API_KEY" -H "Content-Type: application/json" \
             --data "{\"type\":\"A\",\"name\":\"$full_hostname\",\"content\":\"$content\",\"ttl\":1,\"proxied\":true}")
        if echo "$create_response" | jq -e '.success == true' > /dev/null; then log_success "Created DNS A record for ${full_hostname}"; else log_error "Failed to create DNS record for ${full_hostname}:\n$(echo "$create_response" | jq .)"; fi
    fi
}
create_or_update_dns_record "database" "$SERVER_IP"
create_or_update_dns_record "dashboard" "$SERVER_IP"

# Set SSL/TLS mode
SSL_SETTING_RESPONSE=$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/settings/ssl" \
     -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_API_KEY" -H "Content-Type: application/json" \
     --data '{"value":"strict"}')
if echo "$SSL_SETTING_RESPONSE" | jq -e '.success == true' > /dev/null; then log_success "Set SSL/TLS mode to Full (Strict)"; else log_warning "Failed to set SSL/TLS mode. Check manually. Response:\n$(echo "$SSL_SETTING_RESPONSE" | jq .)"; fi

# --- Generate CSR and Request Origin Certificate ---
show_progress "Preparing for Origin Certificate Request"
mkdir -p "${SSL_CERT_DIR}" && chmod 700 "${SSL_CERT_DIR}"

# Generate Key and CSR Conf
openssl genrsa -out "${SSL_CERT_DIR}/origin_private.key" 2048
log_success "Generated private key: ${SSL_CERT_DIR}/origin_private.key"
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

# Generate CSR file
openssl req -new -key "${SSL_CERT_DIR}/origin_private.key" -out "${SSL_CERT_DIR}/origin.csr" -config "${SSL_CERT_DIR}/csr.conf"
log_success "Generated CSR file: ${SSL_CERT_DIR}/origin.csr"

# --- START OF TEMP FILE Cloudflare API Call ---

# Read the CSR content, preserving internal newlines
RAW_CSR=$(sed '/-BEGIN CERTIFICATE REQUEST-/d;/-END CERTIFICATE REQUEST-/d' "${SSL_CERT_DIR}/origin.csr")
if [ -z "$RAW_CSR" ]; then log_error "Failed to read/process CSR content from ${SSL_CERT_DIR}/origin.csr"; exit 1; fi

# Create a temporary file for the JSON payload
TMP_PAYLOAD_FILE=$(mktemp)
if [ -z "$TMP_PAYLOAD_FILE" ] || [ ! -f "$TMP_PAYLOAD_FILE" ]; then
    log_error "Failed to create temporary file for API payload."
    exit 1
fi
log_info "Created temporary payload file: $TMP_PAYLOAD_FILE"

# Generate JSON payload and write it to the temporary file
jq -n \
    --argjson hosts "[\"${DOMAIN}\",\"*.${DOMAIN}\",\"${DATABASE_SUBDOMAIN}\",\"${DASHBOARD_SUBDOMAIN}\"]" \
    --arg csr "$RAW_CSR" \
    '{hostnames: $hosts, requested_validity: 5475, request_type: "origin-rsa", csr: $csr}' > "$TMP_PAYLOAD_FILE"

# Check if jq succeeded and the file is not empty
if [ $? -ne 0 ] || [ ! -s "$TMP_PAYLOAD_FILE" ]; then
    log_error "Failed to generate JSON payload or write to temporary file."
    exit 1
fi

log_info "JSON payload written to temporary file."
# Optional: View the temp file content for debugging
# log_info "DEBUG: Temp file content:"
# cat "$TMP_PAYLOAD_FILE" | jq .

# Request Origin Certificate from Cloudflare using the temporary file
show_progress "Requesting Origin Certificate from Cloudflare API (using temp file)"
CERT_RESPONSE=$(curl -s -w "\nHTTP_STATUS_CODE:%{http_code}\n" -X POST "https://api.cloudflare.com/client/v4/certificates" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json" \
     --data @"$TMP_PAYLOAD_FILE") # <-- Use @ to read data from the file

# Separate HTTP status code from response body
HTTP_STATUS_CODE=$(echo "$CERT_RESPONSE" | grep "HTTP_STATUS_CODE:" | sed 's/HTTP_STATUS_CODE://')
CERT_RESPONSE_BODY=$(echo "$CERT_RESPONSE" | sed '$d')

# Temporary file is automatically removed by the 'trap cleanup EXIT' function

# --- END OF TEMP FILE Cloudflare API Call ---

# Check certificate creation success
if [ "$HTTP_STATUS_CODE" = "200" ] && echo "$CERT_RESPONSE_BODY" | jq -e '.success == true' > /dev/null; then
    log_success "Origin Certificate successfully created (HTTP $HTTP_STATUS_CODE)"
    echo "$CERT_RESPONSE_BODY" | jq -r '.result.certificate' > "${SSL_CERT_DIR}/origin_certificate.pem"
    if [ ! -s "${SSL_CERT_DIR}/origin_certificate.pem" ]; then
        log_error "Extracted certificate file is empty! API Response:\n$(echo "$CERT_RESPONSE_BODY" | jq .)" >&2
        exit 1
    fi
    log_success "Saved Origin Certificate to ${SSL_CERT_DIR}/origin_certificate.pem"
    # Deploy certificates
    cp "${SSL_CERT_DIR}/origin_certificate.pem" "$DB_CERT_FILE"
    cp "${SSL_CERT_DIR}/origin_certificate.pem" "$DASH_CERT_FILE"
    cp "${SSL_CERT_DIR}/origin_private.key" "$DB_KEY_FILE"
    cp "${SSL_CERT_DIR}/origin_private.key" "$DASH_KEY_FILE"
    chmod 644 "$DB_CERT_FILE" "$DASH_CERT_FILE"
    chmod 600 "$DB_KEY_FILE" "$DASH_KEY_FILE"
    log_success "Origin Certificate and Private Key deployed."
else
    log_error "Failed to create Origin Certificate (HTTP $HTTP_STATUS_CODE)."
    CLOUDFLARE_ERRORS=$(echo "$CERT_RESPONSE_BODY" | jq -r '.errors // [] | .[] | "\(.code): \(.message)"' 2>/dev/null)
    if [ -n "$CLOUDFLARE_ERRORS" ]; then log_error "Cloudflare API Errors:\n${RED}${CLOUDFLARE_ERRORS}${NC}" >&2; else log_error "Could not parse specific errors from API response."; fi
    echo "DEBUG: Raw CSR contents fed to jq (truncated):"
    echo "$RAW_CSR" | head -c 80 && echo "..."
    echo "DEBUG: JSON Payload Sent (from temp file, truncated):"
    # Displaying payload from temp file for debug if needed
    head -c 500 "$TMP_PAYLOAD_FILE" && echo "..."
    echo "DEBUG: Full API response body:"
    echo "$CERT_RESPONSE_BODY" | jq . >&2
    echo ""
    log_warning "FALLBACK OPTION: Create Origin Certificate manually..."
    # Fallback instructions omitted for brevity
    exit 1
fi

# --- Configure Nginx ---
show_progress "Creating Nginx configurations"
# Nginx config for database subdomain
cat > /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} << EOF
server { listen 80; server_name ${DATABASE_SUBDOMAIN}; return 301 https://\$host\$request_uri; }
server {
    listen 443 ssl http2; listen [::]:443 ssl http2; server_name ${DATABASE_SUBDOMAIN};
    access_log /var/log/nginx/${DATABASE_SUBDOMAIN}.access.log; error_log /var/log/nginx/${DATABASE_SUBDOMAIN}.error.log;
    ssl_certificate ${DB_CERT_FILE}; ssl_certificate_key ${DB_KEY_FILE};
    ssl_protocols TLSv1.2 TLSv1.3; ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" always;
    location / { proxy_pass http://localhost:8086; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto \$scheme; }
}
EOF
# Nginx config for dashboard subdomain
cat > /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN} << EOF
server { listen 80; server_name ${DASHBOARD_SUBDOMAIN}; return 301 https://\$host\$request_uri; }
server {
    listen 443 ssl http2; listen [::]:443 ssl http2; server_name ${DASHBOARD_SUBDOMAIN};
    access_log /var/log/nginx/${DASHBOARD_SUBDOMAIN}.access.log; error_log /var/log/nginx/${DASHBOARD_SUBDOMAIN}.error.log;
    ssl_certificate ${DASH_CERT_FILE}; ssl_certificate_key ${DASH_KEY_FILE};
    ssl_protocols TLSv1.2 TLSv1.3; ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" always;
    location / { proxy_pass http://localhost:3000; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; proxy_cache_bypass \$http_upgrade; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto \$scheme; proxy_set_header X-Forwarded-Host \$host; }
}
EOF
log_success "Nginx configuration files created."

# Enable Nginx configurations
show_progress "Enabling Nginx configurations & restarting Nginx"
ln -sf /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} /etc/nginx/sites-enabled/
ln -sf /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN} /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
if ! nginx -t; then log_error "Nginx configuration test failed."; exit 1; fi
systemctl restart nginx && systemctl enable nginx
log_success "Nginx configuration applied and service restarted."

# --- Configure Firewall ---
show_progress "Configuring firewall (UFW)"
ufw allow 22/tcp comment 'SSH'
ufw allow 80/tcp comment 'HTTP->HTTPS Redirect'
ufw allow 443/tcp comment 'HTTPS (Nginx)'
ufw --force enable && ufw status verbose
log_success "Firewall configured and enabled."

# --- Final Steps ---
echo -e "\n${BOLD}${GREEN}┌─────────────────────────────────────────────────┐"
echo -e "│        SETUP SCRIPT COMPLETED SUCCESSFULLY        │"
echo -e "└─────────────────────────────────────────────────┘${NC}"
echo -e "${CYAN}SUMMARY & NEXT STEPS:${NC}\n"
echo -e "${BOLD}1. Access Your Services:${NC}"
echo -e "   - InfluxDB API: ${GREEN}https://${DATABASE_SUBDOMAIN}${NC}"
echo -e "   - Grafana UI:   ${GREEN}https://${DASHBOARD_SUBDOMAIN}${NC} (${YELLOW}Login: admin/admin - CHANGE NOW!${NC})"
echo -e ""
echo -e "${BOLD}2. Secure InfluxDB:${NC} (Highly Recommended)"
echo -e "   Run: ${CYAN}influx${NC} -> ${CYAN}CREATE USER myadmin WITH PASSWORD 'YourSecurePassword' WITH ALL PRIVILEGES${NC} -> ${CYAN}exit${NC}"
echo -e "   Edit: ${CYAN}sudo nano /etc/influxdb/influxdb.conf${NC} -> [http] -> ${BOLD}auth-enabled = true${NC}"
echo -e "   Restart: ${CYAN}sudo systemctl restart influxdb${NC}"
echo -e "   ${YELLOW}Update Grafana datasource with credentials.${NC}"
echo -e ""
echo -e "${BOLD}3. Secure Grafana:${NC}"
echo -e "   Login to ${GREEN}https://${DASHBOARD_SUBDOMAIN}${NC}, ${RED}change admin password immediately.${NC}"
echo -e "   Consider disabling sign-up/anonymous in ${CYAN}sudo nano /etc/grafana/grafana.ini${NC}. Restart: ${CYAN}sudo systemctl restart grafana-server${NC}"
echo -e ""
echo -e "${RED}${BOLD}SECURITY REMINDER: Your Cloudflare API Key was entered visibly. Protect your shell history.${NC}"
echo -e "${GREEN}Setup is complete!${NC} ${YELLOW}Allow a few minutes for DNS/SSL propagation if needed.${NC}"

# Explicitly exit 0 on success
exit 0
