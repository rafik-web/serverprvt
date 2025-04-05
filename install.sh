#!/bin/bash

# InfluxDB and Grafana Setup Script for Amazon Lightsail
# Configures Cloudflare for SSL/TLS Mode: Full (using a self-signed certificate)
# *** Attempting Fix for DNS name is invalid error by using $1 directly ***
# *** SECURITY WARNING: API Key input is VISIBLE as requested ***
# Usage: Save as install_cf.sh, chmod +x install_cf.sh, sudo ./install_cf.sh

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
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}${BOLD}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}${BOLD}[ERROR]${NC} $1" >&2; }
show_progress() { echo -e "\n${BOLD}${CYAN}==> $1...${NC}"; }

get_server_ip() {
    local ip=""
    ip=$(curl -s --connect-timeout 3 http://169.254.169.254/latest/meta-data/public-ipv4 2>/dev/null || echo "")
    if [ -z "$ip" ]; then ip=$(curl -4s --connect-timeout 3 https://ifconfig.me 2>/dev/null || echo ""); fi
    if [ -z "$ip" ]; then ip=$(curl -4s --connect-timeout 3 https://icanhazip.com 2>/dev/null || echo ""); fi
    if [ -z "$ip" ]; then ip=$(curl -4s --connect-timeout 3 https://api.ipify.org 2>/dev/null || echo ""); fi
    if [ -z "$ip" ]; then ip=$(curl -4s --connect-timeout 3 https://ipinfo.io/ip 2>/dev/null || echo ""); fi
    if [ -z "$ip" ] && command -v ip &>/dev/null; then local interface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -n1); if [ -n "$interface" ]; then ip=$(ip -4 addr show dev "$interface" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n1); fi; fi
    if [ -z "$ip" ] && command -v ifconfig &>/dev/null; then ip=$(ifconfig | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '127.0.0.1' | head -n1); fi
    echo "$ip"
}

# --- Header ---
echo -e "${BOLD}${MAGENTA}"
echo "┌────────────────────────────────────────────────────────┐"
echo "│     InfluxDB + Grafana + Nginx Setup (Lightsail)       │"
echo "│         *** Configuring for Cloudflare FULL SSL ***      │"
echo "│       (Trying Direct Arg Use for DNS Name Fix)         │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# --- Pre-flight Checks ---
if [ "$EUID" -ne 0 ]; then log_error "Run as root/sudo."; exit 1; fi
for cmd in curl wget gpg apt ufw systemctl openssl jq; do if ! command -v $cmd &>/dev/null; then log_warning "$cmd not found. Installing..."; apt update && apt install -y $cmd || { log_error "Failed install $cmd."; exit 1; }; log_success "$cmd installed."; fi; done

# --- User Input ---
log_info "Gathering required information..."
while [ -z "$DOMAIN" ]; do read -p "$(echo -e "${YELLOW}Enter domain:${NC} ")" DOMAIN; if [[ ! "$DOMAIN" == *"."* ]]; then log_warning "Invalid domain."; DOMAIN=""; fi; done
while [ -z "$CF_EMAIL" ]; do read -p "$(echo -e "${YELLOW}Enter CF email:${NC} ")" CF_EMAIL; if [[ ! "$CF_EMAIL" =~ ^.+@.+\..+$ ]]; then log_warning "Invalid email."; CF_EMAIL=""; fi; done
while [ -z "$CF_API_KEY" ]; do log_warning "API Key needs Zone:Read, DNS:Edit, SSL:Edit"; read -p "$(echo -e "${YELLOW}${BOLD}Enter CF API Key (VISIBLE):${NC} ")" CF_API_KEY; echo; if [ -z "$CF_API_KEY" ]; then log_warning "API Key empty."; fi; done

# Get Zone ID
show_progress "Fetching Cloudflare Zone ID for $DOMAIN"
CF_ZONE_ID_JSON=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN&status=active" -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_API_KEY" -H "Content-Type: application/json")
CF_ZONE_ID=$(echo "$CF_ZONE_ID_JSON" | jq -r '.result[0].id // empty')
if [ -z "$CF_ZONE_ID" ]; then log_error "Could not fetch Zone ID for $DOMAIN."; exit 1; fi
log_success "Found Cloudflare Zone ID: $CF_ZONE_ID"

DATABASE_SUBDOMAIN="database.${DOMAIN}"
DASHBOARD_SUBDOMAIN="dashboard.${DOMAIN}"
SSL_CERT_DIR="/etc/nginx/ssl"
SELF_SIGNED_CERT_FILE="${SSL_CERT_DIR}/nginx-selfsigned.crt"
SELF_SIGNED_KEY_FILE="${SSL_CERT_DIR}/nginx-selfsigned.key"

# Get Server IP
show_progress "Detecting Server Public IPv4 Address"
SERVER_IP=$(get_server_ip)
if [ -z "$SERVER_IP" ]; then log_error "IP detection failed."; while [ -z "$SERVER_IP" ]; do read -p "$(echo -e "${YELLOW}Manually enter server IPv4:${NC} ")" SERVER_IP; if [[ ! "$SERVER_IP" =~ ^[0-9.]+$ ]]; then log_warning "Invalid IPv4."; SERVER_IP=""; fi; done; log_success "Using manual IP: ${SERVER_IP}"; else log_success "Detected IP: ${SERVER_IP}"; fi

# --- Confirmation ---
echo -e "\n${GREEN}Setup will proceed with (Mode: FULL SSL):${NC}"; echo -e "  ${BLUE}Domain:${NC} ${DOMAIN}"; echo -e "  ${BLUE}DB URL:${NC} https://${DATABASE_SUBDOMAIN}"; echo -e "  ${BLUE}Dash URL:${NC} https://${DASHBOARD_SUBDOMAIN}"; echo -e "  ${BLUE}Server IP:${NC} ${SERVER_IP}"; echo -e "  ${BLUE}CF Email:${NC} ${CF_EMAIL}"; echo -e "  ${BLUE}CF Zone ID:${NC} ${CF_ZONE_ID}"; echo -e "  ${BLUE}SSL Dir:${NC} ${SSL_CERT_DIR} (Self-Signed)"; echo -e "  ${RED}${BOLD}API Key visible${NC}\n"
read -p "$(echo -e "${YELLOW}Proceed? (y/n):${NC} ")" confirm
if [[ ! $confirm =~ ^[yY]([eE][sS])?$ ]]; then log_warning "Installation cancelled."; exit 1; fi

# --- Installation ---
show_progress "Updating system and installing packages"
apt update && apt upgrade -y
apt install -y wget curl gnupg2 apt-transport-https software-properties-common ufw nginx jq openssl influxdb grafana
show_progress "Starting InfluxDB & Grafana"
systemctl enable --now influxdb; systemctl enable --now grafana-server
log_success "InfluxDB & Grafana installed and started."

# --- Cloudflare DNS & SSL Settings ---
show_progress "Configuring Cloudflare DNS and setting SSL Mode to FULL"
create_or_update_dns_record() {
    # *** Use $1 and $2 directly, add more debug ***
    local record_name="$1" # Store $1 in a distinct variable just for safety/clarity
    local content="$2"
    local full_hostname="${record_name}.${DOMAIN}"
    local record_id current_ip

    log_info "DNS Func Start: record_name='$record_name', content='$content', domain='$DOMAIN', full_hostname='$full_hostname'"

    # Check if record_name is empty
    if [ -z "$record_name" ]; then
        log_error "DNS function error: record_name (\$1) is empty!"
        return 1 # Return error code
    fi

    log_info "Checking DNS record for '${full_hostname}'..."
    local get_record_response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?type=A&name=${full_hostname}" \
         -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_API_KEY" -H "Content-Type: application/json")
    record_id=$(echo "$get_record_response" | jq -r '.result[0].id // empty')
    current_ip=$(echo "$get_record_response" | jq -r '.result[0].content // empty')

    if [ -n "$record_id" ]; then
        if [ "$current_ip" == "$content" ]; then
            log_success "DNS record OK: '${full_hostname}'"
        else
            log_info "Updating DNS record for '${full_hostname}' -> '$content'..."
            # Debug before update call
            echo "DEBUG DNS Update: full_hostname='${full_hostname}', content='$content', record_id='$record_id'"
            local update_response=$(curl -s -w "\nHTTP_STATUS_CODE:%{http_code}\n" -X PUT "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$record_id" \
                 -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_API_KEY" -H "Content-Type: application/json" \
                 --data "{\"type\":\"A\",\"name\":\"${full_hostname}\",\"content\":\"$content\",\"ttl\":1,\"proxied\":true}")
            local update_http_code=$(echo "$update_response" | grep "HTTP_STATUS_CODE:" | sed 's/HTTP_STATUS_CODE://'); local update_body=$(echo "$update_response" | sed '$d')
            if [ "$update_http_code" = "200" ] && echo "$update_body" | jq -e '.success == true' > /dev/null; then log_success "Updated DNS: '${full_hostname}'"; else log_error "Failed update DNS for '${full_hostname}' (HTTP $update_http_code):\n$(echo "$update_body" | jq .)"; return 1; fi
        fi
    else
        log_info "Creating new DNS record for '${full_hostname}' -> '$content'..."
         # Debug before create call
         echo "DEBUG DNS Create: full_hostname='${full_hostname}', content='$content'"
        local create_response=$(curl -s -w "\nHTTP_STATUS_CODE:%{http_code}\n" -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
             -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_API_KEY" -H "Content-Type: application/json" \
             --data "{\"type\":\"A\",\"name\":\"${full_hostname}\",\"content\":\"$content\",\"ttl\":1,\"proxied\":true}")
        local create_http_code=$(echo "$create_response" | grep "HTTP_STATUS_CODE:" | sed 's/HTTP_STATUS_CODE://'); local create_body=$(echo "$create_response" | sed '$d')
        if [ "$create_http_code" = "200" ] && echo "$create_body" | jq -e '.success == true' > /dev/null; then log_success "Created DNS: '${full_hostname}'"; else log_error "Failed create DNS for '${full_hostname}' (HTTP $create_http_code):\n$(echo "$create_body" | jq .)"; return 1; fi
    fi
    sleep 2
    return 0
}

# Call DNS function, exit if it returns non-zero (error)
create_or_update_dns_record "database" "$SERVER_IP" || { log_error "Exiting due to DNS error."; exit 1; }
create_or_update_dns_record "dashboard" "$SERVER_IP" || { log_error "Exiting due to DNS error."; exit 1; }


# Set Cloudflare SSL/TLS mode to FULL
show_progress "Setting Cloudflare SSL/TLS mode to FULL"
SSL_SETTING_RESPONSE=$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/settings/ssl" -H "X-Auth-Email: $CF_EMAIL" -H "X-Auth-Key: $CF_API_KEY" -H "Content-Type: application/json" --data '{"value":"full"}')
if echo "$SSL_SETTING_RESPONSE" | jq -e '.success == true' > /dev/null; then log_success "Successfully set SSL/TLS mode to FULL"; else log_warning "Failed to set SSL/TLS mode to FULL. Check manually. Response:\n$(echo "$SSL_SETTING_RESPONSE" | jq .)"; fi

# --- Generate Self-Signed Certificate (10 Years) ---
show_progress "Generating 10-Year Self-Signed Certificate for Nginx"
mkdir -p "${SSL_CERT_DIR}" && chmod 700 "${SSL_CERT_DIR}"
if [[ -f "$SELF_SIGNED_CERT_FILE" && -f "$SELF_SIGNED_KEY_FILE" ]]; then log_info "Self-signed cert files exist. Skipping generation."; else
    openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout "${SELF_SIGNED_KEY_FILE}" -out "${SELF_SIGNED_CERT_FILE}" -subj "/C=US/ST=State/L=City/O=Org/OU=Unit/CN=${DOMAIN}"
    if [ $? -eq 0 ]; then log_success "Generated 10-Year Self-Signed Cert/Key"; chmod 600 "${SELF_SIGNED_KEY_FILE}"; else log_error "Failed to generate self-signed cert."; exit 1; fi
fi

# --- Configure Nginx ---
show_progress "Creating & enabling Nginx configurations (using self-signed cert)"
# Configs omitted for brevity - they correctly use SELF_SIGNED_* variables
cat > /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} << EOF
server { listen 80; server_name ${DATABASE_SUBDOMAIN}; return 301 https://\$host\$request_uri; }
server { listen 443 ssl http2; listen [::]:443 ssl http2; server_name ${DATABASE_SUBDOMAIN}; access_log /var/log/nginx/${DATABASE_SUBDOMAIN}.access.log; error_log /var/log/nginx/${DATABASE_SUBDOMAIN}.error.log; ssl_certificate ${SELF_SIGNED_CERT_FILE}; ssl_certificate_key ${SELF_SIGNED_KEY_FILE}; ssl_protocols TLSv1.2 TLSv1.3; ssl_prefer_server_ciphers off; ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384; add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" always; location / { proxy_pass http://localhost:8086; proxy_set_header Host \$host; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto \$scheme; }}
EOF
cat > /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN} << EOF
server { listen 80; server_name ${DASHBOARD_SUBDOMAIN}; return 301 https://\$host\$request_uri; }
server { listen 443 ssl http2; listen [::]:443 ssl http2; server_name ${DASHBOARD_SUBDOMAIN}; access_log /var/log/nginx/${DASHBOARD_SUBDOMAIN}.access.log; error_log /var/log/nginx/${DASHBOARD_SUBDOMAIN}.error.log; ssl_certificate ${SELF_SIGNED_CERT_FILE}; ssl_certificate_key ${SELF_SIGNED_KEY_FILE}; ssl_protocols TLSv1.2 TLSv1.3; ssl_prefer_server_ciphers off; ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384; add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" always; location / { proxy_pass http://localhost:3000; proxy_http_version 1.1; proxy_set_header Upgrade \$http_upgrade; proxy_set_header Connection "upgrade"; proxy_set_header Host \$host; proxy_cache_bypass \$http_upgrade; proxy_set_header X-Real-IP \$remote_addr; proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for; proxy_set_header X-Forwarded-Proto \$scheme; proxy_set_header X-Forwarded-Host \$host; }}
EOF
ln -sf /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} /etc/nginx/sites-enabled/; ln -sf /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN} /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
if ! nginx -t; then log_error "Nginx config test failed."; exit 1; fi
systemctl restart nginx && systemctl enable nginx
log_success "Nginx configuration applied & service restarted."

# --- Configure Firewall ---
show_progress "Configuring firewall (UFW)"
ufw allow 22/tcp comment 'SSH'; ufw allow 80/tcp comment 'HTTP Redirect'; ufw allow 443/tcp comment 'HTTPS'
ufw --force enable && ufw status verbose
log_success "Firewall configured and enabled."

# --- Final Steps ---
# Final messages omitted for brevity
echo -e "\n${BOLD}${GREEN}┌─────────────────────────────────────────────────┐"; echo -e "│   SETUP FOR 'FULL' SSL MODE COMPLETED SUCCESSFULLY  │"; echo -e "└─────────────────────────────────────────────────┘${NC}"
echo -e "${CYAN}SUMMARY & NEXT STEPS:${NC}\n"; echo -e "${BOLD}1. Cloudflare SSL/TLS Mode:${NC} Set to ${GREEN}Full${NC}"; echo -e "${BOLD}2. Server Certificate:${NC} Using 10-Year Self-Signed (${SELF_SIGNED_CERT_FILE})"; echo -e "${BOLD}3. Access Your Services:${NC}"; echo -e "   - InfluxDB API: ${GREEN}https://${DATABASE_SUBDOMAIN}${NC}"; echo -e "   - Grafana UI:   ${GREEN}https://${DASHBOARD_SUBDOMAIN}${NC} (${YELLOW}Login: admin/admin - CHANGE NOW!${NC})\n"
echo -e "${BOLD}4. Secure InfluxDB:${NC} (Recommended)"; echo -e "   Run: ${CYAN}influx${NC} -> ${CYAN}CREATE USER myadmin WITH PASSWORD '...' WITH ALL PRIVILEGES${NC} -> ${CYAN}exit${NC}"; echo -e "   Edit: ${CYAN}sudo nano /etc/influxdb/influxdb.conf${NC} -> [http] -> ${BOLD}auth-enabled = true${NC}"; echo -e "   Restart: ${CYAN}sudo systemctl restart influxdb${NC}"; echo -e "   ${YELLOW}Update Grafana datasource credentials.${NC}\n"
echo -e "${BOLD}5. Secure Grafana:${NC}"; echo -e "   Login to ${GREEN}https://${DASHBOARD_SUBDOMAIN}${NC}, ${RED}change admin password immediately.${NC}"; echo -e "   Consider disabling sign-up/anonymous in ${CYAN}sudo nano /etc/grafana/grafana.ini${NC}. Restart: ${CYAN}sudo systemctl restart grafana-server${NC}\n"
echo -e "${RED}${BOLD}SECURITY REMINDER: API Key visible. Protect shell history.${NC}"; echo -e "${GREEN}Setup is complete!${NC} ${YELLOW}Allow minutes for DNS/SSL propagation.${NC}"

exit 0
