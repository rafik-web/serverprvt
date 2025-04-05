#!/bin/bash

# Enhanced InfluxDB and Grafana Setup Script for Amazon Lightsail
# Automatically generates Cloudflare Origin Certificates via Cloudflare API
# Includes improved IPv4 detection methods
# Fixes CSR parsing issue by using jq for API payload generation.
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
for cmd in curl wget gpg apt ufw systemctl openssl; do
    if ! command -v $cmd &> /dev/null; then
        log_error "$cmd command not found. Please install it or ensure it's in the PATH."
        exit 1
    fi
done
# Specifically check for jq, needed for the fix
if ! command -v jq &> /dev/null; then
    log_warning "jq command not found. Attempting to install..."
    apt update && apt install -y jq || { log_error "Failed to install jq. Please install it manually (sudo apt install jq) and rerun the script."; exit 1; }
    log_success "jq installed successfully."
fi


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
    # Use -s for silent input for the API key
    read -sp "$(echo -e "${YELLOW}Enter your Cloudflare Global API Key:${NC} ")" CF_API_KEY
    echo # Add a newline after silent input
    if [ -z "$CF_API_KEY" ]; then
        log_warning "API Key cannot be empty."
    fi
done

# Get Zone ID for the domain
show_progress "Fetching Cloudflare Zone ID for $DOMAIN"
# Use jq for more robust JSON parsing
CF_ZONE_ID_JSON=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=$DOMAIN&status=active" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json")

CF_ZONE_ID=$(echo "$CF_ZONE_ID_JSON" | jq -r '.result[0].id // empty') # Use // empty for null safety

if [ -z "$CF_ZONE_ID" ]; then
    log_error "Could not fetch Zone ID for $DOMAIN. Please verify:"
    log_error "  1. The domain '$DOMAIN' is active in your Cloudflare account ($CF_EMAIL)."
    log_error "  2. Your Cloudflare API Key is correct and has Zone:Read permissions."
    # Display API errors if any
    API_ERRORS=$(echo "$CF_ZONE_ID_JSON" | jq -r '.errors // [] | .[] | "\(.code): \(.message)"' 2>/dev/null)
     if [ -n "$API_ERRORS" ]; then
        log_error "Cloudflare API Errors:"
        echo -e "${RED}${API_ERRORS}${NC}" >&2
    fi
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
show_progress "Installing Nginx and other essential tools (including jq)"
# Ensure jq is installed here too, although checked earlier, for robustness
apt install -y wget curl gnupg2 apt-transport-https software-properties-common ufw nginx jq openssl

# Install InfluxDB
show_progress "Installing InfluxDB"
wget -qO- https://repos.influxdata.com/influxdata-archive_compat.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg > /dev/null
echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' | tee /etc/apt/sources.list.d/influxdata.list
apt update
apt install -y influxdb
systemctl enable --now influxdb # Enable and start in one command
log_success "InfluxDB installed and started."

# Install Grafana
show_progress "Installing Grafana"
wget -q -O /usr/share/keyrings/grafana.key https://packages.grafana.com/gpg.key
echo "deb [signed-by=/usr/share/keyrings/grafana.key] https://packages.grafana.com/oss/deb stable main" | tee /etc/apt/sources.list.d/grafana.list
apt update
apt install -y grafana
systemctl enable --now grafana-server # Enable and start in one command
log_success "Grafana installed and started."

# Create Cloudflare DNS A records
show_progress "Creating/Updating Cloudflare DNS Records"

# Function to create or update DNS record
create_or_update_dns_record() {
    local name=$1
    local content=$2
    local full_hostname="${name}.${DOMAIN}"

    log_info "Checking DNS record for ${full_hostname}..."

    # Check if record exists using jq for reliability
    local get_record_response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?type=A&name=$full_hostname" \
         -H "X-Auth-Email: $CF_EMAIL" \
         -H "X-Auth-Key: $CF_API_KEY" \
         -H "Content-Type: application/json")

    local record_id=$(echo "$get_record_response" | jq -r '.result[0].id // empty')
    local current_ip=$(echo "$get_record_response" | jq -r '.result[0].content // empty')

    if [ -n "$record_id" ]; then
        if [ "$current_ip" == "$content" ]; then
             log_success "DNS A record for ${full_hostname} already exists and points to ${content}."
             # Optionally check/update proxy status if needed here
        else
            # Update existing record
            log_info "Updating DNS A record for ${full_hostname} from ${current_ip} to ${content}..."
            local update_response=$(curl -s -X PUT "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/$record_id" \
                 -H "X-Auth-Email: $CF_EMAIL" \
                 -H "X-Auth-Key: $CF_API_KEY" \
                 -H "Content-Type: application/json" \
                 --data "{\"type\":\"A\",\"name\":\"$full_hostname\",\"content\":\"$content\",\"ttl\":1,\"proxied\":true}")
            if echo "$update_response" | jq -e '.success == true' > /dev/null; then
                log_success "Updated DNS A record for ${full_hostname}"
            else
                log_error "Failed to update DNS record for ${full_hostname}. Response:"
                echo "$update_response" | jq . >&2
            fi
        fi
    else
        # Create new record
        log_info "Creating new DNS A record for ${full_hostname} pointing to ${content}..."
        local create_response=$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \
             -H "X-Auth-Email: $CF_EMAIL" \
             -H "X-Auth-Key: $CF_API_KEY" \
             -H "Content-Type: application/json" \
             --data "{\"type\":\"A\",\"name\":\"$full_hostname\",\"content\":\"$content\",\"ttl\":1,\"proxied\":true}")
        if echo "$create_response" | jq -e '.success == true' > /dev/null; then
            log_success "Created DNS A record for ${full_hostname}"
        else
            log_error "Failed to create DNS record for ${full_hostname}. Response:"
            echo "$create_response" | jq . >&2
        fi
    fi
}

# Create/Update database and dashboard DNS A records
create_or_update_dns_record "database" "$SERVER_IP"
create_or_update_dns_record "dashboard" "$SERVER_IP"

# Set Cloudflare SSL/TLS mode to Full (Strict)
show_progress "Setting Cloudflare SSL/TLS mode to Full (Strict)"
SSL_SETTING_RESPONSE=$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/settings/ssl" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json" \
     --data '{"value":"strict"}')

if echo "$SSL_SETTING_RESPONSE" | jq -e '.success == true' > /dev/null; then
    log_success "Set SSL/TLS mode to Full (Strict)"
else
    log_warning "Failed to automatically set SSL/TLS mode to Full (Strict). Please check manually in Cloudflare dashboard."
    log_warning "API Response: $(echo "$SSL_SETTING_RESPONSE" | jq .)"
fi

# Prepare SSL Directory
show_progress "Creating SSL certificate directory: ${SSL_CERT_DIR}"
mkdir -p "${SSL_CERT_DIR}"
chmod 700 "${SSL_CERT_DIR}" # Secure directory permissions

# Generate CSR and Private Key for Origin Certificate
show_progress "Generating private key and CSR for Origin Certificate"

# Generate private key
openssl genrsa -out "${SSL_CERT_DIR}/origin_private.key" 2048
log_success "Generated private key: ${SSL_CERT_DIR}/origin_private.key"

# Create CSR configuration file
cat > "${SSL_CERT_DIR}/csr.conf" << EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
CN = ${DOMAIN} # Common Name - can be the base domain

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

# --- START OF Cloudflare API CSR FIX ---

# Read the CSR content, removing header/footer but keeping internal newlines
RAW_CSR=$(sed '/-BEGIN CERTIFICATE REQUEST-/d;/-END CERTIFICATE REQUEST-/d' "${SSL_CERT_DIR}/origin.csr")

# Check if RAW_CSR is empty (sed failed or CSR file was bad)
if [ -z "$RAW_CSR" ]; then
    log_error "Failed to read or process CSR content from ${SSL_CERT_DIR}/origin.csr"
    log_error "Please check the file exists and is a valid CSR."
    exit 1
fi

# Construct the JSON payload using jq to ensure proper escaping of the CSR string
JSON_PAYLOAD=$(jq -n \
  --argjson hosts "[\"${DOMAIN}\",\"*.${DOMAIN}\",\"${DATABASE_SUBDOMAIN}\",\"${DASHBOARD_SUBDOMAIN}\"]" \
  --arg csr "$RAW_CSR" \
  '{hostnames: $hosts, requested_validity: 5475, request_type: "origin-rsa", csr: $csr}')

# Check if jq failed to create the payload
if [ -z "$JSON_PAYLOAD" ]; then
    log_error "Failed to create JSON payload using jq. Is jq installed and working correctly?"
    exit 1
fi

log_info "Successfully created JSON payload for Cloudflare API request."

# Request Origin Certificate from Cloudflare using the generated JSON payload
show_progress "Requesting Origin Certificate from Cloudflare API"
CERT_RESPONSE=$(curl -s -w "\nHTTP_STATUS_CODE:%{http_code}\n" -X POST "https://api.cloudflare.com/client/v4/certificates" \
     -H "X-Auth-Email: $CF_EMAIL" \
     -H "X-Auth-Key: $CF_API_KEY" \
     -H "Content-Type: application/json" \
     --data "$JSON_PAYLOAD")

# Separate HTTP status code from response body
HTTP_STATUS_CODE=$(echo "$CERT_RESPONSE" | grep "HTTP_STATUS_CODE:" | sed 's/HTTP_STATUS_CODE://')
CERT_RESPONSE_BODY=$(echo "$CERT_RESPONSE" | sed '$d') # Remove last line (status code)

# --- END OF Cloudflare API CSR FIX ---

# Check if certificate creation was successful based on HTTP status and JSON content
if [ "$HTTP_STATUS_CODE" = "200" ] && echo "$CERT_RESPONSE_BODY" | jq -e '.success == true' > /dev/null; then
    log_success "Origin Certificate successfully created (HTTP $HTTP_STATUS_CODE)"

    # Extract and save the certificate
    echo "$CERT_RESPONSE_BODY" | jq -r '.result.certificate' > "${SSL_CERT_DIR}/origin_certificate.pem"

    # Check if the certificate file was actually created and is not empty
    if [ ! -s "${SSL_CERT_DIR}/origin_certificate.pem" ]; then
        log_error "Extracted certificate file is empty or missing! API response might be malformed."
        echo "DEBUG: Full API response body:"
        echo "$CERT_RESPONSE_BODY" | jq . >&2
        exit 1
    fi
    log_success "Saved Origin Certificate to ${SSL_CERT_DIR}/origin_certificate.pem"

    # Copy the certificate and key to the required locations
    cp "${SSL_CERT_DIR}/origin_certificate.pem" "$DB_CERT_FILE"
    cp "${SSL_CERT_DIR}/origin_certificate.pem" "$DASH_CERT_FILE"
    cp "${SSL_CERT_DIR}/origin_private.key" "$DB_KEY_FILE"
    cp "${SSL_CERT_DIR}/origin_private.key" "$DASH_KEY_FILE"

    # Set secure permissions
    chmod 644 "$DB_CERT_FILE" "$DASH_CERT_FILE"
    chmod 600 "$DB_KEY_FILE" "$DASH_KEY_FILE"

    log_success "Origin Certificate and Private Key deployed to Nginx SSL locations."
else
    log_error "Failed to create Origin Certificate (HTTP $HTTP_STATUS_CODE)."
    # Try to parse and display Cloudflare errors cleanly
    CLOUDFLARE_ERRORS=$(echo "$CERT_RESPONSE_BODY" | jq -r '.errors // [] | .[] | "\(.code): \(.message)"' 2>/dev/null)
    if [ -n "$CLOUDFLARE_ERRORS" ]; then
        log_error "Cloudflare API Errors:"
        echo -e "${RED}${CLOUDFLARE_ERRORS}${NC}" >&2
    else
        # Fallback if jq fails or errors format is unexpected
        log_error "Could not parse specific errors from API response."
    fi

    # Debug output
    echo "DEBUG: Raw CSR contents fed to jq (should not be empty, truncated):"
    echo "$RAW_CSR" | head -c 80
    echo "..."
    echo "DEBUG: JSON Payload Sent (truncated):"
    echo "$JSON_PAYLOAD" | head -c 500 # Limit output size
    echo "..."
    echo "DEBUG: Full API response body:"
    echo "$CERT_RESPONSE_BODY" | jq . >&2 # Pretty print JSON if possible

    # Fallback procedure suggestion
    echo ""
    log_warning "FALLBACK OPTION: Create Origin Certificate manually from Cloudflare dashboard:"
    echo "1. Go to Cloudflare dashboard → Your Domain → SSL/TLS → Origin Server"
    echo "2. Click 'Create Certificate'"
    echo "3. Choose 'Generate private key and CSR with Cloudflare' (Recommended) or 'Use my private key and CSR'"
    echo "   If using your CSR, paste the contents of: ${SSL_CERT_DIR}/origin.csr"
    echo "4. Ensure hostnames include: ${DOMAIN}, *.${DOMAIN}, ${DATABASE_SUBDOMAIN}, ${DASHBOARD_SUBDOMAIN}"
    echo "5. Choose validity period (e.g., 15 years)"
    echo "6. Click 'Create'. Copy the 'Origin Certificate' (PEM format) and save it as ${SSL_CERT_DIR}/origin_certificate.pem"
    echo "7. Ensure the private key ${SSL_CERT_DIR}/origin_private.key exists (if you generated it locally)."
    echo "8. Manually copy files (run these commands):"
    echo "   sudo cp ${SSL_CERT_DIR}/origin_certificate.pem ${DB_CERT_FILE}"
    echo "   sudo cp ${SSL_CERT_DIR}/origin_certificate.pem ${DASH_CERT_FILE}"
    echo "   sudo cp ${SSL_CERT_DIR}/origin_private.key ${DB_KEY_FILE}"
    echo "   sudo cp ${SSL_CERT_DIR}/origin_private.key ${DASH_KEY_FILE}"
    echo "   sudo chmod 644 ${DB_CERT_FILE} ${DASH_CERT_FILE}"
    echo "   sudo chmod 600 ${DB_KEY_FILE} ${DASH_KEY_FILE}"
    echo "9. Once files are in place, you might need to manually restart Nginx: sudo systemctl restart nginx"
    echo "10. If the script failed before Nginx setup, you may need to continue subsequent steps manually or rerun parts of the script."

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

    access_log /var/log/nginx/${DATABASE_SUBDOMAIN}.access.log;
    error_log /var/log/nginx/${DATABASE_SUBDOMAIN}.error.log;

    # --- SSL Configuration ---
    ssl_certificate ${DB_CERT_FILE};
    ssl_certificate_key ${DB_KEY_FILE};
    # Optional: Add Cloudflare Origin CA Cert if needed (usually not required with Origin Certs)
    # ssl_client_certificate /path/to/cloudflare_origin_ca.pem;
    # ssl_verify_client on;

    # Recommended SSL settings
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    # Modern cipher suite from Mozilla generator (Intermediate)
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off; # Consider security implications if enabled

    # HSTS (Strict Transport Security) - Max Age = 6 months
    add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" always;

    # OCSP Stapling (improves performance) - Requires resolver
    # resolver 1.1.1.1 1.0.0.1 [2606:4700:4700::1111] [2606:4700:4700::1001] valid=300s; # Cloudflare DNS
    # resolver_timeout 5s;
    # ssl_stapling on;
    # ssl_stapling_verify on;
    # ssl_trusted_certificate ${DB_CERT_FILE}; # Often same as cert file for chain


    location / {
        proxy_pass http://localhost:8086; # InfluxDB default port
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        # Add timeouts for long-running queries if needed
        # proxy_connect_timeout       600;
        # proxy_send_timeout          600;
        # proxy_read_timeout          600;
        # send_timeout                600;
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

    access_log /var/log/nginx/${DASHBOARD_SUBDOMAIN}.access.log;
    error_log /var/log/nginx/${DASHBOARD_SUBDOMAIN}.error.log;

    # --- SSL Configuration ---
    ssl_certificate ${DASH_CERT_FILE};
    ssl_certificate_key ${DASH_KEY_FILE};
    # Optional: Add Cloudflare Origin CA Cert if needed
    # ssl_client_certificate /path/to/cloudflare_origin_ca.pem;
    # ssl_verify_client on;

    # Recommended SSL settings (same as above)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # HSTS (Strict Transport Security)
    add_header Strict-Transport-Security "max-age=15768000; includeSubDomains; preload" always;

    # OCSP Stapling (optional, see comments in above block)
    # resolver 1.1.1.1 1.0.0.1 [2606:4700:4700::1111] [2606:4700:4700::1001] valid=300s;
    # resolver_timeout 5s;
    # ssl_stapling on;
    # ssl_stapling_verify on;
    # ssl_trusted_certificate ${DASH_CERT_FILE};


    location / {
        proxy_pass http://localhost:3000; # Grafana default port
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade; # Required for websockets (Grafana Live)
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header X-Forwarded-Host \$host; # Some apps need this
        proxy_set_header X-Forwarded-Port \$server_port;
    }
}
EOF

log_success "Nginx configuration files created."

# Enable Nginx configurations
show_progress "Enabling Nginx configurations"
# Use -f to force creation even if links exist (safer for reruns)
ln -sf /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} /etc/nginx/sites-enabled/
ln -sf /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN} /etc/nginx/sites-enabled/

# Remove default Nginx site if it exists to avoid conflicts
rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration
show_progress "Testing Nginx configuration"
if ! nginx -t; then
    log_error "Nginx configuration test failed. Please check the error messages above."
    log_error "Review Nginx config files: /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} and /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN}"
    log_error "Also check Nginx error logs: /var/log/nginx/error.log"
    exit 1
else
    log_success "Nginx configuration test successful."
fi

# Restart Nginx to apply changes
show_progress "Restarting Nginx service"
systemctl restart nginx
systemctl enable nginx # Ensure it's enabled on boot

# Configure Firewall
show_progress "Configuring firewall (UFW)"
ufw allow 22/tcp   comment 'SSH'
ufw allow 80/tcp   comment 'HTTP (for SSL redirect)'
ufw allow 443/tcp  comment 'HTTPS (Nginx)'
# Optional: Allow InfluxDB/Grafana directly if needed for non-proxied access (less secure)
# ufw allow 8086/tcp comment 'InfluxDB API (direct)'
# ufw allow 3000/tcp comment 'Grafana UI (direct)'

ufw --force enable # Enable UFW non-interactively
ufw status verbose
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

echo -e "${BOLD}2. Secure InfluxDB:${NC} (Highly Recommended)"
echo -e "   - Connect to the InfluxDB shell: ${CYAN}influx${NC}"
echo -e "   - Inside influx shell, run:"
echo -e "     ${CYAN}CREATE USER myadmin WITH PASSWORD 'ReplaceWithAYourVerySecurePassword' WITH ALL PRIVILEGES${NC}"
echo -e "   - Type ${CYAN}exit${NC} to leave the shell."
echo -e "   - Edit the InfluxDB config file: ${CYAN}sudo nano /etc/influxdb/influxdb.conf${NC}"
echo -e "   - Find the ${BOLD}[http]${NC} section and uncomment/set ${BOLD}auth-enabled = true${NC}"
echo -e "   - Save the file (Ctrl+X, then Y, then Enter)."
echo -e "   - Restart InfluxDB: ${CYAN}sudo systemctl restart influxdb${NC}"
echo -e "   - ${YELLOW}IMPORTANT: You MUST update your Grafana InfluxDB datasource configuration with the username (myadmin) and the password you created.${NC}"
echo -e ""

echo -e "${BOLD}3. Secure Grafana:${NC}"
echo -e "   - Log in to Grafana at ${GREEN}https://${DASHBOARD_SUBDOMAIN}${NC} with ${YELLOW}admin / admin${NC}."
echo -e "   - ${RED}IMMEDIATELY change the admin password${NC} via User Preferences."
echo -e "   - Consider disabling anonymous access and user sign-up for better security."
echo -e "     Edit ${CYAN}sudo nano /etc/grafana/grafana.ini${NC}"
echo -e "     Under ${BOLD}[users]${NC}, set ${BOLD}allow_sign_up = false${NC}"
echo -e "     Under ${BOLD}[auth.anonymous]${NC}, set ${BOLD}enabled = false${NC}"
echo -e "     Restart Grafana: ${CYAN}sudo systemctl restart grafana-server${NC}"
echo -e ""

echo -e "${GREEN}Your InfluxDB, Grafana, and Nginx setup with Cloudflare Origin Certificates should now be complete!${NC}"
echo -e "${YELLOW}NOTE: DNS changes and Cloudflare settings can sometimes take a few minutes to fully propagate globally. If you encounter connection issues immediately, wait 5-10 minutes and try again.${NC}"
echo -e "${YELLOW}Check Nginx logs (${CYAN}/var/log/nginx/*.error.log${NC}) if you face issues accessing the URLs.${NC}"

exit 0
