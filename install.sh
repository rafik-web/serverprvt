#!/bin/bash

# Enhanced InfluxDB and Grafana Setup Script for Amazon Lightsail
# Includes Cloudflare Integration and HTTPS Enforcement via Certbot/Nginx
# Usage: bash <(curl -Ls https://raw.githubusercontent.com/yourusername/yourrepo/main/install-enhanced.sh) # Replace with your actual URL

# --- Configuration ---
# Text colors
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
echo "│     Enhanced InfluxDB + Grafana + Nginx Setup          │"
echo "│                Cloudflare & HTTPS                      │"
echo "│                     By Rafik                           │"
echo "└────────────────────────────────────────────────────────┘"
echo -e "${NC}"

# --- Pre-flight Checks ---
# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
  log_error "Please run this script as root or using sudo."
  exit 1
fi

# Check for necessary commands early
for cmd in curl wget gpg apt ufw systemctl nginx certbot; do
    if ! command -v $cmd &> /dev/null && [[ "$cmd" != "nginx" && "$cmd" != "certbot" ]]; then
        log_error "$cmd command not found. Please install it or ensure it's in the PATH."
        exit 1
    fi
done

# --- User Input ---
log_info "Gathering required information..."

# Get Domain
while [ -z "$DOMAIN" ]; do
    read -p "$(echo -e "${YELLOW}Enter your main domain (e.g., rafik.cloud):${NC} ")" DOMAIN
    # Basic validation: check if it contains at least one dot
    if [[ ! "$DOMAIN" == *"."* ]]; then
        log_warning "Invalid domain format. Please enter a valid domain (e.g., example.com)."
        DOMAIN=""
    fi
done

# Get Email for Let's Encrypt
while [ -z "$EMAIL" ]; do
    read -p "$(echo -e "${YELLOW}Enter your email address (for Let's Encrypt SSL certificates):${NC} ")" EMAIL
    # Basic email validation
    if [[ ! "$EMAIL" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log_warning "Invalid email format. Please enter a valid email address."
        EMAIL=""
    fi
done


DATABASE_SUBDOMAIN="database.${DOMAIN}"
DASHBOARD_SUBDOMAIN="dashboard.${DOMAIN}"

# Get Server Public IPv4 Address
show_progress "Fetching Server Public IPv4 Address"
# Prefer AWS metadata service, fallback to external service
SERVER_IP=$(curl -s --connect-timeout 5 http://169.254.169.254/latest/meta-data/public-ipv4 || curl -4s --connect-timeout 5 ifconfig.me || curl -4s --connect-timeout 5 icanhazip.com)

if [ -z "$SERVER_IP" ]; then
    log_error "Could not automatically determine the server's public IPv4 address."
    log_error "Please find it manually (e.g., in your Lightsail console) and configure DNS."
    # Optionally, ask user to input it:
    # read -p "$(echo -e "${YELLOW}Please enter the server's public IPv4 address:${NC} ")" SERVER_IP
    # if [ -z "$SERVER_IP" ]; then exit 1; fi # Exit if still empty
    exit 1 # Exit if we can't get the IP
else
    log_success "Detected Server IPv4: ${SERVER_IP}"
fi

# --- Confirmation ---
echo -e "\n${GREEN}Setup will proceed with the following details:${NC}"
echo -e "  ${BLUE}Domain:${NC} ${DOMAIN}"
echo -e "  ${BLUE}Database URL:${NC} https://${DATABASE_SUBDOMAIN}"
echo -e "  ${BLUE}Dashboard URL:${NC} https://${DASHBOARD_SUBDOMAIN}"
echo -e "  ${BLUE}Server IPv4:${NC} ${SERVER_IP}"
echo -e "  ${BLUE}Let's Encrypt Email:${NC} ${EMAIL}\n"

read -p "$(echo -e "${YELLOW}Proceed with installation? (y/n):${NC} ")" confirm
if [[ ! $confirm =~ ^[yY]([eE][sS])?$ ]]; then
  log_warning "Installation cancelled by user."
  exit 1
fi

# --- Installation and Configuration ---

# Update System
show_progress "Updating system packages"
apt update && apt upgrade -y

# Install Essential Tools & Nginx & Certbot
show_progress "Installing Nginx, Certbot, and other essential tools"
apt install -y wget curl gnupg2 apt-transport-https software-properties-common ufw nginx certbot python3-certbot-nginx

# Install InfluxDB (Using updated key retrieval method)
show_progress "Installing InfluxDB"
wget -qO- https://repos.influxdata.com/influxdata-archive_compat.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg > /dev/null
echo 'deb [signed-by=/etc/apt/trusted.gpg.d/influxdata-archive_compat.gpg] https://repos.influxdata.com/debian stable main' | tee /etc/apt/sources.list.d/influxdata.list
apt update
apt install -y influxdb
systemctl start influxdb
systemctl enable influxdb
log_success "InfluxDB installed and started."

# Install Grafana (Using updated key retrieval method)
show_progress "Installing Grafana"
wget -q -O /usr/share/keyrings/grafana.key https://packages.grafana.com/gpg.key
echo "deb [signed-by=/usr/share/keyrings/grafana.key] https://packages.grafana.com/oss/deb stable main" | tee /etc/apt/sources.list.d/grafana.list
apt update
apt install -y grafana
# Ensure Grafana binds only to localhost initially for security via proxy
# sed -i '/^;http_addr =/c\http_addr = 127.0.0.1' /etc/grafana/grafana.ini # Uncomment if you want Grafana ONLY accessible via Nginx
systemctl start grafana-server
systemctl enable grafana-server
log_success "Grafana installed and started."

# Configure Nginx (Initial HTTP configuration for Certbot)
show_progress "Creating initial Nginx configurations for ${DATABASE_SUBDOMAIN} and ${DASHBOARD_SUBDOMAIN}"

# Nginx config for database subdomain (HTTP only for now)
cat > /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} << EOF
server {
    listen 80;
    server_name ${DATABASE_SUBDOMAIN};

    # ACME challenge location for Certbot
    location ~ /.well-known/acme-challenge {
        allow all;
        root /var/www/html; # Or a dedicated directory
    }

    location / {
        # Return a temporary message or redirect - will be replaced by proxy pass after SSL
        return 404; # Placeholder - Certbot needs a working HTTP server
        # Or temporary redirect: return 301 https://\$host\$request_uri; (but needs SSL block first)
    }
}
EOF

# Nginx config for dashboard subdomain (HTTP only for now)
cat > /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN} << EOF
server {
    listen 80;
    server_name ${DASHBOARD_SUBDOMAIN};

    # ACME challenge location for Certbot
    location ~ /.well-known/acme-challenge {
        allow all;
        root /var/www/html; # Ensure this directory exists or change as needed
    }

    location / {
        # Return a temporary message or redirect - will be replaced by proxy pass after SSL
        return 404; # Placeholder
        # Or temporary redirect: return 301 https://\$host\$request_uri;
    }
}
EOF

# Ensure the ACME challenge directory exists and has correct permissions
mkdir -p /var/www/html
chown www-data:www-data /var/www/html

# Enable Nginx configurations
show_progress "Enabling initial Nginx configurations"
ln -sf /etc/nginx/sites-available/${DATABASE_SUBDOMAIN} /etc/nginx/sites-enabled/
ln -sf /etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN} /etc/nginx/sites-enabled/

# Remove default Nginx site if it exists
rm -f /etc/nginx/sites-enabled/default

# Test Nginx configuration
show_progress "Testing Nginx configuration"
if nginx -t; then
    log_success "Nginx configuration test successful."
    systemctl restart nginx
    systemctl enable nginx
else
    log_error "Nginx configuration test failed. Please check the files in /etc/nginx/sites-available/ and logs."
    exit 1
fi

# Configure Firewall
show_progress "Configuring firewall (UFW)"
ufw allow 22/tcp   # SSH (Ensure this is correct for your setup)
ufw allow 80/tcp   # HTTP (Needed for Certbot and initial access/redirect)
ufw allow 443/tcp  # HTTPS (Needed for secure access)
# Consider restricting InfluxDB/Grafana ports if not binding to localhost
# ufw deny 8086/tcp # Deny direct InfluxDB access if proxied
# ufw deny 3000/tcp # Deny direct Grafana access if proxied
ufw --force enable # Enable UFW non-interactively
log_success "Firewall configured and enabled."

# --- DNS and SSL Setup ---
echo -e "\n${BOLD}${YELLOW}!!!!!!!!!!!!!!!!!! ACTION REQUIRED !!!!!!!!!!!!!!!!!!${NC}"
log_info "Before proceeding, you ${BOLD}MUST${NC} configure DNS records in Cloudflare."
log_info "Go to your Cloudflare dashboard for the domain '${BOLD}${DOMAIN}${NC}' and add/update:"
echo -e "  - Type: ${BOLD}A${NC}, Name: ${BOLD}database${NC}, Content: ${BOLD}${SERVER_IP}${NC}, Proxy status: ${BOLD}DNS Only (Grey Cloud)${NC}"
echo -e "  - Type: ${BOLD}A${NC}, Name: ${BOLD}dashboard${NC}, Content: ${BOLD}${SERVER_IP}${NC}, Proxy status: ${BOLD}DNS Only (Grey Cloud)${NC}"
echo -e "\n${YELLOW}Why 'DNS Only' for now?${NC} Certbot needs to connect directly to your server on port 80 to verify domain ownership. Cloudflare proxying can interfere with this specific validation method."
echo -e "${YELLOW}Wait a few minutes for DNS propagation after adding the records.${NC}"
read -p "$(echo -e "${YELLOW}Press Enter ONLY when you have set the DNS records to 'DNS Only' and they have likely propagated...${NC}")"

# Obtain SSL Certificates with Certbot
show_progress "Attempting to obtain SSL certificates using Certbot"
if certbot --nginx --redirect --agree-tos --email "${EMAIL}" -d "${DATABASE_SUBDOMAIN}" -d "${DASHBOARD_SUBDOMAIN}" --non-interactive --staple-ocsp; then
    log_success "Certbot successfully obtained and installed SSL certificates!"
    log_info "Nginx has been automatically configured for HTTPS and HTTP->HTTPS redirection."

    # Update Nginx configs to add proxy passes AFTER SSL is set up by Certbot
    show_progress "Updating Nginx configurations with service proxy passes"

    # Modify Database Nginx Config (Certbot should have created/updated this)
    # We need to ensure the proxy_pass is correctly set within the SSL server block Certbot created.
    # This is a bit complex to automate reliably without knowing exactly how Certbot modified the file.
    # A safer approach is to MANUALLY edit or provide a template showing the final structure.
    # However, let's try a sed approach (might be fragile):
    # Assuming Certbot added an SSL server block and kept the original server block for redirection.
    # We will add the proxy pass to the location / block within the server block listening on 443.
    # This assumes Certbot adds standard SSL config lines.

    NGINX_CONF_DB="/etc/nginx/sites-available/${DATABASE_SUBDOMAIN}"
    NGINX_CONF_DASH="/etc/nginx/sites-available/${DASHBOARD_SUBDOMAIN}"

    # Add proxy settings to the database config's HTTPS location / block
    # This is tricky, assumes 'location / {' exists within an ssl context
    # A more robust way might be to overwrite the file with a complete template *after* certbot runs,
    # incorporating the SSL paths certbot provides. Let's generate the final expected config.

    cat > ${NGINX_CONF_DB} << EOF
server {
    server_name ${DATABASE_SUBDOMAIN};

    location / {
        proxy_pass http://localhost:8086;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        # Add any InfluxDB specific headers if needed
    }

    listen [::]:443 ssl ipv6only=on; # managed by Certbot
    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/${DATABASE_SUBDOMAIN}/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/${DATABASE_SUBDOMAIN}/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}

server {
    if (\$host = ${DATABASE_SUBDOMAIN}) {
        return 301 https://\$host\$request_uri;
    } # managed by Certbot

    listen 80;
    listen [::]:80;
    server_name ${DATABASE_SUBDOMAIN};
    return 404; # managed by Certbot
}
EOF

    # Add proxy settings to the dashboard config's HTTPS location / block
     cat > ${NGINX_CONF_DASH} << EOF
server {
    server_name ${DASHBOARD_SUBDOMAIN};

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
        # Add Grafana specific headers if needed
    }

    listen [::]:443 ssl ipv6only=on; # managed by Certbot
    listen 443 ssl; # managed by Certbot
    ssl_certificate /etc/letsencrypt/live/${DASHBOARD_SUBDOMAIN}/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/${DASHBOARD_SUBDOMAIN}/privkey.pem; # managed by Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf; # managed by Certbot
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # managed by Certbot
}

server {
    if (\$host = ${DASHBOARD_SUBDOMAIN}) {
        return 301 https://\$host\$request_uri;
    } # managed by Certbot

    listen 80;
    listen [::]:80;
    server_name ${DASHBOARD_SUBDOMAIN};
    return 404; # managed by Certbot
}
EOF

    # Test and restart Nginx again
    show_progress "Testing final Nginx configuration"
    if nginx -t; then
        log_success "Nginx configuration test successful."
        systemctl restart nginx
    else
        log_error "Nginx configuration test failed after adding proxy settings. Please check the config files manually."
        log_error "Files to check: ${NGINX_CONF_DB} and ${NGINX_CONF_DASH}"
        log_warning "SSL Certificates *were* obtained, but Nginx needs manual correction."
        # Don't exit, let user see final instructions
    fi

    echo -e "\n${BOLD}${YELLOW}!!!!!!!!!!!!!!!!!! ACTION REQUIRED (Final Cloudflare step) !!!!!!!!!!!!!!!!!!${NC}"
    log_info "SSL setup is complete on the server."
    log_info "Now, go back to Cloudflare for '${BOLD}${DOMAIN}${NC}' and:"
    echo -e "  1. Change Proxy status for '${BOLD}database${NC}' and '${BOLD}dashboard${NC}' records to: ${BOLD}Proxied (Orange Cloud)${NC}"
    echo -e "  2. Go to the ${BOLD}SSL/TLS${NC} section in Cloudflare."
    echo -e "  3. Set the encryption mode to: ${BOLD}Full (strict)${NC}"
    echo -e "\n${YELLOW}Why 'Full (strict)'?${NC}"
    echo -e "  - ${BOLD}User <-> Cloudflare:${NC} Secured by Cloudflare's certificate."
    echo -e "  - ${BOLD}Cloudflare <-> Your Server:${NC} Secured by the Let's Encrypt certificate you just installed. 'Strict' ensures Cloudflare validates this certificate."

else
    log_error "Certbot failed to obtain SSL certificates."
    log_error "Common reasons include:"
    log_error "  - DNS records not set correctly or not propagated yet (Wait longer? Check DNS?)."
    log_error "  - Firewall blocking port 80."
    log_error "  - Nginx not running or misconfigured."
    log_error "  - Reaching Let's Encrypt rate limits."
    log_warning "Please review the Certbot output above for specific errors."
    log_warning "You can try running Certbot manually later once issues are resolved:"
    echo -e "  ${CYAN}sudo certbot --nginx --redirect --agree-tos --email ${EMAIL} -d ${DATABASE_SUBDOMAIN} -d ${DASHBOARD_SUBDOMAIN}${NC}"
    log_warning "HTTPS will not work until SSL certificates are successfully installed."
    # Do not proceed with final Cloudflare proxy steps if certbot failed.
fi


# --- Final Instructions ---
echo -e "\n${BOLD}${GREEN}"
echo "┌─────────────────────────────────────────────────┐"
echo "│             SETUP SCRIPT FINISHED!              │"
echo "└─────────────────────────────────────────────────┘"
echo -e "${NC}"

echo -e "${CYAN}SUMMARY & NEXT STEPS:${NC}\n"
echo -e "${BOLD}1. Cloudflare Configuration:${NC}"
if systemctl is-active --quiet nginx && [[ -f "/etc/letsencrypt/live/${DATABASE_SUBDOMAIN}/fullchain.pem" ]]; then
  echo -e "   - Ensure DNS A records for '${BOLD}database${NC}' and '${BOLD}dashboard${NC}' point to ${BOLD}${SERVER_IP}${NC}."
  echo -e "   - Set Proxy status to ${BOLD}Proxied (Orange Cloud)${NC}."
  echo -e "   - Set SSL/TLS Encryption mode to ${BOLD}Full (strict)${NC}."
else
  echo -e "   - ${RED}SSL setup likely failed.${NC} Review script output."
  echo -e "   - Keep DNS records ${BOLD}DNS Only (Grey Cloud)${NC} for now."
  echo -e "   - Set Cloudflare SSL/TLS to ${BOLD}Off${NC} or ${BOLD}Flexible${NC} temporarily if needed for testing, but aim for ${BOLD}Full (strict)${NC} once server SSL works."
fi
echo -e ""

echo -e "${BOLD}2. Access Your Services (after DNS propagation & Cloudflare setup):${NC}"
if systemctl is-active --quiet nginx && [[ -f "/etc/letsencrypt/live/${DATABASE_SUBDOMAIN}/fullchain.pem" ]]; then
    echo -e "   - InfluxDB API: ${GREEN}https://${DATABASE_SUBDOMAIN}${NC}"
    echo -e "   - Grafana UI:   ${GREEN}https://${DASHBOARD_SUBDOMAIN}${NC}"
    echo -e "     ${YELLOW}Default Grafana login: admin / admin (CHANGE THIS IMMEDIATELY!)${NC}"
else
    echo -e "   - ${RED}Access via HTTPS will likely fail until SSL is configured correctly.${NC}"
    echo -e "   - You might be able to access via HTTP temporarily if firewall allows and Nginx serves on port 80, but this is NOT recommended: http://${SERVER_IP}:8086, http://${SERVER_IP}:3000"
fi
echo -e ""

echo -e "${BOLD}3. Secure InfluxDB:${NC}"
echo -e "   - Run: ${CYAN}influx${NC}"
echo -e "   - Inside influx shell, create an admin user:"
echo -e "     ${CYAN}CREATE USER myadmin WITH PASSWORD 'YourVerySecurePassword' WITH ALL PRIVILEGES${NC}"
echo -e "   - Then type: ${CYAN}exit${NC}"
echo -e "   - Edit the InfluxDB config: ${CYAN}sudo nano /etc/influxdb/influxdb.conf${NC}"
echo -e "   - Find the ${BOLD}[http]${NC} section."
echo -e "   - Set ${BOLD}auth-enabled = true${NC} (remove the '#' comment if present)."
echo -e "   - Restart InfluxDB: ${CYAN}sudo systemctl restart influxdb${NC}"
echo -e "   - ${YELLOW}IMPORTANT:${NC} Update Grafana's InfluxDB datasource connection details to use this username/password."
echo -e ""

echo -e "${BOLD}4. Secure Grafana:${NC}"
echo -e "   - Log in to Grafana at ${GREEN}https://${DASHBOARD_SUBDOMAIN}${NC} with ${YELLOW}admin / admin${NC}."
echo -e "   - ${RED}IMMEDIATELY change the admin password${NC} via the user profile settings."
echo -e "   - Consider disabling anonymous access and sign-up in Grafana's configuration if not needed (${CYAN}sudo nano /etc/grafana/grafana.ini${NC})."
echo -e ""

echo -e "${BOLD}5. SSL Certificate Renewal:${NC}"
echo -e "   - Certbot automatically installed a systemd timer or cron job to handle renewals."
echo -e "   - You can test the renewal process (without actually renewing) using: ${CYAN}sudo certbot renew --dry-run${NC}"
echo -e ""

echo -e "${GREEN}Enjoy your secured InfluxDB and Grafana setup!${NC}"
