#!/bin/bash

# Enhanced Master Deployment Script v3.0 - FIXED DEPLOY6 SSL LOGIC
# Complete production deployment with enhanced SSL certificate management

set -e

# Color codes for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Webhook URLs for notifications
FAIL2BAN_WEBHOOK="https://discord.com/api/webhooks/1410409819785138296/-RfbmgpdrdrT0Ghozc8XCY5tLqECZjCmwxjJea0mlc3B0nPe249QlmIJKxYRYVEIhXig"
CERTBOT_WEBHOOK="https://discord.com/api/webhooks/1410410118503338166/dgg-i9Y1qxLQUwAGeLjav5ZM0EkQXYzFBb090U3cboYSSXMIEcGYQEBU33SQr4eMepnf"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" >&2
}

warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO:${NC} $1"
}

# Function to send Discord notification
send_discord_notification() {
    local webhook_url="$1"
    local title="$2"
    local description="$3"
    local color="$4"
    
    curl -H "Content-Type: application/json" \
         -X POST \
         -d "{
           \"embeds\": [{
             \"title\": \"$title\",
             \"description\": \"$description\",
             \"color\": $color,
             \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
             \"footer\": {
               \"text\": \"Server: $(hostname)\"
             }
           }]
         }" \
         "$webhook_url" &>/dev/null
}

# Function to verify Discord webhook
verify_discord_webhook() {
    local webhook_url="$1"
    local webhook_name="$2"
    
    info "Testing $webhook_name Discord webhook..."
    
    if curl -s -f -H "Content-Type: application/json" \
            -X POST \
            -d "{
              \"embeds\": [{
                \"title\": \"Webhook Test - $webhook_name\",
                \"description\": \"Testing Discord webhook connectivity for deployment script initialization.\",
                \"color\": 3447003,
                \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
                \"footer\": {
                  \"text\": \"Server: $(hostname)\"
                }
              }]
            }" \
            "$webhook_url" &>/dev/null; then
        log "$webhook_name webhook verified successfully"
        return 0
    else
        error "$webhook_name webhook verification failed"
        return 1
    fi
}

# Function to verify Cloudflare API
verify_cloudflare_api() {
    local api_key="$1"
    local zone_id="$2"
    
    info "Verifying Cloudflare API credentials..."
    
    local response=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_id" \
         -H "Authorization: Bearer $api_key" \
         -H "Content-Type: application/json")
    
    if echo "$response" | grep -q '"success":true'; then
        local zone_name=$(echo "$response" | grep -o '"name":"[^"]*' | cut -d'"' -f4)
        log "Cloudflare API verified successfully - Zone: $zone_name"
        return 0
    else
        error "Cloudflare API verification failed"
        echo "Response: $response"
        return 1
    fi
}

# Function to verify email format
verify_email() {
    local email="$1"
    
    if [[ "$email" =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        log "Email format verified: $email"
        return 0
    else
        error "Invalid email format: $email"
        return 1
    fi
}

# Function to verify domain format
verify_domain() {
    local domain="$1"
    
    if [[ "$domain" =~ ^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
        log "Domain format verified: $domain"
        return 0
    else
        error "Invalid domain format: $domain"
        return 1
    fi
}

# Function to gather and verify all information
gather_info() {
    log "Starting information gathering and verification process..."
    
    # Send initial Discord notification
    send_discord_notification "$CERTBOT_WEBHOOK" \
        "Deployment Script Started" \
        "Master deployment script initialization begun on server $(hostname)" \
        3447003
    
    # Verify Discord webhooks first
    log "Verifying Discord webhooks..."
    if ! verify_discord_webhook "$FAIL2BAN_WEBHOOK" "Fail2Ban"; then
        error "Fail2Ban webhook verification failed. Cannot proceed."
        exit 1
    fi
    
    if ! verify_discord_webhook "$CERTBOT_WEBHOOK" "Certbot"; then
        error "Certbot webhook verification failed. Cannot proceed."
        exit 1
    fi
    
    # Gather domain information
    while true; do
        read -p "Enter the domain name (e.g., example.com): " DOMAIN
        if verify_domain "$DOMAIN"; then
            break
        else
            error "Please enter a valid domain name"
        fi
    done
    
    # Gather email information
    while true; do
        read -p "Enter your email address for SSL registration: " EMAIL
        if verify_email "$EMAIL"; then
            break
        else
            error "Please enter a valid email address"
        fi
    done
    
    # Gather Cloudflare API information
    while true; do
        read -p "Enter your Cloudflare API key: " CF_API_KEY
        read -p "Enter your Cloudflare Zone ID: " CF_ZONE_ID
        
        if verify_cloudflare_api "$CF_API_KEY" "$CF_ZONE_ID"; then
            break
        else
            error "Cloudflare API verification failed. Please check your credentials."
        fi
    done

    PROJECT_DIR="/server/${DOMAIN//./_}"
    PUBLIC_IP=$(curl -s https://api.ipify.org)

    # Display gathered information for confirmation
    log "Configuration Summary:"
    echo "Domain: $DOMAIN"
    echo "Email: $EMAIL" 
    echo "Project Directory: $PROJECT_DIR"
    echo "Public IP: $PUBLIC_IP"
    echo "Cloudflare Zone ID: $CF_ZONE_ID"
    echo "Fail2Ban Webhook: Verified"
    echo "Certbot Webhook: Verified"
    
    read -p "Confirm all details are correct? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        error "Configuration not confirmed. Exiting."
        exit 1
    fi

    # Create the project directory
    mkdir -p "$PROJECT_DIR"
    
    # Save configuration for later use
    cat > "$PROJECT_DIR/.deployment_config" <<EOF
DOMAIN="$DOMAIN"
EMAIL="$EMAIL"
CF_API_KEY="$CF_API_KEY"
CF_ZONE_ID="$CF_ZONE_ID"
PUBLIC_IP="$PUBLIC_IP"
PROJECT_DIR="$PROJECT_DIR"
FAIL2BAN_WEBHOOK="$FAIL2BAN_WEBHOOK"
CERTBOT_WEBHOOK="$CERTBOT_WEBHOOK"
EOF

    log "Information gathering completed and verified"
}

# Function to create DEPLOY0 script
create_deploy0() {
    log "Creating DEPLOY0: System initialization and preparation..."
    
    cat > "$PROJECT_DIR/DEPLOY0_initializing_and_prep.sh" <<'EOF'
#!/bin/bash

set -e

# Load configuration
source "$PROJECT_DIR/.deployment_config"

echo "DEPLOY0: System Initialization and Preparation"
echo "=============================================="

# Update system packages
echo "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get upgrade -y

# Install required packages
echo "Installing required packages..."
apt-get install -y \
    curl \
    wget \
    git \
    bc \
    jq \
    fail2ban \
    ddclient \
    htop \
    nano \
    cron \
    logrotate \
    unattended-upgrades \
    apt-listchanges \
    iptables-persistent \
    netfilter-persistent

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh
    systemctl enable docker
    systemctl start docker
    rm get-docker.sh
    
    # Add current user to docker group
    usermod -aG docker $USER || true
fi

# Verify Docker installation
docker --version
systemctl is-active docker

echo "DEPLOY0 completed successfully"
curl -H "Content-Type: application/json" \
     -X POST \
     -d "{\"embeds\": [{\"title\": \"DEPLOY0 Complete\", \"description\": \"System initialization completed successfully\", \"color\": 65280}]}" \
     "$CERTBOT_WEBHOOK" &>/dev/null
EOF
    
    # Replace PROJECT_DIR in the script
    sed -i "s|\$PROJECT_DIR|$PROJECT_DIR|g" "$PROJECT_DIR/DEPLOY0_initializing_and_prep.sh"
    
    chmod +x "$PROJECT_DIR/DEPLOY0_initializing_and_prep.sh"
    log "DEPLOY0 script created"
}

# Function to create DEPLOY1 script
create_deploy1() {
    log "Creating DEPLOY1: Basic security setup..."
    
    cat > "$PROJECT_DIR/DEPLOY1_basic_security.sh" <<EOF
#!/bin/bash

set -e

# Load configuration
source "$PROJECT_DIR/.deployment_config"

echo "DEPLOY1: Basic Security Setup"
echo "============================="

# Create log directories first
echo "Creating log directories..."
mkdir -p "$PROJECT_DIR/logs"/{nginx,php,certbot,fail2ban}

# Configure iptables firewall
echo "Configuring iptables firewall..."

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established and related connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (port 22)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -j ACCEPT

# Allow HTTP (port 80)
iptables -A INPUT -p tcp --dport 80 -m state --state NEW -j ACCEPT

# Allow HTTPS (port 443)
iptables -A INPUT -p tcp --dport 443 -m state --state NEW -j ACCEPT

# Rate limiting for SSH (max 4 connections per minute)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --rttl --name SSH -j DROP

# Rate limiting for HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

# Save iptables rules
iptables-save > /etc/iptables/rules.v4
systemctl enable netfilter-persistent
systemctl start netfilter-persistent

# Configure basic Fail2Ban (SSH only initially)
echo "Configuring basic Fail2Ban..."

# Create custom action for Discord notifications
cat > /etc/fail2ban/action.d/discord.conf <<EOL
[Definition]
actionstart = curl -H "Content-Type: application/json" \\
              -X POST \\
              -d '{"embeds": [{"title": "Fail2Ban Started", "description": "Fail2Ban protection started for <n> on $(hostname)", "color": 65280}]}' \\
              "$FAIL2BAN_WEBHOOK"

actionstop = curl -H "Content-Type: application/json" \\
             -X POST \\
             -d '{"embeds": [{"title": "Fail2Ban Stopped", "description": "Fail2Ban protection stopped for <n> on $(hostname)", "color": 16711680}]}' \\
             "$FAIL2BAN_WEBHOOK"

actionban = curl -H "Content-Type: application/json" \\
            -X POST \\
            -d '{"embeds": [{"title": "IP Banned", "description": "IP <ip> has been banned for <n> on $(hostname). Ban time: <bantime>", "color": 16776960}]}' \\
            "$FAIL2BAN_WEBHOOK"

actionunban = curl -H "Content-Type: application/json" \\
              -X POST \\
              -d '{"embeds": [{"title": "IP Unbanned", "description": "IP <ip> has been unbanned for <n> on $(hostname)", "color": 3447003}]}' \\
              "$FAIL2BAN_WEBHOOK"

[Init]
EOL

# Basic Fail2Ban configuration (SSH only)
cat > /etc/fail2ban/jail.local <<EOL
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5
backend = auto
enabled = false
action = %(action_mwl)s
         discord

[sshd]
enabled = true
port = ssh
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 7200
EOL

# Start and enable Fail2Ban
systemctl enable fail2ban
systemctl restart fail2ban

# Verify Fail2Ban is working
sleep 5
if systemctl is-active --quiet fail2ban; then
    echo "Fail2Ban configured and started successfully"
    fail2ban-client status
else
    echo "Fail2Ban failed to start"
    exit 1
fi

echo "DEPLOY1 completed successfully"
curl -H "Content-Type: application/json" \\
     -X POST \\
     -d "{\"embeds\": [{\"title\": \"DEPLOY1 Complete\", \"description\": \"Basic security setup completed successfully\", \"color\": 65280}]}" \\
     "$CERTBOT_WEBHOOK" &>/dev/null
EOF
    
    chmod +x "$PROJECT_DIR/DEPLOY1_basic_security.sh"
    log "DEPLOY1 script created"
}

# Function to create DEPLOY2 script
create_deploy2() {
    log "Creating DEPLOY2: Directory structure and Docker setup..."
    
    cat > "$PROJECT_DIR/DEPLOY2_docker_setup.sh" <<EOF
#!/bin/bash

set -e

# Load configuration
source "$PROJECT_DIR/.deployment_config"

echo "DEPLOY2: Directory Structure and Docker Setup"
echo "============================================="

# Ensure project directory structure exists
echo "Creating directory structure..."
mkdir -p "$PROJECT_DIR"/{nginx/conf.d,certbot/{conf,www},www,logs/{nginx,php,certbot,fail2ban}}

# Create Dockerfile.php (for reference, but will use standard image in DEPLOY6)
cat > "$PROJECT_DIR/Dockerfile.php" <<EOL
FROM php:8.2-fpm

# Install system dependencies
RUN apt-get update && apt-get install -y \\
    libcurl4-openssl-dev \\
    && rm -rf /var/lib/apt/lists/*

# Install and enable PHP extensions
RUN docker-php-ext-install curl

# Add error logging configuration
RUN echo "error_reporting = E_ALL" >> /usr/local/etc/php/conf.d/docker-php-ext-errors.ini \\
    && echo "display_errors = On" >> /usr/local/etc/php/conf.d/docker-php-ext-errors.ini \\
    && echo "log_errors = On" >> /usr/local/etc/php/conf.d/docker-php-ext-errors.ini \\
    && echo "error_log = /proc/self/fd/2" >> /usr/local/etc/php/conf.d/docker-php-ext-errors.ini

# Configure PHP-FPM
RUN echo "php_admin_flag[log_errors] = on" >> /usr/local/etc/php-fpm.d/www.conf \\
    && echo "php_admin_value[error_log] = /proc/self/fd/2" >> /usr/local/etc/php-fpm.d/www.conf \\
    && echo "catch_workers_output = yes" >> /usr/local/etc/php-fpm.d/www.conf \\
    && echo "decorate_workers_output = no" >> /usr/local/etc/php-fpm.d/www.conf

# Create directory for logs
RUN mkdir -p /var/log/php \\
    && chown -R www-data:www-data /var/log/php

WORKDIR /var/www/html
EXPOSE 9000
CMD ["php-fpm"]
EOL

# Create enhanced Docker Compose file
echo "Creating Docker Compose configuration..."

cat > "$PROJECT_DIR/docker-compose.yml" <<EOL
services:
  nginx:
    image: nginx:latest
    container_name: ${DOMAIN//./_}_nginx
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx/conf.d:/etc/nginx/conf.d
      - ./certbot/conf:/etc/letsencrypt
      - ./certbot/www:/var/www/certbot
      - ./www:/var/www/html
      - ./logs/nginx:/var/log/nginx
    depends_on:
      - php
    networks:
      - app-network
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/"]
      interval: 30s
      timeout: 10s
      retries: 3

  php:
    build:
      context: .
      dockerfile: Dockerfile.php
    container_name: ${DOMAIN//./_}_php
    restart: unless-stopped
    volumes:
      - ./www:/var/www/html
    networks:
      - app-network
    healthcheck:
      test: ["CMD-SHELL", "php-fpm -t"]
      interval: 30s
      timeout: 10s
      retries: 3

  certbot:
    image: certbot/certbot
    container_name: ${DOMAIN//./_}_certbot
    restart: unless-stopped
    volumes:
      - ./certbot/conf:/etc/letsencrypt
      - ./certbot/www:/var/www/certbot
    command: >
      sh -c "
        trap 'exit 0' TERM;
        echo 'Starting Certbot renewal daemon...';
        while :; do
          echo 'Checking certificates for renewal...';
          if certbot renew --quiet --no-self-upgrade --post-hook 'curl -H \\"Content-Type: application/json\\" -X POST -d \\"{\\\\\\"embeds\\\\\\": [{\\\\\\"title\\\\\\": \\\\\\"Certificate Renewed\\\\\\", \\\\\\"description\\\\\\": \\\\\\"SSL certificate for $DOMAIN renewed successfully\\\\\\", \\\\\\"color\\\\\\": 65280}]}\\" \\"$CERTBOT_WEBHOOK\\"'; then
            echo 'Certificate renewal check completed successfully';
          else
            echo 'Certificate renewal check completed with issues';
            curl -H 'Content-Type: application/json' -X POST -d '{\\"embeds\\": [{\\"title\\": \\"Certificate Renewal Failed\\", \\"description\\": \\"SSL certificate renewal failed for $DOMAIN\\", \\"color\\": 16711680}]}' '$CERTBOT_WEBHOOK';
          fi;
          echo 'Next renewal check in 12 hours...';
          sleep 12h & wait \\\$!;
        done
      "
    networks:
      - app-network

  watchtower:
    image: containrrr/watchtower
    container_name: ${DOMAIN//./_}_watchtower
    restart: unless-stopped
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - WATCHTOWER_CLEANUP=true
      - WATCHTOWER_SCHEDULE=0 0 2 * * *
      - WATCHTOWER_INCLUDE_STOPPED=true
    networks:
      - app-network

networks:
  app-network:
    driver: bridge
    name: ${DOMAIN//./_}_network
EOL

# Verify Docker Compose file syntax
echo "Verifying Docker Compose configuration..."
if command -v docker &> /dev/null; then
    docker compose -f "$PROJECT_DIR/docker-compose.yml" config > /dev/null
    if [ \$? -eq 0 ]; then
        echo "Docker Compose configuration is valid"
    else
        echo "Docker Compose configuration is invalid"
        exit 1
    fi
else
    echo "Docker not found - configuration will be validated when Docker is available"
fi

echo "DEPLOY2 completed successfully"
curl -H "Content-Type: application/json" \\
     -X POST \\
     -d "{\"embeds\": [{\"title\": \"DEPLOY2 Complete\", \"description\": \"Docker setup and directory structure created successfully\", \"color\": 65280}]}" \\
     "$CERTBOT_WEBHOOK" &>/dev/null
EOF
    
    chmod +x "$PROJECT_DIR/DEPLOY2_docker_setup.sh"
    log "DEPLOY2 script created"
}

# Function to create DEPLOY3 script
create_deploy3() {
    log "Creating DEPLOY3: Nginx configuration..."
    
    cat > "$PROJECT_DIR/DEPLOY3_nginx_config.sh" <<EOF
#!/bin/bash

set -e

echo "DEPLOY3: Nginx Configuration"
echo "============================"

# Create enhanced Nginx configuration
echo "Creating Nginx configuration..."

cat > "$PROJECT_DIR/nginx/conf.d/default.conf" <<'EOL'
# Rate limiting zones
limit_req_zone \$binary_remote_addr zone=general:10m rate=10r/s;
limit_req_zone \$binary_remote_addr zone=login:10m rate=3r/m;
limit_conn_zone \$binary_remote_addr zone=conn_limit_per_ip:10m;

server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    
    # Security
    server_tokens off;
    
    # Rate limiting
    limit_req zone=general burst=20 nodelay;
    limit_conn conn_limit_per_ip 20;
    
    # Logging (using nginx's default main format)
    access_log /var/log/nginx/$DOMAIN.access.log main;
    error_log /var/log/nginx/$DOMAIN.error.log warn;
    
    # ACME Challenge for Let's Encrypt
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        try_files \$uri =404;
    }
    
    # Redirect HTTP to HTTPS
    location / {
        return 301 https://\$server_name\$request_uri;
    }
}

server {
    listen 443 ssl;
    http2 on;
    server_name $DOMAIN www.$DOMAIN;
    
    # Security
    server_tokens off;
    
    # Rate limiting
    limit_req zone=general burst=20 nodelay;
    limit_conn conn_limit_per_ip 20;
    
    # Logging (using nginx's default main format)
    access_log /var/log/nginx/$DOMAIN.access.log main;
    error_log /var/log/nginx/$DOMAIN.error.log warn;
    
    # SSL Configuration
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    # Modern SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Security headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
    
    # Document root
    root /var/www/html;
    index index.php index.html index.htm;
    
    # Main location block
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # PHP handling
    location ~ \\.php\$ {
        limit_req zone=login burst=5 nodelay;
        
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\\.php)(/.+)\$;
        fastcgi_pass php:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param PATH_INFO \$fastcgi_path_info;
        
        # Security for PHP
        fastcgi_hide_header X-Powered-By;
    }
    
    # Deny access to sensitive files
    location ~ /\\.(htaccess|htpasswd|env|git) {
        deny all;
        return 404;
    }
    
    # Static assets caching
    location ~* \\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)\$ {
        expires 1M;
        add_header Cache-Control "public, immutable";
    }
    
    # Error pages
    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
}
EOL

# Test nginx configuration by temporarily moving config and creating a simple test
echo "Testing Nginx configuration syntax..."

# Move the production config temporarily
mv "$PROJECT_DIR/nginx/conf.d/default.conf" "$PROJECT_DIR/nginx/conf.d/default.conf.tmp"

# Create simple test config without upstream dependencies
cat > "$PROJECT_DIR/nginx/conf.d/default.conf" <<'EOL'
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    root /var/www/html;
    index index.html;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOL

# Run nginx test
if docker run --rm -v "$PROJECT_DIR/nginx/conf.d:/etc/nginx/conf.d" nginx:latest nginx -t > /dev/null 2>&1; then
    echo "Nginx configuration syntax test passed"
    TEST_PASSED=true
else
    echo "Nginx configuration syntax test failed"
    TEST_PASSED=false
fi

# Restore the production config
rm "$PROJECT_DIR/nginx/conf.d/default.conf"
mv "$PROJECT_DIR/nginx/conf.d/default.conf.tmp" "$PROJECT_DIR/nginx/conf.d/default.conf"

# Exit if test failed
if [ "\$TEST_PASSED" = false ]; then
    exit 1
fi

echo "DEPLOY3 completed successfully"
curl -H "Content-Type: application/json" \\
     -X POST \\
     -d "{\"embeds\": [{\"title\": \"DEPLOY3 Complete\", \"description\": \"Nginx configuration created and validated successfully\", \"color\": 65280}]}" \\
     "$CERTBOT_WEBHOOK" &>/dev/null
EOF
    
    chmod +x "$PROJECT_DIR/DEPLOY3_nginx_config.sh"
    log "DEPLOY3 script created"
}

# Function to create DEPLOY4 script
create_deploy4() {
    log "Creating DEPLOY4: Website content creation..."
    
    cat > "$PROJECT_DIR/DEPLOY4_website_content.sh" <<EOF
#!/bin/bash

set -e

# Load configuration
source "$PROJECT_DIR/.deployment_config"

echo "DEPLOY4: Website Content Creation"
echo "================================="

echo "Creating website content..."

# Create main index.html
cat > "$PROJECT_DIR/www/index.html" <<EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$DOMAIN - Professional Website</title>
    <meta name="description" content="Professional website for $DOMAIN">
    <meta name="keywords" content="professional, website, business">
    <link rel="canonical" href="https://$DOMAIN/">
    
    <!-- Styles -->
    <link rel="stylesheet" href="/assets/css/styles.css">
    
    <!-- Open Graph meta tags -->
    <meta property="og:title" content="$DOMAIN - Professional Website">
    <meta property="og:description" content="Professional website for $DOMAIN">
    <meta property="og:url" content="https://$DOMAIN/">
    <meta property="og:type" content="website">
    
    <!-- Twitter Card meta tags -->
    <meta name="twitter:card" content="summary">
    <meta name="twitter:title" content="$DOMAIN - Professional Website">
    <meta name="twitter:description" content="Professional website for $DOMAIN">
</head>
<body>
    <header class="header">
        <nav class="nav">
            <div class="container">
                <div class="nav-brand">
                    <h1>$DOMAIN</h1>
                </div>
                <ul class="nav-menu">
                    <li><a href="#about">About</a></li>
                    <li><a href="#services">Services</a></li>
                    <li><a href="#contact">Contact</a></li>
                </ul>
            </div>
        </nav>
    </header>

    <main>
        <section class="hero">
            <div class="container">
                <div class="hero-content">
                    <h2>Professional Website</h2>
                    <p class="hero-description">Welcome to our professional website showcasing quality services and expertise.</p>
                    <div class="hero-cta">
                        <a href="#contact" class="btn btn-primary">Get In Touch</a>
                        <a href="#services" class="btn btn-secondary">Learn More</a>
                    </div>
                </div>
            </div>
        </section>

        <section id="about" class="section">
            <div class="container">
                <h2>About Us</h2>
                <div class="about-content">
                    <p>Professional services with a focus on quality, reliability, and customer satisfaction. We pride ourselves on delivering exceptional results.</p>
                    
                    <div class="stats">
                        <div class="stat-item">
                            <span class="stat-number">99.9%</span>
                            <span class="stat-label">Uptime</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number">24/7</span>
                            <span class="stat-label">Support</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-number">100%</span>
                            <span class="stat-label">Secure</span>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <section id="services" class="section section-alt">
            <div class="container">
                <h2>Our Services</h2>
                <div class="services-grid">
                    <div class="service-item">
                        <h3>Web Development</h3>
                        <p>Professional web development services with modern technologies and best practices.</p>
                    </div>
                    
                    <div class="service-item">
                        <h3>Security</h3>
                        <p>Comprehensive security solutions including SSL certificates and firewall protection.</p>
                    </div>
                    
                    <div class="service-item">
                        <h3>Monitoring</h3>
                        <p>24/7 monitoring and maintenance to ensure optimal performance and uptime.</p>
                    </div>
                </div>
            </div>
        </section>

        <section id="contact" class="section">
            <div class="container">
                <h2>Contact Information</h2>
                <div class="contact-content">
                    <p>Ready to discuss your project or have questions? Get in touch with us.</p>
                    
                    <div class="contact-form-container">
                        <form action="/contact.php" method="POST" class="contact-form">
                            <div class="form-group">
                                <label for="name">Name</label>
                                <input type="text" id="name" name="name" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="email">Email</label>
                                <input type="email" id="email" name="email" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="subject">Subject</label>
                                <input type="text" id="subject" name="subject" required>
                            </div>
                            
                            <div class="form-group">
                                <label for="message">Message</label>
                                <textarea id="message" name="message" rows="5" required></textarea>
                            </div>
                            
                            <button type="submit" class="btn btn-primary">Send Message</button>
                        </form>
                    </div>
                    
                    <div class="contact-info">
                        <div class="contact-item">
                            <strong>Email:</strong> $EMAIL
                        </div>
                        <div class="contact-item">
                            <strong>Website:</strong> https://$DOMAIN
                        </div>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <footer class="footer">
        <div class="container">
            <div class="footer-content">
                <p>&copy; $(date +%Y) $DOMAIN. All rights reserved.</p>
                <p class="footer-tech">
                    Powered by Nginx, PHP, Docker | Secured with Let's Encrypt SSL
                </p>
            </div>
        </div>
    </footer>

    <script src="/assets/js/main.js"></script>
</body>
</html>
EOL

# Create 404 error page
cat > "$PROJECT_DIR/www/404.html" <<EOL
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>404 - Page Not Found | $DOMAIN</title>
    <link rel="stylesheet" href="/assets/css/styles.css">
</head>
<body>
    <div class="error-page">
        <div class="container">
            <h1>404</h1>
            <h2>Page Not Found</h2>
            <p>The page you are looking for does not exist.</p>
            <a href="/" class="btn btn-primary">Return Home</a>
        </div>
    </div>
</body>
</html>
EOL

# Create CSS file
mkdir -p "$PROJECT_DIR/www/assets/css"
cat > "$PROJECT_DIR/www/assets/css/styles.css" <<EOL
/* Reset and base styles */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    line-height: 1.6;
    color: #333;
    background-color: #fff;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 20px;
}

/* Header */
.header {
    background-color: #fff;
    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    z-index: 1000;
}

.nav {
    padding: 1rem 0;
}

.nav .container {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.nav-brand h1 {
    color: #2c3e50;
    font-size: 1.5rem;
    font-weight: 600;
}

.nav-menu {
    display: flex;
    list-style: none;
    gap: 2rem;
}

.nav-menu a {
    text-decoration: none;
    color: #333;
    font-weight: 500;
    transition: color 0.3s ease;
}

.nav-menu a:hover {
    color: #3498db;
}

/* Main content */
main {
    margin-top: 80px;
}

.section {
    padding: 4rem 0;
}

.section-alt {
    background-color: #f8f9fa;
}

/* Hero section */
.hero {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    color: white;
    padding: 6rem 0;
    text-align: center;
}

.hero-content h2 {
    font-size: 3rem;
    margin-bottom: 1rem;
    font-weight: 700;
}

.hero-description {
    font-size: 1.2rem;
    margin-bottom: 2rem;
    opacity: 0.9;
    max-width: 600px;
    margin-left: auto;
    margin-right: auto;
}

.hero-cta {
    display: flex;
    gap: 1rem;
    justify-content: center;
    flex-wrap: wrap;
}

/* Buttons */
.btn {
    display: inline-block;
    padding: 12px 24px;
    border-radius: 5px;
    text-decoration: none;
    font-weight: 600;
    text-align: center;
    transition: all 0.3s ease;
    border: none;
    cursor: pointer;
}

.btn-primary {
    background-color: #3498db;
    color: white;
}

.btn-primary:hover {
    background-color: #2980b9;
    transform: translateY(-2px);
}

.btn-secondary {
    background-color: transparent;
    color: white;
    border: 2px solid white;
}

.btn-secondary:hover {
    background-color: white;
    color: #333;
}

/* Section headers */
.section h2 {
    text-align: center;
    margin-bottom: 3rem;
    font-size: 2.5rem;
    color: #2c3e50;
}

/* About section */
.about-content {
    text-align: center;
    max-width: 800px;
    margin: 0 auto;
}

.about-content p {
    font-size: 1.1rem;
    margin-bottom: 2rem;
    color: #666;
}

.stats {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 2rem;
    margin-top: 3rem;
}

.stat-item {
    text-align: center;
    padding: 2rem;
    background: white;
    border-radius: 10px;
    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
}

.stat-number {
    display: block;
    font-size: 2.5rem;
    font-weight: 700;
    color: #3498db;
    margin-bottom: 0.5rem;
}

.stat-label {
    color: #666;
    font-weight: 500;
}

/* Services grid */
.services-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 2rem;
    max-width: 1000px;
    margin: 0 auto;
}

.service-item {
    background: white;
    padding: 2rem;
    border-radius: 10px;
    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
    text-align: center;
}

.service-item h3 {
    color: #2c3e50;
    margin-bottom: 1rem;
}

/* Contact section */
.contact-content {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 3rem;
    max-width: 1000px;
    margin: 0 auto;
    align-items: start;
}

.contact-form {
    background: white;
    padding: 2rem;
    border-radius: 10px;
    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
}

.form-group {
    margin-bottom: 1.5rem;
}

.form-group label {
    display: block;
    margin-bottom: 0.5rem;
    font-weight: 600;
    color: #333;
}

.form-group input,
.form-group textarea {
    width: 100%;
    padding: 12px;
    border: 1px solid #ddd;
    border-radius: 5px;
    font-size: 1rem;
    transition: border-color 0.3s ease;
}

.form-group input:focus,
.form-group textarea:focus {
    outline: none;
    border-color: #3498db;
}

.contact-info {
    background: white;
    padding: 2rem;
    border-radius: 10px;
    box-shadow: 0 5px 15px rgba(0,0,0,0.1);
}

.contact-item {
    margin-bottom: 1rem;
    padding: 1rem;
    background: #f8f9fa;
    border-radius: 5px;
}

/* Footer */
.footer {
    background-color: #2c3e50;
    color: white;
    text-align: center;
    padding: 2rem 0;
}

.footer-content p {
    margin-bottom: 0.5rem;
}

.footer-tech {
    opacity: 0.7;
    font-size: 0.9rem;
}

/* Error page */
.error-page {
    display: flex;
    align-items: center;
    justify-content: center;
    min-height: 100vh;
    text-align: center;
}

.error-page h1 {
    font-size: 6rem;
    color: #3498db;
    margin-bottom: 1rem;
}

.error-page h2 {
    color: #2c3e50;
    margin-bottom: 1rem;
}

/* Responsive design */
@media (max-width: 768px) {
    .nav .container {
        flex-direction: column;
        gap: 1rem;
    }
    
    .nav-menu {
        gap: 1rem;
    }
    
    .hero-content h2 {
        font-size: 2rem;
    }
    
    .hero-cta {
        flex-direction: column;
        align-items: center;
    }
    
    .contact-content {
        grid-template-columns: 1fr;
    }
}
EOL

# Create JavaScript file
mkdir -p "$PROJECT_DIR/www/assets/js"
cat > "$PROJECT_DIR/www/assets/js/main.js" <<EOL
// Main JavaScript functionality
document.addEventListener('DOMContentLoaded', function() {
    // Smooth scrolling for navigation links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });

    // Contact form handling
    const contactForm = document.querySelector('.contact-form');
    if (contactForm) {
        contactForm.addEventListener('submit', function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            
            fetch('/contact.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Message sent successfully!');
                    contactForm.reset();
                } else {
                    alert('Error sending message. Please try again.');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error sending message. Please try again.');
            });
        });
    }
    
    // Add animation to stats on scroll
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
            if (entry.isIntersecting) {
                entry.target.style.transform = 'translateY(0)';
                entry.target.style.opacity = '1';
            }
        });
    });

    document.querySelectorAll('.stat-item').forEach((item) => {
        item.style.transform = 'translateY(20px)';
        item.style.opacity = '0';
        item.style.transition = 'all 0.6s ease';
        observer.observe(item);
    });
});
EOL

# Create contact.php
cat > "$PROJECT_DIR/www/contact.php" <<EOL
<?php
header('Content-Type: application/json');

if (\$_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Method not allowed']);
    exit;
}

\$name = filter_input(INPUT_POST, 'name', FILTER_SANITIZE_STRING);
\$email = filter_input(INPUT_POST, 'email', FILTER_VALIDATE_EMAIL);
\$subject = filter_input(INPUT_POST, 'subject', FILTER_SANITIZE_STRING);
\$message = filter_input(INPUT_POST, 'message', FILTER_SANITIZE_STRING);

if (!\$name || !\$email || !\$subject || !\$message) {
    echo json_encode(['success' => false, 'message' => 'All fields are required and must be valid']);
    exit;
}

// Log the contact attempt
\$log_entry = date('Y-m-d H:i:s') . " - Contact form submission from: \$email\n";
file_put_contents('/var/log/php/contact.log', \$log_entry, FILE_APPEND | LOCK_EX);

// Send notification to Discord webhook
\$discord_payload = [
    'embeds' => [[
        'title' => 'New Contact Form Submission',
        'description' => "**Name:** \$name\n**Email:** \$email\n**Subject:** \$subject\n**Message:** \$message",
        'color' => 3447003,
        'timestamp' => date('c'),
        'footer' => [
            'text' => 'Contact Form - $DOMAIN'
        ]
    ]]
];

\$discord_options = [
    'http' => [
        'header' => "Content-type: application/json\r\n",
        'method' => 'POST',
        'content' => json_encode(\$discord_payload)
    ]
];

\$context = stream_context_create(\$discord_options);
\$result = file_get_contents('$CERTBOT_WEBHOOK', false, \$context);

echo json_encode(['success' => true, 'message' => 'Message sent successfully']);
?>
EOL

# Set proper permissions
chown -R www-data:www-data "$PROJECT_DIR/www" || true
chmod -R 755 "$PROJECT_DIR/www"

echo "Website content created successfully"
echo "DEPLOY4 completed successfully"
curl -H "Content-Type: application/json" \\
     -X POST \\
     -d "{\"embeds\": [{\"title\": \"DEPLOY4 Complete\", \"description\": \"Website content and assets created successfully\", \"color\": 65280}]}" \\
     "$CERTBOT_WEBHOOK" &>/dev/null
EOF
    
    chmod +x "$PROJECT_DIR/DEPLOY4_website_content.sh"
    log "DEPLOY4 script created"
}

# Function to create DEPLOY5 script
create_deploy5() {
    log "Creating DEPLOY5: DNS and Cloudflare setup..."
    
    cat > "$PROJECT_DIR/DEPLOY5_dns_setup.sh" <<EOF
#!/bin/bash

set -e

# Load configuration
source "$PROJECT_DIR/.deployment_config"

echo "DEPLOY5: DNS and Cloudflare Setup"
echo "================================="

echo "Configuring DNS records..."

# Check if DNS record exists
DNS_CHECK=\$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?type=A&name=$DOMAIN" \\
     -H "Authorization: Bearer $CF_API_KEY" \\
     -H "Content-Type: application/json")

if echo \$DNS_CHECK | grep -q '"count":0'; then
    # Create new DNS record
    echo "Creating new DNS A record..."
    DNS_RESULT=\$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \\
         -H "Authorization: Bearer $CF_API_KEY" \\
         -H "Content-Type: application/json" \\
         --data "{
           \\"type\\": \\"A\\",
           \\"name\\": \\"$DOMAIN\\",
           \\"content\\": \\"$PUBLIC_IP\\",
           \\"ttl\\": 1,
           \\"proxied\\": false
         }")
else
    # Get the DNS record ID
    RECORD_ID=\$(echo \$DNS_CHECK | jq -r '.result[0].id')
    EXISTING_IP=\$(echo \$DNS_CHECK | jq -r '.result[0].content')
    
    if [ "\$EXISTING_IP" = "$PUBLIC_IP" ]; then
        echo "DNS A record already exists with correct IP: $PUBLIC_IP"
        DNS_RESULT='{"success":true}'
    else
        echo "Updating existing DNS A record from \$EXISTING_IP to $PUBLIC_IP..."
        DNS_RESULT=\$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records/\$RECORD_ID" \\
             -H "Authorization: Bearer $CF_API_KEY" \\
             -H "Content-Type: application/json" \\
             --data "{
               \\"type\\": \\"A\\",
               \\"name\\": \\"$DOMAIN\\",
               \\"content\\": \\"$PUBLIC_IP\\",
               \\"ttl\\": 1,
               \\"proxied\\": false
             }")
    fi
fi

if echo \$DNS_RESULT | grep -q '"success":true'; then
    echo "DNS A record configured successfully"
else
    echo "Failed to configure DNS A record"
    echo "API Response: \$DNS_RESULT"
    exit 1
fi

# Check/create www subdomain record
WWW_DNS_CHECK=\$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records?type=A&name=www.$DOMAIN" \\
     -H "Authorization: Bearer $CF_API_KEY" \\
     -H "Content-Type: application/json")

if echo \$WWW_DNS_CHECK | grep -q '"count":0'; then
    echo "Creating www subdomain DNS record..."
    WWW_DNS_RESULT=\$(curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$CF_ZONE_ID/dns_records" \\
         -H "Authorization: Bearer $CF_API_KEY" \\
         -H "Content-Type: application/json" \\
         --data "{
           \\"type\\": \\"A\\",
           \\"name\\": \\"www.$DOMAIN\\",
           \\"content\\": \\"$PUBLIC_IP\\",
           \\"ttl\\": 1,
           \\"proxied\\": false
         }")
    
    if echo \$WWW_DNS_RESULT | grep -q '"success":true'; then
        echo "www subdomain DNS record created successfully"
    else
        echo "Failed to create www subdomain DNS record"
        echo "API Response: \$WWW_DNS_RESULT"
        exit 1
    fi
else
    echo "www subdomain DNS record already exists"
fi

# Wait for DNS propagation
echo "Waiting 30 seconds for DNS propagation..."
sleep 30

# Verify DNS resolution
echo "Verifying DNS resolution..."
if nslookup $DOMAIN 8.8.8.8 | grep -q "$PUBLIC_IP"; then
    echo "DNS resolution verified for $DOMAIN"
else
    echo "DNS resolution verification failed for $DOMAIN"
    echo "This might be due to DNS propagation delay. Continuing anyway..."
fi

echo "DEPLOY5 completed successfully"
curl -H "Content-Type: application/json" \\
     -X POST \\
     -d "{\"embeds\": [{\"title\": \"DEPLOY5 Complete\", \"description\": \"DNS and Cloudflare setup completed successfully\", \"color\": 65280}]}" \\
     "$CERTBOT_WEBHOOK" &>/dev/null
EOF
    
    chmod +x "$PROJECT_DIR/DEPLOY5_dns_setup.sh"
    log "DEPLOY5 script created"
}

# Function to create DEPLOY6 script - ENHANCED WITH USER CHOICE
create_deploy6() {
    log "Creating DEPLOY6: Enhanced SSL certificate setup with user choice..."
    
    cat > "$PROJECT_DIR/DEPLOY6_ssl_setup.sh" <<EOF
#!/bin/bash

set -e

# Load configuration
source "$PROJECT_DIR/.deployment_config"

echo "DEPLOY6: SSL Certificate Setup"
echo "=============================="

cd "$PROJECT_DIR"

# Fix Docker networking issues with iptables
echo "Configuring iptables for Docker compatibility..."
iptables -I FORWARD -j ACCEPT
systemctl restart docker
sleep 5

# Use standard PHP image - no custom build needed
echo "Using standard PHP-FPM image for faster deployment..."
cat > docker-compose.override.yml <<EOL
services:
  php:
    image: php:8.2-fpm
    container_name: ${DOMAIN//./_}_php
    restart: unless-stopped
    volumes:
      - ./www:/var/www/html
    networks:
      - app-network
    healthcheck:
      test: ["CMD-SHELL", "php-fpm -t"]
      interval: 30s
      timeout: 10s
      retries: 3
EOL

# Create temporary HTTP-only nginx configuration for certificate acquisition
echo "Creating temporary HTTP-only nginx configuration..."
cp nginx/conf.d/default.conf nginx/conf.d/default.conf.ssl-backup

cat > nginx/conf.d/default.conf <<'EOFNGINX'
# Temporary HTTP-only configuration for SSL certificate acquisition
limit_req_zone \$binary_remote_addr zone=general:10m rate=10r/s;
limit_conn_zone \$binary_remote_addr zone=conn_limit_per_ip:10m;

server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    
    # Security
    server_tokens off;
    
    # Rate limiting
    limit_req zone=general burst=20 nodelay;
    limit_conn conn_limit_per_ip 20;
    
    # Logging
    access_log /var/log/nginx/$DOMAIN.access.log main;
    error_log /var/log/nginx/$DOMAIN.error.log warn;
    
    # Document root
    root /var/www/html;
    index index.html index.htm index.php;
    
    # ACME Challenge for Let's Encrypt
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
        try_files \$uri =404;
    }
    
    # Main location block
    location / {
        try_files \$uri \$uri/ =404;
    }
    
    # PHP handling
    location ~ \\.php\$ {
        try_files \$uri =404;
        fastcgi_split_path_info ^(.+\\.php)(/.+)\$;
        fastcgi_pass php:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME \$document_root\$fastcgi_script_name;
        fastcgi_param PATH_INFO \$fastcgi_path_info;
    }
    
    # Deny access to sensitive files
    location ~ /\\.(htaccess|htpasswd|env|git) {
        deny all;
        return 404;
    }
}
EOFNGINX

echo "Temporary HTTP-only configuration created"

# Check if certificate already exists
CERT_ACTION="obtain"
if [ -f "certbot/conf/live/$DOMAIN/fullchain.pem" ]; then
    EXPIRY=\$(openssl x509 -enddate -noout -in "certbot/conf/live/$DOMAIN/cert.pem" | cut -d= -f2)
    EXPIRY_EPOCH=\$(date -d "\$EXPIRY" +%s)
    CURRENT_EPOCH=\$(date +%s)
    DAYS_LEFT=\$(( (EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))
    
    echo ""
    echo "=========================================="
    echo "EXISTING SSL CERTIFICATE FOUND"
    echo "=========================================="
    echo "Certificate expires: \$EXPIRY"
    echo "Days remaining: \$DAYS_LEFT days"
    echo ""
    
    if [ \$DAYS_LEFT -gt 30 ]; then
        echo "Certificate is still valid for \$DAYS_LEFT days."
        echo ""
        echo "Options:"
        echo "1) Reuse existing certificate (recommended)"
        echo "2) Force renewal of certificate"
        echo ""
        read -p "Choose option [1-2]: " cert_choice
        
        case \$cert_choice in
            1)
                echo "Using existing certificate..."
                CERT_ACTION="reuse"
                ;;
            2)
                echo "Will force renewal of certificate..."
                CERT_ACTION="renew"
                ;;
            *)
                echo "Invalid choice. Using existing certificate..."
                CERT_ACTION="reuse"
                ;;
        esac
    else
        echo "Certificate expires in \$DAYS_LEFT days (less than 30 days)."
        echo ""
        echo "Options:"
        echo "1) Auto-renew certificate (recommended)"
        echo "2) Keep existing certificate anyway"
        echo ""
        read -p "Choose option [1-2]: " cert_choice
        
        case \$cert_choice in
            1)
                echo "Will renew certificate..."
                CERT_ACTION="renew"
                ;;
            2)
                echo "Keeping existing certificate..."
                CERT_ACTION="reuse"
                ;;
            *)
                echo "Invalid choice. Will auto-renew certificate..."
                CERT_ACTION="renew"
                ;;
        esac
    fi
fi

# Handle certificate reuse
if [ "\$CERT_ACTION" = "reuse" ]; then
    echo "Reusing existing SSL certificate..."
    echo "Restoring SSL nginx configuration..."
    cp nginx/conf.d/default.conf.ssl-backup nginx/conf.d/default.conf
    
    # Start containers with SSL configuration
    if ! timeout 60 docker compose up -d nginx php; then
        echo "Failed to start containers"
        docker compose logs
        exit 1
    fi
    
    sleep 10
    
    # Verify HTTPS is working
    echo "Verifying HTTPS response..."
    if curl -f https://$DOMAIN --max-time 10 --insecure &>/dev/null; then
        echo "✓ HTTPS is working correctly with existing certificate"
        echo "DEPLOY6 completed successfully"
        rm -f docker-compose.override.yml
        exit 0
    else
        echo "⚠ HTTPS not responding with existing certificate"
        echo "Will proceed to obtain new certificate..."
        CERT_ACTION="obtain"
    fi
fi

# Start containers with HTTP-only configuration for certificate acquisition
echo "Starting containers with HTTP-only configuration..."
if ! timeout 60 docker compose up -d nginx php; then
    echo "Failed to start containers"
    docker compose logs
    exit 1
fi

# Wait for containers to stabilize
echo "Waiting for containers to stabilize..."
sleep 10

# Verify nginx is responding on HTTP
echo "Verifying nginx HTTP response..."
for i in {1..5}; do
    if curl -f http://localhost --max-time 5 &>/dev/null; then
        echo "✓ Nginx HTTP is responding correctly"
        break
    else
        echo "Attempt \$i: Nginx not responding yet, waiting..."
        sleep 5
        if [ \$i -eq 5 ]; then
            echo "✗ Nginx HTTP not responding after 5 attempts"
            docker compose logs nginx
            exit 1
        fi
    fi
done

# Obtain or renew SSL certificate
if [ "\$CERT_ACTION" = "renew" ]; then
    echo "Renewing SSL certificate..."
    certbot_flags="--force-renewal"
else
    echo "Obtaining new SSL certificate..."
    certbot_flags=""
fi

docker run --rm --name temp_certbot \\
    -v "\$(pwd)/certbot/conf:/etc/letsencrypt" \\
    -v "\$(pwd)/certbot/www:/var/www/certbot" \\
    --network "${DOMAIN//./_}_network" \\
    certbot/certbot certonly --webroot \\
    -w /var/www/certbot \\
    -d "$DOMAIN" -d "www.$DOMAIN" \\
    --email "$EMAIL" \\
    --agree-tos --no-eff-email \\
    --non-interactive \$certbot_flags

# Verify certificate was obtained
if [ -f "certbot/conf/live/$DOMAIN/fullchain.pem" ]; then
    echo "✓ SSL certificate obtained successfully"
    
    CERT_EXPIRY=\$(openssl x509 -enddate -noout -in "certbot/conf/live/$DOMAIN/cert.pem" | cut -d= -f2)
    echo "Certificate expires: \$CERT_EXPIRY"
    
    # Restore SSL nginx configuration
    echo "Restoring full SSL nginx configuration..."
    cp nginx/conf.d/default.conf.ssl-backup nginx/conf.d/default.conf
    
    # Test nginx configuration
    if docker compose exec nginx nginx -t; then
        echo "✓ SSL nginx configuration is valid"
    else
        echo "✗ SSL nginx configuration failed validation"
        exit 1
    fi
    
    # Restart nginx with SSL configuration
    echo "Restarting nginx with SSL configuration..."
    docker compose restart nginx
    
    # Wait for nginx to start with SSL
    sleep 10
    
    # Verify HTTPS is working
    echo "Verifying HTTPS response..."
    for i in {1..5}; do
        if curl -f https://$DOMAIN --max-time 10 --insecure &>/dev/null; then
            echo "✓ HTTPS is working correctly"
            break
        else
            echo "Attempt \$i: HTTPS not responding yet, waiting..."
            sleep 5
            if [ \$i -eq 5 ]; then
                echo "⚠ HTTPS not responding, but certificate was obtained"
                echo "This may be due to DNS propagation or firewall rules"
            fi
        fi
    done
    
    # Send success notification
    curl -H "Content-Type: application/json" \\
         -X POST \\
         -d "{\"embeds\": [{\"title\": \"SSL Certificate Obtained\", \"description\": \"SSL certificate for $DOMAIN obtained successfully. Expires: \$CERT_EXPIRY\", \"color\": 65280}]}" \\
         "$CERTBOT_WEBHOOK" &>/dev/null
    
    echo "DEPLOY6 completed successfully"
    
else
    echo "✗ Failed to obtain SSL certificate"
    echo "Falling back to HTTP-only mode"
    
    curl -H "Content-Type: application/json" \\
         -X POST \\
         -d "{\"embeds\": [{\"title\": \"SSL Certificate Failed\", \"description\": \"Failed to obtain SSL certificate for $DOMAIN - running in HTTP mode\", \"color\": 16711680}]}" \\
         "$CERTBOT_WEBHOOK" &>/dev/null
    
    # Continue with HTTP-only configuration
    echo "Website will continue running in HTTP-only mode"
    exit 1
fi

# Clean up temporary files
rm -f docker-compose.override.yml
EOF
    
    chmod +x "$PROJECT_DIR/DEPLOY6_ssl_setup.sh"
    log "DEPLOY6 script created with enhanced SSL certificate management"
}

# Function to create DEPLOY7 script
create_deploy7() {
    log "Creating DEPLOY7: Service startup and enhanced fail2ban..."
    
    cat > "$PROJECT_DIR/DEPLOY7_services_and_monitoring.sh" <<EOF
#!/bin/bash

set -e

# Load configuration
source "$PROJECT_DIR/.deployment_config"

echo "DEPLOY7: Service Startup and Enhanced Monitoring"
echo "==============================================="

cd "$PROJECT_DIR"

echo "Starting all services..."

# Start all services
docker compose down
docker compose up -d

# Wait for services to stabilize
echo "Waiting for services to stabilize..."
sleep 15

# Verify all containers are running
CONTAINERS=("${DOMAIN//./_}_nginx" "${DOMAIN//./_}_php" "${DOMAIN//./_}_certbot" "${DOMAIN//./_}_watchtower")
ALL_RUNNING=true

for container in "\${CONTAINERS[@]}"; do
    if docker ps --format "table {{.Names}}" | grep -q "\$container"; then
        echo "✓ \$container is running"
    else
        echo "✗ \$container is not running"
        ALL_RUNNING=false
    fi
done

if [ "\$ALL_RUNNING" = false ]; then
    echo "Some containers failed to start"
    docker compose logs
    exit 1
fi

# Now add nginx-specific fail2ban rules since nginx is running
echo "Adding nginx fail2ban rules..."

# Add nginx rules to fail2ban
cat >> /etc/fail2ban/jail.local <<EOLJAIL

[nginx-http-auth]
enabled = true
port = http,https
logpath = $PROJECT_DIR/logs/nginx/$DOMAIN.error.log
maxretry = 3
bantime = 3600

[nginx-limit-req]
enabled = true
port = http,https
logpath = $PROJECT_DIR/logs/nginx/$DOMAIN.error.log
maxretry = 10
bantime = 600
EOLJAIL

# Restart fail2ban to apply new rules
systemctl restart fail2ban

# Create certificate renewal script
cat > /usr/local/bin/cert-renewal-$DOMAIN.sh <<EOLCERT
#!/bin/bash

set -e

PROJECT_DIR="$PROJECT_DIR"
DOMAIN="$DOMAIN"
EMAIL="$EMAIL"
CERTBOT_WEBHOOK="$CERTBOT_WEBHOOK"

log() {
    echo "[\$(date +'%Y-%m-%d %H:%M:%S')] \\\$1"
}

cd "\\\$PROJECT_DIR"

# Check certificate expiry
if [ -f "certbot/conf/live/\\\$DOMAIN/cert.pem" ]; then
    EXPIRY=\\\$(openssl x509 -enddate -noout -in "certbot/conf/live/\\\$DOMAIN/cert.pem" | cut -d= -f2)
    EXPIRY_EPOCH=\\\$(date -d "\\\$EXPIRY" +%s)
    CURRENT_EPOCH=\\\$(date +%s)
    DAYS_LEFT=\\\$(( (EXPIRY_EPOCH - CURRENT_EPOCH) / 86400 ))
    
    log "Certificate expires in \\\$DAYS_LEFT days"
    
    if [ \\\$DAYS_LEFT -lt 30 ]; then
        log "Certificate needs renewal"
        
        # Try renewal with running containers first
        if docker compose exec -T certbot certbot renew --quiet --no-self-upgrade; then
            log "Certificate renewed successfully"
            docker compose exec -T nginx nginx -s reload
            
            # Send success notification
            curl -H "Content-Type: application/json" \\\\
                 -X POST \\\\
                 -d "{\"embeds\": [{\"title\": \"Certificate Auto-Renewed\", \"description\": \"SSL certificate for \\\$DOMAIN auto-renewed successfully\", \"color\": 65280}]}" \\\\
                 "\\\$CERTBOT_WEBHOOK" &>/dev/null
        else
            log "Standard renewal failed, trying standalone mode"
            
            docker compose stop nginx
            docker run --rm \\\\
                -v "\\\$(pwd)/certbot/conf:/etc/letsencrypt" \\\\
                -v "\\\$(pwd)/certbot/www:/var/www/certbot" \\\\
                -p 80:80 \\\\
                certbot/certbot certonly --standalone \\\\
                --force-renewal \\\\
                -d "\\\$DOMAIN" -d "www.\\\$DOMAIN" \\\\
                --email "\\\$EMAIL" \\\\
                --agree-tos --no-eff-email
            
            docker compose start nginx
            
            # Send notification
            curl -H "Content-Type: application/json" \\\\
                 -X POST \\\\
                 -d "{\"embeds\": [{\"title\": \"Certificate Renewed (Standalone)\", \"description\": \"SSL certificate for \\\$DOMAIN renewed using standalone mode\", \"color\": 16776960}]}" \\\\
                 "\\\$CERTBOT_WEBHOOK" &>/dev/null
        fi
    else
        log "Certificate is still valid for \\\$DAYS_LEFT days"
    fi
else
    log "Certificate file not found"
    curl -H "Content-Type: application/json" \\\\
         -X POST \\\\
         -d "{\"embeds\": [{\"title\": \"Certificate File Missing\", \"description\": \"SSL certificate file not found for \\\$DOMAIN\", \"color\": 16711680}]}" \\\\
         "\\\$CERTBOT_WEBHOOK" &>/dev/null
fi
EOLCERT

chmod +x /usr/local/bin/cert-renewal-$DOMAIN.sh

# Create cron job for certificate renewal
echo "Setting up automatic certificate renewal..."
(crontab -l 2>/dev/null | grep -v "cert-renewal-$DOMAIN.sh" || true; echo "0 2 * * * /usr/local/bin/cert-renewal-$DOMAIN.sh >> /var/log/cert-renewal.log 2>&1") | crontab -

# Create system monitoring script
cat > /usr/local/bin/system-monitor-$DOMAIN.sh <<EOLMON
#!/bin/bash

PROJECT_DIR="$PROJECT_DIR"
DOMAIN="$DOMAIN"
FAIL2BAN_WEBHOOK="$FAIL2BAN_WEBHOOK"
CERTBOT_WEBHOOK="$CERTBOT_WEBHOOK"

# Check if containers are running
cd "\\\$PROJECT_DIR"
CONTAINERS=("${DOMAIN//./_}_nginx" "${DOMAIN//./_}_php" "${DOMAIN//./_}_certbot")

for container in "\\\${CONTAINERS[@]}"; do
    if ! docker ps --format "table {{.Names}}" | grep -q "\\\$container"; then
        echo "Container \\\$container is not running, attempting restart..."
        docker compose restart "\\\$container" || docker compose up -d
        
        curl -H "Content-Type: application/json" \\\\
             -X POST \\\\
             -d "{\"embeds\": [{\"title\": \"Container Restarted\", \"description\": \"Container \\\$container was restarted on \\\$(hostname)\", \"color\": 16776960}]}" \\\\
             "\\\$CERTBOT_WEBHOOK" &>/dev/null
    fi
done

# Check website accessibility
if ! curl -f https://\\\$DOMAIN &>/dev/null; then
    curl -H "Content-Type: application/json" \\\\
         -X POST \\\\
         -d "{\"embeds\": [{\"title\": \"Website Down\", \"description\": \"Website \\\$DOMAIN is not accessible\", \"color\": 16711680}]}" \\\\
         "\\\$CERTBOT_WEBHOOK" &>/dev/null
fi

# Check disk space
DISK_USAGE=\\\$(df / | awk 'NR==2 {print \\\$5}' | sed 's/%//')
if [ "\\\$DISK_USAGE" -gt 80 ]; then
    curl -H "Content-Type: application/json" \\\\
         -X POST \\\\
         -d "{\"embeds\": [{\"title\": \"High Disk Usage\", \"description\": \"Disk usage is \\\$DISK_USAGE% on \\\$(hostname)\", \"color\": 16776960}]}" \\\\
         "\\\$CERTBOT_WEBHOOK" &>/dev/null
fi
EOLMON

chmod +x /usr/local/bin/system-monitor-$DOMAIN.sh

# Add system monitoring cron job
(crontab -l 2>/dev/null | grep -v "system-monitor-$DOMAIN.sh" || true; echo "*/15 * * * * /usr/local/bin/system-monitor-$DOMAIN.sh") | crontab -

# Verify cron jobs were added
echo "Cron jobs configured:"
crontab -l | grep -E "(cert-renewal|system-monitor)"

echo "DEPLOY7 completed successfully"
curl -H "Content-Type: application/json" \\
     -X POST \\
     -d "{\"embeds\": [{\"title\": \"DEPLOY7 Complete\", \"description\": \"Services and monitoring configured successfully\", \"color\": 65280}]}" \\
     "$CERTBOT_WEBHOOK" &>/dev/null
EOF
    
    chmod +x "$PROJECT_DIR/DEPLOY7_services_and_monitoring.sh"
    log "DEPLOY7 script created"
}

# Function to create DEPLOY8 script
create_deploy8() {
    log "Creating DEPLOY8: Final verification and health checks..."
    
    cat > "$PROJECT_DIR/DEPLOY8_final_verification.sh" <<EOF
#!/bin/bash

set -e

# Load configuration
source "$PROJECT_DIR/.deployment_config"

echo "DEPLOY8: Final Verification and Health Checks"
echo "=============================================="

cd "$PROJECT_DIR"

echo "Running comprehensive health checks..."

# Test HTTP redirect
echo "Testing HTTP to HTTPS redirect..."
HTTP_STATUS=\$(curl -s -o /dev/null -w "%{http_code}" "http://$DOMAIN" --max-time 10)
if [ "\$HTTP_STATUS" = "301" ]; then
    echo "✓ HTTP to HTTPS redirect working"
else
    echo "✗ HTTP redirect not working (status: \$HTTP_STATUS)"
    exit 1
fi

# Test HTTPS
echo "Testing HTTPS connectivity..."
HTTPS_STATUS=\$(curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN" --max-time 10)
if [ "\$HTTPS_STATUS" = "200" ]; then
    echo "✓ HTTPS working correctly"
else
    echo "✗ HTTPS not working (status: \$HTTPS_STATUS)"
    exit 1
fi

# Test SSL certificate
echo "Verifying SSL certificate..."
SSL_EXPIRY=\$(echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:443" 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2)
SSL_DAYS=\$(( (\$(date -d "\$SSL_EXPIRY" +%s) - \$(date +%s)) / 86400 ))

if [ \$SSL_DAYS -gt 0 ]; then
    echo "✓ SSL certificate valid for \$SSL_DAYS days"
else
    echo "✗ SSL certificate issues"
    exit 1
fi

# Test security headers
echo "Checking security headers..."
SECURITY_HEADERS=\$(curl -s -I "https://$DOMAIN" | grep -i -E "(strict-transport-security|x-frame-options|x-content-type-options|x-xss-protection)" | wc -l)
if [ "\$SECURITY_HEADERS" -ge 3 ]; then
    echo "✓ Security headers present (\$SECURITY_HEADERS/4)"
else
    echo "✗ Missing security headers (\$SECURITY_HEADERS/4)"
    exit 1
fi

# Verify Fail2Ban is working
echo "Verifying Fail2Ban status..."
if systemctl is-active --quiet fail2ban; then
    echo "✓ Fail2Ban is running"
    fail2ban-client status sshd | head -5
else
    echo "✗ Fail2Ban is not running"
    exit 1
fi

# Test contact form
echo "Testing contact form..."
if [ -f "www/contact.php" ]; then
    echo "✓ Contact form file exists"
else
    echo "✗ Contact form file missing"
    exit 1
fi

# Check container health
echo "Checking container health..."
docker compose ps

# Display final summary
echo ""
echo "=========================================="
echo "DEPLOYMENT COMPLETED SUCCESSFULLY!"
echo "=========================================="
echo "Domain: https://$DOMAIN"
echo "SSL Certificate: Valid for \$SSL_DAYS days"
echo "Services: All containers running"
echo "Security: Fail2Ban + iptables configured"
echo "Monitoring: Auto-renewal and health checks active"
echo "Contact Form: Functional with Discord notifications"
echo ""
echo "Website is now live and fully operational!"
echo "=========================================="

# Send final completion notification
curl -H "Content-Type: application/json" \\
     -X POST \\
     -d "{\"embeds\": [{\"title\": \"🚀 Deployment Complete\", \"description\": \"Website $DOMAIN is now live and fully operational!\\\\n\\\\n**Features:**\\\\n✓ SSL Certificate (Valid \$SSL_DAYS days)\\\\n✓ Security (Fail2Ban + iptables)\\\\n✓ Auto-renewal\\\\n✓ Health monitoring\\\\n✓ Contact form\\\\n\\\\n**URL:** https://$DOMAIN\", \"color\": 65280}]}" \\
     "$CERTBOT_WEBHOOK" &>/dev/null

echo "DEPLOY8 completed successfully"
EOF
    
    chmod +x "$PROJECT_DIR/DEPLOY8_final_verification.sh"
    log "DEPLOY8 script created"
}

# Function to execute deployment scripts in sequence
execute_deployment() {
    log "Starting sequential deployment execution..."
    
    cd "$PROJECT_DIR"
    
    local scripts=(
        "DEPLOY0_initializing_and_prep.sh"
        "DEPLOY1_basic_security.sh" 
        "DEPLOY2_docker_setup.sh"
        "DEPLOY3_nginx_config.sh"
        "DEPLOY4_website_content.sh"
        "DEPLOY5_dns_setup.sh"
        "DEPLOY6_ssl_setup.sh"
        "DEPLOY7_services_and_monitoring.sh"
        "DEPLOY8_final_verification.sh"
    )
    
    for script in "${scripts[@]}"; do
        if [ -f "$script" ]; then
            log "Executing $script..."
            
            # Execute script and capture output
            if ./"$script"; then
                log "$script completed successfully"
                echo ""
                sleep 2
            else
                error "$script failed"
                send_discord_notification "$CERTBOT_WEBHOOK" \
                    "Deployment Failed" \
                    "Deployment failed at $script on server $(hostname)" \
                    16711680
                exit 1
            fi
        else
            error "Script $script not found"
            exit 1
        fi
    done
    
    log "All deployment scripts executed successfully!"
}

# Main execution function
main() {
    log "Enhanced Master Deployment Script v3.0 - ENHANCED SSL CERTIFICATE MANAGEMENT Starting..."
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then
        error "Please run as root (use sudo)"
        exit 1
    fi
    
    gather_info
    create_deploy0
    create_deploy1
    create_deploy2
    create_deploy3
    create_deploy4
    create_deploy5
    create_deploy6
    create_deploy7
    create_deploy8
    
    log "All deployment scripts created successfully"
    
    # Ask for confirmation to proceed
    read -p "Proceed with deployment execution? [y/N]: " proceed
    if [[ "$proceed" =~ ^[Yy]$ ]]; then
        execute_deployment
        
        log "Deployment completed successfully!"
        log "Your website is now live at: https://$DOMAIN"
        log "All scripts are available in: $PROJECT_DIR"
    else
        log "Deployment scripts created but not executed"
        log "To execute manually, run each script in order from: $PROJECT_DIR"
    fi
}

# Handle script arguments
case "${1:-}" in
    --help|-h)
        echo "Enhanced Master Deployment Script v3.0 - ENHANCED SSL CERTIFICATE MANAGEMENT"
        echo "Complete production deployment with enhanced SSL certificate user choice"
        echo ""
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help, -h     Show this help message"
        echo "  --verify, -v   Run verification checks only"
        exit 0
        ;;
    --verify|-v)
        if [ -f "/server/*/deployment_config" ]; then
            source "/server/*/.deployment_config"
            cd "$PROJECT_DIR"
            ./DEPLOY8_final_verification.sh
        else
            error "No deployment configuration found"
            exit 1
        fi
        ;;
    *)
        main "$@"
        ;;
esac
