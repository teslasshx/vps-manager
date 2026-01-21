#!/bin/bash

# TeslaSSH VPS Panel Installer
# Silent & Animated Installation

set -e
export DEBIAN_FRONTEND=noninteractive

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

LOG_FILE="/tmp/teslassh_install.log"
LIMITER_SCRIPT="/usr/local/bin/limiter.sh"
LIMITER_SERVICE="/etc/systemd/system/firewallfalcon-limiter.service"



clear
echo ""
echo "--------------------------------------------------------"
echo -e "${GREEN}           TeslaSSH VPS-Manager Installer   ${NC}"
echo "--------------------------------------------------------"
#Ask for license key
read -p "Enter your license key: " LICENSE_KEY

#Check if license key is valid
if [ -z "$LICENSE_KEY" ]; then
    echo -e "${RED}License key is required.${NC}"
    exit 1
fi

validate_license() {
    local key="$1"
    
    # Ensure curl is installed for validation
    if ! command -v curl &> /dev/null; then
        if command -v apt-get &> /dev/null; then
            apt-get update -y &> /dev/null
            apt-get install -y curl &> /dev/null
        elif command -v yum &> /dev/null; then
            yum install -y curl &> /dev/null
        fi
    fi

    # --- NEW VALIDATION API ---
    local VALIDATION_URL="https://xapi.coley.dpdns.org/validate-key?key=$key"
    
    # We use a GET request as specified by the user
    local response=$(curl -s -L "$VALIDATION_URL")
    
    if [[ "$response" == *"\"valid\":true"* ]]; then
        return 0
    else
        return 1
    fi
}

echo -ne "${BLUE}==>${NC} Validating license..."
if validate_license "$LICENSE_KEY"; then
    echo -e "${GREEN} Success!${NC}"
else
    echo -e "${RED} Invalid license key or validation server unreachable.${NC}"
    exit 1
fi



rm -f "$LOG_FILE"

# --- UI Functions ---

hide_cursor() {
    echo -ne "\033[?25l"
}

show_cursor() {
    echo -ne "\033[?25h"
}

cleanup_exit() {
    show_cursor
}
trap cleanup_exit EXIT

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

# Arguments: "Description" "Function/Command"
run_step() {
    local message="$1"
    shift
    
    echo -ne "${BLUE}==>${NC} ${message}..."
    
    # Run command in background, redirecting all output to log
    # We use a subshell to ensure complex commands work
    ( "$@" ) >> "$LOG_FILE" 2>&1 &
    local pid=$!
    
    spinner $pid
    
    wait $pid
    local exit_code=$?
    
    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN} Done!${NC}"
    else
        echo -e "${RED} Failed!${NC}"
        echo -e "${RED}Check $LOG_FILE for details.${NC}"
        exit 1
    fi
}

# --- Logic Functions ---

pre_check() {
    if [[ $EUID -ne 0 ]]; then
       echo "This script must be run as root" 
       exit 1
    fi

    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
    else
        echo "Cannot detect OS. Exiting."
        exit 1
    fi
}

cleanup_services() {
    rm -rf /opt/teslassh/users.json
    
    # Stop & Disable
    local services=(teslassh hysteria-server udp-custom UDPserver dnstt falconproxy v2ray wg-quick@wg0)
    for svc in "${services[@]}"; do
        systemctl stop "$svc" || true
        systemctl disable "$svc" || true
    done
}

install_dependencies() {
    if [[ "$OS" == *"Ubuntu"* ]] || [[ "$OS" == *"Debian"* ]]; then
        apt-get update -y
        apt-get install -y wireguard curl wget openssl iptables-persistent wireguard-tools iptables resolvconf qrencode jq
    elif [[ "$OS" == *"CentOS"* ]]; then
        yum install -y epel-release elrepo-release
        yum install -y wireguard-tools curl wget openssl jq
    fi
}

configure_wireguard() {
    # Detect IP
    SERVER_PUB_IP=$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)
    if [[ -z ${SERVER_PUB_IP} ]]; then
        SERVER_PUB_IP=$(ip -6 addr | sed -ne 's|^.* inet6 \([^/]*\)/.* scope global.*$|\1|p' | head -1)
    fi
    if [[ -z ${SERVER_PUB_IP} ]]; then
        SERVER_PUB_IP="127.0.0.1"
    fi

    mkdir -p /etc/wireguard
    chmod 600 -R /etc/wireguard/

    # Generate Keys
    SERVER_PRIV_KEY=$(wg genkey)
    SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)
    SERVER_PUB_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"

    # Configs
    SERVER_WG_NIC="wg0"
    SERVER_WG_IPV4="10.66.66.1"
    SERVER_WG_IPV6="fd42:42:42::1"
    SERVER_PORT="9201"
    CLIENT_DNS_1="1.1.1.1"
    CLIENT_DNS_2="1.0.0.1"
    ALLOWED_IPS="0.0.0.0/0,::/0"

    cat > /etc/wireguard/params <<EOF
SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_WG_IPV6=${SERVER_WG_IPV6}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
ALLOWED_IPS=${ALLOWED_IPS}
EOF

    cat > /etc/wireguard/${SERVER_WG_NIC}.conf <<EOF
[Interface]
Address = ${SERVER_WG_IPV4}/24,${SERVER_WG_IPV6}/64
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}
EOF

    # Firewall Rules
    if pgrep firewalld; then
        FIREWALLD_IPV4_ADDRESS=$(echo "${SERVER_WG_IPV4}" | cut -d"." -f1-3)".0"
        FIREWALLD_IPV6_ADDRESS=$(echo "${SERVER_WG_IPV6}" | sed 's/:[^:]*$/:0/')
        cat >> /etc/wireguard/${SERVER_WG_NIC}.conf <<EOF2
PostUp = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --add-port ${SERVER_PORT}/udp && firewall-cmd --add-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --add-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
PostDown = firewall-cmd --zone=public --add-interface=${SERVER_WG_NIC} && firewall-cmd --remove-port ${SERVER_PORT}/udp && firewall-cmd --remove-rich-rule='rule family=ipv4 source address=${FIREWALLD_IPV4_ADDRESS}/24 masquerade' && firewall-cmd --remove-rich-rule='rule family=ipv6 source address=${FIREWALLD_IPV6_ADDRESS}/24 masquerade'
EOF2
    else
        cat >> /etc/wireguard/${SERVER_WG_NIC}.conf <<EOF2
PostUp = iptables -I INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostUp = ip6tables -I FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostUp = ip6tables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D INPUT -p udp --dport ${SERVER_PORT} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = ip6tables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT
PostDown = ip6tables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
EOF2
    fi

    # Forwarding
    echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" > /etc/sysctl.d/wg.conf
    sysctl --system

    # Start
    ip link delete ${SERVER_WG_NIC} 2>/dev/null || true
    systemctl enable wg-quick@${SERVER_WG_NIC}
    systemctl restart wg-quick@${SERVER_WG_NIC}

    # UFW
    if command -v ufw >/dev/null; then
        ufw allow ${SERVER_PORT}/udp
        ufw allow 36712/udp
    fi
}

install_panel() {
    INSTALL_DIR="/opt/teslassh"
    mkdir -p $INSTALL_DIR

    if [ -f "teslassh-linux" ]; then
        rm -f $INSTALL_DIR/teslassh
        mv teslassh-linux $INSTALL_DIR/teslassh
        chmod +x $INSTALL_DIR/teslassh
    else
        wget "https://www.dropbox.com/scl/fi/hde648odew4p8hf8h2n51/teslassh-linux?rlkey=52ri5e0f9yrwsi8nwtu75ybn0&st=91n321l4&dl=1" -O teslassh-linux
        mv teslassh-linux $INSTALL_DIR/teslassh
        chmod +x $INSTALL_DIR/teslassh
    fi

    # Credentials
    ADMIN_USER="admin"
    ADMIN_PASS=$(openssl rand -base64 12)

    echo "${ADMIN_USER}
${ADMIN_PASS}" > $INSTALL_DIR/.init_creds
    chmod 600 $INSTALL_DIR/.init_creds

    # Service
    cat <<EOF > /etc/systemd/system/teslassh.service
[Unit]
Description=TeslaSSH Panel
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/teslassh
Restart=always
Environment="WG_CONFIG=/etc/wireguard/wg0.conf"
Environment="LICENSE_KEY=$LICENSE_KEY"
Environment="PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable teslassh
    systemctl restart teslassh

    # NAT Rules for Protocols 
    SERVER_PORT="9201" #wireguard
    NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    UDP_CUSTOM_PORT=":36712"


    iptables -t nat -I PREROUTING -p udp --dport 53 -j RETURN
    iptables -t nat -I PREROUTING -p udp --dport 5300 -j RETURN
    iptables -t nat -I PREROUTING -p udp --dport ${SERVER_PORT} -j RETURN
    ip6tables -t nat -I PREROUTING -p udp --dport ${SERVER_PORT} -j RETURN

    iptables -t nat -A PREROUTING -p udp --dport 1:1288 -j DNAT --to-destination $UDP_CUSTOM_PORT
    ip6tables -t nat -A PREROUTING -p udp --dport 1:1288 -j DNAT --to-destination $UDP_CUSTOM_PORT 
    
    sysctl net.ipv4.conf.all.rp_filter=0
    NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    sysctl net.ipv4.conf.$NIC.rp_filter=0
    echo "net.ipv4.conf.all.rp_filter=0
net.ipv4.conf.$NIC.rp_filter=0" >> /etc/sysctl.conf
    
    netfilter-persistent save

    # Export credentials for display later
    echo "ADMIN_USER='${ADMIN_USER}'" > /tmp/teslassh_creds
    echo "ADMIN_PASS='${ADMIN_PASS}'" >> /tmp/teslassh_creds
    echo "SERVER_PUB_IP='$(ip -4 addr | sed -ne 's|^.* inet \([^/]*\)/.* scope global.*$|\1|p' | awk '{print $1}' | head -1)'" >> /tmp/teslassh_creds
}

# --- Protocol Installers ---

# --- ZiVPN Variables ---
ZIVPN_DIR="/etc/zivpn"
ZIVPN_BIN="/usr/local/bin/zivpn"
ZIVPN_SERVICE_FILE="/etc/systemd/system/zivpn.service"
ZIVPN_CONFIG_FILE="$ZIVPN_DIR/config.json"
ZIVPN_CERT_FILE="$ZIVPN_DIR/zivpn.crt"
ZIVPN_KEY_FILE="$ZIVPN_DIR/zivpn.key"

# --- ZiVPN Installation Logic ---
install_zivpn() { 
    if [ -f "$ZIVPN_SERVICE_FILE" ]; then
        echo -e "\nZiVPN is already installed."
        return
    fi
    local arch=$(uname -m)
    local zivpn_url=""
    
    if [[ "$arch" == "x86_64" ]]; then
        zivpn_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-amd64"

    elif [[ "$arch" == "aarch64" ]]; then
        zivpn_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm64"

    elif [[ "$arch" == "armv7l" || "$arch" == "arm" ]]; then
         zivpn_url="https://github.com/zahidbd2/udp-zivpn/releases/download/udp-zivpn_1.4.9/udp-zivpn-linux-arm"

    else
        echo -e "❌ Unsupported architecture: $arch"
        return
    fi

    if ! wget -q --show-progress -O "$ZIVPN_BIN" "$zivpn_url"; then
        return
    fi
    chmod +x "$ZIVPN_BIN"
    mkdir -p "$ZIVPN_DIR"
    
    # Generate Certificates
    echo -e "🔐 Generating self-signed certificates..."
    if ! command -v openssl &>/dev/null; then apt-get install -y openssl &>/dev/null; fi
    
    openssl req -new -newkey rsa:4096 -days 365 -nodes -x509 \
        -subj "/C=US/ST=California/L=Los Angeles/O=Example Corp/OU=IT Department/CN=zivpn" \
        -keyout "$ZIVPN_KEY_FILE" -out "$ZIVPN_CERT_FILE" 2>/dev/null

    if [ ! -f "$ZIVPN_CERT_FILE" ]; then
        echo -e "❌ Failed to generate certificates."
        return
    fi

    # System Tuning
    sysctl -w net.core.rmem_max=16777216 >/dev/null
    sysctl -w net.core.wmem_max=16777216 >/dev/null

    # Create Service
    cat <<EOF > "$ZIVPN_SERVICE_FILE"
[Unit]
Description=zivpn Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$ZIVPN_DIR
ExecStart=$ZIVPN_BIN server -c $ZIVPN_CONFIG_FILE
Restart=always
RestartSec=3
Environment=ZIVPN_LOG_LEVEL=info
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

    # Configure Passwords 
    input_config="teslasshx,tedhackwell"
    
    if [ -n "$input_config" ]; then
        IFS=',' read -r -a config_array <<< "$input_config"
        # Ensure array format for JSON
        json_passwords=$(printf '"%s",' "${config_array[@]}")
        json_passwords="[${json_passwords%,}]"
    else
        json_passwords='["zi"]'
    fi

    # Create Config File
    cat <<EOF > "$ZIVPN_CONFIG_FILE"
{
  "listen": ":5667",
   "cert": "$ZIVPN_CERT_FILE",
   "key": "$ZIVPN_KEY_FILE",
   "obfs":"zivpn",
   "auth": {
    "mode": "passwords", 
    "config": $json_passwords
  }
}
EOF

    systemctl daemon-reload
    systemctl enable zivpn.service
    systemctl start zivpn.service

    
    # Determine primary interface
    local iface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)
    
    if [ -n "$iface" ]; then
        iptables -t nat -A PREROUTING -i "$iface" -p udp --dport 6000:19999 -j DNAT --to-destination :5667
        # Note: IPTables rules are not persistent by default without iptables-persistent package
    else
        echo ""
    fi

    if command -v ufw &>/dev/null; then
        ufw allow 6000:19999/udp >/dev/null
        ufw allow 5667/udp >/dev/null
        ufw allow 5667/tcp >/dev/null
    fi

    # Cleanup
    rm -f zi.sh zi2.sh 2>/dev/null

    if systemctl is-active --quiet zivpn.service; then
        echo -e "\nZiVPN Installed Successfully!"
        echo -e "   - UDP Port: 5667 (Direct)"
        echo -e "   - UDP Ports: 6000-19999 (Forwarded)"
    else
        echo -e "ZiVPN Service failed to start."
    fi
}


setup_limiter_service() {
    # TeslaSSH SSH/WS User Limiter
    cat > "$LIMITER_SCRIPT" << 'EOF'
#!/bin/bash
DB_FILE="/etc/firewallfalcon/users.db"

while true; do
    if [[ ! -f "$DB_FILE" ]]; then sleep 10; continue; fi
    
    current_ts=$(date +%s)
    while IFS=: read -r user pass expiry limit; do
        [[ -z "$user" || "$user" == \#* ]] && continue
        
        # --- 1. Expiry Check ---
        expiry_ts=$(date -d "$expiry" +%s 2>/dev/null || echo 0)
        if [[ $expiry_ts -lt $current_ts && $expiry_ts -ne 0 ]]; then
            ! passwd -S "$user" | grep -q " L " && usermod -L "$user" &>/dev/null
            killall -u "$user" -9 &>/dev/null
            continue
        fi
        
        # --- 2. Connection Limit Check ---
        ssh_count=$(pgrep -u "$user" sshd | wc -l)
        [[ ! "$limit" =~ ^[0-9]+$ ]] && limit=2
        
        if [[ "$ssh_count" -gt "$limit" ]]; then
            if ! passwd -S "$user" | grep -q " L "; then
                usermod -L "$user" &>/dev/null
                killall -u "$user" -9 &>/dev/null
                (sleep 120; usermod -U "$user" &>/dev/null) & 
            else
                killall -u "$user" -9 &>/dev/null
            fi
        fi
    done < "$DB_FILE"
    
    sleep 3
done
EOF
    chmod +x "$LIMITER_SCRIPT"

    cat > "$LIMITER_SERVICE" << EOF
[Unit]
Description=TeslaSSH Unified Protocol Limiter
After=network.target

[Service]
Type=simple
ExecStart=$LIMITER_SCRIPT
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable firewallfalcon-limiter &>/dev/null
    systemctl restart firewallfalcon-limiter &>/dev/null
}


install_udp_custom() {
    UDP_CUSTOM_DIR="/root/udp"
    UDP_CUSTOM_SERVICE="/etc/systemd/system/udp-custom.service"
    
    systemctl stop udp-custom || true
    
    mkdir -p "$UDP_CUSTOM_DIR"
    ARCH=$(uname -m)
    if [[ "$ARCH" == "x86_64" ]]; then
        URL="https://raw.githubusercontent.com/Haris131/UDP-Custom/main/udp-custom-linux-amd64"
    elif [[ "$ARCH" == "aarch64" ]]; then
        URL="https://raw.githubusercontent.com/Haris131/UDP-Custom/main/udp-custom-linux-arm64"
    else
        return 0 # Skip unsupported
    fi
    
    wget -q -O "$UDP_CUSTOM_DIR/udp-custom" "$URL"
    chmod +x "$UDP_CUSTOM_DIR/udp-custom"
    
    cat > "$UDP_CUSTOM_DIR/config.json" <<EOF
{
  "listen": ":36712",
  "stream_buffer": 33554432,
  "receive_buffer": 83886080,
  "auth": {
    "mode": "passwords"
  }
}
EOF
    
    cat > "$UDP_CUSTOM_SERVICE" <<EOF
[Unit]
Description=UDP Custom Service
After=network.target

[Service]
User=root
Type=simple
ExecStart=$UDP_CUSTOM_DIR/udp-custom server -exclude 53, 5300, 1289-65535
WorkingDirectory=$UDP_CUSTOM_DIR/
Restart=always
RestartSec=2s

[Install]
WantedBy=default.target
EOF

    systemctl daemon-reload
    systemctl enable udp-custom
    systemctl start udp-custom
}

install_dnstt() {
    DNSTT_BIN="/usr/local/bin/dnstt-server"
    DNSTT_SERVICE="/etc/systemd/system/dnstt.service"
    DNSTT_KEYS="/etc/dnstt/keys"
    
    systemctl stop dnstt || true
    
    mkdir -p $(dirname "$DNSTT_KEYS")
    
    ARCH=$(uname -m)
    if [[ "$ARCH" == "x86_64" ]]; then
        URL="https://dnstt.network/dnstt-server-linux-amd64"
    elif [[ "$ARCH" == "aarch64" ]]; then
        URL="https://dnstt.network/dnstt-server-linux-arm64"
    else
        return 0
    fi
    
    wget -q -O "$DNSTT_BIN" "$URL"
    chmod +x "$DNSTT_BIN"
    
    mkdir -p "$DNSTT_KEYS"
    "$DNSTT_BIN" -gen-key -privkey-file "$DNSTT_KEYS/server.key" -pubkey-file "$DNSTT_KEYS/server.pub"
    
    cat > "$DNSTT_SERVICE" <<EOF
[Unit]
Description=DNSTT Server
After=network.target
[Service]
Type=simple
User=root
ExecStart=$DNSTT_BIN -udp :5300 -privkey-file $DNSTT_KEYS/server.key example.com 127.0.0.1:22
Restart=always
RestartSec=3
[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
}

install_v2ray() {
    bash <(curl -L https://raw.githubusercontent.com/v2fly/fhs-install-v2ray/master/install-release.sh)
    mkdir -p /var/log/v2ray
    # Ensure v2ray can write to logs
    touch /var/log/v2ray/access.log
    chmod 666 /var/log/v2ray/access.log
    systemctl enable v2ray
    systemctl start v2ray
}

install_falcon_proxy() {
    # Falcon Proxy Core
    FP_BIN="/usr/local/bin/falconproxy"
    FP_SERVICE="/etc/systemd/system/falconproxy.service"
    
    # Clean up old Python Service if it exists
    systemctl stop ssh-ws || true
    systemctl disable ssh-ws || true
    rm -f /etc/systemd/system/ssh-ws.service
    rm -f /usr/local/bin/ws_proxy.py

    ARCH=$(uname -m)
    if [[ "$ARCH" == "x86_64" ]]; then
       URL="https://github.com/firewallfalcons/FirewallFalcon-Manager/releases/download/v1.2-RustFast/falconproxy" 
    elif [[ "$ARCH" == "aarch64" ]]; then
       URL="https://github.com/firewallfalcons/FirewallFalcon-Manager/releases/download/v1.2-RustFast/falconproxyarm"
    else
        return 0
    fi

    wget -q -O "$FP_BIN" "$URL"
    chmod +x "$FP_BIN"

    if grep -q "t.me/firewallfalcons" "$FP_BIN"; then
        sed -i 's|t.me/firewallfalcons|t.me/teslasshx      |g' "$FP_BIN"
    fi
    
    cat > "$FP_SERVICE" <<EOF
[Unit]
Description=Proxy core (SSH-WS)
After=network.target

[Service]
User=root
Type=simple
ExecStart=$FP_BIN -p 8080
Restart=always
RestartSec=2s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable falconproxy
    systemctl restart falconproxy
}

install_udp_request() {
    BIN_PATH="/usr/bin/udpServer"
    SERVICE_FILE="/etc/systemd/system/UDPserver.service"

    systemctl stop UDPserver || true
    wget -q -O "$BIN_PATH" 'https://bitbucket.org/iopmx/udprequestserver/downloads/udpServer'
    chmod +x "$BIN_PATH"
    
    IP=$(curl -s https://api.ipify.org || echo "127.0.0.1") 
    ETH=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

    EXCLUDE_LOW="1-1288"
    EXCLUDE_Others="9201,5300,53,36712,5667,6000-19999"
    
    cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=UDP Request Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root
ExecStart=$BIN_PATH -ip=$IP -net=$ETH -exclude=$EXCLUDE_LOW,$EXCLUDE_Others -mode=system
Restart=always
RestartSec=3s

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable UDPserver
    systemctl restart UDPserver
}

install_badvpn() {
    BADVPN_BUILD_DIR="/tmp/badvpn_build"
    BADVPN_SERVICE_FILE="/etc/systemd/system/badvpn.service"

    # Cleanup if exists
    rm -rf "$BADVPN_BUILD_DIR"
    
    # Dependencies
    apt-get install -y cmake g++ make screen git build-essential libssl-dev libnspr4-dev libnss3-dev pkg-config

    # Clone & Build
    git clone https://github.com/ambrop72/badvpn.git "$BADVPN_BUILD_DIR"
    if [ ! -d "$BADVPN_BUILD_DIR" ]; then
        echo "Failed to clone badvpn"
        return 1
    fi
    
    cd "$BADVPN_BUILD_DIR"
    cmake .
    make
    
    badvpn_binary=$(find "$BADVPN_BUILD_DIR" -name "badvpn-udpgw" -type f | head -n 1)
    if [[ -z "$badvpn_binary" || ! -f "$badvpn_binary" ]]; then
        echo "Error: badvpn binary not found"
        rm -rf "$BADVPN_BUILD_DIR"
        return 1
    fi

    mv "$badvpn_binary" /usr/local/bin/badvpn-udpgw
    chmod +x /usr/local/bin/badvpn-udpgw
    rm -rf "$BADVPN_BUILD_DIR"

    # Service
    cat > "$BADVPN_SERVICE_FILE" <<EOF
[Unit]
Description=BadVPN UDP Gateway
After=network.target

[Service]
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 0.0.0.0:7300 --max-clients 1000 --max-connections-for-client 999 --loglevel 3
User=root
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable badvpn
    systemctl start badvpn

    # Firewall
    if command -v ufw >/dev/null; then
        ufw allow 7300/udp
    fi
    
    if pgrep firewalld; then
        firewall-cmd --zone=public --add-port=7300/udp --permanent
        firewall-cmd --reload
    else
        iptables -I INPUT -p udp --dport 7300 -j ACCEPT
        if command -v netfilter-persistent >/dev/null; then
            netfilter-persistent save
        fi
    fi
}


install_nginx() {
    if ! command -v nginx >/dev/null; then
        apt-get update && apt-get install -y nginx
    fi
     
    mkdir -p /etc/ssl/certs /etc/ssl/private
    if [ ! -f /etc/ssl/certs/nginx-selfsigned.pem ]; then
         openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
            -keyout /etc/ssl/private/nginx-selfsigned.key \
            -out /etc/ssl/certs/nginx-selfsigned.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
    fi

    cat > /etc/nginx/sites-available/default <<'EOF'
map $http_upgrade $backend_upstream {
    default http://127.0.0.1:2082;
    "~*websocket" http://127.0.0.1:8080;
}

server {
    listen 80;
    listen [::]:80;
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    ssl_certificate /etc/ssl/certs/nginx-selfsigned.pem;
    ssl_certificate_key /etc/ssl/private/nginx-selfsigned.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    server_name _;

    location /vless {
        if ($http_upgrade != "websocket") {
            return 404;
        }
        proxy_redirect off;
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass $backend_upstream;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 86400;
        proxy_send_timeout 86400;
        proxy_connect_timeout 86400;
        proxy_buffering off; 
    }
}
EOF
    systemctl restart nginx
    systemctl enable nginx
}

optimize_parameters() {
    # Enable BBR
    if ! grep -q "net.core.default_qdisc=fq" /etc/sysctl.conf; then
        echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
        echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
    fi

    # Optimize Network
    cat >> /etc/sysctl.conf <<EOF
fs.file-max = 1000000
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_mem = 25600 51200 102400
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
EOF
    sysctl -p
}

configure_banner() {
    cat > /etc/issue.net << 'EOF'
<div><span style="color: #ff0000">T</span><span style="color: #ff0e00">e</span><span style="color: #ff1c00">s</span><span style="color: #ff2a00">l</span><span style="color: #ff3800">a</span><span style="color: #ff4700">S</span><span style="color: #ff5500">S</span><span style="color: #ff6300">H</span><span style="color: #ff7100"> </span><span style="color: #ff7f00">P</span><span style="color: #ff8c00">a</span><span style="color: #ff9900">n</span><span style="color: #ffa500">e</span><span style="color: #ffb200">l</span><span style="color: #ffbf00">.</span><span style="color: #ffcc00"> </span><span style="color: #ffd900">A</span><span style="color: #ffe500">l</span><span style="color: #fff200">l</span><span style="color: #ffff00"> </span><span style="color: #e3ff00">r</span><span style="color: #c6ff00">i</span><span style="color: #aaff00">g</span><span style="color: #8eff00">h</span><span style="color: #71ff00">t</span><span style="color: #55ff00">s</span><span style="color: #39ff00"> </span><span style="color: #1cff00">r</span><span style="color: #00ff00">e</span><span style="color: #00ff1c">s</span><span style="color: #00ff39">e</span><span style="color: #00ff55">r</span><span style="color: #00ff71">v</span><span style="color: #00ff8e">e</span><span style="color: #00ffaa">d</span><span style="color: #00ffc6">!</span></div><div><span style="color: #00ffe3">T</span><span style="color: #00ffff">e</span><span style="color: #00e6ff">l</span><span style="color: #00ccff">e</span><span style="color: #00b3ff">g</span><span style="color: #0099ff">r</span><span style="color: #0080ff">a</span><span style="color: #0066ff">m</span><span style="color: #004dff">:</span><span style="color: #0033ff"> </span><span style="color: #001aff">@</span><span style="color: #0000ff">t</span><span style="color: #0f00ff">e</span><span style="color: #1f00ff">s</span><span style="color: #2e00ff">l</span><span style="color: #3e00ff">a</span><span style="color: #4d00ff">s</span><span style="color: #5d00ff">s</span><span style="color: #6c00ff">h</span><span style="color: #7c00ff">X</span><span style="color: #8b00ff"> </span></div>
EOF
    if grep -q "^Banner" /etc/ssh/sshd_config; then
        sed -i '/^Banner/d' /etc/ssh/sshd_config
    fi
    echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config
    
    # Keep Alive & QoS Settings
    sed -i '/^ClientAliveInterval/d' /etc/ssh/sshd_config
    sed -i '/^ClientAliveCountMax/d' /etc/ssh/sshd_config
    sed -i '/^TCPKeepAlive/d' /etc/ssh/sshd_config
    sed -i '/^IPQoS/d' /etc/ssh/sshd_config
    sed -i '/^MaxStartups/d' /etc/ssh/sshd_config
    
    echo "ClientAliveInterval 15" >> /etc/ssh/sshd_config
    echo "ClientAliveCountMax 10" >> /etc/ssh/sshd_config
    echo "TCPKeepAlive yes" >> /etc/ssh/sshd_config
    echo "IPQoS throughput" >> /etc/ssh/sshd_config
    echo "MaxStartups 100" >> /etc/ssh/sshd_config
    
    # Ensure Forwarding
    sed -i '/^AllowTcpForwarding/d' /etc/ssh/sshd_config
    echo "AllowTcpForwarding yes" >> /etc/ssh/sshd_config
    sed -i '/^GatewayPorts/d' /etc/ssh/sshd_config
    echo "GatewayPorts yes" >> /etc/ssh/sshd_config
    systemctl restart sshd || systemctl restart ssh || true
}

# --- Main Execution ---

hide_cursor
echo -e "${GREEN}Starting TeslaSSH Installation...${NC}"
echo "-----------------------------------"

run_step "Checking environment" pre_check
run_step "Cleaning up old services" cleanup_services
run_step "Installing dependencies" install_dependencies
run_step "Configuring WireGuard" configure_wireguard
run_step "Installing TeslaSSH Panel" install_panel

# Protocols
run_step "Installing ZiVPN" install_zivpn
run_step "Installing UDP Custom" install_udp_custom
run_step "Installing DNSTT" install_dnstt
run_step "Installing SSH Proxy" install_falcon_proxy
run_step "Installing UDP Request" install_udp_request
run_step "Installing BadVPN" install_badvpn
run_step "Installing V2Ray" install_v2ray
run_step "Configuring Nginx" install_nginx
run_step "Configuring Banner" configure_banner
run_step "Optimizing Network (BBR)" optimize_parameters

# --- Display Results ---

if [ -f /tmp/teslassh_creds ]; then
    . /tmp/teslassh_creds
fi

SERVER_PUB_IP=${SERVER_PUB_IP:-"127.0.0.1"}

clear
echo ""
echo "--------------------------------------------------------"
echo -e "${GREEN}           TeslaSSH Installation Complete!   ${NC}"
echo "--------------------------------------------------------"
echo " Dashboard available at: http://${SERVER_PUB_IP}"
echo ""
echo "--------------------------------------------------------"
echo -e "${GREEN}          Admin Login Credentials           ${NC}"
echo "--------------------------------------------------------"
echo -e "   Username: ${GREEN}${ADMIN_USER}${NC}"
echo -e "   Password: ${GREEN}${ADMIN_PASS}${NC}"
echo "--------------------------------------------------------"
echo " Note: Please save these credentials."
echo "--------------------------------------------------------"
echo ""

