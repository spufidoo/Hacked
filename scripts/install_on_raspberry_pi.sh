#!/bin/bash
# HackedSSH Installation Script for Raspberry Pi
# Usage: sudo bash install_on_raspberry_pi.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}"
echo "=========================================="
echo "  HackedSSH - Raspberry Pi Installation"
echo "  For Heimdall Gateway"
echo "=========================================="
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}ERROR: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# Check if running on Raspberry Pi
if [ ! -f /proc/device-tree/model ]; then
    echo -e "${YELLOW}WARNING: This doesn't appear to be a Raspberry Pi${NC}"
    read -p "Continue anyway? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
else
    PI_MODEL=$(cat /proc/device-tree/model)
    echo -e "${GREEN}Detected: $PI_MODEL${NC}"
fi

# Check temperature
TEMP=$(vcgencmd measure_temp 2>/dev/null | cut -d= -f2 | cut -d\' -f1 || echo "N/A")
echo -e "Current temperature: ${TEMP}°C"
if [ "$TEMP" != "N/A" ] && (( $(echo "$TEMP > 70" | bc -l) )); then
    echo -e "${YELLOW}WARNING: Temperature is high. Ensure adequate cooling.${NC}"
fi

echo ""
echo "This script will install:"
echo "  - Python dependencies"
echo "  - Nginx web server"
echo "  - Postfix mail server"
echo "  - Security tools (Fail2Ban, UFW, etc.)"
echo "  - HackedSSH monitoring service"
echo ""
read -p "Continue with installation? (y/n): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 0
fi

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo ""
echo -e "${BLUE}Step 1: Updating system...${NC}"
apt update
apt upgrade -y

echo ""
echo -e "${BLUE}Step 2: Installing Python dependencies...${NC}"
apt install -y python3 python3-pip python3-venv

# Try to install via apt first (Debian packages are preferred)
echo "Installing Python packages via apt (preferred method)..."
apt install -y python3-jinja2 python3-systemd 2>/dev/null || true

# For packages not available via apt, use pip with --break-system-packages
# This is safe for system services that need specific versions
echo "Installing remaining Python packages..."
pip3 install --break-system-packages folium geoip2 configparser 2>/dev/null || \
    pip3 install folium geoip2 configparser 2>/dev/null || \
    echo -e "${YELLOW}Warning: Some Python packages may not have installed. Will try to continue...${NC}"

echo ""
echo -e "${BLUE}Step 3: Installing Nginx web server...${NC}"
apt install -y nginx
systemctl enable nginx
systemctl start nginx
mkdir -p /var/www/html
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html

echo ""
echo -e "${BLUE}Step 4: Installing Postfix mail server...${NC}"
echo "postfix postfix/main_mailer_type select Internet Site" | debconf-set-selections
echo "postfix postfix/mailname string heimdall.local" | debconf-set-selections
apt install -y postfix mailutils

echo ""
echo -e "${BLUE}Step 5: Installing security tools...${NC}"
if [ -f "$PROJECT_DIR/scripts/install_security_tools.sh" ]; then
    bash "$PROJECT_DIR/scripts/install_security_tools.sh"
else
    echo -e "${YELLOW}Security tools script not found, installing essentials...${NC}"
    apt install -y fail2ban ufw auditd
    systemctl enable fail2ban
    systemctl start fail2ban
fi

echo ""
echo -e "${BLUE}Step 6: Configuring firewall for gateway...${NC}"
echo -e "${YELLOW}IMPORTANT: Configuring UFW for gateway device${NC}"

# Configure UFW for gateway
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw default allow routed  # CRITICAL for gateway

# Allow SSH from local network
echo "Enter your local network (e.g., 192.168.1.0/24):"
read -p "Local network CIDR: " LOCAL_NET
if [ -n "$LOCAL_NET" ]; then
    ufw allow from $LOCAL_NET to any port 22 comment 'SSH from local network'
fi

# Allow web server
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

# Allow DNS if needed
read -p "Is Heimdall a DNS server? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ufw allow 53/tcp comment 'DNS'
    ufw allow 53/udp comment 'DNS'
fi

# Allow DHCP if needed
read -p "Is Heimdall a DHCP server? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    ufw allow 67/udp comment 'DHCP'
    ufw allow 68/udp comment 'DHCP'
fi

ufw --force enable
ufw status verbose

echo ""
echo -e "${BLUE}Step 7: Installing HackedSSH service...${NC}"
if [ -f "$PROJECT_DIR/scripts/install_hackedssh_service.sh" ]; then
    bash "$PROJECT_DIR/scripts/install_hackedssh_service.sh"
else
    echo -e "${YELLOW}Installing HackedSSH manually...${NC}"
    
    # Copy files
    cp "$PROJECT_DIR/HackedSSH.py" /usr/local/bin/
    cp "$PROJECT_DIR/countries.py" /usr/local/bin/
    cp "$PROJECT_DIR/HackedSSH.html" /usr/local/bin/
    cp "$PROJECT_DIR/HackedSSH.ini" /usr/local/bin/
    cp "$PROJECT_DIR/GeoLite2-City.mmdb" /usr/local/bin/ 2>/dev/null || true
    cp "$PROJECT_DIR/GeoLite2-Country.mmdb" /usr/local/bin/ 2>/dev/null || true
    
    chmod 755 /usr/local/bin/HackedSSH.py
    
    # Install service files
    if [ -f "$PROJECT_DIR/config_examples/hackedssh.service" ]; then
        cp "$PROJECT_DIR/config_examples/hackedssh.service" /etc/systemd/system/
        cp "$PROJECT_DIR/config_examples/hackedssh.timer" /etc/systemd/system/
        systemctl daemon-reload
        systemctl enable hackedssh.timer
        systemctl start hackedssh.timer
    fi
fi

echo ""
echo -e "${BLUE}Step 8: Configuring for Heimdall...${NC}"
if [ -f /usr/local/bin/HackedSSH.ini ]; then
    echo "Updating configuration for Heimdall..."
    sed -i 's/sender_email = .*/sender_email = heimdall@davage.me/' /usr/local/bin/HackedSSH.ini
    sed -i 's/hostname = .*/hostname = heimdall.local/' /usr/local/bin/HackedSSH.ini
    sed -i 's|report_url = .*|report_url = http://heimdall.local/HackedSSH_Report.html|' /usr/local/bin/HackedSSH.ini
    sed -i 's|local_url = .*|local_url = http://heimdall.local/HackedSSH_Report.html|' /usr/local/bin/HackedSSH.ini
fi

echo ""
echo -e "${BLUE}Step 9: Testing installation...${NC}"

# Test email
read -p "Enter email address for test: " TEST_EMAIL
if [ -n "$TEST_EMAIL" ]; then
    echo "Test email from Heimdall installation" | mail -s "Heimdall HackedSSH Test" "$TEST_EMAIL" || \
        echo -e "${YELLOW}Email test failed - check postfix configuration${NC}"
fi

# Run HackedSSH once
echo "Running HackedSSH test..."
python3 /usr/local/bin/HackedSSH.py --from_date today --to_date today || \
    echo -e "${YELLOW}HackedSSH test run had issues - check logs${NC}"

echo ""
echo -e "${BLUE}Step 10: Creating monitoring script...${NC}"
cat > /home/$SUDO_USER/monitor_heimdall.sh << 'EOF'
#!/bin/bash
echo "=== Heimdall Status ==="
echo "Temperature: $(vcgencmd measure_temp 2>/dev/null || echo 'N/A')"
echo "Memory: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
echo "CPU Load: $(uptime | awk -F'load average:' '{print $2}')"
echo "Disk: $(df -h / | tail -1 | awk '{print $3 "/" $2 " (" $5 ")"}')"
echo "Active Connections: $(ss -tuna | wc -l)"
if command -v fail2ban-client &> /dev/null; then
    echo "Fail2Ban Bans: $(fail2ban-client status sshd 2>/dev/null | grep 'Currently banned' | awk '{print $4}' || echo '0')"
fi
echo "HackedSSH Service: $(systemctl is-active hackedssh.timer)"
EOF

chmod +x /home/$SUDO_USER/monitor_heimdall.sh
chown $SUDO_USER:$SUDO_USER /home/$SUDO_USER/monitor_heimdall.sh

echo ""
echo -e "${GREEN}=========================================="
echo "  Installation Complete!"
echo "==========================================${NC}"
echo ""
echo -e "${GREEN}System Information:${NC}"
echo "  Pi Model: $(cat /proc/device-tree/model 2>/dev/null || echo 'Unknown')"
echo "  Temperature: $(vcgencmd measure_temp 2>/dev/null || echo 'N/A')"
echo "  Memory: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
echo "  Disk: $(df -h / | tail -1 | awk '{print $5 " used"}')"
echo ""
echo -e "${GREEN}Services Status:${NC}"
systemctl status hackedssh.timer --no-pager | grep Active || true
systemctl status nginx --no-pager | grep Active || true
systemctl status postfix --no-pager | grep Active || true
systemctl status fail2ban --no-pager | grep Active || true
echo ""
echo -e "${GREEN}Next Steps:${NC}"
echo "  1. Review configuration: nano /usr/local/bin/HackedSSH.ini"
echo "  2. Update email address if needed"
echo "  3. Check web report: http://heimdall.local/HackedSSH_Report.html"
echo "  4. Monitor system: ~/monitor_heimdall.sh"
echo "  5. View logs: sudo journalctl -u hackedssh.service -f"
echo ""
echo -e "${GREEN}Useful Commands:${NC}"
echo "  sudo systemctl status hackedssh.timer"
echo "  sudo systemctl start hackedssh.service  # Run manually"
echo "  sudo journalctl -u hackedssh.service -f  # View logs"
echo "  vcgencmd measure_temp                    # Check temperature"
echo "  ~/monitor_heimdall.sh                    # System status"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC}"
echo "  - Monitor temperature regularly (should stay below 80°C)"
echo "  - Check disk space weekly (SD cards fill up fast)"
echo "  - Test backups regularly"
echo "  - Keep system updated"
echo ""
echo -e "${GREEN}Installation log saved to: /var/log/hackedssh_install.log${NC}"
echo ""

