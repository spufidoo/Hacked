#!/bin/bash
# Install HackedSSH as a systemd service
# This script installs HackedSSH files and enables the automated reporting

set -e

echo "=========================================="
echo "  HackedSSH Service Installation"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Get the directory where the script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Step 1: Installing HackedSSH files to /usr/local/bin..."
cp "$PROJECT_DIR/HackedSSH.py" /usr/local/bin/
cp "$PROJECT_DIR/countries.py" /usr/local/bin/
cp "$PROJECT_DIR/HackedSSH.html" /usr/local/bin/
cp "$PROJECT_DIR/HackedSSH.ini" /usr/local/bin/
cp "$PROJECT_DIR/GeoLite2-City.mmdb" /usr/local/bin/ 2>/dev/null || echo "Warning: GeoLite2-City.mmdb not found"
cp "$PROJECT_DIR/GeoLite2-Country.mmdb" /usr/local/bin/ 2>/dev/null || echo "Warning: GeoLite2-Country.mmdb not found"

echo "Step 2: Setting permissions..."
chmod 755 /usr/local/bin/HackedSSH.py
chmod 644 /usr/local/bin/HackedSSH.html
chmod 644 /usr/local/bin/HackedSSH.ini
chmod 644 /usr/local/bin/countries.py
chmod 644 /usr/local/bin/GeoLite2-*.mmdb 2>/dev/null || true

echo "Step 3: Creating web directory if it doesn't exist..."
mkdir -p /var/www/html
chown www-data:www-data /var/www/html

echo "Step 4: Installing Python dependencies..."
pip3 install folium geoip2 jinja2 systemd-python configparser || {
    echo "Warning: Some Python packages may not have installed correctly"
    echo "You may need to install them manually:"
    echo "  sudo pip3 install folium geoip2 jinja2 systemd-python"
}

echo "Step 5: Installing systemd service files..."
cp "$PROJECT_DIR/config_examples/hackedssh.service" /etc/systemd/system/
cp "$PROJECT_DIR/config_examples/hackedssh.timer" /etc/systemd/system/
chmod 644 /etc/systemd/system/hackedssh.service
chmod 644 /etc/systemd/system/hackedssh.timer

echo "Step 6: Reloading systemd daemon..."
systemctl daemon-reload

echo "Step 7: Enabling and starting the timer..."
systemctl enable hackedssh.timer
systemctl start hackedssh.timer

echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
echo "Service Status:"
systemctl status hackedssh.timer --no-pager
echo ""
echo "Timer Status:"
systemctl list-timers hackedssh.timer --no-pager
echo ""
echo "Useful Commands:"
echo "  - Check timer status:    sudo systemctl status hackedssh.timer"
echo "  - View timer schedule:   sudo systemctl list-timers"
echo "  - Run report manually:   sudo systemctl start hackedssh.service"
echo "  - View service logs:     sudo journalctl -u hackedssh.service"
echo "  - Disable timer:         sudo systemctl disable hackedssh.timer"
echo "  - Stop timer:            sudo systemctl stop hackedssh.timer"
echo ""
echo "Configuration file:        /usr/local/bin/HackedSSH.ini"
echo "Report output:             /var/www/html/HackedSSH_Report.html"
echo "Map output:                /var/www/html/HackedSSH_Map.html"
echo ""

