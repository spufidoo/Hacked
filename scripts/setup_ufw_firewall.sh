#!/bin/bash
# UFW Firewall Setup Script for Thor
# This script configures a secure firewall using UFW (Uncomplicated Firewall)
# Usage: sudo bash setup_ufw_firewall.sh

set -e  # Exit on error

echo "=========================================="
echo "  UFW Firewall Setup for Thor"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Check if UFW is installed
if ! command -v ufw &> /dev/null; then
    echo "UFW is not installed. Installing..."
    apt-get update
    apt-get install -y ufw
fi

echo "Step 1: Resetting UFW to default settings..."
ufw --force reset

echo "Step 2: Setting default policies..."
# Default: deny all incoming, allow all outgoing
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed

echo "Step 3: Allowing SSH (Port 22)..."
# IMPORTANT: Allowing SSH before enabling firewall to prevent lockout
ufw allow 22/tcp comment 'SSH'

# If you changed SSH port, uncomment and modify:
# ufw allow 2222/tcp comment 'SSH Custom Port'

echo "Step 4: Allowing HTTP and HTTPS..."
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'

echo "Step 5: Allowing specific services (optional)..."
# Uncomment as needed:

# FTP
# ufw allow 21/tcp comment 'FTP'

# MySQL/MariaDB (only if needed externally)
# ufw allow from 192.168.1.0/24 to any port 3306 comment 'MySQL from local network'

# PostgreSQL (only if needed externally)
# ufw allow from 192.168.1.0/24 to any port 5432 comment 'PostgreSQL from local network'

# RDP
# ufw allow 3389/tcp comment 'RDP'

# Mail server
# ufw allow 25/tcp comment 'SMTP'
# ufw allow 587/tcp comment 'SMTP Submission'
# ufw allow 465/tcp comment 'SMTPS'
# ufw allow 993/tcp comment 'IMAPS'
# ufw allow 995/tcp comment 'POP3S'

# VPN (OpenVPN)
# ufw allow 1194/udp comment 'OpenVPN'

# DNS (only if running DNS server)
# ufw allow 53/tcp comment 'DNS'
# ufw allow 53/udp comment 'DNS'

# Custom web services
# ufw allow 3579/tcp comment 'Express Server'
# ufw allow 5000/tcp comment 'Flask App'

echo "Step 6: Rate limiting SSH to prevent brute force..."
ufw limit 22/tcp comment 'SSH Rate Limit'
# If you changed SSH port:
# ufw limit 2222/tcp comment 'SSH Custom Port Rate Limit'

echo "Step 7: Blocking specific IPs (optional)..."
# Add known malicious IPs here:
# ufw deny from 1.2.3.4 comment 'Known attacker'

echo "Step 8: Allowing from trusted IPs (optional)..."
# Allow all traffic from trusted IPs:
# ufw allow from 192.168.1.100 comment 'Trusted device'

echo "Step 9: Logging configuration..."
ufw logging on
# For more verbose logging:
# ufw logging high

echo "Step 10: Enabling UFW..."
ufw --force enable

echo ""
echo "=========================================="
echo "  Firewall Setup Complete!"
echo "=========================================="
echo ""
echo "Current UFW Status:"
ufw status verbose
echo ""
echo "Numbered rules:"
ufw status numbered
echo ""
echo "IMPORTANT NOTES:"
echo "  - SSH is allowed on port 22"
echo "  - HTTP (80) and HTTPS (443) are allowed"
echo "  - All other incoming connections are blocked"
echo "  - To add more rules: ufw allow <port>/<protocol>"
echo "  - To delete a rule: ufw delete <rule_number>"
echo "  - To disable UFW: sudo ufw disable"
echo ""
echo "View logs with: sudo tail -f /var/log/ufw.log"
echo ""

