#!/bin/bash
# Setup fail2ban to monitor UFW logs and report to abuseipdb
# This allows UFW to block at firewall level while still reporting to abuseipdb
# Run this on Heimdall as root or with sudo

echo "==================================================================="
echo "Setting up UFW → fail2ban → abuseipdb Integration"
echo "==================================================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root or with sudo"
    exit 1
fi

# Backup existing configuration
echo "Backing up existing fail2ban configuration..."
if [ -f /etc/fail2ban/filter.d/ufw-ssh-block.conf ]; then
    cp /etc/fail2ban/filter.d/ufw-ssh-block.conf /etc/fail2ban/filter.d/ufw-ssh-block.conf.backup.$(date +%Y%m%d_%H%M%S)
fi
if [ -f /etc/fail2ban/jail.d/ufw-ssh.conf ]; then
    cp /etc/fail2ban/jail.d/ufw-ssh.conf /etc/fail2ban/jail.d/ufw-ssh.conf.backup.$(date +%Y%m%d_%H%M%S)
fi

# Create UFW SSH block filter
echo "Creating UFW SSH block filter..."
cat > /etc/fail2ban/filter.d/ufw-ssh-block.conf << 'EOF'
# Fail2Ban filter for UFW SSH blocks
# This monitors UFW logs and reports repeated SSH attack attempts to abuseipdb

[Definition]

# Match UFW BLOCK entries for SSH (port 22)
failregex = ^\s*\S+\s+\S+\s+\S+\s+kernel:.*\[UFW BLOCK\].*SRC=<HOST>.*DPT=22\s

ignoreregex =
EOF

# Enable UFW logging if not already enabled
echo "Ensuring UFW logging is enabled..."
ufw logging on

# Create UFW SSH jail
echo "Creating UFW SSH jail configuration..."
cat > /etc/fail2ban/jail.d/ufw-ssh.conf << 'EOF'
# Fail2Ban jail for UFW SSH blocks
# This reports UFW-blocked SSH attacks to abuseipdb without additional banning

[ufw-ssh]
enabled  = true
filter   = ufw-ssh-block
backend  = systemd
journalmatch = _TRANSPORT=kernel
maxretry = 3
findtime = 600
bantime  = 1
action   = %(action_abuseipdb)s[abuseipdb_apikey="1ff46f49e78d7681df43f14ea971a36a733b9be888a5d3580bd19041b4ddd488c64035a624021f26", abuseipdb_category="18,22"]
destemail = marcus@davage.me
sender = heimdall@heimdall.local
EOF

# Test the filter
echo ""
echo "Testing the UFW filter..."
fail2ban-regex systemd-journal /etc/fail2ban/filter.d/ufw-ssh-block.conf --print-all-matched | head -20

# Restart fail2ban
echo ""
echo "Restarting fail2ban service..."
systemctl restart fail2ban

# Wait a moment for service to start
sleep 3

# Check status
echo ""
echo "==================================================================="
echo "fail2ban Status:"
echo "==================================================================="
fail2ban-client status

echo ""
echo "==================================================================="
echo "UFW-SSH Jail Status:"
echo "==================================================================="
fail2ban-client status ufw-ssh 2>/dev/null || echo "UFW-SSH jail is starting up..."

echo ""
echo "==================================================================="
echo "Configuration complete!"
echo "==================================================================="
echo ""
echo "How it works:"
echo "  1. UFW blocks external SSH attempts at firewall level (secure)"
echo "  2. fail2ban monitors UFW's kernel logs"
echo "  3. If an IP is blocked 3+ times in 10 minutes → report to abuseipdb"
echo "  4. No additional banning (UFW already blocks)"
echo ""
echo "To monitor activity:"
echo "  sudo tail -f /var/log/fail2ban.log | grep ufw-ssh"
echo ""
echo "To check UFW blocks:"
echo "  sudo journalctl --since=today | grep 'UFW BLOCK.*DPT=22' | wc -l"
echo ""
echo "To check reported IPs:"
echo "  sudo fail2ban-client status ufw-ssh"
echo ""
echo "==================================================================="

