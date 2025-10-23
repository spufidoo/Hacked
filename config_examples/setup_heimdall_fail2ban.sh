#!/bin/bash
# Setup fail2ban with abuseipdb reporting on Heimdall
# Run this on Heimdall as root or with sudo

echo "==================================================================="
echo "Setting up fail2ban with abuseipdb on Heimdall"
echo "==================================================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root or with sudo"
    exit 1
fi

# Backup existing configuration
echo "Backing up existing fail2ban configuration..."
cp /etc/fail2ban/jail.d/defaults-debian.conf /etc/fail2ban/jail.d/defaults-debian.conf.backup.$(date +%Y%m%d_%H%M%S)
cp /etc/fail2ban/action.d/abuseipdb.conf /etc/fail2ban/action.d/abuseipdb.conf.backup.$(date +%Y%m%d_%H%M%S)

# Update abuseipdb.conf with API key
echo "Configuring abuseipdb API key..."
sed -i 's/^abuseipdb_apikey =.*/abuseipdb_apikey = 1ff46f49e78d7681df43f14ea971a36a733b9be888a5d3580bd19041b4ddd488c64035a624021f26/' /etc/fail2ban/action.d/abuseipdb.conf

# Create comprehensive jail configuration
echo "Creating fail2ban jail configuration..."
cat > /etc/fail2ban/jail.d/defaults-debian.conf << 'EOF'
[sshd]
enabled = true
action = %(action_)s
         %(action_abuseipdb)s[abuseipdb_apikey="1ff46f49e78d7681df43f14ea971a36a733b9be888a5d3580bd19041b4ddd488c64035a624021f26", abuseipdb_category="18,22"]
destemail = marcus@davage.me
sender = heimdall@heimdall.local
mta = sendmail
protocol = tcp
port = 0:65535
fail2ban_agent = Fail2Ban/%(fail2ban_version)s
EOF

# Restart fail2ban
echo "Restarting fail2ban service..."
systemctl restart fail2ban

# Wait a moment for service to start
sleep 2

# Check status
echo ""
echo "==================================================================="
echo "fail2ban Status:"
echo "==================================================================="
fail2ban-client status

echo ""
echo "==================================================================="
echo "SSHD Jail Status:"
echo "==================================================================="
fail2ban-client status sshd

echo ""
echo "==================================================================="
echo "Configuration complete!"
echo "==================================================================="
echo ""
echo "fail2ban is now configured to report SSH attacks to abuseipdb.com"
echo ""
echo "To monitor activity:"
echo "  sudo tail -f /var/log/fail2ban.log"
echo ""
echo "To check for abuseipdb reports:"
echo "  sudo grep -i 'abuseipdb\|curl.*api.abuseipdb' /var/log/fail2ban.log"
echo ""
echo "To check banned IPs:"
echo "  sudo fail2ban-client status sshd"
echo ""
echo "==================================================================="

