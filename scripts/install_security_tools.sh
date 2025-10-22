#!/bin/bash
# Security Tools Installation Script for Thor
# This script installs and configures essential security tools
# Usage: sudo bash install_security_tools.sh

set -e

echo "=========================================="
echo "  Security Tools Installation for Thor"
echo "=========================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: This script must be run as root (use sudo)"
    exit 1
fi

# Update package lists
echo "Step 1: Updating package lists..."
apt-get update

# ===== FAIL2BAN =====
echo ""
echo "Step 2: Installing Fail2Ban..."
if command -v fail2ban-client &> /dev/null; then
    echo "  Fail2Ban already installed, skipping..."
else
    apt-get install -y fail2ban
    echo "  ✓ Fail2Ban installed"
fi

# ===== UFW FIREWALL =====
echo ""
echo "Step 3: Installing UFW Firewall..."
if command -v ufw &> /dev/null; then
    echo "  UFW already installed, skipping..."
else
    apt-get install -y ufw
    echo "  ✓ UFW installed"
fi

# ===== AUDITD =====
echo ""
echo "Step 4: Installing Auditd (system auditing)..."
if command -v auditctl &> /dev/null; then
    echo "  Auditd already installed, skipping..."
else
    apt-get install -y auditd audispd-plugins
    systemctl enable auditd
    systemctl start auditd
    echo "  ✓ Auditd installed and enabled"
fi

# ===== AIDE (File Integrity Monitoring) =====
echo ""
echo "Step 5: Installing AIDE (Advanced Intrusion Detection Environment)..."
if command -v aide &> /dev/null; then
    echo "  AIDE already installed, skipping..."
else
    apt-get install -y aide aide-common
    echo "  Initializing AIDE database (this may take several minutes)..."
    aideinit
    if [ -f /var/lib/aide/aide.db.new ]; then
        mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
    fi
    echo "  ✓ AIDE installed and database initialized"
fi

# ===== RKHUNTER (Rootkit Detection) =====
echo ""
echo "Step 6: Installing RKHunter (Rootkit Hunter)..."
if command -v rkhunter &> /dev/null; then
    echo "  RKHunter already installed, skipping..."
else
    apt-get install -y rkhunter
    echo "  Updating RKHunter database..."
    rkhunter --update
    rkhunter --propupd
    echo "  ✓ RKHunter installed and updated"
fi

# ===== CLAMAV (Antivirus) =====
echo ""
echo "Step 7: Installing ClamAV (Antivirus)..."
if command -v clamscan &> /dev/null; then
    echo "  ClamAV already installed, skipping..."
else
    apt-get install -y clamav clamav-daemon
    echo "  Updating ClamAV virus definitions (this may take a while)..."
    systemctl stop clamav-freshclam 2>/dev/null || true
    freshclam
    systemctl start clamav-freshclam
    systemctl enable clamav-daemon
    systemctl start clamav-daemon
    echo "  ✓ ClamAV installed and updated"
fi

# ===== LOGWATCH =====
echo ""
echo "Step 8: Installing Logwatch (Log Analysis)..."
if command -v logwatch &> /dev/null; then
    echo "  Logwatch already installed, skipping..."
else
    apt-get install -y logwatch
    echo "  ✓ Logwatch installed"
fi

# ===== CHKROOTKIT =====
echo ""
echo "Step 9: Installing Chkrootkit (Rootkit Detection)..."
if command -v chkrootkit &> /dev/null; then
    echo "  Chkrootkit already installed, skipping..."
else
    apt-get install -y chkrootkit
    echo "  ✓ Chkrootkit installed"
fi

# ===== TIGER (Security Audit Tool) =====
echo ""
echo "Step 10: Installing Tiger (Security Audit)..."
if command -v tiger &> /dev/null; then
    echo "  Tiger already installed, skipping..."
else
    apt-get install -y tiger
    echo "  ✓ Tiger installed"
fi

# ===== LYNIS (Security Auditing) =====
echo ""
echo "Step 11: Installing Lynis (Security Auditing)..."
if command -v lynis &> /dev/null; then
    echo "  Lynis already installed, skipping..."
else
    apt-get install -y lynis
    echo "  ✓ Lynis installed"
fi

# ===== PSAD (Port Scan Attack Detector) =====
echo ""
echo "Step 12: Installing PSAD (Port Scan Attack Detector)..."
if command -v psad &> /dev/null; then
    echo "  PSAD already installed, skipping..."
else
    apt-get install -y psad
    echo "  ✓ PSAD installed"
fi

# ===== PYTHON DEPENDENCIES FOR HACKEDSSH =====
echo ""
echo "Step 13: Installing Python dependencies for HackedSSH..."
pip3 install --upgrade folium geoip2 jinja2 systemd-python configparser 2>/dev/null || {
    echo "  Warning: Some Python packages may have failed to install"
    echo "  You may need to install them manually"
}
echo "  ✓ Python dependencies installed"

# ===== GOOGLE AUTHENTICATOR (Optional 2FA) =====
echo ""
echo "Step 14: Installing Google Authenticator (2FA - Optional)..."
read -p "Do you want to install Google Authenticator for 2FA? (y/n): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    apt-get install -y libpam-google-authenticator
    echo "  ✓ Google Authenticator installed"
    echo "  To configure for a user, run: google-authenticator"
else
    echo "  Skipped Google Authenticator installation"
fi

# ===== SUMMARY =====
echo ""
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo ""
echo "Installed Security Tools:"
echo "  ✓ Fail2Ban           - Intrusion prevention"
echo "  ✓ UFW                - Firewall"
echo "  ✓ Auditd             - System auditing"
echo "  ✓ AIDE               - File integrity monitoring"
echo "  ✓ RKHunter           - Rootkit detection"
echo "  ✓ ClamAV             - Antivirus"
echo "  ✓ Logwatch           - Log analysis"
echo "  ✓ Chkrootkit         - Rootkit detection"
echo "  ✓ Tiger              - Security audit"
echo "  ✓ Lynis              - Security audit"
echo "  ✓ PSAD               - Port scan detector"
echo ""
echo "Next Steps:"
echo "  1. Configure Fail2Ban:  Copy config_examples/fail2ban_jail.local to /etc/fail2ban/jail.local"
echo "  2. Configure UFW:       Run scripts/setup_ufw_firewall.sh"
echo "  3. Configure SSH:       Review config_examples/sshd_config.hardened"
echo "  4. Configure Auditd:    Copy config_examples/audit.rules to /etc/audit/rules.d/"
echo "  5. Run security audit:  bash scripts/system_security_audit.sh"
echo "  6. Install HackedSSH:   bash scripts/install_hackedssh_service.sh"
echo ""
echo "Useful Commands:"
echo "  - Run Lynis audit:      sudo lynis audit system"
echo "  - Run RKHunter scan:    sudo rkhunter --check"
echo "  - Run AIDE check:       sudo aide --check"
echo "  - Run ClamAV scan:      sudo clamscan -r /home"
echo "  - Run Tiger audit:      sudo tiger"
echo "  - View Logwatch report: sudo logwatch --detail high --range today"
echo ""

