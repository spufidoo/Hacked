#!/bin/bash
#
# HackedSSH Security Tools Installation Script
# Installs and configures all security monitoring tools for comprehensive system protection
#
# Tools installed:
# - auditd: Linux auditing system
# - AIDE: Advanced Intrusion Detection Environment
# - rkhunter: Rootkit Hunter
# - chkrootkit: Check for rootkits
# - ClamAV: Antivirus scanner
# - Lynis: Security auditing tool
# - Tiger: Security audit and intrusion detection tool
# - psad: Port Scan Attack Detector
# - logwatch: Log analysis and reporting
#

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}This script must be run as root (use sudo)${NC}" 
   exit 1
fi

echo -e "${CYAN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║  HackedSSH Security Tools Installation       ║${NC}"
echo -e "${CYAN}║  Comprehensive System Protection Suite       ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${NC}"
echo ""

# Update package list
echo -e "${YELLOW}[1/10] Updating package list...${NC}"
apt-get update -qq

# 1. Install auditd (Linux Audit Framework)
echo -e "${YELLOW}[2/10] Installing auditd (Linux Audit Framework)...${NC}"
apt-get install -y auditd audispd-plugins
systemctl enable auditd
systemctl start auditd

# Configure auditd for security monitoring
echo -e "${GREEN}   Configuring auditd rules...${NC}"
cat > /etc/audit/rules.d/security.rules <<'EOF'
# Monitor authentication and authorization
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/sudoers -p wa -k sudoers_changes
-w /var/log/auth.log -p wa -k auth_log_changes

# Monitor system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time_change

# Monitor network configuration
-w /etc/hosts -p wa -k hosts_changes
-w /etc/network/ -p wa -k network_changes

# Monitor SSH
-w /etc/ssh/sshd_config -p wa -k sshd_config_changes
EOF

augenrules --load
echo -e "${GREEN}   ✓ auditd installed and configured${NC}"

# 2. Install AIDE (Advanced Intrusion Detection Environment)
echo -e "${YELLOW}[3/10] Installing AIDE (File Integrity Monitor)...${NC}"
apt-get install -y aide aide-common

# Initialize AIDE database
echo -e "${GREEN}   Initializing AIDE database (this may take a while)...${NC}"
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Configure daily AIDE checks
cat > /etc/cron.daily/aide <<'EOF'
#!/bin/bash
/usr/bin/aide --check | tee /var/log/aide/aide.log
EOF
chmod +x /etc/cron.daily/aide
mkdir -p /var/log/aide

echo -e "${GREEN}   ✓ AIDE installed and initialized${NC}"

# 3. Install rkhunter (Rootkit Hunter)
echo -e "${YELLOW}[4/10] Installing rkhunter (Rootkit Hunter)...${NC}"
apt-get install -y rkhunter

# Update rkhunter database
rkhunter --update
rkhunter --propupd

# Configure rkhunter
sed -i 's/^UPDATE_MIRRORS=.*/UPDATE_MIRRORS=1/' /etc/rkhunter.conf
sed -i 's/^MIRRORS_MODE=.*/MIRRORS_MODE=0/' /etc/rkhunter.conf
sed -i 's/^WEB_CMD=.*/WEB_CMD=""/' /etc/rkhunter.conf

# Configure daily rkhunter check
cat > /etc/cron.daily/rkhunter <<'EOF'
#!/bin/bash
/usr/bin/rkhunter --cronjob --update --report-warnings-only | tee -a /var/log/rkhunter.log
EOF
chmod +x /etc/cron.daily/rkhunter

echo -e "${GREEN}   ✓ rkhunter installed and configured${NC}"

# 4. Install chkrootkit
echo -e "${YELLOW}[5/10] Installing chkrootkit...${NC}"
apt-get install -y chkrootkit

# Configure daily chkrootkit check
cat > /etc/cron.daily/chkrootkit <<'EOF'
#!/bin/bash
/usr/sbin/chkrootkit | tee /var/log/chkrootkit.log
EOF
chmod +x /etc/cron.daily/chkrootkit

echo -e "${GREEN}   ✓ chkrootkit installed${NC}"

# 5. Install ClamAV (Antivirus)
echo -e "${YELLOW}[6/10] Installing ClamAV (Antivirus)...${NC}"
apt-get install -y clamav clamav-daemon clamav-freshclam

# Stop freshclam to update virus database
systemctl stop clamav-freshclam
freshclam
systemctl start clamav-freshclam
systemctl enable clamav-freshclam

# Start ClamAV daemon
systemctl enable clamav-daemon
systemctl start clamav-daemon

# Configure weekly scan
cat > /etc/cron.weekly/clamav-scan <<'EOF'
#!/bin/bash
/usr/bin/clamscan -r /home /root --log=/var/log/clamav/clamav-scan.log
EOF
chmod +x /etc/cron.weekly/clamav-scan
mkdir -p /var/log/clamav

echo -e "${GREEN}   ✓ ClamAV installed and configured${NC}"

# 6. Install Lynis (Security Auditing Tool)
echo -e "${YELLOW}[7/10] Installing Lynis (Security Auditing)...${NC}"
apt-get install -y lynis

# Configure weekly Lynis audit
cat > /etc/cron.weekly/lynis <<'EOF'
#!/bin/bash
/usr/sbin/lynis audit system --quick --quiet | tee /var/log/lynis.log
EOF
chmod +x /etc/cron.weekly/lynis

echo -e "${GREEN}   ✓ Lynis installed${NC}"

# 7. Install Tiger (Security Audit Tool)
echo -e "${YELLOW}[8/10] Installing Tiger (Security Audit)...${NC}"
apt-get install -y tiger

# Configure Tiger
mkdir -p /var/log/tiger
cat > /etc/tiger/cronrc <<'EOF'
Tiger_Check_PASSWD=Y
Tiger_Check_GROUP=Y
Tiger_Check_ACCOUNTS=Y
Tiger_Check_RHOSTS=Y
Tiger_Check_NETRC=Y
Tiger_Check_ALIASES=Y
Tiger_Check_CRON=Y
Tiger_Check_ANONFTP=Y
Tiger_Check_EXPORTS=Y
Tiger_Check_INETD=Y
Tiger_Check_SERVICES=Y
Tiger_Check_FILESYS=Y
Tiger_Check_PERMS=Y
Tiger_Check_SUID=Y
Tiger_Check_SIGNATURES=Y
EOF

echo -e "${GREEN}   ✓ Tiger installed and configured${NC}"

# 8. Install psad (Port Scan Attack Detector)
echo -e "${YELLOW}[9/10] Installing psad (Port Scan Detector)...${NC}"
apt-get install -y psad

# Configure psad
sed -i 's/^EMAIL_ADDRESSES.*;/EMAIL_ADDRESSES root@localhost;/' /etc/psad/psad.conf
sed -i 's/^HOSTNAME.*;/HOSTNAME '$(hostname)';/' /etc/psad/psad.conf
sed -i 's/^ENABLE_AUTO_IDS.*;/ENABLE_AUTO_IDS Y;/' /etc/psad/psad.conf
sed -i 's/^ENABLE_AUTO_IDS_EMAILS.*;/ENABLE_AUTO_IDS_EMAILS Y;/' /etc/psad/psad.conf

# Update psad signatures
psad --sig-update
psad -H

# Restart psad
systemctl enable psad
systemctl restart psad

echo -e "${GREEN}   ✓ psad installed and configured${NC}"

# 9. Install logwatch (Log Analysis)
echo -e "${YELLOW}[10/10] Installing logwatch (Log Analysis)...${NC}"
apt-get install -y logwatch

# Configure logwatch for daily summaries
cat > /etc/cron.daily/00logwatch <<'EOF'
#!/bin/bash
/usr/sbin/logwatch --output mail --mailto root --detail high
EOF
chmod +x /etc/cron.daily/00logwatch

echo -e "${GREEN}   ✓ logwatch installed${NC}"

# Summary
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Installation Complete!                       ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Installed Security Tools:${NC}"
echo -e "  ✓ auditd       - System call auditing"
echo -e "  ✓ AIDE         - File integrity monitoring"
echo -e "  ✓ rkhunter     - Rootkit detection"
echo -e "  ✓ chkrootkit   - Rootkit scanning"
echo -e "  ✓ ClamAV       - Antivirus scanning"
echo -e "  ✓ Lynis        - Security auditing"
echo -e "  ✓ Tiger        - Security audit scripts"
echo -e "  ✓ psad         - Port scan detection"
echo -e "  ✓ logwatch     - Log analysis and reporting"
echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo -e "  1. Run initial scans: ${CYAN}sudo rkhunter --check${NC}"
echo -e "  2. Check logs in: ${CYAN}/var/log/${NC}"
echo -e "  3. Generate HackedSSH report to see security events"
echo ""
echo -e "${GREEN}All tools are now monitoring your system!${NC}"
