#!/bin/bash
# System Security Audit Script for Thor
# This script collects security-related configuration and status information
# Usage: sudo bash system_security_audit.sh [output_file]

set -e

# Output file
OUTPUT_FILE="${1:-/tmp/thor_security_audit_$(date +%Y%m%d_%H%M%S).txt}"

# Colors for terminal output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print section headers
print_header() {
    echo "=========================================="
    echo "  $1"
    echo "=========================================="
    echo ""
}

# Function to print with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Redirect all output to both terminal and file
exec > >(tee -a "$OUTPUT_FILE")
exec 2>&1

log "Starting security audit of Thor..."
echo ""

# ===== SYSTEM INFORMATION =====
print_header "SYSTEM INFORMATION"
echo "Hostname: $(hostname)"
echo "Kernel: $(uname -r)"
echo "OS: $(lsb_release -d | cut -f2)"
echo "Uptime: $(uptime -p)"
echo "Last Boot: $(who -b | awk '{print $3, $4}')"
echo ""

# ===== SSH CONFIGURATION =====
print_header "SSH CONFIGURATION"
if [ -f /etc/ssh/sshd_config ]; then
    echo "SSH Configuration (/etc/ssh/sshd_config):"
    echo "---"
    grep -v "^#" /etc/ssh/sshd_config | grep -v "^$" || echo "No active configuration found"
    echo ""
    
    # Check for security issues
    echo "Security Checks:"
    if grep -q "^PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null; then
        echo -e "${RED}✗ WARNING: Root login is ENABLED${NC}"
    else
        echo -e "${GREEN}✓ Root login is disabled or not explicitly enabled${NC}"
    fi
    
    if grep -q "^PasswordAuthentication yes" /etc/ssh/sshd_config 2>/dev/null; then
        echo -e "${YELLOW}⚠ Password authentication is ENABLED${NC}"
    else
        echo -e "${GREEN}✓ Password authentication is disabled${NC}"
    fi
    
    if grep -q "^PermitEmptyPasswords yes" /etc/ssh/sshd_config 2>/dev/null; then
        echo -e "${RED}✗ CRITICAL: Empty passwords are ALLOWED${NC}"
    else
        echo -e "${GREEN}✓ Empty passwords are not allowed${NC}"
    fi
else
    echo "SSH configuration file not found!"
fi
echo ""

# ===== FIREWALL STATUS =====
print_header "FIREWALL STATUS"
if command -v ufw &> /dev/null; then
    echo "UFW Status:"
    ufw status verbose || echo "UFW not active"
else
    echo "UFW not installed"
fi
echo ""

if command -v iptables &> /dev/null; then
    echo "IPTables Rules:"
    iptables -L -n -v || echo "Cannot read iptables rules"
fi
echo ""

# ===== FAIL2BAN STATUS =====
print_header "FAIL2BAN STATUS"
if command -v fail2ban-client &> /dev/null; then
    if systemctl is-active --quiet fail2ban; then
        echo "Fail2Ban Status: ${GREEN}ACTIVE${NC}"
        echo ""
        echo "Jails Status:"
        fail2ban-client status || echo "Cannot get fail2ban status"
        echo ""
        echo "Current Bans:"
        for jail in $(fail2ban-client status | grep "Jail list" | sed 's/.*://;s/,//g'); do
            echo "  $jail:"
            fail2ban-client status $jail | grep "Currently banned" || true
        done
    else
        echo -e "${YELLOW}⚠ Fail2Ban is installed but NOT ACTIVE${NC}"
    fi
else
    echo -e "${RED}✗ Fail2Ban is NOT INSTALLED${NC}"
fi
echo ""

# ===== USER ACCOUNTS =====
print_header "USER ACCOUNTS"
echo "Users with login shells:"
awk -F: '$7 !~ /nologin|false/ {print $1 " (UID: " $3 ")"}' /etc/passwd
echo ""

echo "Users with UID 0 (root privileges):"
awk -F: '$3 == 0 {print $1}' /etc/passwd
echo ""

echo "Recent Successful Logins (last 20):"
last -n 20 || echo "Cannot read last login data"
echo ""

echo "Recent Failed Login Attempts (last 20):"
lastb -n 20 2>/dev/null || echo "No failed login data or insufficient permissions"
echo ""

# ===== SUDO CONFIGURATION =====
print_header "SUDO CONFIGURATION"
echo "Sudoers Configuration:"
grep -v "^#" /etc/sudoers | grep -v "^$" || echo "Cannot read sudoers file"
echo ""

echo "Additional Sudoers Files:"
ls -la /etc/sudoers.d/ 2>/dev/null || echo "No additional sudoers files"
echo ""

# ===== NETWORK SERVICES =====
print_header "NETWORK SERVICES"
echo "Listening Ports and Services:"
ss -tulpn | grep LISTEN || echo "Cannot get listening ports"
echo ""

echo "Active Internet Connections:"
ss -tuna | head -20
echo ""

# ===== SECURITY UPDATES =====
print_header "SECURITY UPDATES"
if command -v apt &> /dev/null; then
    echo "Checking for security updates..."
    apt list --upgradable 2>/dev/null | grep -i security || echo "No security updates available"
else
    echo "APT not available"
fi
echo ""

# ===== RUNNING SERVICES =====
print_header "RUNNING SERVICES"
echo "Active systemd services:"
systemctl list-units --type=service --state=running | head -20
echo ""

# ===== CRON JOBS =====
print_header "CRON JOBS"
echo "System Crontab:"
cat /etc/crontab 2>/dev/null || echo "Cannot read /etc/crontab"
echo ""

echo "Cron directories:"
for dir in /etc/cron.{hourly,daily,weekly,monthly}; do
    echo "$dir:"
    ls -la "$dir" 2>/dev/null || echo "  Not accessible"
done
echo ""

echo "User crontabs:"
for user in $(cut -f1 -d: /etc/passwd); do
    crontab -u $user -l 2>/dev/null && echo "User: $user"
done || echo "No user crontabs or insufficient permissions"
echo ""

# ===== AUDITD STATUS =====
print_header "AUDITD STATUS"
if command -v auditctl &> /dev/null; then
    if systemctl is-active --quiet auditd; then
        echo -e "Auditd Status: ${GREEN}ACTIVE${NC}"
        echo ""
        echo "Audit Rules:"
        auditctl -l | head -20 || echo "Cannot read audit rules"
    else
        echo -e "${YELLOW}⚠ Auditd is installed but NOT ACTIVE${NC}"
    fi
else
    echo -e "${RED}✗ Auditd is NOT INSTALLED${NC}"
fi
echo ""

# ===== PAM CONFIGURATION =====
print_header "PAM CONFIGURATION"
echo "PAM SSH Configuration (/etc/pam.d/sshd):"
cat /etc/pam.d/sshd 2>/dev/null || echo "Cannot read PAM SSH configuration"
echo ""

# ===== FILE INTEGRITY =====
print_header "FILE INTEGRITY"
if command -v aide &> /dev/null; then
    echo -e "AIDE Status: ${GREEN}INSTALLED${NC}"
    echo "AIDE database location: /var/lib/aide/"
else
    echo -e "${YELLOW}⚠ AIDE is NOT INSTALLED${NC}"
fi
echo ""

if command -v rkhunter &> /dev/null; then
    echo -e "RKHunter Status: ${GREEN}INSTALLED${NC}"
else
    echo -e "${YELLOW}⚠ RKHunter is NOT INSTALLED${NC}"
fi
echo ""

# ===== DISK USAGE =====
print_header "DISK USAGE"
df -h | grep -v tmpfs
echo ""

# ===== HACKEDSSH STATUS =====
print_header "HACKEDSSH STATUS"
if [ -f /usr/local/bin/HackedSSH.py ]; then
    echo -e "HackedSSH Installation: ${GREEN}FOUND${NC}"
    echo "Location: /usr/local/bin/HackedSSH.py"
    
    if systemctl list-unit-files | grep -q hackedssh.timer; then
        echo ""
        echo "Timer Status:"
        systemctl status hackedssh.timer --no-pager || true
        echo ""
        echo "Next Scheduled Run:"
        systemctl list-timers hackedssh.timer --no-pager || true
    else
        echo -e "${YELLOW}⚠ HackedSSH timer not installed${NC}"
    fi
else
    echo -e "${YELLOW}⚠ HackedSSH not found in /usr/local/bin/${NC}"
fi
echo ""

# ===== RECENT SECURITY EVENTS =====
print_header "RECENT SECURITY EVENTS (Last 50)"
echo "SSH Authentication Failures:"
journalctl -u ssh.service --since "24 hours ago" | grep -i "failed\|failure" | tail -20 || echo "No recent SSH failures"
echo ""

echo "Sudo Usage:"
journalctl --since "24 hours ago" | grep -i "sudo.*COMMAND" | tail -20 || echo "No recent sudo usage"
echo ""

echo "HackedSSH Logs:"
journalctl -t HackedSSH --since "7 days ago" | tail -20 || echo "No recent HackedSSH logs"
echo ""

# ===== SUMMARY =====
print_header "SECURITY AUDIT SUMMARY"
echo "Audit completed at: $(date)"
echo "Report saved to: $OUTPUT_FILE"
echo ""

# Count issues
issues=0
[[ $(grep -c "PermitRootLogin yes" /etc/ssh/sshd_config 2>/dev/null || echo 0) -gt 0 ]] && ((issues++))
[[ ! $(systemctl is-active --quiet fail2ban) ]] && ((issues++))
[[ ! $(command -v aide) ]] && ((issues++))
[[ ! $(command -v rkhunter) ]] && ((issues++))

if [ $issues -eq 0 ]; then
    echo -e "${GREEN}✓ No major security issues detected${NC}"
else
    echo -e "${YELLOW}⚠ $issues potential security issues found. Review the report above.${NC}"
fi

echo ""
echo "To address security issues:"
echo "  1. Review hardened configs in: config_examples/"
echo "  2. Install missing security tools"
echo "  3. Run HackedSSH regularly to monitor attacks"
echo ""

