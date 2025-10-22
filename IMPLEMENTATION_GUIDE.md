# HackedSSH Implementation Guide

## 🎉 Implementation Complete!

All security enhancements have been successfully implemented for your Thor server monitoring system.

---

## 📋 What Has Been Implemented

### ✅ Core Application Enhancements

#### 1. **Successful Login Detection** (CRITICAL!)
- Added patterns to detect successful SSH, sudo, and su logins
- Successful logins are now classified as **CRITICAL** events
- Immediate email alerts sent when any successful login is detected
- Prominently displayed in HTML reports with red highlighting

#### 2. **Enhanced Attack Detection Patterns**
- **Web Attacks**: SQL injection, path traversal, web shells, scanner detection
- **Privilege Escalation**: sudo/su attempts (failed and successful)
- **Network Attacks**: Port scanning, SYN flooding
- **Database Attacks**: MySQL, PostgreSQL, MongoDB
- **Account Enumeration**: Invalid users, root login attempts
- **Brute Force Detection**: Multiple authentication failures

#### 3. **Severity-Based Classification**
- **Critical**: Successful logins, web shells, root access
- **High**: SQL injection, port scans, privilege escalation failures
- **Medium**: Standard failed logins, invalid users
- **Low**: Connection attempts, negotiation failures

#### 4. **Real-Time Critical Alerts**
- New `send_critical_alert()` function for immediate notifications
- High-priority email flags for critical events
- Detailed event information in alerts

#### 5. **Code Security Fixes**
- Context managers for GeoIP readers (prevents resource leaks)
- Fixed command injection vulnerabilities (subprocess calls)
- Removed dangerous Express.js endpoint in HackedSSH.js

#### 6. **Enhanced HTML Reports**
- Successful login section (red highlighted if any detected)
- Severity-based event tables (Critical, High, Medium, Low)
- Improved summary statistics
- Better visual hierarchy with color coding

---

## 📁 New Files Created

### Configuration Examples (`config_examples/`)
1. **sshd_config.hardened** - Production-ready hardened SSH configuration
2. **sshd_banner** - SSH login warning banner
3. **fail2ban_jail.local** - Fail2Ban jail configuration
4. **fail2ban_filter_hackedssh.conf** - Custom Fail2Ban filter
5. **pam_sshd** - PAM configuration for SSH
6. **pam_common-auth** - PAM authentication configuration
7. **pam_common-account** - PAM account management
8. **security_limits.conf** - System resource limits
9. **audit.rules** - Comprehensive auditd rules
10. **hackedssh.service** - Systemd service definition
11. **hackedssh.timer** - Systemd timer for daily reports

### Scripts (`scripts/`)
1. **setup_ufw_firewall.sh** - UFW firewall configuration script
2. **install_hackedssh_service.sh** - Install HackedSSH as systemd service
3. **install_security_tools.sh** - Install all security tools
4. **system_security_audit.sh** - Comprehensive security audit

---

## 🚀 Quick Start Implementation

### Phase 1: Test the Enhanced HackedSSH (5 minutes)

```bash
cd /home/marcus/Code/python/Hacked

# Run with debug mode to see what it detects
sudo python3 HackedSSH.py --debug

# Check the generated report
firefox /var/www/html/HackedSSH_Report.html
```

### Phase 2: Install Security Tools (15-30 minutes)

```bash
# Install all security tools
sudo bash scripts/install_security_tools.sh

# This installs:
# - Fail2Ban
# - UFW
# - Auditd
# - AIDE (file integrity)
# - RKHunter (rootkit detection)
# - ClamAV (antivirus)
# - Lynis (security audit)
# - And more...
```

### Phase 3: Configure Firewall (5 minutes)

```bash
# Set up UFW firewall
sudo bash scripts/setup_ufw_firewall.sh

# Verify firewall is active
sudo ufw status verbose
```

### Phase 4: Configure Fail2Ban (10 minutes)

```bash
# Copy configuration
sudo cp config_examples/fail2ban_jail.local /etc/fail2ban/jail.local
sudo cp config_examples/fail2ban_filter_hackedssh.conf /etc/fail2ban/filter.d/hackedssh.conf

# Edit email address
sudo nano /etc/fail2ban/jail.local
# Change: destemail = marcus@davage.me (verify this is correct)

# Restart Fail2Ban
sudo systemctl restart fail2ban
sudo systemctl enable fail2ban

# Check status
sudo fail2ban-client status
```

### Phase 5: Harden SSH Configuration (15 minutes - CAREFUL!)

**⚠️ CRITICAL: DO THIS CAREFULLY!**

```bash
# BEFORE YOU START:
# 1. Make sure you have SSH keys set up
# 2. Keep current SSH session open
# 3. Test in another terminal before closing this one

# Backup original config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup.$(date +%Y%m%d)

# Review the hardened config
nano config_examples/sshd_config.hardened

# Edit for your needs (especially AllowUsers line!)
# Change: AllowUsers marcus  (use your username!)

# Copy hardened config
sudo cp config_examples/sshd_config.hardened /etc/ssh/sshd_config

# Copy banner
sudo cp config_examples/sshd_banner /etc/ssh/sshd_banner

# TEST THE CONFIG (IMPORTANT!)
sudo sshd -t

# If test passes, restart SSH
sudo systemctl restart sshd

# TEST LOGIN IN NEW TERMINAL BEFORE CLOSING THIS ONE!
# Open new terminal: ssh marcus@thor
```

### Phase 6: Configure Auditd (10 minutes)

```bash
# Copy audit rules
sudo cp config_examples/audit.rules /etc/audit/rules.d/audit.rules

# Load rules
sudo augenrules --load

# Restart auditd
sudo systemctl restart auditd
sudo systemctl enable auditd

# Verify rules loaded
sudo auditctl -l | head -20
```

### Phase 7: Install HackedSSH Service (5 minutes)

```bash
# Install as systemd service for daily reports
sudo bash scripts/install_hackedssh_service.sh

# Verify timer is active
sudo systemctl status hackedssh.timer

# View next scheduled run
sudo systemctl list-timers hackedssh.timer
```

### Phase 8: Run Security Audit (5 minutes)

```bash
# Run comprehensive security audit
sudo bash scripts/system_security_audit.sh

# Review the report
cat /tmp/thor_security_audit_*.txt
```

---

## 🔍 Verification Steps

### 1. Test HackedSSH Detections

```bash
# Generate some test events
# (These will be detected in next report)

# Trigger a failed SSH attempt (use wrong password)
ssh wronguser@localhost

# View what was detected
sudo python3 HackedSSH.py --debug --from_date today --to_date today
```

### 2. Check Fail2Ban is Working

```bash
# View active jails
sudo fail2ban-client status

# Check SSH jail specifically
sudo fail2ban-client status sshd

# View fail2ban logs
sudo tail -f /var/log/fail2ban.log
```

### 3. Verify Firewall is Active

```bash
# Check UFW status
sudo ufw status numbered

# View UFW logs
sudo tail -f /var/log/ufw.log
```

### 4. Test Email Alerts

```bash
# Run HackedSSH manually
sudo systemctl start hackedssh.service

# Check if email was sent
sudo journalctl -u hackedssh.service -n 50

# Check mail logs
sudo tail -f /var/log/mail.log
```

### 5. Monitor Successful Logins

```bash
# Your next successful SSH login should:
# 1. Be detected by HackedSSH
# 2. Show in red in the HTML report
# 3. Trigger a critical alert email
# 4. Appear in auditd logs

# After your next login, check:
sudo journalctl -t HackedSSH --since "1 hour ago"
```

---

## 📊 Daily Monitoring Routine

### Every Morning
1. Check email for HackedSSH report (sent at 1:00 AM)
2. Review any critical alerts (successful logins)
3. Check Fail2Ban ban count: `sudo fail2ban-client status sshd`

### Weekly
1. Run security audit: `sudo bash scripts/system_security_audit.sh`
2. Review Fail2Ban logs: `sudo fail2ban-client status`
3. Check for system updates: `sudo apt update && sudo apt list --upgradable`
4. Run rootkit scan: `sudo rkhunter --check --skip-keypress`

### Monthly
1. Full security audit with Lynis: `sudo lynis audit system`
2. AIDE file integrity check: `sudo aide --check`
3. ClamAV virus scan: `sudo clamscan -r /home`
4. Review and update security configurations
5. Update GeoIP databases

---

## 🚨 Critical Alert Response

### If You Receive a Successful Login Alert:

1. **Don't Panic** - Check if it was you
2. **Verify the details**:
   - IP address (was it you?)
   - Time (were you logged in then?)
   - User account (correct user?)
3. **If NOT you**:
   ```bash
   # Immediately check active sessions
   who
   w
   
   # Check recent logins
   last -20
   
   # Kill suspicious sessions
   sudo pkill -u suspicious_user
   
   # Change passwords immediately
   sudo passwd compromised_user
   
   # Review auditd logs
   sudo ausearch -ts recent -m USER_LOGIN
   
   # Check what was done
   sudo ausearch -ts recent -k exec
   ```

4. **Lock down the system**:
   ```bash
   # Temporarily disable SSH password auth
   sudo nano /etc/ssh/sshd_config
   # Set: PasswordAuthentication no
   sudo systemctl restart sshd
   
   # Ban the attacker IP
   sudo ufw deny from <attacker_ip>
   sudo fail2ban-client set sshd banip <attacker_ip>
   ```

5. **Investigate**:
   ```bash
   # Check what was accessed
   sudo ausearch -ts recent -ui <compromised_uid>
   
   # Check for backdoors
   sudo rkhunter --check
   
   # Run full antivirus scan
   sudo clamscan -r /
   ```

---

## 🎯 Key Files to Monitor

### Log Files
- `/var/log/auth.log` - Authentication events
- `/var/log/syslog` - System events
- `/var/log/fail2ban.log` - Fail2Ban actions
- `/var/log/ufw.log` - Firewall events
- `/var/log/audit/audit.log` - Auditd events

### Configuration Files
- `/etc/ssh/sshd_config` - SSH configuration
- `/etc/fail2ban/jail.local` - Fail2Ban configuration
- `/etc/audit/rules.d/audit.rules` - Audit rules
- `/usr/local/bin/HackedSSH.ini` - HackedSSH config

### Report Files
- `/var/www/html/HackedSSH_Report.html` - Main report
- `/var/www/html/HackedSSH_Map.html` - Attack map

---

## 🛠️ Useful Commands Cheat Sheet

### HackedSSH
```bash
# Run report manually
sudo systemctl start hackedssh.service

# View logs
sudo journalctl -u hackedssh.service -f

# Check timer
sudo systemctl list-timers hackedssh.timer

# Disable timer
sudo systemctl stop hackedssh.timer
```

### Fail2Ban
```bash
# Status overview
sudo fail2ban-client status

# SSH jail status
sudo fail2ban-client status sshd

# Unban an IP
sudo fail2ban-client set sshd unbanip <IP>

# Ban an IP manually
sudo fail2ban-client set sshd banip <IP>
```

### UFW
```bash
# Status
sudo ufw status verbose

# Allow port
sudo ufw allow 8080/tcp

# Deny IP
sudo ufw deny from <IP>

# Delete rule
sudo ufw delete <rule_number>
```

### Auditd
```bash
# Search recent events
sudo ausearch -ts recent

# Search by user
sudo ausearch -ui <uid>

# Search by key
sudo ausearch -k ssh_key_changes

# Generate report
sudo aureport --auth
```

---

## 📈 Expected Results

After full implementation, you should have:

✅ **Reduced Attack Surface**
- SSH properly hardened
- Firewall blocking unwanted traffic
- Fail2Ban auto-banning attackers

✅ **Comprehensive Monitoring**
- Daily security reports emailed to you
- Successful login tracking
- Attack pattern detection
- Geographic tracking of threats

✅ **Immediate Alerting**
- Critical events trigger instant emails
- Successful logins prominently displayed
- Severity-based event classification

✅ **Audit Trail**
- Auditd logging all system calls
- File integrity monitoring with AIDE
- Fail2Ban logging all bans

✅ **Regular Security Checks**
- Automated daily HackedSSH reports
- Easy-to-run security audit script
- Rootkit and malware detection tools

---

## 🎓 Next Level Security (Optional)

### Consider Adding:
1. **Two-Factor Authentication (2FA)**
   ```bash
   sudo apt install libpam-google-authenticator
   google-authenticator
   ```

2. **VPN for Remote Access**
   - Use WireGuard or OpenVPN
   - Only allow SSH through VPN

3. **Honeypot**
   - Install Cowrie honeypot
   - Gather intelligence on attackers

4. **Centralized Logging**
   - Set up rsyslog to remote server
   - Prevent attacker from deleting logs

5. **OSSEC or Wazuh**
   - Enterprise-grade HIDS
   - More advanced detection

---

## 📞 Support & Troubleshooting

### Common Issues

**Issue**: HackedSSH not detecting events
```bash
# Check if journalctl has data
sudo journalctl -u ssh.service --since today

# Run with debug
sudo python3 HackedSSH.py --debug
```

**Issue**: Email not sending
```bash
# Test sendmail
echo "Test" | sendmail -v marcus@davage.me

# Check mail logs
sudo tail -f /var/log/mail.log
```

**Issue**: Timer not running
```bash
# Reload systemd
sudo systemctl daemon-reload
sudo systemctl restart hackedssh.timer
sudo systemctl status hackedssh.timer
```

---

## ✅ Implementation Checklist

- [ ] Tested enhanced HackedSSH.py
- [ ] Installed security tools
- [ ] Configured UFW firewall
- [ ] Configured Fail2Ban
- [ ] Hardened SSH configuration (CAREFULLY!)
- [ ] Configured Auditd
- [ ] Installed HackedSSH systemd service
- [ ] Ran security audit
- [ ] Verified email alerts work
- [ ] Documented your custom configurations
- [ ] Set up calendar reminders for weekly/monthly checks

---

## 🎉 Congratulations!

Your Thor server now has enterprise-grade security monitoring and protection!

**Remember**: Security is an ongoing process. Stay vigilant and monitor your alerts regularly.

---

**Questions or issues?** Check the logs:
```bash
sudo journalctl -t HackedSSH -f
```

**Stay safe!** 🛡️

