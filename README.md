# HackedSSH - Advanced Security Monitoring System

![Security](https://img.shields.io/badge/Security-Enhanced-green)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

A comprehensive security monitoring and reporting system that tracks failed and **successful** login attempts, detects various cyber attacks, and provides automated alerts for Thor (your Ubuntu server).

## 🎯 Features

### Core Monitoring
- ✅ **SSH Login Monitoring** - Failed and successful attempts
- ✅ **Multi-Service Support** - SSH, RDP, FTP, MySQL, Nginx, Apache, SMTP, and more
- ✅ **Successful Login Detection** - **NEW!** Critical security feature
- ✅ **Real-time Critical Alerts** - Immediate email notifications for security events
- ✅ **Severity-based Classification** - Critical, High, Medium, Low event categorization
- ✅ **Geographic Tracking** - IP geolocation with interactive maps
- ✅ **Attack Pattern Detection** - Web attacks, SQL injection, port scanning, privilege escalation

### Enhanced Security Detection
- 🔍 **Web Attacks**: SQL injection, path traversal, web shells, scanner detection
- 🔍 **Privilege Escalation**: sudo/su attempts (failed and successful)
- 🔍 **Network Attacks**: Port scanning, SYN flooding
- 🔍 **Database Attacks**: MySQL, PostgreSQL, MongoDB authentication failures
- 🔍 **Account Enumeration**: Invalid user detection, root login attempts
- 🔍 **Brute Force Detection**: Multiple authentication failures

### Reporting & Alerts
- 📊 **Beautiful HTML Reports** with collapsible sections
- 📧 **Email Notifications** with severity indicators
- 🗺️ **Interactive Maps** showing attack origins with:
  - Security event markers (Critical/High/Medium severity)
  - Nginx access IP markers
  - Configurable map legend
  - Multiple map tile options
- 📈 **Statistics Dashboard** - Countries, cities, users, IPs
- 🚨 **Critical Event Highlighting** - Immediate attention to successful logins

### Advanced Geolocation
- 🌍 **Dual Geolocation Methods**:
  - **API Method** (ip-api.com): Fast, accurate, always up-to-date with batch processing (100 IPs/request)
  - **Database Method** (GeoLite2): Local, offline-capable with automatic download support
- 🔄 **Automatic Database Updates**: Downloads GeoLite2 databases from MaxMind when missing
- 💾 **Smart Caching**: API responses cached locally to minimize requests and respect rate limits

## 🚀 Quick Start

### Installation

1. **Clone the repository:**
```bash
cd /home/<your-user-id>/Code/python
git clone <your-repo-url> Hacked
cd Hacked
```

2. **Install dependencies:**
```bash
sudo pip3 install folium geoip2 jinja2 systemd-python configparser
```

3. **Configure settings:**
```bash
# Copy template to standard location (or current directory for development)
sudo cp config.ini.template /usr/local/etc/HackedSSH.ini
# Or for development:
cp config.ini.template HackedSSH.ini

# Edit configuration
sudo nano /usr/local/etc/HackedSSH.ini
# Or for development:
nano HackedSSH.ini

# Configure:
# - Email settings (sender_email, recipient_email)
# - Web URLs (report_url, local_url)
# - Map settings (tiles, markers, geolocation method)
# - MaxMind credentials (if using database method)
```

4. **Run manually:**
```bash
sudo python3 HackedSSH.py
```

5. **Install as automated service:**
```bash
sudo bash scripts/install_hackedssh_service.sh
```

## 📋 Usage

### Basic Usage
```bash
# Process yesterday's logs (default)
sudo python3 HackedSSH.py

# Specify date range
sudo python3 HackedSSH.py --from_date '2024-05-16' --to_date '2024-05-17'

# Send to different email
sudo python3 HackedSSH.py --email custom@email.com

# Debug mode
sudo python3 HackedSSH.py --debug
```

### Automated Daily Reports

The system includes systemd timer for automated daily reports at 1:00 AM:

```bash
# Check timer status
sudo systemctl status hackedssh.timer

# View next scheduled run
sudo systemctl list-timers hackedssh.timer

# Run report manually
sudo systemctl start hackedssh.service

# View logs
sudo journalctl -u hackedssh.service
```

## 🔒 Security Hardening

### Step 1: Install Security Tools

Run the comprehensive security tools installer:
```bash
sudo bash scripts/install_security_tools.sh
```

This installs:
- **Fail2Ban** - Intrusion prevention
- **UFW** - Firewall management
- **Auditd** - System call auditing
- **AIDE** - File integrity monitoring
- **RKHunter** - Rootkit detection
- **ClamAV** - Antivirus protection
- **Lynis** - Security auditing
- And more...

### Step 2: Configure SSH (Critical!)

**Copy and customize the hardened SSH configuration:**
```bash
# Backup original
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Review and customize hardened config
sudo nano config_examples/sshd_config.hardened

# Apply (carefully!)
sudo cp config_examples/sshd_config.hardened /etc/ssh/sshd_config

# IMPORTANT: Test configuration before restarting
sudo sshd -t

# If test passes, restart SSH
sudo systemctl restart sshd
```

**Key SSH Security Settings:**
- ✅ Disable root login: `PermitRootLogin no`
- ✅ Use key-based auth only: `PasswordAuthentication no`
- ✅ Limit authentication attempts: `MaxAuthTries 3`
- ✅ Use strong ciphers and MACs
- ✅ Set idle timeout
- ✅ Optional: Change default port

### Step 3: Configure Firewall

```bash
sudo bash scripts/setup_ufw_firewall.sh
```

This configures:
- Default deny incoming
- Allow SSH, HTTP, HTTPS
- Rate limiting on SSH
- Logging enabled

### Step 4: Configure Fail2Ban

```bash
# Copy jail configuration
sudo cp config_examples/fail2ban_jail.local /etc/fail2ban/jail.local

# Copy custom filter
sudo cp config_examples/fail2ban_filter_hackedssh.conf /etc/fail2ban/filter.d/hackedssh.conf

# Edit email settings
sudo nano /etc/fail2ban/jail.local

# Restart Fail2Ban
sudo systemctl restart fail2ban
sudo systemctl enable fail2ban

# Check status
sudo fail2ban-client status
```

### Step 5: Configure Auditd

```bash
# Copy audit rules
sudo cp config_examples/audit.rules /etc/audit/rules.d/audit.rules

# Load rules
sudo augenrules --load

# Restart auditd
sudo systemctl restart auditd

# Verify rules
sudo auditctl -l
```

### Step 6: Configure PAM (Optional but Recommended)

```bash
# Backup original files
sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.backup
sudo cp /etc/pam.d/common-auth /etc/pam.d/common-auth.backup

# Review PAM configurations
cat config_examples/pam_sshd
cat config_examples/pam_common-auth

# Apply with caution - test in a safe environment first!
```

### Step 7: Run Security Audit

```bash
sudo bash scripts/system_security_audit.sh
# Review the generated report
```

## 📊 Report Output

The system generates:

1. **HackedSSH_Report.html** - Main security report
   - Summary statistics
   - **Successful logins section** (highlighted in red if any detected)
   - **Severity-based event classification**
   - Failed attempts by country
   - Failed attempts by user
   - Links to AbuseIPDB for each IP

2. **HackedSSH_Map.html** - Interactive map showing attack origins

3. **Email alerts** - Immediate notifications for:
   - Any successful login
   - Critical security events
   - High severity attacks

## 🎨 Sample Report

The HTML report includes:
- 📊 Summary dashboard with total attempts, successful logins, critical events
- 🚨 **Prominent successful login warnings** (red background)
- 🌍 Country-by-country breakdown with IP details
- 👤 User attempt statistics
- 🗺️ Interactive geographic map
- 📊 Severity-level event tables
- 🔗 Links to AbuseIPDB for threat intelligence

## 🔧 Configuration Files

### HackedSSH.ini

Configuration file location (checked in priority order):
1. `/usr/local/etc/HackedSSH.ini` (standard system location)
2. `/usr/local/bin/HackedSSH.ini` (backward compatibility)
3. `./HackedSSH.ini` (current directory, for development)

```ini
[EMAIL]
sender_email = odin@davage.me
recipient_email = marcus@davage.me

[WEB]
hostname = home.davage.me
report_url = http://home.davage.me/HackedSSH_Report.html
local_url = http://odin.local/HackedSSH_Report.html

[MAP]
# Base map tiles (OpenStreetMap, CartoDB positron, CartoDB dark_matter, Stamen Terrain)
tiles = CartoDB positron

# Enable/disable map features
enable_security_event_markers = True
enable_nginx_markers = True
enable_legend = False

# Geolocation method: 'api' (ip-api.com - faster, more accurate) or 'database' (GeoLite2 - local)
geolocation_method = api

# MaxMind credentials (required for automatic GeoLite2 database download)
# Get free account at: https://www.maxmind.com/en/geolite2/signup
# maxmind_account_id = YOUR_ACCOUNT_ID_HERE
# maxmind_license_key = YOUR_LICENSE_KEY_HERE
```

## 📁 Project Structure

```
Hacked/
├── HackedSSH.py              # Main monitoring script
├── HackedSSH.html            # HTML report template
├── config.ini.template        # Configuration template
├── HackedSSH.ini             # Configuration file (not in git, contains secrets)
├── HackedSSH.js              # Express server (optional)
├── HackedSSH.sh              # Shell wrapper
├── countries.py              # Country code mappings
├── .geo_cache.json           # API geolocation cache (auto-generated)
├── GeoLite2-City.mmdb        # GeoIP database (auto-downloaded if missing)
└── GeoLite2-Country.mmdb     # GeoIP database (auto-downloaded if missing)
├── config_examples/          # Security configuration examples
│   ├── sshd_config.hardened  # Hardened SSH config
│   ├── sshd_banner           # SSH login banner
│   ├── fail2ban_jail.local   # Fail2Ban configuration
│   ├── fail2ban_filter_hackedssh.conf
│   ├── pam_sshd              # PAM SSH configuration
│   ├── pam_common-auth       # PAM authentication
│   ├── pam_common-account    # PAM account management
│   ├── security_limits.conf  # Resource limits
│   ├── audit.rules           # Auditd rules
│   ├── hackedssh.service     # Systemd service
│   └── hackedssh.timer       # Systemd timer
└── scripts/                  # Installation & management scripts
    ├── install_hackedssh_service.sh
    ├── install_security_tools.sh
    ├── setup_ufw_firewall.sh
    └── system_security_audit.sh
```

## 🚨 Critical Security Notes

### ⚠️ BEFORE YOU START

1. **Test SSH changes in a safe environment** - Lock yourself out at your own risk!
2. **Always keep a backup SSH session open** when making SSH config changes
3. **Test SSH config** with `sudo sshd -t` before restarting
4. **Document your changes** - especially custom SSH ports or allowed users
5. **Review logs regularly** - Security is an ongoing process

### 🔑 Best Practices

1. **Use SSH keys** instead of passwords
2. **Enable 2FA** for critical accounts (Google Authenticator)
3. **Change default SSH port** to reduce automated attacks
4. **Limit SSH access** by IP when possible
5. **Monitor logs daily** - Automated reports help!
6. **Keep system updated** - `sudo apt update && sudo apt upgrade`
7. **Regular security audits** - Run audit script weekly
8. **Review Fail2Ban bans** - `sudo fail2ban-client status sshd`
9. **Check successful logins** - **ANY unexpected login is critical**
10. **Test backups** - Can you recover if attacked?

## 📊 Attack Detection Coverage

| Attack Type | Detection | Severity | Alert |
|------------|-----------|----------|-------|
| Successful SSH Login | ✅ | Critical | Email |
| Successful Sudo | ✅ | Critical | Email |
| Failed SSH Login | ✅ | Medium | Report |
| SQL Injection | ✅ | High | Report |
| Path Traversal | ✅ | High | Report |
| Web Shell Upload | ✅ | Critical | Email |
| Port Scanning | ✅ | High | Report |
| Brute Force | ✅ | Medium | Report |
| Account Enumeration | ✅ | Medium | Report |
| Root Login Attempt | ✅ | Medium | Report |
| Privilege Escalation | ✅ | High | Report |

## 🛠️ Troubleshooting

### No data in report
```bash
# Check if services are generating logs
sudo journalctl -u ssh.service --since today

# Run with debug mode
sudo python3 HackedSSH.py --debug
```

### Email not sending
```bash
# Check sendmail configuration
sudo sendmail -v marcus@davage.me < /dev/null

# View HackedSSH logs
sudo journalctl -t HackedSSH
```

### Timer not running
```bash
# Check timer status
sudo systemctl status hackedssh.timer

# Reload systemd
sudo systemctl daemon-reload
sudo systemctl restart hackedssh.timer
```

## 🔄 Geolocation Configuration

### Choosing a Geolocation Method

**API Method (Recommended)** - `geolocation_method = api`
- ✅ Fast batch processing (100 IPs per request)
- ✅ Always up-to-date data
- ✅ More accurate location data
- ✅ Automatic caching to minimize API calls
- ⚠️ Requires internet connection
- ⚠️ Rate limit: 45 requests/minute (handled automatically)

**Database Method** - `geolocation_method = database`
- ✅ Works offline
- ✅ No rate limits
- ⚠️ Requires local database files
- ⚠️ May be outdated (databases updated weekly by MaxMind)

### Automatic GeoLite2 Database Download

If using the database method, HackedSSH can automatically download GeoLite2 databases when missing:

1. **Get a free MaxMind account:**
   - Sign up at https://www.maxmind.com/en/geolite2/signup
   - Find your Account ID and License Key in your account portal

2. **Add credentials to config:**
   ```ini
   [MAP]
   maxmind_account_id = YOUR_ACCOUNT_ID_HERE
   maxmind_license_key = YOUR_LICENSE_KEY_HERE
   ```

3. **Automatic download:**
   - Databases are downloaded to `/usr/local/etc/` (or `/usr/local/bin/` if that doesn't exist)
   - Compatible with MaxMind's current R2 presigned URL system
   - Uses Basic Authentication (AccountID + LicenseKey)
   - Follows official documentation: https://dev.maxmind.com/geoip/updating-databases/

### Manual Database Updates

If you prefer manual updates:
```bash
# Download from MaxMind account portal using permalinks
# Place in /usr/local/etc/ or /usr/local/bin/
```

## 📈 Future Enhancements

- [ ] Web dashboard for real-time monitoring
- [ ] Machine learning for anomaly detection
- [ ] Integration with threat intelligence feeds
- [ ] Automated response actions (auto-ban, auto-alert)
- [ ] Historical trending and analytics
- [ ] Multi-server monitoring support
- [ ] Mobile app notifications
- [ ] Honeypot integration

## 🤝 Contributing

Contributions are welcome! Areas for improvement:
- Additional attack pattern detection
- More service integrations
- Better visualization
- Performance optimizations
- Documentation improvements

## 📝 License

MIT License - Feel free to use and modify as needed.

## 🙏 Acknowledgments

- GeoIP data from MaxMind
- AbuseIPDB for threat intelligence
- Folium for mapping
- The security community for best practices

## 📧 Contact

Marcus Davage - marcus@davage.me

## ⚠️ Disclaimer

This tool is for monitoring and detecting security threats on systems you own or have permission to monitor. Always ensure you comply with local laws and regulations regarding system monitoring and logging.

---

**Remember**: Security is not a destination, it's a journey. Stay vigilant! 🛡️
