# HackedSSH Installation Guide for Raspberry Pi (Heimdall)

## 🍓 Installing on Raspberry Pi Gateway

This guide covers installing HackedSSH on your Raspberry Pi (Heimdall) which serves as your internet gateway.

---

## 📋 Prerequisites

### System Requirements
- **Raspberry Pi**: 3B+, 4, or 5 (recommended)
- **OS**: Raspberry Pi OS (Debian-based)
- **RAM**: 1GB minimum, 2GB+ recommended
- **Storage**: 8GB SD card minimum, 16GB+ recommended
- **Network**: Configured as gateway/router

### Check Your Setup
```bash
# On Heimdall, check system info
uname -a
cat /proc/cpuinfo | grep Model
free -h
df -h
```

---

## 🚀 Quick Installation

### Option 1: Automated Installation (Recommended)

```bash
# SSH into Heimdall
ssh pi@heimdall.local
# or
ssh pi@heimdall

# Copy the entire Hacked directory to Heimdall
# From your local machine:
scp -r /home/marcus/Code/python/Hacked pi@heimdall:~/

# On Heimdall, run the installation
cd ~/Hacked
sudo bash scripts/install_security_tools.sh
sudo bash scripts/install_hackedssh_service.sh
```

### Option 2: Manual Step-by-Step Installation

See detailed steps below.

---

## 📦 Step 1: System Update

```bash
# On Heimdall
sudo apt update
sudo apt upgrade -y
sudo apt autoremove -y
```

---

## 🐍 Step 2: Install Python Dependencies

### For Debian 12 (Bookworm) and newer (with externally-managed-environment):

```bash
# Install Python 3 and pip
sudo apt install python3 python3-pip python3-venv -y

# Install available packages via apt (preferred method)
sudo apt install python3-jinja2 python3-systemd -y

# Install remaining packages with --break-system-packages
# (Safe for system services like HackedSSH)
sudo pip3 install --break-system-packages folium geoip2 configparser
```

### For older Debian/Raspbian versions:

```bash
# Install Python 3 and pip
sudo apt install python3 python3-pip -y

# Install required Python packages
sudo pip3 install folium geoip2 jinja2 systemd-python configparser
```

### Alternative: Using Virtual Environment (Optional)

If you prefer isolation:
```bash
python3 -m venv ~/hackedssh-venv
source ~/hackedssh-venv/bin/activate
pip install folium geoip2 jinja2 systemd-python configparser

# Then modify the service file to use:
# ExecStart=/home/pi/hackedssh-venv/bin/python3 /usr/local/bin/HackedSSH.py
```

---

## 📁 Step 3: Copy Files to Heimdall

### From Thor or your development machine:

```bash
# Create directory on Heimdall
ssh pi@heimdall "mkdir -p ~/Hacked"

# Copy all files
scp -r /home/marcus/Code/python/Hacked/* pi@heimdall:~/Hacked/

# Or use rsync (better for updates):
rsync -avz --progress /home/marcus/Code/python/Hacked/ pi@heimdall:~/Hacked/
```

### Alternatively, clone from Git:

```bash
# On Heimdall
cd ~
git clone <your-repo-url> Hacked
cd Hacked
```

---

## 🔧 Step 4: Configure for Raspberry Pi

### Update Configuration File

```bash
# On Heimdall
cd ~/Hacked
nano HackedSSH.ini
```

Update for Heimdall:
```ini
[EMAIL]
sender_email = heimdall@davage.me
recipient_email = marcus@davage.me

[WEB]
hostname = heimdall.local
report_url = http://heimdall.local/HackedSSH_Report.html
local_url = http://heimdall.local/HackedSSH_Report.html
```

### Modify HackedSSH.py for Raspberry Pi

The script needs slight modification for Raspberry Pi's architecture:

```bash
nano HackedSSH.py
```

Check the ROOT path detection works:
```python
# Should detect correctly, but verify:
if os.getlogin() == 'root':
    ROOT = '/usr/local/bin'
else:
    ROOT = '.'
```

---

## 🌐 Step 5: Install Web Server

```bash
# Install nginx (lighter than Apache for Pi)
sudo apt install nginx -y

# Create web directory
sudo mkdir -p /var/www/html

# Set permissions
sudo chown -R www-data:www-data /var/www/html
sudo chmod -R 755 /var/www/html

# Enable and start nginx
sudo systemctl enable nginx
sudo systemctl start nginx

# Test
curl http://localhost
```

---

## 📧 Step 6: Configure Email (Postfix)

```bash
# Install postfix for sending emails
sudo apt install postfix mailutils -y

# During installation, select:
# - Internet Site
# - System mail name: heimdall.local (or your domain)

# Test email
echo "Test from Heimdall" | mail -s "Test Email" marcus@davage.me

# Check mail logs
sudo tail -f /var/log/mail.log
```

### Configure Postfix for External SMTP (Optional)

If you want to use external SMTP (Gmail, etc.):

```bash
sudo nano /etc/postfix/main.cf
```

Add:
```
relayhost = [smtp.gmail.com]:587
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = hash:/etc/postfix/sasl_passwd
smtp_sasl_security_options = noanonymous
smtp_tls_security_level = encrypt
```

Create credentials:
```bash
sudo nano /etc/postfix/sasl_passwd
# Add:
[smtp.gmail.com]:587 your-email@gmail.com:your-app-password

sudo postmap /etc/postfix/sasl_passwd
sudo chmod 600 /etc/postfix/sasl_passwd*
sudo systemctl restart postfix
```

---

## 🔒 Step 7: Install Security Tools

```bash
cd ~/Hacked

# Run security tools installer
sudo bash scripts/install_security_tools.sh

# This installs:
# - Fail2Ban
# - UFW (firewall)
# - Auditd
# - AIDE
# - RKHunter
# - ClamAV
# - And more...
```

---

## 🛡️ Step 8: Configure Firewall (IMPORTANT!)

**⚠️ CRITICAL: Be careful with firewall on gateway device!**

```bash
# Configure UFW carefully
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw default allow routed  # IMPORTANT for gateway!

# Allow SSH from local network only
sudo ufw allow from 192.168.1.0/24 to any port 22

# Allow web server
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Allow DNS (if Heimdall is DNS server)
sudo ufw allow 53/tcp
sudo ufw allow 53/udp

# Allow DHCP (if Heimdall is DHCP server)
sudo ufw allow 67/udp
sudo ufw allow 68/udp

# Enable UFW
sudo ufw enable

# Check status
sudo ufw status verbose
```

---

## ⏰ Step 9: Install HackedSSH Service

```bash
cd ~/Hacked

# Run the installer
sudo bash scripts/install_hackedssh_service.sh

# This will:
# - Copy files to /usr/local/bin
# - Install systemd service and timer
# - Enable daily reports at 1:00 AM

# Verify installation
sudo systemctl status hackedssh.timer
sudo systemctl list-timers hackedssh.timer
```

---

## 🧪 Step 10: Test Everything

### Test HackedSSH Manually

```bash
# Run once manually
sudo python3 /usr/local/bin/HackedSSH.py --debug

# Check output
ls -la /var/www/html/HackedSSH*

# View report in browser
# From another device: http://heimdall.local/HackedSSH_Report.html
```

### Test Email

```bash
# Trigger the service manually
sudo systemctl start hackedssh.service

# Check logs
sudo journalctl -u hackedssh.service -n 50

# Check if email was sent
sudo tail -f /var/log/mail.log
```

---

## 🎯 Raspberry Pi Specific Optimizations

### 1. Reduce Memory Usage

```bash
# Limit journal size
sudo nano /etc/systemd/journald.conf
```

Set:
```ini
SystemMaxUse=100M
RuntimeMaxUse=50M
```

```bash
sudo systemctl restart systemd-journald
```

### 2. Use Lighter Services

```bash
# If memory is tight, use lighter alternatives
# - Use nginx instead of Apache
# - Limit ClamAV scans to weekly
# - Reduce Fail2Ban check frequency
```

### 3. SD Card Longevity

```bash
# Reduce writes to SD card
# Move logs to tmpfs (RAM)
sudo nano /etc/fstab
```

Add:
```
tmpfs /tmp tmpfs defaults,noatime,nosuid,size=100m 0 0
tmpfs /var/tmp tmpfs defaults,noatime,nosuid,size=50m 0 0
```

### 4. Schedule Intensive Tasks

```bash
# Schedule resource-intensive tasks during low-traffic times
# Edit timer to run at 3 AM instead of 1 AM:
sudo nano /etc/systemd/system/hackedssh.timer
```

Change:
```ini
OnCalendar=*-*-* 03:00:00
```

---

## 📊 Monitoring Heimdall's Performance

### Check Resource Usage

```bash
# CPU and memory
htop

# Disk I/O
sudo iotop

# Network
sudo iftop

# Temperature (important for Pi!)
vcgencmd measure_temp
```

### Create Monitoring Script

```bash
nano ~/monitor_heimdall.sh
```

```bash
#!/bin/bash
echo "=== Heimdall Status ==="
echo "Temperature: $(vcgencmd measure_temp)"
echo "Memory: $(free -h | grep Mem | awk '{print $3 "/" $2}')"
echo "CPU Load: $(uptime | awk -F'load average:' '{print $2}')"
echo "Disk: $(df -h / | tail -1 | awk '{print $3 "/" $2 " (" $5 ")"}')"
echo "Active Connections: $(ss -tuna | wc -l)"
echo "Fail2Ban Bans: $(sudo fail2ban-client status sshd | grep "Currently banned" | awk '{print $4}')"
```

```bash
chmod +x ~/monitor_heimdall.sh
```

---

## 🌐 Monitoring Traffic from Thor Through Heimdall

Since Heimdall is your gateway, you can monitor all traffic:

### Option 1: Monitor Forwarded Traffic

Add to HackedSSH.py to monitor iptables logs:

```bash
# Enable iptables logging
sudo iptables -A FORWARD -j LOG --log-prefix "FORWARD: "

# HackedSSH can parse these logs too
```

### Option 2: Monitor Multiple Machines

Create separate configs for each machine:

```bash
# On Heimdall, monitor both Heimdall and Thor
sudo python3 HackedSSH.py --from_date today --to_date today

# The journald logs will include forwarded auth attempts
```

### Option 3: Centralized Logging

Set up Thor to send logs to Heimdall:

**On Thor:**
```bash
sudo nano /etc/rsyslog.conf
```

Add:
```
*.* @@heimdall:514
```

**On Heimdall:**
```bash
sudo nano /etc/rsyslog.conf
```

Add:
```
$ModLoad imtcp
$InputTCPServerRun 514
```

```bash
sudo systemctl restart rsyslog
```

Now HackedSSH on Heimdall sees logs from both!

---

## 🔧 Troubleshooting

### Issue: Service fails to start

```bash
# Check Python path
which python3

# Check permissions
sudo chown root:root /usr/local/bin/HackedSSH.py
sudo chmod 755 /usr/local/bin/HackedSSH.py

# Check logs
sudo journalctl -u hackedssh.service -n 100
```

### Issue: Email not sending

```bash
# Check postfix
sudo systemctl status postfix

# Test mail
echo "Test" | mail -s "Test" marcus@davage.me

# Check mail queue
mailq

# View mail log
sudo tail -f /var/log/mail.log
```

### Issue: High CPU usage

```bash
# Check what's using CPU
top

# Reduce scan frequency
sudo systemctl stop clamav-freshclam
sudo systemctl stop aide.timer

# Adjust HackedSSH timer
sudo systemctl edit hackedssh.timer
```

### Issue: SD Card full

```bash
# Check disk usage
df -h
du -sh /var/log/*

# Clean up
sudo journalctl --vacuum-size=50M
sudo apt clean
sudo apt autoremove
```

### Issue: Overheating

```bash
# Check temperature
vcgencmd measure_temp

# If >80°C, consider:
# - Better cooling/heatsink
# - Reduce services
# - Lower overclock settings
```

---

## 📝 Raspberry Pi Best Practices

### 1. Regular Backups

```bash
# Backup SD card regularly
# From another machine:
sudo dd if=/dev/sdX of=~/heimdall-backup.img bs=4M status=progress
```

### 2. Monitor Temperature

```bash
# Add temperature monitoring to cron
crontab -e
```

Add:
```
*/15 * * * * vcgencmd measure_temp >> /var/log/temperature.log
```

### 3. Use Quality SD Card

- Use Class 10 or better
- Prefer SD cards rated for continuous use
- Consider USB/SSD boot (Pi 4/5)

### 4. UPS/Power Backup

- Use a UPS for power protection
- Prevents corruption from power loss

### 5. Keep System Updated

```bash
# Weekly updates
sudo apt update && sudo apt upgrade -y
sudo rpi-update  # Firmware updates
```

---

## 🎛️ Performance Tuning for Pi

### Increase Swap (if needed)

```bash
# Check current swap
free -h

# Increase swap
sudo dphys-swapfile swapoff
sudo nano /etc/dphys-swapfile
# Set: CONF_SWAPSIZE=2048

sudo dphys-swapfile setup
sudo dphys-swapfile swapon
```

### Optimize Python

```bash
# Use PyPy for better performance (optional)
sudo apt install pypy3 -y

# Modify service to use PyPy
sudo nano /etc/systemd/system/hackedssh.service
# Change: ExecStart=/usr/bin/pypy3 /usr/local/bin/HackedSSH.py
```

---

## 🔄 Updating HackedSSH on Heimdall

```bash
# From Thor/development machine
cd /home/marcus/Code/python/Hacked
git pull  # If using git

# Sync to Heimdall
rsync -avz --progress --exclude '__pycache__' \
  /home/marcus/Code/python/Hacked/ pi@heimdall:~/Hacked/

# On Heimdall, reinstall if needed
cd ~/Hacked
sudo bash scripts/install_hackedssh_service.sh
sudo systemctl daemon-reload
sudo systemctl restart hackedssh.service
```

---

## 📋 Complete Installation Checklist

- [ ] System updated
- [ ] Python and dependencies installed
- [ ] Files copied to Heimdall
- [ ] Configuration updated
- [ ] Web server (nginx) installed and running
- [ ] Email (postfix) configured and tested
- [ ] Security tools installed
- [ ] Firewall configured (carefully!)
- [ ] HackedSSH service installed
- [ ] Timer configured and enabled
- [ ] Manual test successful
- [ ] Email test successful
- [ ] Web report accessible
- [ ] Temperature monitoring OK
- [ ] Documentation reviewed

---

## 🎯 Quick Commands Reference

```bash
# Check service status
sudo systemctl status hackedssh.timer
sudo systemctl status hackedssh.service

# Run manual report
sudo systemctl start hackedssh.service

# View logs
sudo journalctl -u hackedssh.service -f

# Check next scheduled run
sudo systemctl list-timers

# Test email
echo "Test" | mail -s "Heimdall Test" marcus@davage.me

# View web report
# From browser: http://heimdall.local/HackedSSH_Report.html

# Check temperature
vcgencmd measure_temp

# Check disk space
df -h

# Check memory
free -h

# Monitor live
htop
```

---

## 🚨 Important Notes

1. **Gateway Role**: Heimdall is critical infrastructure - test changes carefully!
2. **Firewall**: Don't lock yourself out - allow routing and necessary services
3. **Resources**: Monitor CPU/memory/temperature regularly
4. **SD Card**: Use quality card and monitor disk usage
5. **Backups**: Regular backups are essential
6. **Power**: Consider UPS for stability
7. **Cooling**: Ensure adequate cooling
8. **Updates**: Keep system updated but test first

---

## 📞 Getting Help

### View All Logs

```bash
# HackedSSH logs
sudo journalctl -t HackedSSH -f

# All systemd logs
sudo journalctl -xe

# Mail logs
sudo tail -f /var/log/mail.log

# Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log

# System logs
sudo tail -f /var/log/syslog
```

### Performance Issues

```bash
# Run security audit
sudo bash ~/Hacked/scripts/system_security_audit.sh

# Check what's using resources
sudo ps aux --sort=-%mem | head
sudo ps aux --sort=-%cpu | head
```

---

**Your Heimdall gateway is now a comprehensive security monitoring station!** 🍓🛡️

Report Location: http://heimdall.local/HackedSSH_Report.html

