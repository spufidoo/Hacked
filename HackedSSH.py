# HackedSSH
import os
import re
import folium
import argparse
import subprocess
import configparser
import getpass
import random
import json
import time
import urllib.request
import urllib.error
import tarfile
import tempfile
import base64
from jinja2 import Environment, FileSystemLoader
from systemd import journal
from datetime import datetime, timedelta
from countries import country_names
from collections import defaultdict
from geoip2.database import Reader

# Global Variables
# Check for config file in standard locations (in priority order)
# 1. /usr/local/etc/ (standard for locally installed software)
# 2. /usr/local/bin/ (backward compatibility)
# 3. Current directory (development)
CONFIG_ROOT = None
if os.path.exists('/usr/local/etc/HackedSSH.ini'):
    CONFIG_ROOT = '/usr/local/etc'
elif os.path.exists('/usr/local/bin/HackedSSH.ini'):
    CONFIG_ROOT = '/usr/local/bin'
else:
    CONFIG_ROOT = '.'

# ROOT is used for templates and data files (keep in /usr/local/bin or current dir)
# Check for data files in standard locations
if os.path.exists('/usr/local/bin/HackedSSH.html'):
    ROOT = '/usr/local/bin'
else:
    ROOT = '.'

IP_REGEX = r"(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+)"

config = configparser.ConfigParser()
config.read(f'{CONFIG_ROOT}/HackedSSH.ini')
sender_email = config['EMAIL']['sender_email']
recipient_email = config['EMAIL']['recipient_email']
hostname = config['WEB']['hostname']
report_url = config['WEB']['report_url']
local_url = config['WEB']['local_url']
# Optional map tiles configuration; defaults to CartoDB Positron (English labels)
tiles_default = (config.get('MAP', 'tiles', fallback='CartoDB positron')).strip()
# Map feature flags from config
ENABLE_SECURITY_EVENT_MARKERS = config.getboolean('MAP', 'enable_security_event_markers', fallback=True)
ENABLE_NGINX_MARKERS = config.getboolean('MAP', 'enable_nginx_markers', fallback=True)
ENABLE_LEGEND = config.getboolean('MAP', 'enable_legend', fallback=False)
# Geolocation method: 'api' (ip-api.com) or 'database' (GeoLite2)
GEOLOCATION_METHOD = config.get('MAP', 'geolocation_method', fallback='database').strip().lower()
# Cache for API lookups (to avoid rate limits)
geo_cache = {}
geo_cache_file = f"{ROOT}/.geo_cache.json"

TOTAL_ATTEMPTS   = 0
HACKER_REPORT    = "/var/www/html/HackedSSH_Report.html"
HACKER_MAP       = "/var/www/html/HackedSSH_Map.html"
HACKER_TEMPLATE  = "HackedSSH.html"

# Find GeoLite2 database files (check multiple locations like config file)
def find_geo_database(filename):
    """Find GeoLite2 database file in standard locations"""
    search_paths = [
        '/usr/local/etc',  # Primary location (matches config)
        '/usr/local/bin',  # Backward compatibility
        '.'                # Current directory (development)
    ]
    for path in search_paths:
        db_path = f"{path}/{filename}"
        if os.path.exists(db_path):
            return db_path
    return None

# Get GeoLite2 database paths
GEO_CITY_PATH = find_geo_database('GeoLite2-City.mmdb')
GEO_COUNTRY_PATH = find_geo_database('GeoLite2-Country.mmdb')

# Determine where to store databases (same priority as config)
GEO_DB_ROOT = None
if os.path.exists('/usr/local/etc'):
    GEO_DB_ROOT = '/usr/local/etc'
elif os.path.exists('/usr/local/bin'):
    GEO_DB_ROOT = '/usr/local/bin'
else:
    GEO_DB_ROOT = '.'

# Function to extract various attack attempts from the journal
def extract_attack_attempts(from_date, to_date,debug=False):
    attack_attempts = defaultdict(lambda: defaultdict(int))
    TOTAL_ATTEMPTS = 0
    
    try:
        # Fetch logs per unit (journalctl matches are AND-ed; do OR by merging per-unit output)
        units = [
            "ssh.service", "xrdp.service", "vsftpd.service", "apache2.service",
            "nginx.service", "mysql.service", "rdp.service", "smtp.service",
            "openvpn.service", "wireshark.service", "rdc.service", "telnet.service",
            "sftp.service"
        ]
        logs = []
        for unit in units:
            try:
                out = subprocess.check_output(
                    ["journalctl", f"_SYSTEMD_UNIT={unit}", f"--since={from_date}", f"--until={to_date}", "--no-pager"]
                ).decode("utf-8")
                logs.append(out)
            except subprocess.CalledProcessError:
                continue
        journal_logs = "\n".join(logs)
        
        # Define patterns for different services and set default user id when not available
        patterns = {
            "ssh": (re.compile(rf"Failed password for (?:invalid user )?(\w+) from ({IP_REGEX})"), None),
            "ssh1": (re.compile(rf"Unable to negotiate with ({IP_REGEX})"), "None"),
            "ssh2": (re.compile(rf"Connection closed by ({IP_REGEX})"), "None"),
            "ssh3": (re.compile(rf"Connection closed by (?:invalid user ?(\w+)) ({IP_REGEX})"), None),
            "ssh4": (re.compile(rf"banner exchange: Connection from ({IP_REGEX})"), "None"),
            "ssh5": (re.compile(rf"Connection reset by ({IP_REGEX})"), "None"),
            "root": (re.compile(rf"User (\w+) from ({IP_REGEX})"), "None"),
            "xrdp": (re.compile(rf"xrdp-sesman\[\d+\]: (?:pam_unix\(xrdp-sesman:auth\): authentication failure|Failed to start session for user (\w+)) from ({IP_REGEX})"), "None"),
            "xrdp_ipv6": (re.compile(r"::ffff:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"), "None"),
            "ftp": (re.compile(rf"vsftpd: pam_unix\(vsftpd:auth\): authentication failure;.*rhost=({IP_REGEX})"), "None"),
            "apache": (re.compile(rf"apache2: (?:Invalid user|Failed login) (\w+) from ({IP_REGEX})"), None),
            "nginx": (re.compile(rf'nginx.*"GET.*" 401 .* from ({IP_REGEX})'), "None"),
            "mysql": (re.compile(rf"Access denied for user '(\w+)'@'({IP_REGEX})'"), None),
            "smtp": (re.compile(rf"postfix/smtpd.*: warning: ({IP_REGEX}): SASL .* authentication failed"), "None"),
            "openvpn": (re.compile(rf"openvpn\[\d+\]: (\w+\/)?(\w+)\/({IP_REGEX}): (?:AUTH_FAILED|TLS handshake failed)"), None),
            "wireshark": (re.compile(rf"wireshark.*Authentication failure from ({IP_REGEX})"), "None"),
            "rdc": (re.compile(rf"rdc.*: Failed connection attempt from ({IP_REGEX})"), "None"),
            "telnet": (re.compile(rf"telnetd: .* login failed for (\w+) from ({IP_REGEX})"), None),
            "sftp": (re.compile(rf"sftp-server\[\d+\]: (\w+): user auth failure from ({IP_REGEX})"), None)
        }

        # Process each line in the journal logs
        for line in journal_logs.splitlines():
            match_found = False
            for service, (pattern, default_userid) in patterns.items():
                match = pattern.search(line)
                if match:
                    # Extract user ID and IP address (or use default)
                    userid = match.group(1) if match.lastindex > 1 else default_userid or match.group(1)
                    ip_address = match.group(match.lastindex)
                    
                    # Update attack attempt counts
                    attack_attempts[ip_address][userid] += 1
                    TOTAL_ATTEMPTS += 1
                    match_found = True
                    if debug:
                        print(f"{line} -- Match found for {service}: {userid} from {ip_address}")  # Debugging match info
            if not match_found and debug:
                print(f"{line}")  # Debug output to verify each line

    except Exception as e:
        journal.send(MESSAGE=f"Error reading journal logs: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
    
    return attack_attempts, TOTAL_ATTEMPTS

# Function to extract UFW firewall blocks from kernel logs
def extract_ufw_blocks(from_date, to_date, debug=False):
    ufw_blocks = defaultdict(lambda: defaultdict(int))  # {ip: {port: count}}
    TOTAL_UFW_BLOCKS = 0
    
    try:
        # Fetch kernel logs for UFW blocks
        kernel_logs = subprocess.check_output(
            [
                "journalctl",
                "_TRANSPORT=kernel",
                f"--since={from_date}",
                f"--until={to_date}",
                "--no-pager",
            ]
        ).decode("utf-8")
        
        # Pattern to match UFW BLOCK entries
        # Example: kernel: [UFW BLOCK] ... SRC=1.2.3.4 ... DPT=22 ...
        ufw_pattern = re.compile(r'\[UFW BLOCK\].*SRC=([0-9.]+).*DPT=(\d+)')
        
        for line in kernel_logs.splitlines():
            match = ufw_pattern.search(line)
            if match:
                ip_address = match.group(1)
                port = match.group(2)
                ufw_blocks[ip_address][port] += 1
                TOTAL_UFW_BLOCKS += 1
                if debug:
                    print(f"UFW BLOCK: {ip_address}:{port}")
        
    except Exception as e:
        journal.send(MESSAGE=f"Error reading UFW logs: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
    
    return ufw_blocks, TOTAL_UFW_BLOCKS

# Function to extract nginx access logs
def extract_nginx_logs(from_date, to_date, debug=False):
    nginx_access = defaultdict(lambda: defaultdict(int))  # {ip: {status: count}}
    nginx_errors = []
    TOTAL_NGINX_REQUESTS = 0
    
    try:
        # Parse nginx access logs (including rotated .1 and .gz)
        # Format: IP - - [date] "REQUEST" status bytes "referrer" "user-agent"
        access_log = subprocess.check_output(
            ["bash", "-lc", "zcat -f /var/log/nginx/access.log* 2>/dev/null || cat /var/log/nginx/access.log 2>/dev/null"]
        ).decode("utf-8")
        
        for line in access_log.splitlines():
            try:
                # Extract IP, date, status code
                match = re.match(rf'^({IP_REGEX}) - - \[([^\]]+)\] "([^"]*)" (\d+)', line)
                if match:
                    ip_address = match.group(1)
                    log_date_str = match.group(2)
                    request = match.group(3)
                    status = match.group(4)
                    
                    # Parse date: 23/Oct/2025:14:42:31 +0100
                    log_date = datetime.strptime(log_date_str.split()[0], '%d/%b/%Y:%H:%M:%S')
                    
                    # Filter by date range - handle both date objects and strings
                    if isinstance(from_date, str):
                        from_dt = datetime.strptime(from_date, '%Y-%m-%d %H:%M:%S')
                    else:
                        from_dt = datetime.combine(from_date, datetime.min.time())
                    
                    if isinstance(to_date, str):
                        to_dt = datetime.strptime(to_date, '%Y-%m-%d %H:%M:%S')
                    else:
                        to_dt = datetime.combine(to_date, datetime.max.time())
                    
                    if from_dt <= log_date <= to_dt:
                        # Skip local IPs
                        if not ip_address.startswith(('127.', '192.168.', '10.', '172.')):
                            nginx_access[ip_address][status] += 1
                            TOTAL_NGINX_REQUESTS += 1
                            if debug:
                                print(f"NGINX: {ip_address} - {status} - {request[:50]}")
            except Exception as e:
                continue  # Skip malformed lines
                    
        # Parse nginx error logs (including rotated)
        try:
            error_log = subprocess.check_output(
                ["bash", "-lc", "zcat -f /var/log/nginx/error.log* 2>/dev/null || cat /var/log/nginx/error.log 2>/dev/null"]
            ).decode("utf-8")
            
            for line in error_log.splitlines():
                try:
                    # Extract date from error log
                    date_match = re.search(r'(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})', line)
                    if date_match:
                        log_date = datetime.strptime(date_match.group(1), '%Y/%m/%d %H:%M:%S')
                        
                        # Handle both date objects and strings
                        if isinstance(from_date, str):
                            from_dt = datetime.strptime(from_date, '%Y-%m-%d %H:%M:%S')
                        else:
                            from_dt = datetime.combine(from_date, datetime.min.time())
                        
                        if isinstance(to_date, str):
                            to_dt = datetime.strptime(to_date, '%Y-%m-%d %H:%M:%S')
                        else:
                            to_dt = datetime.combine(to_date, datetime.max.time())
                        
                        if from_dt <= log_date <= to_dt:
                            # Extract error level and message
                            error_match = re.search(r'\[(\w+)\] \d+#\d+: (.+)', line)
                            if error_match:
                                level = error_match.group(1)
                                message = error_match.group(2).strip()
                                nginx_errors.append({'level': level, 'message': message, 'time': log_date})
                except Exception as e:
                    continue
        except (FileNotFoundError, subprocess.CalledProcessError) as e:
            if debug:
                print(f"nginx error.log not accessible: {e}")
                
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        journal.send(MESSAGE=f"nginx access.log not accessible: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
    except Exception as e:
        journal.send(MESSAGE=f"Error reading nginx logs: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
    
    return nginx_access, nginx_errors, TOTAL_NGINX_REQUESTS

# Function to extract security events and categorize by severity
def extract_security_events(ssh_attempts, nginx_access, nginx_errors, from_date, to_date, debug=False):
    critical_events = []
    high_events = []
    medium_events = []
    low_events = []
    successful_logins = defaultdict(lambda: {'user': '', 'count': 0, 'timestamps': [], 'method': ''})
    
    # 1. Check for successful SSH logins (CRITICAL)
    try:
        auth_logs = subprocess.check_output([
            "journalctl", "_SYSTEMD_UNIT=ssh.service",
            f"--since={from_date}", f"--until={to_date}",
            "--no-pager"
        ]).decode("utf-8")
        
        for line in auth_logs.splitlines():
            if "Accepted password" in line or "Accepted publickey" in line:
                method = "password" if "Accepted password" in line else "publickey"
                match = re.search(r'(\w+\s+\d+\s+\d+:\d+:\d+).*Accepted.*for (\S+) from (\S+)', line)
                if match:
                    timestamp = match.group(1)
                    user = match.group(2)
                    ip = match.group(3)
                    
                    # Add to successful logins tracking
                    successful_logins[ip]['user'] = user
                    successful_logins[ip]['count'] += 1
                    successful_logins[ip]['method'] = method
                    successful_logins[ip]['timestamps'].append(timestamp)
                    
                    # Also add to critical events
                    critical_events.append({
                        'service': 'SSH',
                        'event': f'Successful Login ({method})',
                        'user': user,
                        'ip': ip,
                        'timestamp': timestamp,
                        'message': line.strip()
                    })
    except Exception as e:
        if debug:
            print(f"Error checking SSH successful logins: {e}")
    
    # 2. Check for root login attempts (CRITICAL if successful, HIGH if failed)
    for ip, users in ssh_attempts.items():
        if 'root' in users:
            high_events.append({
                'service': 'SSH',
                'event': 'Root Login Attempts',
                'user': 'root',
                'ip': ip,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'message': f"{users['root']} failed root login attempts from {ip}"
            })
    
    # 3. Check for rapid failed attempts from same IP (HIGH)
    for ip, users in ssh_attempts.items():
        total_attempts = sum(users.values())
        if total_attempts >= 50:
            high_events.append({
                'service': 'SSH',
                'event': 'Brute Force Attack',
                'user': ', '.join(list(users.keys())[:3]),
                'ip': ip,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'message': f"Intense brute force: {total_attempts} attempts from {ip}"
            })
    
    # 4. Analyze nginx logs for attack patterns
    for ip, statuses in nginx_access.items():
        # Check for scanning activity (many 404s)
        if '404' in statuses and statuses['404'] >= 10:
            medium_events.append({
                'service': 'nginx',
                'event': 'Web Scanning',
                'user': 'N/A',
                'ip': ip,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'message': f"Possible directory scanning: {statuses['404']} 404 errors from {ip}"
            })
        
        # Check for 403 Forbidden (attempting restricted access)
        if '403' in statuses and statuses['403'] >= 5:
            high_events.append({
                'service': 'nginx',
                'event': 'Unauthorized Access Attempts',
                'user': 'N/A',
                'ip': ip,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'message': f"Repeated forbidden access attempts: {statuses['403']} from {ip}"
            })
        
        # Check for 500 errors (possible exploitation attempts)
        if '500' in statuses or '502' in statuses:
            high_events.append({
                'service': 'nginx',
                'event': 'Server Errors',
                'user': 'N/A',
                'ip': ip,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'message': f"Server errors triggered by {ip} - possible exploitation"
            })
    
    # 5. Check rkhunter logs (CRITICAL if warnings found)
    try:
        rkhunter_log = subprocess.check_output(["cat", "/var/log/rkhunter.log"], stderr=subprocess.DEVNULL).decode("utf-8")
        for line in rkhunter_log.splitlines():
            if "Warning:" in line:
                critical_events.append({
                    'service': 'rkhunter',
                    'event': 'Rootkit Warning',
                    'user': 'system',
                    'ip': 'localhost',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': line.strip()
                })
    except:
        pass
    
    # 6. Check AIDE (Advanced Intrusion Detection) logs
    try:
        aide_log = subprocess.check_output(["cat", "/var/log/aide/aide.log"], stderr=subprocess.DEVNULL).decode("utf-8")
        for line in aide_log.splitlines():
            if "changed:" in line.lower() or "added:" in line.lower() or "removed:" in line.lower():
                critical_events.append({
                    'service': 'AIDE',
                    'event': 'File System Change',
                    'user': 'system',
                    'ip': 'localhost',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': line.strip()
                })
    except:
        pass
    
    # 7. Check ClamAV for virus detections
    try:
        clam_log = subprocess.check_output(["cat", "/var/log/clamav/clamav.log"], stderr=subprocess.DEVNULL).decode("utf-8")
        for line in clam_log.splitlines():
            if "FOUND" in line:
                critical_events.append({
                    'service': 'ClamAV',
                    'event': 'Malware Detected',
                    'user': 'system',
                    'ip': 'localhost',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': line.strip()
                })
    except:
        pass
    
    # 8. Check chkrootkit logs
    try:
        chkrootkit_log = subprocess.check_output(["cat", "/var/log/chkrootkit.log"], stderr=subprocess.DEVNULL).decode("utf-8")
        for line in chkrootkit_log.splitlines():
            if "INFECTED" in line or "Vulnerable" in line:
                critical_events.append({
                    'service': 'chkrootkit',
                    'event': 'Rootkit Detected',
                    'user': 'system',
                    'ip': 'localhost',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': line.strip()
                })
    except:
        pass
    
    # 9. Check auditd logs for suspicious activity
    try:
        audit_logs = subprocess.check_output(
            ["bash", "-lc", f"ausearch -ts '{from_date}' -te '{to_date}' -m USER_AUTH,USER_LOGIN,EXECVE -i 2>/dev/null"]
        ).decode("utf-8")
        
        for line in audit_logs.splitlines():
            if "failed" in line.lower():
                high_events.append({
                    'service': 'auditd',
                    'event': 'Authentication Failure',
                    'user': 'various',
                    'ip': 'localhost',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': line.strip()[:200]
                })
    except:
        pass
    
    # 10. Check psad (Port Scan Attack Detector) logs
    try:
        psad_log = subprocess.check_output(["cat", "/var/log/psad/psad.log"], stderr=subprocess.DEVNULL).decode("utf-8")
        for line in psad_log.splitlines():
            if "scan detected" in line.lower() or "danger level" in line.lower():
                match = re.search(r'from:\s*(\S+)', line)
                ip = match.group(1) if match else 'unknown'
                high_events.append({
                    'service': 'psad',
                    'event': 'Port Scan Detected',
                    'user': 'N/A',
                    'ip': ip,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': line.strip()
                })
    except:
        pass
    
    # 11. Check Lynis audit recommendations
    try:
        lynis_log = subprocess.check_output(["cat", "/var/log/lynis.log"], stderr=subprocess.DEVNULL).decode("utf-8")
        for line in lynis_log.splitlines():
            if "Warning" in line:
                medium_events.append({
                    'service': 'Lynis',
                    'event': 'Security Warning',
                    'user': 'system',
                    'ip': 'localhost',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': line.strip()[:200]
                })
    except:
        pass
    
    # 12. Check Tiger audit logs
    try:
        tiger_log = subprocess.check_output(["cat", "/var/log/tiger/security.report.txt"], stderr=subprocess.DEVNULL).decode("utf-8")
        for line in tiger_log.splitlines():
            if "FAIL" in line or "ALERT" in line:
                high_events.append({
                    'service': 'Tiger',
                    'event': 'Security Check Failed',
                    'user': 'system',
                    'ip': 'localhost',
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'message': line.strip()[:200]
                })
    except:
        pass
    
    # 13. Check for sudo usage anomalies
    try:
        sudo_logs = subprocess.check_output([
            "journalctl", "_COMM=sudo",
            f"--since={from_date}", f"--until={to_date}",
            "--no-pager"
        ]).decode("utf-8")
        
        sudo_failures = 0
        for line in sudo_logs.splitlines():
            if "authentication failure" in line.lower():
                sudo_failures += 1
        
        if sudo_failures >= 5:
            high_events.append({
                'service': 'sudo',
                'event': 'Multiple Sudo Failures',
                'user': 'various',
                'ip': 'localhost',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'message': f"{sudo_failures} failed sudo attempts detected"
            })
    except:
        pass
    
    # Sort events by timestamp (most recent first)
    critical_events = sorted(critical_events, key=lambda x: x['timestamp'], reverse=True)
    high_events = sorted(high_events, key=lambda x: x['timestamp'], reverse=True)
    medium_events = sorted(medium_events, key=lambda x: x['timestamp'], reverse=True)
    
    if debug:
        print(f"Security Events: Critical={len(critical_events)}, High={len(high_events)}, Medium={len(medium_events)}")
        print(f"Successful Logins: {len(successful_logins)}")
    
    return critical_events, high_events, medium_events, successful_logins

# Download GeoLite2 database if missing
def download_geolite2_database(db_type='City'):
    """Download GeoLite2 database from MaxMind (requires free account, account ID and license key)
    
    Compatible with MaxMind's current download system as documented at:
    https://dev.maxmind.com/geoip/updating-databases/
    """
    # MaxMind requires both AccountID and LicenseKey for Basic Authentication
    # Users need to sign up at https://www.maxmind.com/en/geolite2/signup
    account_id = config.get('MAP', 'maxmind_account_id', fallback='').strip()
    license_key = config.get('MAP', 'maxmind_license_key', fallback='').strip()
    
    if not account_id or not license_key:
        journal.send(MESSAGE="GeoLite2 database missing and MaxMind credentials not configured. "
                    "Sign up at https://www.maxmind.com/en/geolite2/signup and add both "
                    "maxmind_account_id and maxmind_license_key to your config file.",
                    SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
        return False
    
    try:
        # Use MaxMind's permalink format with Basic Authentication
        # MaxMind uses R2 presigned URLs that redirect - urllib handles redirects automatically
        if db_type == 'City':
            # GeoLite2-City permalink format
            url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key={license_key}&suffix=tar.gz"
            filename = 'GeoLite2-City.mmdb'
        else:  # Country
            url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key={license_key}&suffix=tar.gz"
            filename = 'GeoLite2-Country.mmdb'
        
        journal.send(MESSAGE=f"Downloading GeoLite2-{db_type} database from MaxMind...", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")
        
        # Create Basic Auth header (MaxMind requires AccountID:LicenseKey)
        credentials = f"{account_id}:{license_key}".encode('utf-8')
        auth_header = base64.b64encode(credentials).decode('utf-8')
        
        # Download the tar.gz file with Basic Authentication
        # MaxMind redirects to R2 storage - urllib.request.urlopen handles redirects automatically
        req = urllib.request.Request(url)
        req.add_header('Authorization', f'Basic {auth_header}')
        req.add_header('User-Agent', 'HackedSSH/1.0')
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.tar.gz') as tmp_file:
            tmp_path = tmp_file.name
            with urllib.request.urlopen(req, timeout=60) as response:
                # Follow redirects (MaxMind uses R2 presigned URLs)
                tmp_file.write(response.read())
        
        # Extract the .mmdb file from the tar.gz
        target_path = f"{GEO_DB_ROOT}/{filename}"
        with tarfile.open(tmp_path, 'r:gz') as tar:
            # Find the .mmdb file in the archive
            for member in tar.getmembers():
                if member.name.endswith('.mmdb'):
                    # Extract to temporary location first
                    extracted_member = tar.extractfile(member)
                    if extracted_member:
                        # Write directly to target path
                        with open(target_path, 'wb') as out_file:
                            out_file.write(extracted_member.read())
                        os.chmod(target_path, 0o644)
                        journal.send(MESSAGE=f"GeoLite2-{db_type} database downloaded to {target_path}",
                                    SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")
                        os.unlink(tmp_path)
                        return True
        
        os.unlink(tmp_path)
        journal.send(MESSAGE=f"Could not find .mmdb file in GeoLite2-{db_type} archive",
                    SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
        return False
        
    except urllib.error.HTTPError as e:
        if e.code == 401:
            journal.send(MESSAGE="Invalid MaxMind credentials (401 Unauthorized). Please check your account_id and license_key in the config file.",
                        SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
        elif e.code == 403:
            journal.send(MESSAGE="MaxMind access forbidden (403). Your account may not have access to GeoLite2 databases or your subscription may have expired.",
                        SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
        else:
            journal.send(MESSAGE=f"Failed to download GeoLite2-{db_type}: HTTP {e.code} - {e.reason}",
                        SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
        return False
    except urllib.error.URLError as e:
        journal.send(MESSAGE=f"Network error downloading GeoLite2-{db_type}: {e.reason}. Check firewall/proxy settings for access to mm-prod-geoip-databases.a2649acb697e2c09b632799562c076f2.r2.cloudflarestorage.com",
                    SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
        return False
    except Exception as e:
        journal.send(MESSAGE=f"Error downloading GeoLite2-{db_type}: {e}",
                    SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
        return False

# Check and download GeoLite2 databases if missing (when using database method)
if GEOLOCATION_METHOD == 'database':
    if not GEO_CITY_PATH:
        if download_geolite2_database('City'):
            GEO_CITY_PATH = find_geo_database('GeoLite2-City.mmdb')
    if not GEO_COUNTRY_PATH:
        if download_geolite2_database('Country'):
            GEO_COUNTRY_PATH = find_geo_database('GeoLite2-Country.mmdb')

# Load geo cache from file
def load_geo_cache():
    global geo_cache
    try:
        if os.path.exists(geo_cache_file):
            with open(geo_cache_file, 'r') as f:
                geo_cache = json.load(f)
    except Exception:
        geo_cache = {}

# Save geo cache to file
def save_geo_cache():
    try:
        with open(geo_cache_file, 'w') as f:
            json.dump(geo_cache, f)
    except Exception:
        pass

# Batch lookup IPs using ip-api.com batch API (up to 100 IPs per request)
def batch_lookup_ips(ip_list):
    """Batch lookup multiple IPs using ip-api.com batch API (15 requests/minute, up to 100 IPs per request)"""
    if not ip_list:
        return
    
    # Filter out local IPs and already cached IPs
    ips_to_lookup = []
    for ip in ip_list:
        if not ip.startswith(('127.', '192.168.', '10.', '172.')) and ip != 'localhost':
            # Check if not in cache or cache expired
            if ip not in geo_cache or (time.time() - geo_cache[ip].get('timestamp', 0) >= 2592000):
                ips_to_lookup.append(ip)
    
    if not ips_to_lookup:
        return
    
    # Batch into groups of 100 (API limit)
    for i in range(0, len(ips_to_lookup), 100):
        batch = ips_to_lookup[i:i+100]
        try:
            # Use batch API endpoint
            url = "http://ip-api.com/batch?fields=status,countryCode,city,lat,lon"
            data = json.dumps(batch).encode('utf-8')
            req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
            
            with urllib.request.urlopen(req, timeout=10) as response:
                results = json.loads(response.read().decode())
                # Process results
                for idx, result in enumerate(results):
                    if idx < len(batch):
                        ip = batch[idx]
                        if result.get('status') == 'success':
                            geo_cache[ip] = {
                                'country': result.get('countryCode', 'Unknown'),
                                'city': result.get('city', 'Unknown'),
                                'lat': result.get('lat'),
                                'lon': result.get('lon'),
                                'timestamp': time.time()
                            }
        except Exception as e:
            # If batch fails, continue with remaining IPs
            journal.send(MESSAGE=f"Batch geolocation lookup failed: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
            continue
        
        # Rate limiting: batch API allows 15 requests/minute, so wait 4 seconds between batches
        if i + 100 < len(ips_to_lookup):
            time.sleep(4)

# Get geolocation from API cache (after batch lookup)
def get_geo_from_api(ip_address):
    """Get geolocation from cache (populated by batch_lookup_ips)"""
    # Skip local/private IPs
    if ip_address.startswith(('127.', '192.168.', '10.', '172.')) or ip_address == 'localhost':
        return None, None, None, None
    
    # Check cache
    if ip_address in geo_cache:
        cached_data = geo_cache[ip_address]
        # Cache valid for 30 days
        if time.time() - cached_data.get('timestamp', 0) < 2592000:
            return cached_data.get('country'), cached_data.get('city'), cached_data.get('lat'), cached_data.get('lon')
    
    return None, None, None, None

# Function to get country from IP address
def get_country_from_ip(ip_address):
    if GEOLOCATION_METHOD == 'api':
        country, _, _, _ = get_geo_from_api(ip_address)
        if country:
            return country
        # Fall back to database if API fails
    
    # Use GeoLite2 database
    if not GEO_COUNTRY_PATH:
        return "Unknown"
    
    try:
        reader = Reader(GEO_COUNTRY_PATH)
        response = reader.country(ip_address)
        country = response.country.iso_code
        reader.close()
        return country
    except Exception as e:
        # IP not in database is normal, don't log as error
        if "not in the database" not in str(e):
            journal.send(MESSAGE=f"Error getting country from IP {ip_address}: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
        return "Unknown"

# Function to get city and coordinates from IP address
def get_city_and_coords_from_ip(ip_address):
    if GEOLOCATION_METHOD == 'api':
        _, city, lat, lon = get_geo_from_api(ip_address)
        if city and lat and lon:
            return city, lat, lon
        # Fall back to database if API fails
    
    # Use GeoLite2 database
    if not GEO_CITY_PATH:
        return "Unknown", None, None
    
    try:
        reader = Reader(GEO_CITY_PATH)
        response = reader.city(ip_address)
        city = response.city.name
        lat = response.location.latitude
        lon = response.location.longitude
        reader.close()
        return city, lat, lon
    except Exception as e:
        # IP not in database is normal, don't log as error
        if "not in the database" not in str(e):
            journal.send(MESSAGE=f"Error getting city from IP {ip_address}: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
        return "Unknown", None, None

# Function to get city from IP address
def get_city_from_ip(ip_address):
    if GEOLOCATION_METHOD == 'api':
        _, city, _, _ = get_geo_from_api(ip_address)
        if city:
            return city
        # Fall back to database if API fails
    
    # Use GeoLite2 database
    if not GEO_CITY_PATH:
        return "Unknown"
    
    try:
        reader = Reader(GEO_CITY_PATH)
        response = reader.city(ip_address)
        city = response.city.name
        reader.close()
        return city
    except Exception as e:
        # IP not in database is normal, don't log as error
        if "not in the database" not in str(e):
            journal.send(MESSAGE=f"Error getting city from IP {ip_address}: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
        return "Unknown"

# Function to generate HTML report
def generate_html_report(ssh_attempts, TOTAL_ATTEMPTS, ufw_blocks, TOTAL_UFW_BLOCKS, nginx_access, TOTAL_NGINX_REQUESTS, nginx_errors, from_date, to_date,debug=False, tiles_override=None):
    env = Environment(loader=FileSystemLoader(ROOT))
    template = env.get_template(HACKER_TEMPLATE)
    # Choose tiles: CLI override > config default
    base_tiles = tiles_override if tiles_override else tiles_default
    m = folium.Map(location=[0, 0], zoom_start=2, tiles=base_tiles)  # Create a map object with selected tiles
    # Add alternative base layers for easy backout/switching
    try:
        if base_tiles.lower() != 'openstreetmap':
            folium.TileLayer('OpenStreetMap', name='OpenStreetMap').add_to(m)
        if base_tiles.lower() != 'cartodb positron':
            folium.TileLayer('CartoDB positron', name='CartoDB Positron').add_to(m)
        # Optional: add Dark Matter as another alternative
        if base_tiles.lower() != 'cartodb dark_matter':
            folium.TileLayer('CartoDB dark_matter', name='CartoDB Dark Matter').add_to(m)
        folium.LayerControl(collapsed=True).add_to(m)
    except Exception as e:
        # Non-fatal if a tile provider name is not available in this folium version
        journal.send(MESSAGE=f"Tile layer setup warning: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
    # Extract security events early so we can add them to the map
    # Wrap in try/except to prevent errors from breaking map generation
    try:
        critical_events, high_events, medium_events, successful_logins = extract_security_events(
            ssh_attempts, nginx_access, nginx_errors, from_date, to_date, debug
        )
    except Exception as e:
        journal.send(MESSAGE=f"Error extracting security events for map: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
        if debug:
            print(f"Warning: Error extracting security events: {e}")
        critical_events, high_events, medium_events, successful_logins = [], [], [], {}
    
    # Collect unique IPs from security events
    security_event_ips = {
        'critical': set(),
        'high': set(),
        'medium': set()
    }
    for event in critical_events:
        if event.get('ip') and event['ip'] != 'localhost':
            security_event_ips['critical'].add(event['ip'])
    for event in high_events:
        if event.get('ip') and event['ip'] != 'localhost':
            security_event_ips['high'].add(event['ip'])
    for event in medium_events:
        if event.get('ip') and event['ip'] != 'localhost':
            security_event_ips['medium'].add(event['ip'])
    
    # Collect all unique IPs that need geolocation for batch lookup
    if GEOLOCATION_METHOD == 'api':
        all_ips = set()
        all_ips.update(ssh_attempts.keys())
        all_ips.update(ufw_blocks.keys())
        all_ips.update(nginx_access.keys())
        all_ips.update(security_event_ips['critical'])
        all_ips.update(security_event_ips['high'])
        all_ips.update(security_event_ips['medium'])
        # Perform batch lookup for all IPs at once
        if debug:
            print(f"Batch looking up {len(all_ips)} unique IPs...")
        batch_lookup_ips(list(all_ips))
        if debug:
            print(f"Batch lookup complete. Cache now has {len(geo_cache)} entries.")
    
    country_attempts = defaultdict(int)
    user_attempts = defaultdict(int)
    city_attempts = defaultdict(int)
    country_details = defaultdict(lambda: defaultdict(lambda: {'city': '', 'users': defaultdict(int)}))

    # Track locations to add slight jitter for overlapping markers
    location_counts = defaultdict(int)
    
    # Add SSH attack attempts to map
    for ip_address, attempts in ssh_attempts.items():
        country = get_country_from_ip(ip_address)
        country_name = country_names.get(country, "Unknown")
        total_count = sum(attempts.values())
        country_attempts[country_name] += total_count
        city, lat, lon = get_city_and_coords_from_ip(ip_address)
        city_attempts[city] += total_count

        for userid, count in attempts.items():
            user_attempts[userid] += count
            if ip_address not in country_details[country_name] or 'city' not in country_details[country_name][ip_address]:
                country_details[country_name][ip_address]['city'] = city
            country_details[country_name][ip_address]['users'][userid] += count

        if lat is not None and lon is not None:
            # Add slight jitter to avoid overlapping markers (0.1 degrees ~11km)
            location_key = f"{lat:.1f},{lon:.1f}"
            jitter = location_counts[location_key] * 0.05
            location_counts[location_key] += 1
            
            jittered_lat = lat + (random.random() - 0.5) * jitter
            jittered_lon = lon + (random.random() - 0.5) * jitter
            
            # Color based on severity: red for high attempts, yellow for medium, green for low
            if total_count > 100:
                color = 'red'
                radius = 10
            elif total_count > 50:
                color = 'orange'
                radius = 8
            elif total_count > 10:
                color = 'yellow'
                radius = 6
            else:
                color = 'green'
                radius = 4
            
            folium.CircleMarker(
                location=[jittered_lat, jittered_lon],
                radius=radius,
                popup=f"<b>{city}</b><br>IP: {ip_address}<br>SSH Attempts: {total_count}<br>Users: {', '.join(list(attempts.keys())[:5])}",
                color=color,
                fill=True,
                fillColor=color,
                fillOpacity=0.7
            ).add_to(m)

    # Add UFW blocked IPs to map with different markers
    for ip_address, ports in ufw_blocks.items():
        city, lat, lon = get_city_and_coords_from_ip(ip_address)
        total_blocks = sum(ports.values())
        
        if lat is not None and lon is not None:
            # Add slight jitter to avoid overlapping markers
            location_key = f"{lat:.1f},{lon:.1f}"
            jitter = location_counts[location_key] * 0.05
            location_counts[location_key] += 1
            
            jittered_lat = lat + (random.random() - 0.5) * jitter
            jittered_lon = lon + (random.random() - 0.5) * jitter
            
            # Color based on UFW block severity: dark purple for high blocks, purple for medium, light purple for low
            if total_blocks > 100:
                color = 'darkviolet'
                radius = 12
            elif total_blocks > 50:
                color = 'purple'
                radius = 10
            elif total_blocks > 10:
                color = 'mediumpurple'
                radius = 8
            else:
                color = 'plum'
                radius = 6
            
            # Create popup with port information
            port_info = ', '.join([f"{port}({count})" for port, count in sorted(ports.items())])
            
            folium.CircleMarker(
                location=[jittered_lat, jittered_lon],
                radius=radius,
                popup=f"<b>{city}</b><br>IP: {ip_address}<br>UFW Blocks: {total_blocks}<br>Ports: {port_info}",
                color=color,
                fill=True,
                fillColor=color,
                fillOpacity=0.7
            ).add_to(m)
    
    # Add some test UFW data for demonstration if no real data exists
    if not ufw_blocks:
        test_ufw_data = {
            '8.8.8.8': {'22': 15, '80': 8, '443': 12},  # Google DNS - SSH, HTTP, HTTPS
            '1.1.1.1': {'22': 25, '3389': 5},          # Cloudflare DNS - SSH, RDP
            '208.67.222.222': {'22': 30, '21': 10},     # OpenDNS - SSH, FTP
        }
        
        for ip_address, ports in test_ufw_data.items():
            city, lat, lon = get_city_and_coords_from_ip(ip_address)
            total_blocks = sum(ports.values())
            
            if lat is not None and lon is not None:
                # Add slight jitter to avoid overlapping markers
                location_key = f"{lat:.1f},{lon:.1f}"
                jitter = location_counts[location_key] * 0.05
                location_counts[location_key] += 1
                
                jittered_lat = lat + (random.random() - 0.5) * jitter
                jittered_lon = lon + (random.random() - 0.5) * jitter
                
                # Color based on UFW block severity
                if total_blocks > 20:
                    color = 'darkviolet'
                    radius = 12
                elif total_blocks > 10:
                    color = 'purple'
                    radius = 10
                else:
                    color = 'mediumpurple'
                    radius = 8
                
                # Create popup with port information
                port_info = ', '.join([f"{port}({count})" for port, count in sorted(ports.items())])
                
                folium.CircleMarker(
                    location=[jittered_lat, jittered_lon],
                    radius=radius,
                    popup=f"<b>{city}</b><br>IP: {ip_address}<br>UFW Blocks: {total_blocks}<br>Ports: {port_info}<br><em>(Test Data)</em>",
                    color=color,
                    fill=True,
                    fillColor=color,
                    fillOpacity=0.7
                ).add_to(m)
    
    # Add security event IPs to map (Critical/High/Medium)
    if ENABLE_SECURITY_EVENT_MARKERS:
        # Add security event IPs directly to map (not using FeatureGroups to avoid breaking the map)
        for ip_address in security_event_ips['critical']:
            city, lat, lon = get_city_and_coords_from_ip(ip_address)
            if lat is not None and lon is not None:
                # Count events for this IP
                event_count = sum(1 for e in critical_events if e.get('ip') == ip_address)
                event_types = ', '.join(set(e.get('event', 'Unknown') for e in critical_events if e.get('ip') == ip_address))
                
                location_key = f"{lat:.1f},{lon:.1f}"
                jitter = location_counts[location_key] * 0.05
                location_counts[location_key] += 1
                
                jittered_lat = lat + (random.random() - 0.5) * jitter
                jittered_lon = lon + (random.random() - 0.5) * jitter
                
                folium.CircleMarker(
                    location=[jittered_lat, jittered_lon],
                    radius=12,
                    popup=f"<b>{city}</b><br>IP: {ip_address}<br>Critical Events: {event_count}<br>Types: {event_types}",
                    color='darkred',
                    fill=True,
                    fillColor='red',
                    fillOpacity=0.8,
                    weight=3
                ).add_to(m)
        
        for ip_address in security_event_ips['high']:
            city, lat, lon = get_city_and_coords_from_ip(ip_address)
            if lat is not None and lon is not None:
                # Count events for this IP
                event_count = sum(1 for e in high_events if e.get('ip') == ip_address)
                event_types = ', '.join(set(e.get('event', 'Unknown') for e in high_events if e.get('ip') == ip_address))
                
                location_key = f"{lat:.1f},{lon:.1f}"
                jitter = location_counts[location_key] * 0.05
                location_counts[location_key] += 1
                
                jittered_lat = lat + (random.random() - 0.5) * jitter
                jittered_lon = lon + (random.random() - 0.5) * jitter
                
                folium.CircleMarker(
                    location=[jittered_lat, jittered_lon],
                    radius=10,
                    popup=f"<b>{city}</b><br>IP: {ip_address}<br>High Events: {event_count}<br>Types: {event_types}",
                    color='darkorange',
                    fill=True,
                    fillColor='orange',
                    fillOpacity=0.8,
                    weight=3
                ).add_to(m)
        
        for ip_address in security_event_ips['medium']:
            city, lat, lon = get_city_and_coords_from_ip(ip_address)
            if lat is not None and lon is not None:
                # Count events for this IP
                event_count = sum(1 for e in medium_events if e.get('ip') == ip_address)
                event_types = ', '.join(set(e.get('event', 'Unknown') for e in medium_events if e.get('ip') == ip_address))
                
                location_key = f"{lat:.1f},{lon:.1f}"
                jitter = location_counts[location_key] * 0.05
                location_counts[location_key] += 1
                
                jittered_lat = lat + (random.random() - 0.5) * jitter
                jittered_lon = lon + (random.random() - 0.5) * jitter
                
                folium.CircleMarker(
                    location=[jittered_lat, jittered_lon],
                    radius=8,
                    popup=f"<b>{city}</b><br>IP: {ip_address}<br>Medium Events: {event_count}<br>Types: {event_types}",
                    color='gold',
                    fill=True,
                    fillColor='yellow',
                    fillOpacity=0.8,
                    weight=3
                ).add_to(m)
    
    # Add nginx IPs to map
    if ENABLE_NGINX_MARKERS:
        # Add nginx IPs to map (add directly to map, not in FeatureGroup, so they're always visible)
        nginx_count = 0
        for ip_address in nginx_access.keys():
            city, lat, lon = get_city_and_coords_from_ip(ip_address)
            if lat is not None and lon is not None:
                total_requests = sum(nginx_access[ip_address].values())
                status_info = ', '.join([f"{status}({count})" for status, count in sorted(nginx_access[ip_address].items(), key=lambda x: int(x[0]))[:5]])
                
                location_key = f"{lat:.1f},{lon:.1f}"
                jitter = location_counts[location_key] * 0.05
                location_counts[location_key] += 1
                
                jittered_lat = lat + (random.random() - 0.5) * jitter
                jittered_lon = lon + (random.random() - 0.5) * jitter
                
                # Color based on request count
                if total_requests > 1000:
                    color = 'darkblue'
                    radius = 10
                elif total_requests > 100:
                    color = 'blue'
                    radius = 8
                elif total_requests > 10:
                    color = 'lightblue'
                    radius = 6
                else:
                    color = 'cyan'
                    radius = 4
                
                folium.CircleMarker(
                    location=[jittered_lat, jittered_lon],
                    radius=radius,
                    popup=f"<b>{city}</b><br>IP: {ip_address}<br>Nginx Requests: {total_requests}<br>Status Codes: {status_info}",
                    color=color,
                    fill=True,
                    fillColor=color,
                    fillOpacity=0.7,
                    weight=2
                ).add_to(m)
                nginx_count += 1
        
        if debug:
            print(f"Added {nginx_count} nginx IP markers to map (out of {len(nginx_access)} total nginx IPs)")
    
    m.save(HACKER_MAP)  # Save the map to an HTML file
    
    # Add legend to map
    if ENABLE_LEGEND:
        # Add custom legend by injecting HTML into the saved map file using a safer method
        try:
            with open(HACKER_MAP, 'r', encoding='utf-8') as f:
                map_content = f.read()
            
            # Legend HTML to inject
            legend_html = '''
    <div id="map-legend" style="position: fixed; 
                bottom: 50px; right: 10px; width: 130px; height: auto; 
                background-color: white; z-index:9999; font-size:10px;
                border:1px solid grey; border-radius: 3px; padding: 4px 6px;
                font-family: Arial, sans-serif; box-shadow: 0 0 10px rgba(0,0,0,0.2);">
    <h4 style="margin-top:0; margin-bottom:3px; font-size:11px; font-weight:bold;">Map Legend</h4>
    <p style="margin:1px 0; line-height:1.2;"><span style="color:red; font-size:12px;">●</span> Critical Events</p>
    <p style="margin:1px 0; line-height:1.2;"><span style="color:orange; font-size:12px;">●</span> High Events</p>
    <p style="margin:1px 0; line-height:1.2;"><span style="color:yellow; font-size:12px;">●</span> Medium Events</p>
    <p style="margin:1px 0; line-height:1.2;"><span style="color:blue; font-size:12px;">●</span> Nginx IPs</p>
    <p style="margin:1px 0; line-height:1.2;"><span style="color:#ff0000; font-size:12px;">●</span> SSH Attempts</p>
    <p style="margin:1px 0; line-height:1.2;"><span style="color:#9400d3; font-size:12px;">●</span> UFW Blocks</p>
    </div>
'''
            
            # Find where to inject - look for the map div and inject legend right after it
            pattern = r'(<div class="folium-map"[^>]*></div>)'
            if re.search(pattern, map_content):
                # Insert legend after the map div, before any following content
                map_content = re.sub(pattern, r'\1' + legend_html, map_content, count=1)
            elif '</body>' in map_content:
                # Fallback: inject before closing body tag
                map_content = map_content.replace('</body>', legend_html + '\n</body>')
            elif '</html>' in map_content:
                map_content = map_content.replace('</html>', legend_html + '\n</html>')
            
            with open(HACKER_MAP, 'w', encoding='utf-8') as f:
                f.write(map_content)
        except Exception as e:
            # If legend injection fails, log but don't break the map
            journal.send(MESSAGE=f"Failed to add legend to map: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
            if debug:
                print(f"Warning: Could not add legend to map: {e}")
    journal.send(MESSAGE=f"Map template {ROOT}/{HACKER_TEMPLATE} saved to {HACKER_MAP}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")

    country_attempts = sorted(country_attempts.items(), key=lambda x: x[1], reverse=True)
    user_attempts = sorted(user_attempts.items(), key=lambda x: x[0])
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Add country information to successful logins
    successful_country_attempts = defaultdict(int)
    for ip, login_data in successful_logins.items():
        country = get_country_from_ip(ip)
        country_name = country_names.get(country, "Unknown")
        city = get_city_from_ip(ip)
        
        # Add geo data to login info
        login_data['country'] = country_name
        login_data['city'] = city
        
        successful_country_attempts[country_name] += login_data['count']
    
    successful_country_attempts = sorted(successful_country_attempts.items(), key=lambda x: x[1], reverse=True)
    TOTAL_SUCCESS = sum(login['count'] for login in successful_logins.values())
    
    # Process UFW blocks by country and port
    ufw_country_attempts = defaultdict(int)
    ufw_port_summary = defaultdict(int)
    ufw_details = {}
    
    for ip_address, ports in ufw_blocks.items():
        country = get_country_from_ip(ip_address)
        country_name = country_names.get(country, "Unknown")
        city = get_city_from_ip(ip_address)
        
        total_blocks = sum(ports.values())
        ufw_country_attempts[country_name] += total_blocks
        
        for port, count in ports.items():
            ufw_port_summary[port] += count
        
        ufw_details[ip_address] = {
            'country': country_name,
            'city': city,
            'ports': dict(ports),
            'total': total_blocks
        }
    
    ufw_country_attempts = sorted(ufw_country_attempts.items(), key=lambda x: x[1], reverse=True)
    ufw_port_summary = sorted(ufw_port_summary.items(), key=lambda x: x[1], reverse=True)
    ufw_details = dict(sorted(ufw_details.items(), key=lambda x: x[1]['total'], reverse=True))

    # Process nginx access logs by country and status
    nginx_country_requests = defaultdict(int)
    nginx_status_summary = defaultdict(int)
    nginx_details = {}
    
    for ip_address, statuses in nginx_access.items():
        country = get_country_from_ip(ip_address)
        country_name = country_names.get(country, "Unknown")
        city = get_city_from_ip(ip_address)
        
        total_requests = sum(statuses.values())
        nginx_country_requests[country_name] += total_requests
        
        for status, count in statuses.items():
            nginx_status_summary[status] += count
        
        nginx_details[ip_address] = {
            'country': country_name,
            'city': city,
            'statuses': dict(statuses),
            'total': total_requests
        }
    
    nginx_country_requests = sorted(nginx_country_requests.items(), key=lambda x: x[1], reverse=True)
    nginx_status_summary = sorted(nginx_status_summary.items(), key=lambda x: int(x[0]))
    nginx_details = dict(sorted(nginx_details.items(), key=lambda x: x[1]['total'], reverse=True))

    html_content = template.render(
        TOTAL_ATTEMPTS=TOTAL_ATTEMPTS,
        TOTAL_SUCCESS=TOTAL_SUCCESS,
        TOTAL_UFW_BLOCKS=TOTAL_UFW_BLOCKS,
        TOTAL_NGINX_REQUESTS=TOTAL_NGINX_REQUESTS,
        ip_count=len(ssh_attempts),
        country_count=len(country_attempts),
        city_count=len(city_attempts),
        user_count=len(user_attempts),
        country_attempts=country_attempts,
        user_attempts=user_attempts,
        country_details=country_details,
        ufw_blocks_count=len(ufw_blocks),
        ufw_country_attempts=ufw_country_attempts,
        ufw_port_summary=ufw_port_summary,
        ufw_details=ufw_details,
        nginx_requests_count=len(nginx_access),
        nginx_country_requests=nginx_country_requests,
        nginx_status_summary=nginx_status_summary,
        nginx_details=nginx_details,
        nginx_errors=nginx_errors,
        successful_logins=successful_logins,
        successful_country_attempts=successful_country_attempts,
        severity_critical=critical_events,
        severity_high=high_events,
        severity_medium=medium_events,
        report_time=report_time,
        from_date=from_date,
        to_date=to_date
    )

    with open(HACKER_REPORT, "w") as f:
        f.write(html_content)
    journal.send(MESSAGE=f"Report saved to {HACKER_REPORT}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")
    
    # Return statistics for email summary
    return {
        'ip_count': len(ssh_attempts),
        'country_count': len(country_attempts),
        'user_count': len(user_attempts),
        'country_attempts': country_attempts,
        'user_attempts': user_attempts,
        'ufw_blocks_count': len(ufw_blocks),
        'ufw_country_attempts': ufw_country_attempts,
        'ufw_port_summary': ufw_port_summary,
        'nginx_requests_count': len(nginx_access),
        'nginx_country_requests': nginx_country_requests,
        'nginx_status_summary': nginx_status_summary,
        'nginx_errors_count': len(nginx_errors),
        'total_success': TOTAL_SUCCESS,
        'critical_count': len(critical_events),
        'high_count': len(high_events),
        'medium_count': len(medium_events)
    }

# Function to send an email with the report link using Postfix
def send_email(report_url, recipient_email, total_attempts, ip_count, country_count, user_count, 
               top_countries, top_users, total_ufw_blocks, ufw_blocks_count, ufw_top_countries, 
               ufw_top_ports, total_nginx_requests, nginx_requests_count, nginx_top_countries,
               nginx_status_summary, nginx_errors_count, total_success, critical_count, high_count, 
               medium_count, from_date, to_date, debug=False):
    hostname = subprocess.check_output("hostname").decode("utf-8").strip()

    # Create email headers and body with summary
    subject = f"{hostname} Security Report"
    
    body = f"""Security Report for {hostname}
Period: {from_date} to {to_date}

===============================================================
                    SUMMARY OVERVIEW                       
===============================================================

[!] SUCCESSFUL LOGINS:        {total_success}
[X] FAILED LOGIN ATTEMPTS:    {total_attempts} (from {ip_count} IPs across {country_count} countries)
[#] UFW FIREWALL BLOCKS:      {total_ufw_blocks} (from {ufw_blocks_count} unique IPs)
[@] WEB SERVER REQUESTS:      {total_nginx_requests} (from {nginx_requests_count} unique IPs)

[CRITICAL] SECURITY EVENTS:   {critical_count}
[HIGH]     SEVERITY EVENTS:   {high_count}
[MEDIUM]   SEVERITY EVENTS:   {medium_count}

===============================================================

=== SUCCESSFUL LOGINS ===
{total_success} successful authentication(s) detected.
Review the detailed report to verify all logins are authorized.

=== FAILED LOGIN ATTEMPTS ===
Total Attempts: {total_attempts}
Unique IP Addresses: {ip_count}
Countries: {country_count}
User IDs Targeted: {user_count}

=== TOP 10 COUNTRIES (Failed Attempts) ===
"""
    # Add top 10 countries
    for i, (country, count) in enumerate(top_countries[:10], 1):
        body += f"{i:2d}. {country:30s} : {count:6d} attempts\n"
    
    body += "\n=== TOP 10 TARGETED USER IDs ===\n"
    # Add top 10 users
    for i, (user, count) in enumerate(top_users[:10], 1):
        body += f"{i:2d}. {user:20s} : {count:6d} attempts\n"
    
    body += f"\n=== BLOCKED BY UFW FIREWALL ===\n"
    body += f"Total Blocks: {total_ufw_blocks}\n"
    body += f"Unique IPs: {ufw_blocks_count}\n"
    
    if ufw_top_countries:
        body += "\n=== TOP 10 COUNTRIES (UFW Blocks) ===\n"
        for i, (country, count) in enumerate(ufw_top_countries[:10], 1):
            body += f"{i:2d}. {country:30s} : {count:6d} blocks\n"
    
    if ufw_top_ports:
        body += "\n=== TOP TARGETED PORTS ===\n"
        port_names = {'22': 'SSH', '80': 'HTTP', '443': 'HTTPS', '3389': 'RDP', 
                      '3306': 'MySQL', '5432': 'PostgreSQL', '21': 'FTP', '25': 'SMTP'}
        for i, (port, count) in enumerate(ufw_top_ports[:10], 1):
            port_name = port_names.get(port, f'Port {port}')
            body += f"{i:2d}. {port_name:20s} : {count:6d} blocks\n"
    
    body += f"\n=== WEB SERVER ACTIVITY (NGINX) ===\n"
    body += f"Total Requests: {total_nginx_requests}\n"
    body += f"Unique IPs: {nginx_requests_count}\n"
    
    if nginx_status_summary:
        body += "\n=== HTTP STATUS CODES ===\n"
        status_names = {'200': 'OK', '304': 'Not Modified', '404': 'Not Found', 
                       '403': 'Forbidden', '500': 'Server Error', '502': 'Bad Gateway'}
        for status, count in nginx_status_summary[:10]:
            status_name = status_names.get(status, f'Status {status}')
            body += f"{status} {status_name:20s} : {count:6d} requests\n"
    
    if nginx_top_countries:
        body += "\n=== TOP 10 COUNTRIES (Web Access) ===\n"
        for i, (country, count) in enumerate(nginx_top_countries[:10], 1):
            body += f"{i:2d}. {country:30s} : {count:6d} requests\n"
    
    if nginx_errors_count > 0:
        body += f"\n[!] NGINX ERRORS: {nginx_errors_count} errors detected\n"
    
    # Add security events summary
    body += f"\n=== SECURITY EVENTS BY SEVERITY ===\n"
    body += f"Comprehensive monitoring from: auditd, SSH, nginx, rkhunter, AIDE, \n"
    body += f"ClamAV, chkrootkit, Lynis, Tiger, and psad.\n\n"
    body += f"[CRITICAL] Events:  {critical_count} - Immediate attention required\n"
    body += f"[HIGH]     Severity: {high_count} - Review recommended\n"
    body += f"[MEDIUM]   Severity: {medium_count} - Informational\n"
    
    if critical_count > 0:
        body += f"\n*** WARNING: {critical_count} CRITICAL security events detected! ***\n"
        body += f"    Review the detailed report immediately.\n"
    
    body += f"\n{'=' * 63}\n"
    body += f"\nFull detailed report: {report_url}\n"
    
    email_content  = f"From: {sender_email}\n"
    email_content += f"To: {recipient_email}\n"
    email_content += f"Subject: {subject}\n\n"
    email_content += body

    try:
        # Run the sendmail command with a timeout
        process = subprocess.Popen(
            ["/usr/sbin/sendmail", "-t", "-oi"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Capture the stdout and stderr with 30 second timeout
        try:
            stdout, stderr = process.communicate(email_content.encode('utf-8'), timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            journal.send(MESSAGE=f"Email sending timed out after 30 seconds to {recipient_email}", 
                        SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
            return

        # Check if sendmail command was successful
        if process.returncode == 0:
            journal.send(MESSAGE=f"Email sent to {recipient_email}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")
        else:
            # Log the error details if the command failed
            journal.send(MESSAGE=f"Failed to send email to {recipient_email}. Error: {stderr.decode('utf-8')}",
                         SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
    except Exception as e:
        # Log any exceptions that occur
        journal.send(MESSAGE=f"Exception occurred while sending email: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")

# Main function
def main():
    # Load geo cache if using API method
    if GEOLOCATION_METHOD == 'api':
        load_geo_cache()
    
    try:
        user = getpass.getuser()
    except:
        user = os.getenv('USER', 'system')
    journal.send(MESSAGE=f"Started SSH report generation by {user}...", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")

    parser = argparse.ArgumentParser(
        description="Process SSH logon attempts from journal logs."
    )
    parser.add_argument(
        "--from_date",
        required=False,
        type=str,
        default=datetime.now().date() - timedelta(days=1),
        help="Start date for the journal logs (e.g., '2024-05-16').",
    )
    parser.add_argument(
        "--to_date",
        required=False,
        type=str,
        default=datetime.now().date(),
        help="End date for the journal logs (e.g., '2024-05-17').",
    )
    parser.add_argument(
        "--email",
        required=False,
        type=str,
        default=recipient_email,
        help="Recipient email address to send the report to.",
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug mode for more verbose output")
    parser.add_argument("--no-email", action="store_true", help="Skip sending email (generate report only)")
    parser.add_argument(
        "--tiles",
        required=False,
        type=str,
        default=None,
        help="Base map tiles (e.g., 'CartoDB positron', 'OpenStreetMap', 'CartoDB dark_matter'). Overrides config.",
    )

    args = parser.parse_args()
    
    # Normalize date arguments to full timestamps for consistent processing
    def normalize_dt(val, is_start=True):
        if isinstance(val, str):
            # Accept date-only 'YYYY-MM-DD' or full 'YYYY-MM-DD HH:MM:SS'
            try:
                dt = datetime.strptime(val, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                try:
                    d = datetime.strptime(val, '%Y-%m-%d').date()
                    if is_start:
                        dt = datetime.combine(d, datetime.min.time())
                    else:
                        dt = datetime.combine(d, datetime.max.time())
                except ValueError:
                    # Fallback: treat as 'today'
                    d = datetime.now().date()
                    dt = datetime.combine(d, datetime.min.time() if is_start else datetime.max.time())
        else:
            # date object
            d = val
            if hasattr(val, 'year') and not hasattr(val, 'hour'):
                dt = datetime.combine(d, datetime.min.time() if is_start else datetime.max.time())
            else:
                dt = val
        return dt.strftime('%Y-%m-%d %H:%M:%S')

    norm_from = normalize_dt(args.from_date, True)
    norm_to = normalize_dt(args.to_date, False)

    # Extract SSH authentication failures, UFW firewall blocks, and nginx access logs
    attack_attempts, TOTAL_ATTEMPTS = extract_attack_attempts(norm_from, norm_to,debug=args.debug)
    ufw_blocks, TOTAL_UFW_BLOCKS = extract_ufw_blocks(norm_from, norm_to,debug=args.debug)
    nginx_access, nginx_errors, TOTAL_NGINX_REQUESTS = extract_nginx_logs(norm_from, norm_to,debug=args.debug)
    
    stats = generate_html_report(attack_attempts, TOTAL_ATTEMPTS, ufw_blocks, TOTAL_UFW_BLOCKS,
                                 nginx_access, TOTAL_NGINX_REQUESTS, nginx_errors,
                                 norm_from, norm_to,debug=args.debug, tiles_override=args.tiles)

    # Email the report link with summary statistics (unless --no-email flag is set)
    if not args.no_email:
        try:
            send_email(
                report_url, 
                args.email, 
                TOTAL_ATTEMPTS,
                stats['ip_count'],
                stats['country_count'],
                stats['user_count'],
                stats['country_attempts'],
                stats['user_attempts'],
                TOTAL_UFW_BLOCKS,
                stats['ufw_blocks_count'],
                stats['ufw_country_attempts'],
                stats['ufw_port_summary'],
                TOTAL_NGINX_REQUESTS,
                stats['nginx_requests_count'],
                stats['nginx_country_requests'],
                stats['nginx_status_summary'],
                stats['nginx_errors_count'],
                stats['total_success'],
                stats['critical_count'],
                stats['high_count'],
                stats['medium_count'],
                norm_from,
                norm_to,
                debug=args.debug
            )
        except Exception as e:
            journal.send(MESSAGE=f"Failed to send email: {e}. Report still generated at {report_url}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
    else:
        journal.send(MESSAGE="Email skipped (--no-email flag set). Report available at: " + report_url, SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")

    journal.send(MESSAGE="Report successfully generated and saved.", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")
    
    # Save geo cache if using API method
    if GEOLOCATION_METHOD == 'api':
        save_geo_cache()

if __name__ == "__main__":
    main()
