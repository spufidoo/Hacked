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
import gzip
import ipaddress
import time
import urllib.request
import urllib.error
import tarfile
import tempfile
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate, make_msgid
from html import escape as html_escape
from jinja2 import Environment, FileSystemLoader
from systemd import journal
from datetime import datetime, timedelta
from countries import country_names
from collections import defaultdict
from geoip2.database import Reader

# Global Variables
# Resolve config/data locations. Search order prefers the directory the script
# lives in and the current working directory (development in Code/python/Hacked)
# before the installed locations (/usr/local/etc, /usr/local/bin). This means a
# checkout can be edited and run in-place without picking up an installed copy.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

def _find_root(filename):
    """Return the first search path that contains filename, else '.'."""
    for path in (SCRIPT_DIR, '.', '/usr/local/etc', '/usr/local/bin'):
        if os.path.exists(os.path.join(path, filename)):
            return path
    return '.'

# CONFIG_ROOT holds HackedSSH.ini; ROOT holds the Jinja template + data files.
CONFIG_ROOT = _find_root('HackedSSH.ini')
ROOT = _find_root('HackedSSH.html')

IP_REGEX = r"(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|[0-9a-fA-F:]+)"

config = configparser.ConfigParser()
config.read(f'{CONFIG_ROOT}/HackedSSH.ini')
sender_email = config['EMAIL']['sender_email']
recipient_email = config['EMAIL']['recipient_email']
hostname = config['WEB']['hostname']
report_url = config['WEB']['report_url']
local_url = config['WEB']['local_url']
# Optional map tiles configuration; defaults to OpenStreetMap.
# NOTE: CartoDB basemaps now require an API key and render an "API KEY REQUIRED"
# watermark when used unauthenticated, so OpenStreetMap is the safe default.
tiles_default = (config.get('MAP', 'tiles', fallback='OpenStreetMap')).strip()
# Map feature flags from config
ENABLE_SECURITY_EVENT_MARKERS = config.getboolean('MAP', 'enable_security_event_markers', fallback=True)
ENABLE_NGINX_MARKERS = config.getboolean('MAP', 'enable_nginx_markers', fallback=True)
ENABLE_LEGEND = config.getboolean('MAP', 'enable_legend', fallback=False)
# Geolocation method: 'api' (ip-api.com) or 'database' (GeoLite2)
GEOLOCATION_METHOD = config.get('MAP', 'geolocation_method', fallback='database').strip().lower()
# Daily JSON archives for date scrolling (gzipped, capped detail)
ARCHIVE_DIR = config.get('ARCHIVE', 'archive_dir', fallback='/var/www/html/reports').strip()
ARCHIVE_TOP_N = config.getint('ARCHIVE', 'archive_top_n', fallback=50)
ARCHIVE_MAX_DAYS = config.getint('ARCHIVE', 'archive_max_days', fallback=730)
# Per-event archive: stores individual log lines so the report page can filter
# and group them in the browser. ~30 KB gzipped for a busy day.
ARCHIVE_EVENTS = config.getboolean('ARCHIVE', 'archive_events', fallback=True)
ARCHIVE_MAX_EVENTS = config.getint('ARCHIVE', 'archive_max_events', fallback=20000)

# Successful SSH from private/Tailscale/listed networks is informational.
# Unexpected public IPs stay critical.
_ALWAYS_TRUSTED = (
    '127.0.0.0/8', '::1/128',
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
    '100.64.0.0/10',          # Tailscale CGNAT
    'fd7a:115c:a1e0::/48',    # Tailscale IPv6
)
_trusted_networks = []
for _net in list(_ALWAYS_TRUSTED) + [
        n.strip() for n in config.get('TRUSTED', 'trusted_ips', fallback='').split(',')
        if n.strip()]:
    try:
        _trusted_networks.append(ipaddress.ip_network(_net, strict=False))
    except ValueError:
        pass


def _is_trusted_ip(ip):
    """True for LAN, Tailscale, loopback, and IPs listed in [TRUSTED]."""
    if not ip or ip in ('localhost', '-', 'unknown'):
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _trusted_networks)

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
        SCRIPT_DIR,        # Alongside the script (development checkout)
        '.',               # Current directory (development)
        '/usr/local/etc',  # Installed location (matches config)
        '/usr/local/bin',  # Backward compatibility
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

# Combined-format nginx access line, with optional trailing host=/proxy= fields
# added by the vhost log_format. Older rotated logs without those fields still match.
NGINX_ACCESS_RE = re.compile(
    rf'^({IP_REGEX}) - \S+ \[([^\]]+)\] "([^"]*)" (\d+) (\d+|-)(?: "([^"]*)" "([^"]*)")?(?: host=(\S+))?(?: proxy=(\S*))?'
)


def _parse_nginx_access_line(line):
    """Return a dict for one access.log line, or None if it is not parseable."""
    m = NGINX_ACCESS_RE.match(line)
    if not m:
        return None
    ip, ts, request, status, size, referer, agent, host, proxy = m.groups()
    try:
        when = datetime.strptime(ts.split()[0], '%d/%b/%Y:%H:%M:%S')
    except ValueError:
        return None
    host = (host or '').strip()
    if not host or host in ('-', '_'):
        host = '(unknown)'
    return {
        'ip': ip,
        'when': when,
        'request': request or '',
        'status': status,
        'size': size,
        'referer': referer,
        'agent': agent,
        'host': host,
        'proxy': proxy or '',
    }


def _finalise_nginx_hosts(raw_hosts):
    """Turn the per-host collector into a JSON-friendly list sorted by volume."""
    summary = []
    for host, data in raw_hosts.items():
        summary.append({
            'host': host,
            'total': data['total'],
            'ips': len(data['ips']),
            'statuses': dict(data['statuses']),
            'proxied': data['proxied'],
        })
    summary.sort(key=lambda d: d['total'], reverse=True)
    return summary


# Function to extract nginx access logs
def extract_nginx_logs(from_date, to_date, debug=False):
    nginx_access = defaultdict(lambda: defaultdict(int))  # {ip: {status: count}}
    nginx_hosts = defaultdict(lambda: {
        'total': 0, 'ips': set(), 'statuses': defaultdict(int), 'proxied': False,
    })
    nginx_errors = []
    TOTAL_NGINX_REQUESTS = 0
    from_dt, to_dt = _range_bounds(from_date, to_date)

    try:
        # Parse nginx access logs (including rotated .1 and .gz)
        # Format: IP - - [date] "REQUEST" status bytes "referrer" "user-agent" [host=... proxy=...]
        access_log = subprocess.check_output(
            ["bash", "-lc", "zcat -f /var/log/nginx/access.log* 2>/dev/null || cat /var/log/nginx/access.log 2>/dev/null"]
        ).decode("utf-8")

        for line in access_log.splitlines():
            rec = _parse_nginx_access_line(line)
            if not rec:
                continue
            if not (from_dt <= rec['when'] <= to_dt):
                continue
            ip_address = rec['ip']
            # Skip local IPs
            if ip_address.startswith(('127.', '192.168.', '10.', '172.')):
                continue
            status = rec['status']
            nginx_access[ip_address][status] += 1
            TOTAL_NGINX_REQUESTS += 1
            host_rec = nginx_hosts[rec['host']]
            host_rec['total'] += 1
            host_rec['ips'].add(ip_address)
            host_rec['statuses'][status] += 1
            if rec['proxy'] and rec['proxy'] not in ('-', ''):
                host_rec['proxied'] = True
            if debug:
                print(f"NGINX: {ip_address} host={rec['host']} {status} {rec['request'][:50]}")
                    
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

    return nginx_access, nginx_errors, TOTAL_NGINX_REQUESTS, _finalise_nginx_hosts(nginx_hosts)

# ---------------------------------------------------------------------------
# Per-event extraction for the browsable daily log archive.
#
# The aggregate extractors above answer "how many"; these answer "which lines".
# Events are emitted with full ISO timestamps (the report window can span more
# than one calendar day) and short keys, because the archive is gzipped and
# these files are fetched by the browser.
# ---------------------------------------------------------------------------

def _range_bounds(from_date, to_date):
    """Normalise the report window to a pair of datetimes."""
    if isinstance(from_date, str):
        from_dt = datetime.strptime(from_date, '%Y-%m-%d %H:%M:%S')
    else:
        from_dt = datetime.combine(from_date, datetime.min.time())
    if isinstance(to_date, str):
        to_dt = datetime.strptime(to_date, '%Y-%m-%d %H:%M:%S')
    else:
        to_dt = datetime.combine(to_date, datetime.max.time())
    return from_dt, to_dt


def _journal_iso(unit_args, from_date, to_date):
    """Run journalctl with ISO timestamps so events can be parsed without guessing the year."""
    cmd = ["journalctl", *unit_args, "-o", "short-iso",
           f"--since={from_date}", f"--until={to_date}", "--no-pager"]
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode("utf-8", "replace")
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


ISO_PREFIX = re.compile(r'^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})')


def _iso_parts(line):
    m = ISO_PREFIX.match(line)
    if not m:
        return None, None
    return m.group(1), m.group(2)


def extract_nginx_events(from_date, to_date, max_events, debug=False):
    """Individual nginx requests in range, newest last."""
    events = []
    from_dt, to_dt = _range_bounds(from_date, to_date)
    try:
        access_log = subprocess.check_output(
            ["bash", "-lc", "zcat -f /var/log/nginx/access.log* 2>/dev/null || cat /var/log/nginx/access.log 2>/dev/null"]
        ).decode("utf-8", "replace")
    except (FileNotFoundError, subprocess.CalledProcessError):
        return events

    for line in access_log.splitlines():
        rec = _parse_nginx_access_line(line)
        if not rec:
            continue
        if not (from_dt <= rec['when'] <= to_dt):
            continue
        parts = rec['request'].split(' ')
        method = parts[0][:10] if parts and parts[0] else ''
        url = parts[1][:200] if len(parts) > 1 else rec['request'][:200]
        events.append({
            'ts': rec['when'].strftime('%Y-%m-%d %H:%M:%S'),
            'ip': rec['ip'],
            'host': rec['host'],
            'method': method,
            'url': url,
            'status': int(rec['status']),
            'bytes': int(rec['size']) if rec['size'].isdigit() else 0,
            'ref': (rec['referer'] or '')[:200] if rec['referer'] and rec['referer'] != '-' else '',
            'ua': (rec['agent'] or '')[:160] if rec['agent'] and rec['agent'] != '-' else '',
        })
    if debug:
        print(f"nginx events collected: {len(events)}")
    return events[-max_events:] if max_events and len(events) > max_events else events


def extract_ufw_events(from_date, to_date, max_events, debug=False):
    """Individual UFW firewall blocks in range."""
    events = []
    logs = _journal_iso(["_TRANSPORT=kernel"], from_date, to_date)
    pattern = re.compile(r'\[UFW BLOCK\].*?SRC=(\S+).*?DST=(\S+).*?PROTO=(\S+)(?:.*?DPT=(\d+))?')
    for line in logs.splitlines():
        if '[UFW BLOCK]' not in line:
            continue
        day, clock = _iso_parts(line)
        if not day:
            continue
        m = pattern.search(line)
        if not m:
            continue
        src, _dst, proto, dpt = m.groups()
        events.append({
            'ts': f'{day} {clock}',
            'ip': src,
            'port': int(dpt) if dpt else 0,
            'proto': proto,
        })
    if debug:
        print(f"ufw events collected: {len(events)}")
    return events[-max_events:] if max_events and len(events) > max_events else events


def extract_ssh_events(from_date, to_date, max_events, debug=False):
    """Individual SSH authentication outcomes in range."""
    events = []
    logs = _journal_iso(["_SYSTEMD_UNIT=ssh.service"], from_date, to_date)
    accepted = re.compile(r'Accepted (\S+) for (\S+) from (\S+)')
    failed = re.compile(r'Failed (\S+) for (?:invalid user )?(\S+) from (\S+)')
    invalid = re.compile(r'Invalid user (\S+) from (\S+)')
    for line in logs.splitlines():
        day, clock = _iso_parts(line)
        if not day:
            continue
        ts = f'{day} {clock}'
        m = accepted.search(line)
        if m:
            events.append({'ts': ts, 'ip': m.group(3), 'user': m.group(2),
                           'outcome': 'accepted', 'method': m.group(1)})
            continue
        m = failed.search(line)
        if m:
            events.append({'ts': ts, 'ip': m.group(3), 'user': m.group(2),
                           'outcome': 'failed', 'method': m.group(1)})
            continue
        m = invalid.search(line)
        if m:
            events.append({'ts': ts, 'ip': m.group(2), 'user': m.group(1),
                           'outcome': 'invalid', 'method': 'none'})
    if debug:
        print(f"ssh events collected: {len(events)}")
    return events[-max_events:] if max_events and len(events) > max_events else events


def save_events_archive(from_date, to_date, debug=False):
    """Write the day's individual log events so the page can re-process them client-side."""
    if not ARCHIVE_EVENTS:
        return None
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    day = _archive_date(from_date)
    payload = {
        'date': day,
        'from_date': str(from_date),
        'to_date': str(to_date),
        'nginx': extract_nginx_events(from_date, to_date, ARCHIVE_MAX_EVENTS, debug),
        'ufw': extract_ufw_events(from_date, to_date, ARCHIVE_MAX_EVENTS, debug),
        'ssh': extract_ssh_events(from_date, to_date, ARCHIVE_MAX_EVENTS, debug),
    }
    body = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    path = os.path.join(ARCHIVE_DIR, f'{day}.events.json.gz')
    with gzip.open(path, 'wb', compresslevel=9) as f:
        f.write(body)
    counts = {k: len(payload[k]) for k in ('nginx', 'ufw', 'ssh')}
    journal.send(
        MESSAGE=f"Event archive saved to {path} ({os.path.getsize(path)} bytes gz, {counts})",
        SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")
    if debug:
        print(f"Event archive {path}: {counts}")
    return counts


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

                    event = {
                        'service': 'SSH',
                        'event': f'Successful Login ({method})',
                        'user': user,
                        'ip': ip,
                        'timestamp': timestamp,
                        'message': line.strip()
                    }
                    # Expected (LAN / Tailscale / listed WAN) is informational.
                    # An unexpected public IP stays critical.
                    if _is_trusted_ip(ip):
                        event['event'] += ' (expected)'
                        medium_events.append(event)
                    else:
                        critical_events.append(event)
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

def _json_default(obj):
    if isinstance(obj, datetime):
        return obj.strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(obj, set):
        return list(obj)
    raise TypeError(f"Not JSON serializable: {type(obj)}")


def _archive_date(from_date):
    """Name the daily archive after the report window start date."""
    if isinstance(from_date, str):
        try:
            return datetime.strptime(from_date[:10], '%Y-%m-%d').date().isoformat()
        except ValueError:
            return datetime.now().date().isoformat()
    if hasattr(from_date, 'date'):
        return from_date.date().isoformat()
    return str(from_date)[:10]


def _top_n_items(mapping, n, total_fn):
    """Return mapping limited to the n keys with the highest total_fn(value)."""
    ranked = sorted(mapping.items(), key=lambda kv: total_fn(kv[1]), reverse=True)
    return dict(ranked[:n])


def _cap_country_details(country_details, n):
    rows = []
    for country, ips in country_details.items():
        for ip, details in ips.items():
            users = dict(details.get('users') or {})
            total = sum(users.values())
            rows.append((total, country, ip, details.get('city', ''), users))
    rows.sort(key=lambda r: r[0], reverse=True)
    out = {}
    for _total, country, ip, city, users in rows[:n]:
        out.setdefault(country, {})[ip] = {'city': city, 'users': users}
    return out


def _serialize_successful_logins(successful_logins):
    out = {}
    for ip, data in successful_logins.items():
        out[ip] = {
            'user': data.get('user', ''),
            'count': data.get('count', 0),
            'method': data.get('method', ''),
            'timestamps': list(data.get('timestamps') or []),
            'country': data.get('country', 'Unknown'),
            'city': data.get('city', 'Unknown'),
        }
    return out


def _serialize_events(events):
    serialized = []
    for event in events:
        serialized.append({
            'service': event.get('service', ''),
            'event': event.get('event', ''),
            'user': event.get('user', ''),
            'ip': event.get('ip', ''),
            'timestamp': event.get('timestamp', ''),
            'message': (event.get('message') or '')[:500],
        })
    return serialized


def prune_archives(archive_dir, max_days):
    if max_days <= 0:
        return
    cutoff = datetime.now().date() - timedelta(days=max_days)
    try:
        names = os.listdir(archive_dir)
    except FileNotFoundError:
        return
    for name in names:
        if not name.endswith(('.json.gz', '.events.json.gz')) or len(name) < 10:
            continue
        try:
            day = datetime.strptime(name[:10], '%Y-%m-%d').date()
        except ValueError:
            continue
        if day < cutoff:
            try:
                os.remove(os.path.join(archive_dir, name))
            except OSError:
                pass


def update_archive_index(archive_dir, day, headline):
    index_path = os.path.join(archive_dir, 'index.json')
    dates = []
    if os.path.exists(index_path):
        try:
            with open(index_path, encoding='utf-8') as f:
                existing = json.load(f)
            dates = existing.get('dates') or []
        except (OSError, json.JSONDecodeError):
            dates = []
    dates = [d for d in dates if d.get('date') != day]
    dates.append(headline)
    dates.sort(key=lambda d: d.get('date', ''), reverse=True)
    # Drop index entries whose gzip file was pruned, and flag which days have
    # a per-event archive available for the client-side log viewer.
    keep = []
    for entry in dates:
        gz = os.path.join(archive_dir, f"{entry.get('date')}.json.gz")
        if not os.path.exists(gz):
            continue
        entry['events'] = os.path.exists(
            os.path.join(archive_dir, f"{entry.get('date')}.events.json.gz"))
        keep.append(entry)
    with open(index_path, 'w', encoding='utf-8') as f:
        json.dump({'dates': keep}, f, separators=(',', ':'))


def save_report_archive(payload, from_date):
    """Write a gzipped JSON snapshot and refresh reports/index.json."""
    os.makedirs(ARCHIVE_DIR, exist_ok=True)
    day = _archive_date(from_date)
    gz_path = os.path.join(ARCHIVE_DIR, f'{day}.json.gz')
    body = json.dumps(payload, default=_json_default, separators=(',', ':')).encode('utf-8')
    with gzip.open(gz_path, 'wb') as f:
        f.write(body)
    prune_archives(ARCHIVE_DIR, ARCHIVE_MAX_DAYS)
    update_archive_index(ARCHIVE_DIR, day, {
        'date': day,
        'failed': payload.get('TOTAL_ATTEMPTS', 0),
        'ufw': payload.get('TOTAL_UFW_BLOCKS', 0),
        'success': payload.get('TOTAL_SUCCESS', 0),
        'nginx': payload.get('TOTAL_NGINX_REQUESTS', 0),
        'critical': payload.get('critical_count', 0),
        'high': payload.get('high_count', 0),
        'medium': payload.get('medium_count', 0),
    })
    journal.send(MESSAGE=f"Archive saved to {gz_path} ({len(body)} bytes uncompressed)",
                 SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")
    return gz_path

# Function to generate HTML report
def generate_html_report(ssh_attempts, TOTAL_ATTEMPTS, ufw_blocks, TOTAL_UFW_BLOCKS, nginx_access, TOTAL_NGINX_REQUESTS, nginx_errors, from_date, to_date,debug=False, tiles_override=None, archive_only=False, nginx_host_summary=None):
    env = Environment(loader=FileSystemLoader(ROOT))
    template = env.get_template(HACKER_TEMPLATE)
    nginx_host_summary = nginx_host_summary or []
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
    map_points = []
    
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
            map_points.append({
                'ip': ip_address, 'lat': lat, 'lon': lon, 'kind': 'ssh',
                'count': total_count, 'city': city or ''
            })

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
            map_points.append({
                'ip': ip_address, 'lat': lat, 'lon': lon, 'kind': 'ufw',
                'count': total_blocks, 'city': city or ''
            })
    
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
                map_points.append({
                    'ip': ip_address, 'lat': lat, 'lon': lon, 'kind': 'critical',
                    'count': event_count, 'city': city or ''
                })
        
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
                map_points.append({
                    'ip': ip_address, 'lat': lat, 'lon': lon, 'kind': 'high',
                    'count': event_count, 'city': city or ''
                })
        
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
                map_points.append({
                    'ip': ip_address, 'lat': lat, 'lon': lon, 'kind': 'medium',
                    'count': event_count, 'city': city or ''
                })
    
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
                map_points.append({
                    'ip': ip_address, 'lat': lat, 'lon': lon, 'kind': 'nginx',
                    'count': total_requests, 'city': city or ''
                })
                nginx_count += 1
        
        if debug:
            print(f"Added {nginx_count} nginx IP markers to map (out of {len(nginx_access)} total nginx IPs)")
    
    if not archive_only:
        m.save(HACKER_MAP)  # Save the map to an HTML file
    
    # Add legend to map
    if ENABLE_LEGEND and not archive_only:
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
        nginx_host_summary=nginx_host_summary,
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
        hostname=hostname,
        from_date=from_date,
        to_date=to_date
    )

    if not archive_only:
        with open(HACKER_REPORT, "w") as f:
            f.write(html_content)
        journal.send(MESSAGE=f"Report saved to {HACKER_REPORT}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")

    # Individual log events for the in-page viewer (written before the summary
    # so the index can flag which days have event data).
    try:
        save_events_archive(from_date, to_date, debug=debug)
    except Exception as e:
        journal.send(MESSAGE=f"Failed to write event archive: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
        if debug:
            print(f"Warning: Failed to write event archive: {e}")

    nginx_errors_archive = []
    for err in nginx_errors[-20:]:
        nginx_errors_archive.append({
            'time': err.get('time'),
            'level': err.get('level', ''),
            'message': (err.get('message') or '')[:300],
        })
    try:
        save_report_archive({
            'hostname': hostname,
            'report_time': report_time,
            'from_date': from_date,
            'to_date': to_date,
            'TOTAL_ATTEMPTS': TOTAL_ATTEMPTS,
            'TOTAL_SUCCESS': TOTAL_SUCCESS,
            'TOTAL_UFW_BLOCKS': TOTAL_UFW_BLOCKS,
            'TOTAL_NGINX_REQUESTS': TOTAL_NGINX_REQUESTS,
            'ip_count': len(ssh_attempts),
            'country_count': len(country_attempts),
            'city_count': len(city_attempts),
            'user_count': len(user_attempts),
            'country_attempts': country_attempts,
            'user_attempts': user_attempts,
            'country_details': _cap_country_details(country_details, ARCHIVE_TOP_N),
            'ufw_blocks_count': len(ufw_blocks),
            'ufw_country_attempts': ufw_country_attempts,
            'ufw_port_summary': ufw_port_summary,
            'ufw_details': _top_n_items(ufw_details, ARCHIVE_TOP_N, lambda d: d.get('total', 0)),
            'nginx_requests_count': len(nginx_access),
            'nginx_host_summary': nginx_host_summary,
            'nginx_country_requests': nginx_country_requests,
            'nginx_status_summary': nginx_status_summary,
            'nginx_details': _top_n_items(nginx_details, ARCHIVE_TOP_N, lambda d: d.get('total', 0)),
            'nginx_errors': nginx_errors_archive,
            'successful_logins': _serialize_successful_logins(successful_logins),
            'successful_country_attempts': successful_country_attempts,
            'severity_critical': _serialize_events(critical_events),
            'severity_high': _serialize_events(high_events),
            'severity_medium': _serialize_events(medium_events),
            'critical_count': len(critical_events),
            'high_count': len(high_events),
            'medium_count': len(medium_events),
            'map_points': map_points,
        }, from_date)
    except Exception as e:
        journal.send(MESSAGE=f"Failed to write report archive: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="warning")
        if debug:
            print(f"Warning: Failed to write report archive: {e}")
    
    # Return statistics for email summary
    return {
        'total_attempts': TOTAL_ATTEMPTS,
        'total_ufw_blocks': TOTAL_UFW_BLOCKS,
        'total_nginx_requests': TOTAL_NGINX_REQUESTS,
        'ip_count': len(ssh_attempts),
        'country_count': len(country_attempts),
        'user_count': len(user_attempts),
        'country_attempts': country_attempts,
        'user_attempts': user_attempts,
        'ufw_blocks_count': len(ufw_blocks),
        'ufw_country_attempts': ufw_country_attempts,
        'ufw_port_summary': ufw_port_summary,
        'nginx_requests_count': len(nginx_access),
        'nginx_host_summary': nginx_host_summary,
        'nginx_country_requests': nginx_country_requests,
        'nginx_status_summary': nginx_status_summary,
        'nginx_errors_count': len(nginx_errors),
        'total_success': TOTAL_SUCCESS,
        'critical_count': len(critical_events),
        'high_count': len(high_events),
        'medium_count': len(medium_events)
    }

# ---------------------------------------------------------------------------
# Email report.
#
# The nightly mail is a summary, not a replacement for the web report, so it
# leads with the numbers that decide whether anyone needs to look, then gives
# the top few entries per section. Anything with a zero count is omitted
# rather than printed as an empty heading.
# ---------------------------------------------------------------------------

# Friendly names for the ports and status codes that turn up in these reports.
PORT_NAMES = {
    '21': 'FTP', '22': 'SSH', '23': 'Telnet', '25': 'SMTP', '53': 'DNS',
    '80': 'HTTP', '110': 'POP3', '143': 'IMAP', '443': 'HTTPS', '445': 'SMB',
    '1433': 'MSSQL', '3306': 'MySQL', '3389': 'RDP', '5432': 'PostgreSQL',
    '5900': 'VNC', '6379': 'Redis', '8080': 'HTTP alt', '9090': 'Cockpit',
    '22221': 'SSH proxy to loki', '22222': 'SSH proxy to thor',
    '22223': 'SSH proxy to odin',
}

STATUS_NAMES = {
    '200': 'OK', '204': 'No Content', '206': 'Partial', '301': 'Moved',
    '302': 'Found', '304': 'Not Modified', '400': 'Bad Request',
    '401': 'Unauthorized', '403': 'Forbidden', '404': 'Not Found',
    '405': 'Not Allowed', '408': 'Timeout', '413': 'Too Large',
    '416': 'Bad Range', '429': 'Rate Limited', '444': 'No Response',
    '499': 'Client Closed', '500': 'Server Error', '502': 'Bad Gateway',
    '503': 'Unavailable',
}

EMAIL_TOP_N = 5


def _num(value):
    """Thousands-separated integer, tolerant of junk."""
    try:
        return f'{int(value):,}'
    except (TypeError, ValueError):
        return str(value)


def _short_dt(value):
    """'2026-09-10 00:00:00' -> '10 Sep 2026 00:00'."""
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(str(value), fmt).strftime('%-d %b %Y %H:%M')
        except ValueError:
            continue
    return str(value)


def _report_day(value):
    """Short day label used in the subject line."""
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(str(value), fmt).strftime('%-d %b')
        except ValueError:
            continue
    return str(value)


def _port_label(port):
    name = PORT_NAMES.get(str(port))
    return f'{port} ({name})' if name else str(port)


def _status_label(status):
    name = STATUS_NAMES.get(str(status))
    return f'{status} {name}' if name else str(status)


def _text_rows(rows, indent='  '):
    """Align (label, value) pairs into two columns."""
    rows = [(str(label), str(value)) for label, value in rows]
    if not rows:
        return ''
    width = max(len(label) for label, _ in rows)
    return ''.join(f'{indent}{label:<{width}}   {value}\n' for label, value in rows)


def _plural(count, singular, plural=None):
    """'1 IP' / '5 IPs', with an explicit plural for irregular nouns."""
    plural = plural or singular + 's'
    try:
        n = int(count)
    except (TypeError, ValueError):
        return f'{count} {plural}'
    return f'{_num(n)} {singular if n == 1 else plural}'


def _email_subject(hostname, stats, to_date):
    """Put the day's headline in the subject so triage needs no click."""
    day = _report_day(to_date)
    critical = stats.get('critical_count', 0)
    high = stats.get('high_count', 0)
    if critical:
        return f'[CRITICAL] {hostname} security report, {day}: {critical} critical event(s)'
    if high:
        return f'[HIGH] {hostname} security report, {day}: {high} high-severity event(s)'
    return (f'{hostname} security report, {day}: '
            f'{_num(stats.get("total_ufw_blocks", 0))} blocked, '
            f'{_num(stats.get("total_success", 0))} login(s)')


def _glance_rows(stats):
    """The five numbers that decide whether the full report needs reading."""
    def total(count, *detail):
        """Append the 'from N IPs' detail only when there is something to say."""
        if not count:
            return '0'
        return '%s (%s)' % (_num(count), ', '.join(detail)) if detail else _num(count)

    return [
        ('Successful logins', _num(stats.get('total_success', 0))),
        ('Failed SSH logins', total(
            stats.get('total_attempts', 0),
            _plural(stats.get('ip_count', 0), 'IP'),
            _plural(stats.get('country_count', 0), 'country', 'countries'))),
        ('Firewall blocks', total(
            stats.get('total_ufw_blocks', 0),
            _plural(stats.get('ufw_blocks_count', 0), 'IP'))),
        ('Web requests', total(
            stats.get('total_nginx_requests', 0),
            _plural(stats.get('nginx_requests_count', 0), 'IP'))),
        ('Security events', '%s critical, %s high, %s medium' % (
            _num(stats.get('critical_count', 0)),
            _num(stats.get('high_count', 0)),
            _num(stats.get('medium_count', 0)))),
    ]


def _build_email_text(report_url, hostname, stats, from_date, to_date):
    """Plain-text alternative: compact, aligned, no ASCII art."""
    out = [
        f'Security report for {hostname}',
        f'{_short_dt(from_date)} to {_short_dt(to_date)}',
        '',
        'AT A GLANCE',
        _text_rows(_glance_rows(stats)).rstrip('\n'),
    ]

    critical = stats.get('critical_count', 0)
    if critical:
        out += ['', f'ACTION NEEDED: {critical} critical event(s). See the full report.']

    hosts = stats.get('nginx_host_summary') or []
    if hosts:
        rows = [(rec['host'], '%s from %s%s' % (
            _plural(rec['total'], 'request'), _plural(rec['ips'], 'IP'),
            ' (proxied)' if rec.get('proxied') else ''))
            for rec in hosts[:EMAIL_TOP_N]]
        out += ['', 'WEB REQUESTS BY HOST', _text_rows(rows).rstrip('\n')]

    statuses = stats.get('nginx_status_summary') or []
    if statuses:
        top = sorted(statuses, key=lambda kv: -kv[1])[:EMAIL_TOP_N]
        rows = [(_status_label(s), _num(c)) for s, c in top]
        out += ['', 'TOP HTTP STATUS CODES', _text_rows(rows).rstrip('\n')]

    errors = stats.get('nginx_errors_count', 0)
    if errors:
        out += ['', f'nginx logged {_num(errors)} error(s).']

    ufw_countries = stats.get('ufw_country_attempts') or []
    ufw_ports = stats.get('ufw_port_summary') or []
    if ufw_countries or ufw_ports:
        out += ['', 'FIREWALL BLOCKS']
        if ufw_countries:
            rows = [(c, _num(n)) for c, n in ufw_countries[:EMAIL_TOP_N]]
            out += ['  By country:', _text_rows(rows, indent='    ').rstrip('\n')]
        if ufw_ports:
            rows = [(_port_label(p), _num(n)) for p, n in ufw_ports[:EMAIL_TOP_N]]
            out += ['  By port:', _text_rows(rows, indent='    ').rstrip('\n')]

    ssh_countries = stats.get('country_attempts') or []
    ssh_users = stats.get('user_attempts') or []
    if ssh_countries or ssh_users:
        out += ['', 'FAILED SSH LOGINS']
        if ssh_countries:
            rows = [(c, _num(n)) for c, n in ssh_countries[:EMAIL_TOP_N]]
            out += ['  By country:', _text_rows(rows, indent='    ').rstrip('\n')]
        if ssh_users:
            rows = [(u, _num(n)) for u, n in ssh_users[:EMAIL_TOP_N]]
            out += ['  Targeted usernames:', _text_rows(rows, indent='    ').rstrip('\n')]

    out += ['', f'Full report: {report_url}']
    return '\n'.join(out) + '\n'


def _html_table(rows, headers=None):
    """Minimal inline-styled table; email clients ignore stylesheets."""
    cell = 'padding:3px 12px 3px 0;border-bottom:1px solid #eee;'
    parts = ['<table style="border-collapse:collapse;font-size:14px;">']
    if headers:
        parts.append('<tr>' + ''.join(
            f'<th style="{cell}text-align:left;color:#666;font-weight:600;">{html_escape(str(h))}</th>'
            for h in headers) + '</tr>')
    for row in rows:
        parts.append('<tr>' + ''.join(
            f'<td style="{cell}">{html_escape(str(v))}</td>' for v in row) + '</tr>')
    parts.append('</table>')
    return ''.join(parts)


def _build_email_html(report_url, hostname, stats, from_date, to_date):
    """HTML alternative: same content, easier to scan."""
    critical = stats.get('critical_count', 0)
    high = stats.get('high_count', 0)
    accent = '#c0392b' if critical else '#e67e22' if high else '#2c7a4b'

    parts = [
        '<html><body style="margin:0;padding:20px;'
        'font-family:-apple-system,Segoe UI,Helvetica,Arial,sans-serif;'
        'color:#222;background:#fff;">',
        f'<h2 style="margin:0 0 4px;font-size:20px;color:{accent};">'
        f'Security report for {html_escape(hostname)}</h2>',
        f'<p style="margin:0 0 18px;color:#666;font-size:13px;">'
        f'{html_escape(_short_dt(from_date))} to {html_escape(_short_dt(to_date))}</p>',
    ]

    if critical:
        parts.append(
            f'<p style="margin:0 0 18px;padding:10px 14px;background:#fdecea;'
            f'border-left:4px solid #c0392b;font-size:14px;">'
            f'<strong>Action needed:</strong> {_num(critical)} critical event(s).</p>')

    def section(title, body):
        parts.append(f'<h3 style="margin:22px 0 8px;font-size:15px;color:#333;">'
                     f'{html_escape(title)}</h3>')
        parts.append(body)

    section('At a glance', _html_table(_glance_rows(stats)))

    hosts = stats.get('nginx_host_summary') or []
    if hosts:
        rows = [(rec['host'], _num(rec['total']), _num(rec['ips']),
                 'Reverse proxy' if rec.get('proxied') else 'Local')
                for rec in hosts[:EMAIL_TOP_N]]
        section('Web requests by host',
                _html_table(rows, ['Host', 'Requests', 'IPs', 'Type']))

    statuses = stats.get('nginx_status_summary') or []
    if statuses:
        top = sorted(statuses, key=lambda kv: -kv[1])[:EMAIL_TOP_N]
        section('Top HTTP status codes',
                _html_table([(_status_label(s), _num(c)) for s, c in top],
                            ['Status', 'Requests']))

    errors = stats.get('nginx_errors_count', 0)
    if errors:
        parts.append(f'<p style="margin:14px 0 0;font-size:14px;">'
                     f'nginx logged {_num(errors)} error(s).</p>')

    ufw_countries = stats.get('ufw_country_attempts') or []
    if ufw_countries:
        section('Firewall blocks by country',
                _html_table([(c, _num(n)) for c, n in ufw_countries[:EMAIL_TOP_N]],
                            ['Country', 'Blocks']))

    ufw_ports = stats.get('ufw_port_summary') or []
    if ufw_ports:
        section('Firewall blocks by port',
                _html_table([(_port_label(p), _num(n)) for p, n in ufw_ports[:EMAIL_TOP_N]],
                            ['Port', 'Blocks']))

    ssh_countries = stats.get('country_attempts') or []
    if ssh_countries:
        section('Failed SSH logins by country',
                _html_table([(c, _num(n)) for c, n in ssh_countries[:EMAIL_TOP_N]],
                            ['Country', 'Attempts']))

    ssh_users = stats.get('user_attempts') or []
    if ssh_users:
        section('Targeted usernames',
                _html_table([(u, _num(n)) for u, n in ssh_users[:EMAIL_TOP_N]],
                            ['Username', 'Attempts']))

    parts.append(
        f'<p style="margin:26px 0 0;font-size:14px;">'
        f'<a href="{html_escape(report_url, quote=True)}" '
        f'style="color:#1a6dd4;">View the full report</a></p>')
    parts.append('</body></html>')
    return ''.join(parts)


# Function to send an email with the report link using Postfix
def send_email(report_url, recipient_email, stats, from_date, to_date, debug=False):
    hostname = subprocess.check_output("hostname").decode("utf-8").strip()

    subject = _email_subject(hostname, stats, to_date)
    text_body = _build_email_text(report_url, hostname, stats, from_date, to_date)
    html_body = _build_email_html(report_url, hostname, stats, from_date, to_date)

    if debug:
        print(subject)
        print(text_body)

    # multipart/alternative: clients that refuse HTML still get a readable mail.
    message = MIMEMultipart('alternative')
    message['Subject'] = subject
    message['From'] = sender_email
    message['To'] = recipient_email
    message['Date'] = formatdate(localtime=True)
    message['Message-ID'] = make_msgid(domain=hostname.split()[0] or 'localhost')
    message.attach(MIMEText(text_body, 'plain', 'utf-8'))
    message.attach(MIMEText(html_body, 'html', 'utf-8'))
    email_content = message.as_string()

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
    parser.add_argument("--archive-only", action="store_true",
                        help="Write the JSON archives for the date range without overwriting the live report/map or emailing (used for backfill)")
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
    nginx_access, nginx_errors, TOTAL_NGINX_REQUESTS, nginx_host_summary = extract_nginx_logs(norm_from, norm_to,debug=args.debug)
    
    stats = generate_html_report(attack_attempts, TOTAL_ATTEMPTS, ufw_blocks, TOTAL_UFW_BLOCKS,
                                 nginx_access, TOTAL_NGINX_REQUESTS, nginx_errors,
                                 norm_from, norm_to,debug=args.debug, tiles_override=args.tiles,
                                 archive_only=args.archive_only, nginx_host_summary=nginx_host_summary)

    # Email the report link with summary statistics (unless --no-email flag is set)
    if not args.no_email and not args.archive_only:
        try:
            send_email(report_url, args.email, stats, norm_from, norm_to, debug=args.debug)
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
