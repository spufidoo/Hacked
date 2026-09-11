# HackedSSH - Security monitoring and nightly reports

![Security](https://img.shields.io/badge/Security-Enhanced-green)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

Nightly security reporter for a small homelab. It reads journald, UFW and nginx logs, writes an HTML report plus a compact JSON archive, and emails a short summary.

Production currently runs on **heimdall** (Raspberry Pi, public nginx) from `/usr/local/bin/HackedSSH.py` at midnight. Development is in this tree; odin is the test host (`http://odin.local/HackedSSH_Report.html`).

## Features

- SSH failed and successful logins, UFW blocks, nginx access (including Host / vhost)
- Severity buckets: unexpected public SSH success is **critical**; LAN, Tailscale and listed WAN IPs are **informational**
- HTML report with date scrolling (Prev / date / Next)
- Gzipped daily JSON under `/var/www/html/reports/` (summaries + optional raw events)
- Shared Leaflet map for archived days (no extra Folium HTML per day)
- Multipart email: HTML plus a short plain-text fallback; subject carries the day's headline
- GeoIP via GeoLite2 databases or ip-api.com
- Config/template/GeoLite2 search: script directory → cwd → `/usr/local/etc` → `/usr/local/bin`

## Quick start

```bash
git clone git@github.com:spufidoo/Hacked.git
cd Hacked
sudo apt install python3-folium python3-geoip2 python3-jinja2 python3-systemd
# or: pip install folium geoip2 jinja2 systemd-python   (see TROUBLESHOOTING_DEBIAN12.md)

cp config.ini.template HackedSSH.ini
# Edit EMAIL, WEB, MAP, TRUSTED, ARCHIVE

sudo python3 HackedSSH.py --no-email --debug
```

Install:

```bash
sudo cp HackedSSH.py HackedSSH.html HackedSSH.sh countries.py /usr/local/bin/
sudo cp config.ini.template /usr/local/etc/HackedSSH.ini
sudo chmod 755 /usr/local/bin/HackedSSH.py /usr/local/bin/HackedSSH.sh
# cron (heimdall):  0 0 * * * /usr/bin/python3 /usr/local/bin/HackedSSH.py >> /var/log/hackedssh.log 2>&1
# or systemd:       sudo bash scripts/install_hackedssh_service.sh
```

### Useful flags

```bash
sudo python3 HackedSSH.py                              # yesterday → today, email
sudo python3 HackedSSH.py --from_date 2026-09-10 --to_date 2026-09-11
sudo python3 HackedSSH.py --no-email
sudo python3 HackedSSH.py --archive-only --from_date 2026-09-01 --to_date 2026-09-01
sudo python3 HackedSSH.py --debug
sudo bash scripts/backfill_archives.sh 100             # last 100 days of JSON archives
```

## Configuration

Search order for `HackedSSH.ini` (first match wins): directory of the script, current directory, `/usr/local/etc`, `/usr/local/bin`.

```ini
[EMAIL]
sender_email = reports@example.com
recipient_email = you@example.com

[WEB]
hostname = home.example.com
report_url = https://home.example.com/HackedSSH_Report.html
local_url = http://host.local/HackedSSH_Report.html

[MAP]
tiles = OpenStreetMap
geolocation_method = database
# maxmind_account_id = ...
# maxmind_license_key = ...

[TRUSTED]
# Successful SSH from these IPs/CIDRs is informational, not critical.
# LAN, loopback and Tailscale are always trusted as well.
trusted_ips = 203.0.113.10, 198.51.100.0/24

[ARCHIVE]
archive_dir = /var/www/html/reports
archive_top_n = 50
archive_max_days = 730
archive_events = True
archive_max_events = 20000
```

Do not commit a filled-in `HackedSSH.ini` (it is gitignored). Use `config.ini.template`.

### Nginx on a reverse proxy

Public `odin` / `loki` / `thor` vhosts should not be open to the world. Examples:

- `config_examples/nginx-vhost-log-format.conf` — log `host=$host proxy=$proxy_host`
- `config_examples/nginx-internal-only.conf` — LAN / Tailscale / allowlisted WAN
- `config_examples/nginx-odin.conf` — sample reverse-proxy vhost

Enable `gzip_static` (and `gunzip` if you serve `.json.gz` without uncompressed copies) for `/reports/`.

## Report output

| File | Role |
|------|------|
| `/var/www/html/HackedSSH_Report.html` | Live report (tables + date picker) |
| `/var/www/html/HackedSSH_Map.html` | Folium map for the latest run |
| `/var/www/html/reports/YYYY-MM-DD.json.gz` | Compact daily summary |
| `/var/www/html/reports/YYYY-MM-DD.events.json.gz` | Optional per-line events |
| `/var/www/html/reports/index.json` | Date picker index |

nginx access logs without `host=` show as `(unknown)` until the new log format rotates in.

## Security hardening (optional)

Scripts and sample configs under `scripts/` and `config_examples/` cover Fail2Ban, UFW, auditd, AIDE, RKHunter, ClamAV, Lynis, PAM and a hardened `sshd_config`. Apply SSH changes with a spare session open and `sudo sshd -t` first.

```bash
sudo bash scripts/install_security_tools.sh
sudo bash scripts/setup_ufw_firewall.sh
sudo bash scripts/system_security_audit.sh
```

## Attack detection (summary)

| Event | Severity |
|-------|----------|
| Successful SSH from an unexpected public IP | Critical |
| Successful SSH from LAN / Tailscale / `[TRUSTED]` | Medium (informational) |
| Root login *attempts*, brute force, 403/5xx bursts | High |
| Failed SSH, directory scanning, Lynis warnings | Medium |

Successful logins still appear in the dedicated report section even when they are not critical.

## Project layout

```
Hacked/
├── HackedSSH.py
├── HackedSSH.html
├── HackedSSH.sh
├── HackedSSH.js
├── countries.py
├── config.ini.template
├── config_examples/
├── scripts/
│   ├── backfill_archives.sh
│   ├── install_hackedssh_service.sh
│   ├── install_on_raspberry_pi.sh
│   ├── install_security_tools.sh
│   ├── setup_ufw_firewall.sh
│   └── system_security_audit.sh
└── docs (see below)
```

## Documentation

| File | Contents |
|------|----------|
| [README.md](README.md) | This file |
| [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) | Original enhancement rollout |
| [CHANGES_SUMMARY.md](CHANGES_SUMMARY.md) | What changed in the 2025 security pass |
| [SECURITY_ENHANCEMENT_SESSION.md](SECURITY_ENHANCEMENT_SESSION.md) | Session notes from that pass |
| [RASPBERRY_PI_INSTALL.md](RASPBERRY_PI_INSTALL.md) | Installing on heimdall |
| [TROUBLESHOOTING_DEBIAN12.md](TROUBLESHOOTING_DEBIAN12.md) | `externally-managed-environment` / pip vs apt |
| [HEIMDALL_ABUSEIPDB_SUMMARY.md](HEIMDALL_ABUSEIPDB_SUMMARY.md) | Fail2Ban → AbuseIPDB on heimdall |
| [DASHBOARD_IMPLEMENTATION.md](DASHBOARD_IMPLEMENTATION.md) | Sketch for a live web dashboard (not built) |
| [OSS_SECURITY_TOOLS_COMPARISON.md](OSS_SECURITY_TOOLS_COMPARISON.md) | Wazuh, CrowdSec, Fail2Ban vs this tool |
| [config_examples/BANNER_README.md](config_examples/BANNER_README.md) | SSH banners |
| [config_examples/ABUSEIPDB_VERIFICATION.md](config_examples/ABUSEIPDB_VERIFICATION.md) | AbuseIPDB checks |
| [config_examples/UFW_ABUSEIPDB_SUMMARY.md](config_examples/UFW_ABUSEIPDB_SUMMARY.md) | UFW + AbuseIPDB |

## Troubleshooting

```bash
sudo journalctl -u ssh.service --since today
sudo python3 HackedSSH.py --debug --no-email
sudo journalctl -t HackedSSH
```

Debian 12 pip issues: see [TROUBLESHOOTING_DEBIAN12.md](TROUBLESHOOTING_DEBIAN12.md).

## License

MIT. See [LICENSE](LICENSE).

GeoIP data from MaxMind; maps via Folium / OpenStreetMap; IP reputation links go to AbuseIPDB.

## Disclaimer

For systems you own or are authorised to monitor. Comply with local law on logging and monitoring.
