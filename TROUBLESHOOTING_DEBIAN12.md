# Troubleshooting: Debian 12 (Bookworm) Python Package Installation

## The Problem

If you see this error:
```
error: externally-managed-environment

× This environment is externally managed
╰─> To install Python packages system-wide, try apt install
    python3-xyz, where xyz is the package you are trying to
    install.
```

This is a **new security feature** in Debian 12 (Bookworm) and Python 3.11+ that prevents direct pip installations to the system Python to avoid conflicts.

---

## Solution Options

### ✅ Option 1: Use the Fixed Installation Script (Recommended)

The `install_on_raspberry_pi.sh` script has been updated to handle this automatically:

```bash
cd ~/Hacked
sudo bash scripts/install_on_raspberry_pi.sh
```

The script now:
1. Installs packages via `apt` first (preferred)
2. Uses `--break-system-packages` for remaining packages (safe for system services)

---

### ✅ Option 2: Manual Installation with --break-system-packages

For HackedSSH (a system service), it's safe to use `--break-system-packages`:

```bash
# Install via apt first (preferred)
sudo apt install python3-jinja2 python3-systemd -y

# Install remaining packages
sudo pip3 install --break-system-packages folium geoip2 configparser
```

**Why this is safe for HackedSSH:**
- HackedSSH is a system service, not a development environment
- The packages don't conflict with system packages
- You control when the system updates
- It's a dedicated Raspberry Pi for this purpose

---

### ✅ Option 3: Install via APT (Most Stable)

Check if packages are available via apt:

```bash
# Available via apt:
sudo apt install python3-jinja2      # jinja2
sudo apt install python3-systemd     # systemd-python

# Check what's available:
apt search python3-folium
apt search python3-geoip2

# If available, install them:
sudo apt install python3-folium python3-geoip2 -y
```

Note: Not all packages may be available in Debian repos.

---

### ⚙️ Option 4: Virtual Environment (Development)

For development or if you want complete isolation:

```bash
# Create virtual environment
python3 -m venv ~/hackedssh-venv

# Activate it
source ~/hackedssh-venv/bin/activate

# Install packages
pip install folium geoip2 jinja2 systemd-python configparser

# Modify service file to use venv
sudo nano /etc/systemd/system/hackedssh.service
```

Change:
```ini
ExecStart=/usr/bin/python3 /usr/local/bin/HackedSSH.py
```

To:
```ini
ExecStart=/home/pi/hackedssh-venv/bin/python3 /usr/local/bin/HackedSSH.py
```

Then reload:
```bash
sudo systemctl daemon-reload
sudo systemctl restart hackedssh.service
```

---

## Quick Fix for Current Installation

If you're in the middle of installation and hit this error:

```bash
# Just run this command:
sudo pip3 install --break-system-packages folium geoip2 jinja2 systemd-python configparser

# Then continue with the installation
```

---

## Verify Installation

Check if packages are installed:

```bash
python3 -c "import folium; print('folium OK')"
python3 -c "import geoip2; print('geoip2 OK')"
python3 -c "import jinja2; print('jinja2 OK')"
python3 -c "from systemd import journal; print('systemd OK')"
python3 -c "import configparser; print('configparser OK')"
```

All should print "OK" without errors.

---

## Why Does This Exist?

Debian 12 introduced [PEP 668](https://peps.python.org/pep-0668/) to prevent:
- Conflicts between pip and apt-managed packages
- Breaking system tools that depend on Python
- Accidental system-wide package pollution

**For production systems like HackedSSH on dedicated Raspberry Pi, using `--break-system-packages` is acceptable.**

---

## What If I Already Broke Something?

If you installed packages and things broke:

```bash
# Remove pip-installed packages
sudo pip3 uninstall folium geoip2 jinja2 systemd-python configparser

# Reinstall via apt where possible
sudo apt install --reinstall python3-jinja2 python3-systemd

# Then reinstall correctly
sudo pip3 install --break-system-packages folium geoip2 configparser
```

---

## For Other Python Projects

If you're developing Python projects on the Pi, always use virtual environments:

```bash
# Create project venv
python3 -m venv myproject-venv

# Activate
source myproject-venv/bin/activate

# Install packages
pip install whatever-you-need

# Deactivate when done
deactivate
```

This keeps your projects isolated and doesn't affect the system.

---

## References

- [PEP 668 - Marking Python base environments as "externally managed"](https://peps.python.org/pep-0668/)
- [Debian Python Policy](https://wiki.debian.org/Python)
- [Python venv documentation](https://docs.python.org/3/library/venv.html)

---

## Quick Commands Cheat Sheet

```bash
# Check Python version
python3 --version

# Check if package is installed
python3 -c "import PACKAGE_NAME"

# List pip packages
pip3 list

# Install with break-system-packages
sudo pip3 install --break-system-packages PACKAGE_NAME

# Install via apt (preferred)
sudo apt install python3-PACKAGE_NAME

# Check what apt packages are available
apt search python3- | grep PACKAGE_NAME

# Create virtual environment
python3 -m venv ~/venv_name

# Activate venv
source ~/venv_name/bin/activate
```

---

**For HackedSSH on Heimdall, the updated install script handles this automatically! Just run it again.** 🍓✅

