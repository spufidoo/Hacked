# HackedSSH
import os
import re
import folium
import argparse
import subprocess
import configparser
from jinja2 import Environment, FileSystemLoader
from systemd import journal
from datetime import datetime, timedelta
from countries import country_names
from collections import defaultdict
from geoip2.database import Reader

# Global Variables
if os.getlogin() == 'root':
    ROOT = '/usr/local/bin'
else:
    ROOT = '.'

config = configparser.ConfigParser()
config.read(f'{ROOT}/HackedSSH.ini')
sender_email = config['EMAIL']['sender_email']
recipient_email = config['EMAIL']['recipient_email']
hostname = config['WEB']['hostname']
report_url = config['WEB']['report_url']

TOTAL_ATTEMPTS   = 0
HACKER_REPORT    = "/var/www/html/HackedSSH_Report.html"
HACKER_MAP       = "/var/www/html/HackedSSH_Map.html"
HACKER_TEMPLATE  = "HackedSSH.html"
# Path to the GeoLite2 database files
GEO_CITY_PATH    = f"{ROOT}/GeoLite2-City.mmdb"
GEO_COUNTRY_PATH = f"{ROOT}/GeoLite2-Country.mmdb"

# Function to extract various attack attempts from the journal
def extract_attack_attempts(from_date, to_date,debug=False):
    attack_attempts = defaultdict(lambda: defaultdict(int))
    TOTAL_ATTEMPTS = 0
    
    try:
        # Fetch logs from journalctl for multiple services
        journal_logs = subprocess.check_output(
            [
                "journalctl",
                "_SYSTEMD_UNIT=ssh.service", "_SYSTEMD_UNIT=xrdp.service",
                "_SYSTEMD_UNIT=vsftpd.service", "_SYSTEMD_UNIT=apache2.service",
                "_SYSTEMD_UNIT=nginx.service", "_SYSTEMD_UNIT=mysql.service",
                "_SYSTEMD_UNIT=rdp.service", "_SYSTEMD_UNIT=smtp.service",
                "_SYSTEMD_UNIT=openvpn.service", "_SYSTEMD_UNIT=wireshark.service",
                "_SYSTEMD_UNIT=rdc.service", "_SYSTEMD_UNIT=telnet.service",
                "_SYSTEMD_UNIT=sftp.service", f"--since={from_date}", f"--until={to_date}", "--no-pager",
            ]
        ).decode("utf-8")
        
        # Define patterns for different services and set default user id when not available
        patterns = {
            "ssh": (re.compile(r"Failed password for (?:invalid user )?(\w+) from ([0-9.]+)"), None),
            "ssh1": (re.compile(r"Unable to negotiate with ([0-9.]+)"), "None"),
            "ssh2": (re.compile(r"Connection closed by ([0-9.]+)"), "None"),
            "ssh3": (re.compile(r"Connection closed by (?:invalid user ?(\w+)) ([0-9.]+)"), None),
            "ssh4": (re.compile(r"banner exchange: Connection from ([0-9.]+)"), "None"),
            "ssh5": (re.compile(r"Connection reset by ([0-9.]+)"), "None"),
            "root": (re.compile(r"User (\w+) from ([0-9.]+)"), "None"),
            "xrdp": (re.compile(r"xrdp-sesman\[\d+\]: (?:pam_unix\(xrdp-sesman:auth\): authentication failure|Failed to start session for user (\w+)) from ([0-9.]+)"), "None"),
            "xrdp_ipv6": (re.compile(r"::ffff:([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)"), "None"),
            "ftp": (re.compile(r"vsftpd: pam_unix\(vsftpd:auth\): authentication failure;.*rhost=([0-9.]+)"), "None"),
            "apache": (re.compile(r"apache2: (?:Invalid user|Failed login) (\w+) from ([0-9.]+)"), None),
            "nginx": (re.compile(r'nginx.*"GET.*" 401 .* from ([0-9.]+)'), "None"),
            "mysql": (re.compile(r"Access denied for user '(\w+)'@'([0-9.]+)'"), None),
            "smtp": (re.compile(r"postfix/smtpd.*: warning: ([0-9.]+): SASL .* authentication failed"), "None"),
            "openvpn": (re.compile(r"openvpn\[\d+\]: (\w+\/)?(\w+)\/([0-9.]+): (?:AUTH_FAILED|TLS handshake failed)"), None),
            "wireshark": (re.compile(r"wireshark.*Authentication failure from ([0-9.]+)"), "None"),
            "rdc": (re.compile(r"rdc.*: Failed connection attempt from ([0-9.]+)"), "None"),
            "telnet": (re.compile(r"telnetd: .* login failed for (\w+) from ([0-9.]+)"), None),
            "sftp": (re.compile(r"sftp-server\[\d+\]: (\w+): user auth failure from ([0-9.]+)"), None)
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
        journal.send(message=f"Error reading journal logs: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
    
    return attack_attempts, TOTAL_ATTEMPTS

# Function to get country from IP address
def get_country_from_ip(ip_address):
    try:
        reader = Reader(GEO_COUNTRY_PATH)
        response = reader.country(ip_address)
        country = response.country.iso_code
        reader.close()
        return country
    except Exception as e:
        journal.send(message=f"Error getting country from IP: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
        return "Unknown"

# Function to get city and coordinates from IP address
def get_city_and_coords_from_ip(ip_address):
    try:
        reader = Reader(GEO_CITY_PATH)
        response = reader.city(ip_address)
        city = response.city.name
        lat = response.location.latitude
        lon = response.location.longitude
        reader.close()
        return city, lat, lon
    except Exception as e:
        journal.send(message=f"Error getting city and coordinates from IP: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
        return "Unknown", None, None

# Function to get city from IP address
def get_city_from_ip(ip_address):
    try:
        reader = Reader(GEO_CITY_PATH)
        response = reader.city(ip_address)
        city = response.city.name
        reader.close()
        return city
    except Exception as e:
        journal.send(message=f"Error getting city from IP: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
        return "Unknown"

# Function to generate HTML report
def generate_html_report(ssh_attempts, TOTAL_ATTEMPTS, from_date, to_date,debug=False):
    env = Environment(loader=FileSystemLoader(ROOT))
    template = env.get_template(HACKER_TEMPLATE)
    m = folium.Map(location=[0, 0], zoom_start=2)  # Create a map object
    country_attempts = defaultdict(int)
    user_attempts = defaultdict(int)
    city_attempts = defaultdict(int)
    country_details = defaultdict(lambda: defaultdict(lambda: {'city': '', 'users': defaultdict(int)}))

    for ip_address, attempts in ssh_attempts.items():
        country = get_country_from_ip(ip_address)
        country_name = country_names.get(country, "Unknown")
        country_attempts[country_name] += sum(attempts.values())
        city, lat, lon = get_city_and_coords_from_ip(ip_address)
        city_attempts[city] += sum(attempts.values())

        for userid, count in attempts.items():
            user_attempts[userid] += count
            if ip_address not in country_details[country_name] or 'city' not in country_details[country_name][ip_address]:
                country_details[country_name][ip_address]['city'] = city
            country_details[country_name][ip_address]['users'][userid] += count

        if lat is not None and lon is not None:
            folium.Marker([lat, lon], popup=f"City: {city}\nIP Address: {ip_address}").add_to(m)  # Add marker to the map

    m.save(HACKER_MAP)  # Save the map to an HTML file
    journal.send(message=f"Map template {ROOT}/{HACKER_TEMPLATE} saved to {HACKER_MAP}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")

    country_attempts = sorted(country_attempts.items(), key=lambda x: x[1], reverse=True)
    user_attempts = sorted(user_attempts.items(), key=lambda x: x[0])
    report_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_content = template.render(
        TOTAL_ATTEMPTS=TOTAL_ATTEMPTS,
        ip_count=len(ssh_attempts),
        country_count=len(country_attempts),
        city_count=len(city_attempts),
        user_count=len(user_attempts),
        country_attempts=country_attempts,
        user_attempts=user_attempts,
        country_details=country_details,
        report_time=report_time,
        from_date=from_date,
        to_date=to_date
    )

    with open(HACKER_REPORT, "w") as f:
        f.write(html_content)
    journal.send(message=f"Report saved to {HACKER_REPORT}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")

# Function to send an email with the report link using Postfix
def send_email(report_url, recipient_email,debug=False):
    hostname = subprocess.check_output("hostname").decode("utf-8").strip()

    # Create email headers and body
    body           = f"Please find the {hostname} SSH logon attempts report at the following link: {report_url}"
    subject        = f"{hostname} SSH Logon Attempts Report"
    #sender_email   = f"{hostname} <{hostname}@{server}>"
    
    email_content  = f"From: {sender_email}\n"
    email_content += f"To: {recipient_email}\n"
    email_content += f"Subject: {subject}\n\n"
    email_content += body

    try:
        # Run the sendmail command
        process = subprocess.Popen(
            ["/usr/sbin/sendmail", "-t", "-oi"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Capture the stdout and stderr
        stdout, stderr = process.communicate(email_content.encode('utf-8'))

        # Check if sendmail command was successful
        if process.returncode == 0:
            journal.send(message=f"Email sent to {recipient_email}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")
        else:
            # Log the error details if the command failed
            journal.send(message=f"Failed to send email to {recipient_email}. Error: {stderr.decode('utf-8')}",
                         SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
    except Exception as e:
        # Log any exceptions that occur
        journal.send(message=f"Exception occurred while sending email: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")

# Main function
def main():
    journal.send(message=f"Started SSH report generation by {os.getlogin()}...", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")

    parser = argparse.ArgumentParser(description="Process SSH logon attempts from journal logs.")
    parser.add_argument("--from_date",required=False,type=str,default=datetime.now().date() - timedelta(days=1),help="Start date for the journal logs (e.g., '2024-05-16').")
    parser.add_argument("--to_date",required=False,type=str,default=datetime.now().date(),help="End date for the journal logs (e.g., '2024-05-17').")
    parser.add_argument("--email",required=False,type=str,default=recipient_email,help="Recipient email address to send the report to.")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode for more verbose output")

    args = parser.parse_args()
    
    attack_attempts, TOTAL_ATTEMPTS = extract_attack_attempts(args.from_date, args.to_date,debug=args.debug)
    generate_html_report(attack_attempts, TOTAL_ATTEMPTS, args.from_date, args.to_date,debug=args.debug)

    # Email the report link
    send_email(report_url, args.email,debug=args.debug)

    journal.send(message="Report successfully generated and saved.", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")

if __name__ == "__main__":
    main()
