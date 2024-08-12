#!/usr/bin/python
# HackedSSH
import folium
import subprocess
import re
import os
import argparse
import datetime
from collections import defaultdict
from geoip2.database import Reader
from countries import country_names
from jinja2 import Environment, FileSystemLoader
from systemd import journal
import configparser

# Global Variables

config = configparser.ConfigParser()
config.read('config.ini')

sender_email = config['EMAIL']['sender_email']
recipient_email = config['EMAIL']['recipient_email']

hostname = config['WEB']['hostname']
report_url = config['WEB']['report_url']

ROOT             = "."
#ROOT             = "/usr/local/bin"
TOTAL_ATTEMPTS   = 0
HACKER_REPORT    = "/var/www/html/HackedSSH_Report.html"
HACKER_MAP       = "/var/www/html/HackedSSH_Map.html"
HACKER_TEMPLATE  = "HackedSSH.html"
# Path to the GeoLite2 database files
GEO_CITY_PATH    = f"{ROOT}/GeoLite2-City.mmdb"
GEO_COUNTRY_PATH = f"{ROOT}/GeoLite2-Country.mmdb"

# Function to extract ssh logon attempts from the journal
def extract_ssh_attempts(from_date, to_date):
    ssh_attempts = defaultdict(lambda: defaultdict(int))
    TOTAL_ATTEMPTS = 0
    try:
        journal_logs = subprocess.check_output(
            [
                "journalctl",
                "_SYSTEMD_UNIT=ssh.service",
                f"--since={from_date}",
                f"--until={to_date}",
                "--no-pager",
            ]
        ).decode("utf-8")
        for line in journal_logs.splitlines():
            match = re.search(r"Failed password for (?:invalid user )?(\w+) from ([0-9.]+)", line)
            if match:
                userid = match.group(1)
                ip_address = match.group(2)
                ssh_attempts[ip_address][userid] += 1
                TOTAL_ATTEMPTS += 1
            match = re.search(r"Unable to negotiate with ([0-9.]+)", line)
            if match:
                ip_address = match.group(1)
                ssh_attempts[ip_address]["None"] += 1
                TOTAL_ATTEMPTS += 1
    except Exception as e:
        journal.send(message=f"Error reading journal logs: {e}", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="err")
    return ssh_attempts, TOTAL_ATTEMPTS

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
def generate_html_report(ssh_attempts, TOTAL_ATTEMPTS, from_date, to_date):
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
    report_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

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
def send_email(report_url, recipient_email):
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
    parser = argparse.ArgumentParser(
        description="Process SSH logon attempts from journal logs."
    )
    parser.add_argument(
        "--from_date",
        required=False,
        type=str,
        default="yesterday",
        help="Start date for the journal logs (e.g., '2024-05-16').",
    )
    parser.add_argument(
        "--to_date",
        required=False,
        type=str,
        default="today",
        help="End date for the journal logs (e.g., '2024-05-17').",
    )
    parser.add_argument(
        "--email",
        required=False,
        type=str,
        default=recipient_email,
        help="Recipient email address to send the report to.",
    )

    journal.send(message="Starting SSH report generation...", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")

    args = parser.parse_args()
    ssh_attempts, TOTAL_ATTEMPTS = extract_ssh_attempts(args.from_date, args.to_date)
    generate_html_report(ssh_attempts, TOTAL_ATTEMPTS, args.from_date, args.to_date)

    # Email the report link
    # report_url = "http://home.davage.me/HackedSSH_Report.html"
    send_email(report_url, args.email)

    journal.send(message="Report successfully generated and saved.", SYSLOG_IDENTIFIER="HackedSSH", PRIORITY="info")

if __name__ == "__main__":
    main()
