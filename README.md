# HackedSSH
SSH Logon Attempts

Welcome to my little "SSH Logon Attempts" project.

The present iteration is a Python program that reads SSH logon attempts from journal logs, and bundles them into a nice little HTML report, with collapsible fields and nice little map.

The program is invoked thus:
    python HackedSSH.py                           -- The default. Process yesterday's logs
    python HackedSSH.py {--from_date [yesterday | '2024-05-16'] --to_date [today | '2024-05-16'] --email to_email_address }

The html report output looks like this:
![image](https://github.com/user-attachments/assets/47e30a0c-79a1-4412-9e10-8bccec5a7a76)
and has collapsible Country and User fields, and a link to abuseipdb for each hostile IP address.
There is also a nice map with IP geo-locations.


## Configuration

To run this project, you need to create a configuration file with your sensitive information.

1. Copy the template file to create your configuration file:

    ```bash
    cp config.ini.template config.ini
    ```

2. Edit the `config.ini` file and fill in your details (email addresses, SMTP credentials, etc.).

3. Ensure the `config.ini` file is not added to version control by verifying it is listed in `.gitignore`.

## Prerequisites
```
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
```
The GeoIP database files must also be present in the same directory as the program.
