# HackedSSH
SSH Logon Attempts

Welcome to my little "SSH Logon Attempts" project.

The present iteration is a Python program that reads SSH logon attempts from journal logs, and bundles them into a nice little HTML report, with collapsible fields and nice little map.

The program is invoked thus:
    python HackedSSH.py                           -- The default. Process yesterday's logs
    python HackedSSH.py {--from_date [yesterday | '2024-05-16'] --to_date [today | '2024-05-16'] --email to_email_address }

## Configuration

To run this project, you need to create a configuration file with your sensitive information.

1. Copy the template file to create your configuration file:

    ```bash
    cp config.ini.template config.ini
    ```

2. Edit the `config.ini` file and fill in your details (email addresses, SMTP credentials, etc.).

3. Ensure the `config.ini` file is not added to version control by verifying it is listed in `.gitignore`.
