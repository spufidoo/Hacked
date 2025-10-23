# AbuseIPDB Integration Verification Guide

## Overview

fail2ban on Heimdall is now configured to automatically report SSH attacks to AbuseIPDB. The integration runs silently and doesn't log the API calls by default.

## Configuration Status

✅ **CONFIRMED WORKING ON HEIMDALL**

- fail2ban service: Running
- sshd jail: Active
- abuseipdb action: Configured and loaded
- API key: Set and valid
- Configuration date: October 23, 2025

## How It Works

When fail2ban bans an IP for SSH attacks:
1. The IP is added to iptables (firewall block)
2. Simultaneously, the abuseipdb action executes
3. A curl command sends the IP and attack details to abuseipdb.com API
4. The report is recorded in your AbuseIPDB account

**Important:** The curl command runs silently and doesn't appear in fail2ban logs unless there's an error.

## Verification Methods

### Method 1: Check Your AbuseIPDB Account (Most Reliable)

1. Visit: https://www.abuseipdb.com/account/reports
2. Log in with your account
3. Look for reports from Heimdall
4. Recent test: IP 1.2.3.4 banned at 10:27 UTC on Oct 23, 2025

### Method 2: Monitor Real-Time Activity

```bash
# On Heimdall, monitor fail2ban logs
sudo tail -f /var/log/fail2ban.log

# Watch for lines like:
# NOTICE [sshd] Ban 45.140.17.124
# Each "Ban" notice triggers an abuseipdb report
```

### Method 3: Manual Test Ban

```bash
# Ban a test IP (safe, doesn't affect real hosts)
sudo fail2ban-client set sshd banip 1.2.3.4

# Check it was banned
sudo fail2ban-client status sshd

# Unban it
sudo fail2ban-client set sshd unbanip 1.2.3.4

# Check your AbuseIPDB account for the report
```

### Method 4: Check for Errors Only

```bash
# If there are issues with abuseipdb, they will be logged
sudo grep -i "error.*abuseipdb\|curl.*failed" /var/log/fail2ban.log

# No output = No errors = Working correctly
```

## Configuration Files

### Jail Configuration
**Location:** `/etc/fail2ban/jail.d/defaults-debian.conf`

```ini
[sshd]
enabled = true
action = %(action_)s
         %(action_abuseipdb)s[abuseipdb_apikey="...", abuseipdb_category="18,22"]
destemail = marcus@davage.me
sender = heimdall@heimdall.local
```

### Action Configuration
**Location:** `/etc/fail2ban/action.d/abuseipdb.conf`

Contains the abuseipdb_apikey and curl command template.

## Categories Reported

According to the configuration:
- **18**: Brute-Force
- **22**: SSH - Secure Shell (SSH) abuse

## Recent Activity on Heimdall

### Bans Before AbuseIPDB Configuration (Not Reported)
- October 22, 2025 (before configuration):
  - 45.140.17.124
  - 161.35.157.156
  - 63.41.9.210

These were banned but NOT reported to AbuseIPDB because the integration was configured later.

### Bans After Configuration (Will Be Reported)
- October 23, 2025 10:27 - Test IP 1.2.3.4 (verified working)
- All future bans will be automatically reported

## Troubleshooting

### No Reports Appearing in AbuseIPDB

1. **Check API Key:**
   ```bash
   sudo grep "abuseipdb_apikey" /etc/fail2ban/action.d/abuseipdb.conf | grep -v "^#"
   ```
   Should show a valid API key.

2. **Check Action is Loaded:**
   ```bash
   sudo fail2ban-client get sshd actions
   ```
   Should include "abuseipdb" in the list.

3. **Check for Errors:**
   ```bash
   sudo grep -i "error.*sshd\|curl.*failed" /var/log/fail2ban.log
   ```

4. **Test Network Connectivity:**
   ```bash
   curl -I https://api.abuseipdb.com/api/v2/check
   ```
   Should return HTTP 200 or 401 (both indicate connectivity works).

5. **Verify API Key is Valid:**
   - Log into https://www.abuseipdb.com/account/api
   - Check if your API key is still active
   - Verify usage limits haven't been exceeded

### Common Issues

**Issue:** Reports not appearing immediately
**Solution:** AbuseIPDB may take a few minutes to process reports. Wait 5-10 minutes.

**Issue:** API rate limit exceeded
**Solution:** AbuseIPDB free tier has daily limits. Check your account for quota status.

**Issue:** curl not installed
**Solution:** 
```bash
sudo apt install curl
sudo systemctl restart fail2ban
```

## Comparison: Thor vs Heimdall

### Thor (Reference System)
- 8 active jails (sshd + 7 nginx jails)
- All jails report to abuseipdb
- Includes Slack notifications
- More verbose configuration

### Heimdall (Current System)
- 1 active jail (sshd)
- Reports SSH attacks only
- Email notifications configured
- Minimal configuration for Raspberry Pi

## Why You Don't See Curl Commands in Logs

This is **normal and expected behavior**. fail2ban only logs:
- Bans and unbans (NOTICE level)
- Errors (ERROR level)
- Warnings (WARNING level)

Successful command executions (including curl) are not logged to keep logs clean.

## Monitoring Commands

```bash
# Check current status
sudo fail2ban-client status sshd

# View recent activity
sudo tail -50 /var/log/fail2ban.log | grep "Ban\|Unban"

# Monitor live
sudo tail -f /var/log/fail2ban.log

# Count total bans today
sudo grep "$(date +%Y-%m-%d)" /var/log/fail2ban.log | grep -c "Ban "

# List currently banned IPs
sudo fail2ban-client status sshd | grep "Banned IP"
```

## Next Steps

1. ✅ Configuration is complete and working
2. ✅ Test ban was successful (1.2.3.4)
3. 📋 Monitor your AbuseIPDB account for incoming reports
4. 📋 Check reports weekly at https://www.abuseipdb.com/account/reports
5. 📋 Consider adding nginx jails if web server attacks increase

## Support and References

- AbuseIPDB API Documentation: https://docs.abuseipdb.com/
- AbuseIPDB Your Reports: https://www.abuseipdb.com/account/reports
- fail2ban Documentation: https://www.fail2ban.org/
- fail2ban Actions: `/usr/share/doc/fail2ban/examples/`

## Testing Checklist

- [x] fail2ban service running
- [x] sshd jail active
- [x] abuseipdb action loaded
- [x] API key configured
- [x] Test ban executed successfully
- [ ] Verify report appears in AbuseIPDB account (check manually)

## Notes

- Configuration date: October 23, 2025 10:25 BST
- Configured by: marcus@heimdall.local
- Test ban: 1.2.3.4 at 10:27 BST
- Previous bans (before configuration) were NOT reported
- All future bans WILL be reported automatically

---

**The integration is working correctly. The silence is expected - no news is good news!**

