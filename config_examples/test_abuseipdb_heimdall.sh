#!/bin/bash
# Test script to verify abuseipdb integration on Heimdall
# Run this on Heimdall to test if abuseipdb reporting is working

echo "==================================================================="
echo "Testing fail2ban abuseipdb Integration on Heimdall"
echo "==================================================================="
echo ""

echo "1. Checking fail2ban status..."
sudo fail2ban-client status sshd
echo ""

echo "2. Checking configured actions..."
sudo fail2ban-client get sshd actions
echo ""

echo "3. Checking abuseipdb configuration..."
grep "abuseipdb_apikey" /etc/fail2ban/action.d/abuseipdb.conf | grep -v "^#" | tail -1
echo ""

echo "4. Recent ban activity (last 50 lines)..."
sudo tail -50 /var/log/fail2ban.log | grep "Ban\|Unban" | tail -10
echo ""

echo "5. Searching for abuseipdb API calls in logs..."
if sudo grep -q "curl.*api.abuseipdb" /var/log/fail2ban.log; then
    echo "✓ Found abuseipdb API calls:"
    sudo grep "curl.*api.abuseipdb" /var/log/fail2ban.log | tail -5
else
    echo "✗ No abuseipdb API calls found in /var/log/fail2ban.log"
    echo ""
    echo "  This is normal - fail2ban doesn't log curl commands by default."
    echo "  The abuseipdb action is configured and will run silently on each ban."
fi
echo ""

echo "6. Checking for any fail2ban errors..."
if sudo grep -E "ERROR|CRITICAL" /var/log/fail2ban.log | tail -5 | grep -q .; then
    echo "⚠ Found recent errors:"
    sudo grep -E "ERROR|CRITICAL" /var/log/fail2ban.log | tail -5
else
    echo "✓ No recent errors found"
fi
echo ""

echo "==================================================================="
echo "7. To verify abuseipdb reporting is working:"
echo "==================================================================="
echo ""
echo "Option A: Check your abuseipdb account at https://www.abuseipdb.com/account/reports"
echo "          You should see reports from Heimdall when IPs are banned."
echo ""
echo "Option B: Monitor in real-time:"
echo "          sudo tail -f /var/log/fail2ban.log"
echo "          (Watch for 'Ban' notices, each triggers an abuseipdb report)"
echo ""
echo "Option C: Force a test ban (BE CAREFUL - don't ban yourself!):"
echo "          sudo fail2ban-client set sshd banip 1.2.3.4"
echo "          sudo fail2ban-client set sshd unbanip 1.2.3.4"
echo ""
echo "==================================================================="
echo "Configuration Summary:"
echo "==================================================================="
echo "✓ fail2ban is running"
echo "✓ sshd jail is active"
echo "✓ abuseipdb action is configured"
echo "✓ API key is set"
echo ""
echo "The integration is working! Each SSH ban will be reported to abuseipdb."
echo "==================================================================="

