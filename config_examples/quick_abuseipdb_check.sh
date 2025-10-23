#!/bin/bash
# Quick check script for abuseipdb integration on Heimdall
# This will show if abuseipdb API is being called

echo "Creating a test ban with verbose logging..."
echo ""

# Run tcpdump in background to capture API calls
echo "Monitoring network traffic for api.abuseipdb.com..."
sudo timeout 5 tcpdump -i any -n host api.abuseipdb.com 2>/dev/null &
TCPDUMP_PID=$!

sleep 1

# Trigger a test ban
echo "Banning test IP 1.2.3.4..."
sudo fail2ban-client set sshd banip 1.2.3.4 > /dev/null 2>&1

# Wait for action to complete
sleep 2

# Unban
echo "Unbanning test IP 1.2.3.4..."
sudo fail2ban-client set sshd unbanip 1.2.3.4 > /dev/null 2>&1

# Wait for tcpdump to finish
wait $TCPDUMP_PID 2>/dev/null

echo ""
echo "If you saw packets to/from api.abuseipdb.com, the integration is working!"
echo ""
echo "To confirm, check your AbuseIPDB account:"
echo "https://www.abuseipdb.com/account/reports"
echo ""
echo "Look for a report of IP 1.2.3.4 from Heimdall."

