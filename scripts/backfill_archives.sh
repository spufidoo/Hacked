#!/bin/bash
# Backfill daily HackedSSH JSON archives from whatever logs still exist.
#
# nginx access logs are kept for 14 days (logrotate), so web data only exists
# for that window. journald usually reaches back much further, so SSH and UFW
# events can be recovered for many more days. Days outside a source's retention
# simply come back empty.
#
# Usage:
#   sudo ./backfill_archives.sh              # from oldest journal entry to yesterday
#   sudo ./backfill_archives.sh 30           # last 30 days
#   sudo ./backfill_archives.sh 2026-06-01   # from an explicit start date
set -uo pipefail

HACKED=${HACKED:-/usr/local/bin/HackedSSH.py}

if [ "$EUID" -ne 0 ]; then
    echo "ERROR: must run as root (journald and /var/log/nginx need privileges)" >&2
    exit 1
fi

oldest_journal_date() {
    journalctl -o short-iso --no-pager 2>/dev/null | head -1 | cut -c1-10
}

arg=${1:-}
if [ -z "$arg" ]; then
    START=$(oldest_journal_date)
elif [[ "$arg" =~ ^[0-9]+$ ]]; then
    START=$(date -d "$arg days ago" +%F)
else
    START=$arg
fi

if [ -z "${START:-}" ]; then
    echo "ERROR: could not determine a start date" >&2
    exit 1
fi

END=$(date -d yesterday +%F)
TOTAL=$(( ($(date -d "$END" +%s) - $(date -d "$START" +%s)) / 86400 + 1 ))

if [ "$TOTAL" -le 0 ]; then
    echo "Nothing to do: start $START is after end $END"
    exit 0
fi

echo "Backfilling $TOTAL day(s): $START .. $END"
start_ts=$(date +%s)
day=$START
n=0
while [ "$(date -d "$day" +%s)" -le "$(date -d "$END" +%s)" ]; do
    n=$((n + 1))
    printf '[%d/%d] %s ' "$n" "$TOTAL" "$day"
    if python3 "$HACKED" --archive-only --from_date "$day" --to_date "$day" >/dev/null 2>&1; then
        echo "ok"
    else
        echo "FAILED"
    fi
    day=$(date -d "$day + 1 day" +%F)
done

echo "Done in $(( $(date +%s) - start_ts ))s. Archives:"
du -sh "$(python3 - <<'PY'
import configparser, os
for root in ('/usr/local/etc', '/usr/local/bin', '.'):
    p = os.path.join(root, 'HackedSSH.ini')
    if os.path.exists(p):
        c = configparser.ConfigParser(); c.read(p)
        print(c.get('ARCHIVE', 'archive_dir', fallback='/var/www/html/reports')); break
else:
    print('/var/www/html/reports')
PY
)"
