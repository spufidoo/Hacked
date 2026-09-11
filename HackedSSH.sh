#!/bin/bash
# Run HackedSSH from the directory this script lives in, so config, template and
# GeoLite2 databases are resolved relative to the install/checkout regardless of
# the caller's working directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "$(pwd) ${BASH_SOURCE[0]}"

# Pass through any args (e.g. --no-email, --debug, --from_date ...).
exec /usr/bin/python3 ./HackedSSH.py "$@"
