#!/bin/bash
# ShadoWATCH refresh job: OpenCTI data first, then the dashboard page. Run from cron.
# Adjust INSTALL_DIR and WEB_DIR to your layout.
INSTALL_DIR=/opt/ShadoWATCH
WEB_DIR=/var/www/html/shadowatch

exec 9>/tmp/shadowatch.lock
flock -n 9 || exit 0            # never run two refreshes at once

set -a; . /etc/shadowatch.env; set +a
mkdir -p "$WEB_DIR"
export CTI_OUT="$WEB_DIR/cti.json"

python3 "$INSTALL_DIR/misp_cti.py" || echo "OpenCTI refresh failed (page keeps the last copy)"
python3 "$INSTALL_DIR/misp_ioc_dashboard.py" --geo --out "$WEB_DIR/index.html"
