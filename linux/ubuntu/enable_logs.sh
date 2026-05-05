#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

mkdir -p /var/log/snort /var/log/suricata /var/log/postgresql /var/log/samba
touch /var/log/snort/alert /var/log/suricata/eve.json /var/log/samba/audit.log

echo "Base log directories prepared."
echo "Next, apply service-specific config from README.md (Snort/Suricata/PostgreSQL/Samba)."
