#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root."
  exit 1
fi

mkdir -p /var/log/samba /var/log/snort /var/log/suricata /var/log/postgresql
touch /var/log/samba/audit.log /var/log/snort/alert /var/log/suricata/eve.json

# Zentyal/Samba AD: enforce dedicated include for audit parameters.
mkdir -p /etc/samba/smb.conf.d
cat > /etc/samba/smb.conf.d/99-vant-audit.conf <<'EOF'
[global]
vfs objects = full_audit
full_audit:prefix = %u|%I|%S
full_audit:success = connect disconnect mkdir rmdir open close read pread write pwrite rename unlink
full_audit:failure = none
full_audit:facility = LOCAL5
full_audit:priority = NOTICE
EOF

if ! grep -q "include = /etc/samba/smb.conf.d/99-vant-audit.conf" /etc/samba/smb.conf; then
  echo "include = /etc/samba/smb.conf.d/99-vant-audit.conf" >> /etc/samba/smb.conf
fi

cat > /etc/rsyslog.d/49-samba-audit.conf <<'EOF'
local5.notice    /var/log/samba/audit.log
& stop
EOF

systemctl restart rsyslog || true
systemctl restart samba-ad-dc || systemctl restart smbd || true

echo "Samba audit pipeline enabled to /var/log/samba/audit.log"
echo "Review README.md before using in production because Zentyal may regenerate Samba config."
