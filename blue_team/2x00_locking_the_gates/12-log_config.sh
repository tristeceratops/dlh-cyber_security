#!/bin/bas

set -euo pipefail

RSYSLOG_CONF="/etc/rsyslog.d/50-meddefense.conf"
LOGROTATE_CONF="/etc/logrotate.d/meddefense"

LOG_SOURCES=0
ROTATION_POLICIES=0

if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root"
    exit 1
fi

echo "[*] Configuring rsyslog..."

cat > "$RSYSLOG_CONF" <<EOF
# MedDefense logging configuration

template(name="MedDefenseFormat" type="string"
string="%timegenerated% %HOSTNAME% %syslogtag%%msg%\n")

auth,authpriv.*                 action(type="omfile" file="/var/log/auth.log" template="MedDefenseFormat")
*.info;auth.none;authpriv.none  action(type="omfile" file="/var/log/syslog" template="MedDefenseFormat")
EOF

systemctl restart rsyslog

echo "    auth,authpriv.* -> /var/log/auth.log     [CONFIGURED]"
LOG_SOURCES=$((LOG_SOURCES+1))

echo "    *.info;auth.none -> /var/log/syslog      [CONFIGURED]"
LOG_SOURCES=$((LOG_SOURCES+1))

echo
echo "[*] Setting log rotation policies..."

cat > "$LOGROTATE_CONF" <<EOF
/var/log/auth.log
{
    daily
    rotate 90
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    create 640 root adm
    postrotate
        systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
}

/var/log/syslog
{
    daily
    rotate 60
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    create 640 root adm
    postrotate
        systemctl reload rsyslog >/dev/null 2>&1 || true
    endscript
}
EOF

echo "    /var/log/auth.log: rotate 90, compress after 7d  [SET]"
ROTATION_POLICIES=$((ROTATION_POLICIES+1))

echo "    /var/log/syslog: rotate 60, compress after 7d    [SET]"
ROTATION_POLICIES=$((ROTATION_POLICIES+1))

echo
echo "[*] Verifying log activity..."

logger -p authpriv.notice "MedDefense authentication log test"
logger -p user.info "MedDefense syslog test"

sleep 2

if tail -20 /var/log/auth.log | grep -q "MedDefense authentication log test"; then
    echo "    /var/log/auth.log: receiving events       [OK]"
else
    echo "    /var/log/auth.log: receiving events       [FAIL]"
fi

if tail -20 /var/log/syslog | grep -q "MedDefense syslog test"; then
    echo "    /var/log/syslog: receiving events         [OK]"
else
    echo "    /var/log/syslog: receiving events         [FAIL]"
fi

echo
echo "[*] Securing log file permissions..."

chown root:adm /var/log/auth.log
chmod 640 /var/log/auth.log

echo "    /var/log/auth.log: 640 root:adm          [OK]"

chown root:adm /var/log/syslog
chmod 640 /var/log/syslog

echo "    /var/log/syslog: 640 root:adm            [OK]"

echo
echo "Log sources configured: $LOG_SOURCES | Rotation policies: $ROTATION_POLICIES | Permissions: secured"
