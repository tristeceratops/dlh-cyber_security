#!/bin/bash

set -euo pipefail

RULES_FILE="/etc/audit/rules.d/meddefense.rules"

RULE_COUNT=0

if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root"
    exit 1
fi


echo "[*] Checking auditd..."

if ! dpkg -s auditd >/dev/null 2>&1; then
    apt-get update
    apt-get install -y auditd audispd-plugins
fi


systemctl enable auditd >/dev/null
systemctl restart auditd >/dev/null

echo "[*] Enabling auditd service..."

if systemctl is-active --quiet auditd; then
    echo "    auditd.service: active (running)"
else
    echo "Error: auditd failed to start"
    exit 1
fi


echo "[*] Deploying MedDefense audit rules..."


cat > "$RULES_FILE" <<EOF
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/pam.d/ -p wa -k pam_config
-w /etc/ssh/sshd_config -p wa -k sshd_config
-w /usr/bin/sudo -p x -k priv_esc
-w /usr/bin/su -p x -k priv_esc
-w /etc/sudoers -p wa -k sudoers
-w /usr/bin/wget -p x -k suspicious_download
-w /usr/bin/curl -p x -k suspicious_download
-w /usr/bin/nc -p x -k suspicious_netcat
-w /var/lib/mysql/ -p wa -k meddefense_db
-w /etc/apache2/ -p wa -k meddefense_web
-w /etc/init.d/ -p wa -k startup_scripts
EOF


while read -r rule; do
    [[ -z "$rule" ]] && continue
    echo "    $rule  [ADDED]"
    RULE_COUNT=$((RULE_COUNT + 1))
done < "$RULES_FILE"


echo "[*] Loading rules..."

if augenrules --load >/dev/null 2>&1; then
    echo "    augenrules --load: OK"
else
    echo "    augenrules --load: FAILED"
    exit 1
fi


echo "[*] Verifying..."

LOADED_RULES=$(auditctl -l | wc -l)

echo "    auditctl -l: $LOADED_RULES rules loaded"


echo "[*] Test: reading /etc/shadow..."

cat /etc/shadow >/dev/null


sleep 2


EVENTS=$(ausearch -ts recent -k identity 2>/dev/null | grep -c "^type=" || true)

if [[ "$EVENTS" -gt 0 ]]; then
    echo "    ausearch -ts recent -k identity: $EVENTS event found [PASS]"
else
    echo "    ausearch -ts recent -k identity: 0 event found [FAIL]"
fi
