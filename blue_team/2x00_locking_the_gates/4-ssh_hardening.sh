#!/bin/bash

set -euo pipefail


SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.bak"
BANNER="/etc/issue.net"

SETTINGS_APPLIED=0


if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root"
    exit 1
fi


if [[ ! -f "$SSHD_CONFIG" ]]; then
    echo "Error: $SSHD_CONFIG not found"
    exit 1
fi


echo "[*] Backing up $SSHD_CONFIG"

cp "$SSHD_CONFIG" "$BACKUP"


echo "[*] Applying SSH hardening settings..."


# Disable direct root login - addresses privilege escalation and stolen credential abuse
sed -i '/^[#]*PermitRootLogin/d' "$SSHD_CONFIG"
echo "PermitRootLogin no" >> "$SSHD_CONFIG"
echo "    PermitRootLogin no"
SETTINGS_APPLIED=$((SETTINGS_APPLIED+1))


# Disable password authentication - addresses brute force attacks and password compromise
sed -i '/^[#]*PasswordAuthentication/d' "$SSHD_CONFIG"
echo "PasswordAuthentication no" >> "$SSHD_CONFIG"
echo "    PasswordAuthentication no"
SETTINGS_APPLIED=$((SETTINGS_APPLIED+1))


# Prevent empty passwords - addresses unauthorized account access
sed -i '/^[#]*PermitEmptyPasswords/d' "$SSHD_CONFIG"
echo "PermitEmptyPasswords no" >> "$SSHD_CONFIG"
echo "    PermitEmptyPasswords no"
SETTINGS_APPLIED=$((SETTINGS_APPLIED+1))


# Disable X11 forwarding - addresses unnecessary SSH attack surface
sed -i '/^[#]*X11Forwarding/d' "$SSHD_CONFIG"
echo "X11Forwarding no" >> "$SSHD_CONFIG"
echo "    X11Forwarding no"
SETTINGS_APPLIED=$((SETTINGS_APPLIED+1))


# Limit authentication attempts - addresses SSH brute force attacks
sed -i '/^[#]*MaxAuthTries/d' "$SSHD_CONFIG"
echo "MaxAuthTries 3" >> "$SSHD_CONFIG"
echo "    MaxAuthTries 3"
SETTINGS_APPLIED=$((SETTINGS_APPLIED+1))


# Configure idle timeout - addresses abandoned SSH sessions and session hijacking
sed -i '/^[#]*ClientAliveInterval/d' "$SSHD_CONFIG"
echo "ClientAliveInterval 300" >> "$SSHD_CONFIG"
echo "    ClientAliveInterval 300"
SETTINGS_APPLIED=$((SETTINGS_APPLIED+1))


# Limit inactive sessions - addresses persistent unauthorized sessions
sed -i '/^[#]*ClientAliveCountMax/d' "$SSHD_CONFIG"
echo "ClientAliveCountMax 2" >> "$SSHD_CONFIG"
echo "    ClientAliveCountMax 2"
SETTINGS_APPLIED=$((SETTINGS_APPLIED+1))


# Restrict SSH access - addresses unauthorized administrator access
sed -i '/^[#]*AllowUsers/d' "$SSHD_CONFIG"
echo "AllowUsers medadmin sysadmin" >> "$SSHD_CONFIG"
echo "    AllowUsers medadmin sysadmin"
SETTINGS_APPLIED=$((SETTINGS_APPLIED+1))


# Force SSH protocol version 2 - addresses legacy SSH protocol vulnerabilities
sed -i '/^[#]*Protocol/d' "$SSHD_CONFIG"
echo "Protocol 2" >> "$SSHD_CONFIG"
echo "    Protocol 2"
SETTINGS_APPLIED=$((SETTINGS_APPLIED+1))


# Reduce login grace period - addresses brute force and connection exhaustion
sed -i '/^[#]*LoginGraceTime/d' "$SSHD_CONFIG"
echo "LoginGraceTime 60" >> "$SSHD_CONFIG"
echo "    LoginGraceTime 60"
SETTINGS_APPLIED=$((SETTINGS_APPLIED+1))


# Configure SSH banner - addresses unauthorized access warning requirements
sed -i '/^[#]*Banner/d' "$SSHD_CONFIG"
echo "Banner /etc/issue.net" >> "$SSHD_CONFIG"
echo "    Banner /etc/issue.net"
SETTINGS_APPLIED=$((SETTINGS_APPLIED+1))



echo "[*] Creating SSH banner file..."


cat > "$BANNER" <<EOF
******************************************************************
* WARNING: Authorized access only                                  *
* All SSH activity may be monitored and recorded.                 *
* Unauthorized access is prohibited and may be prosecuted.         *
******************************************************************
EOF



echo "[*] Validating SSH configuration..."


if sshd -t; then

    echo "    sshd -t: OK"

else

    echo "    sshd -t: FAILED"
    echo "[!] restore backup configuration"

    cp "$BACKUP" "$SSHD_CONFIG"

    exit 1

fi



echo "[*] Restarting SSH service..."


systemctl restart ssh


if systemctl is-active --quiet ssh; then

    echo "    ssh.service: active (running)"

else

    echo "[!] SSH service failed after restart"
    echo "[!] Restoring backup"

    cp "$BACKUP" "$SSHD_CONFIG"

    systemctl restart ssh

    exit 1

fi


echo "Settings applied: $SETTINGS_APPLIED"
