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



set_sshd_option() {

    local option="$1"
    local value="$2"
    local comment="$3"


    # Remove existing active or commented configuration line
    sed -i -E "/^[# ]*${option}[[:space:]]+/d" "$SSHD_CONFIG"


    echo "" >> "$SSHD_CONFIG"
    echo "# $comment" >> "$SSHD_CONFIG"
    echo "${option} ${value}" >> "$SSHD_CONFIG"


    echo "    ${option} ${value}"


    SETTINGS_APPLIED=$((SETTINGS_APPLIED + 1))
}



# Disable direct root login - addresses privilege escalation and credential compromise threats
set_sshd_option \
"PermitRootLogin" \
"no" \
"Disable direct root login - addresses unauthorized privilege escalation and stolen root credential abuse"



# Disable SSH password authentication - addresses brute force attacks and password theft
set_sshd_option \
"PasswordAuthentication" \
"no" \
"Disable SSH password authentication - addresses brute force attacks and compromised password usage"



# Prevent empty passwords - addresses unauthorized account access vulnerabilities
set_sshd_option \
"PermitEmptyPasswords" \
"no" \
"Prevent empty passwords - addresses weak authentication and unauthorized access"



# Disable X11 forwarding - addresses SSH session attack surface expansion
set_sshd_option \
"X11Forwarding" \
"no" \
"Disable X11 forwarding - addresses unnecessary remote session attack surface"



# Limit authentication attempts - addresses SSH brute force attacks
set_sshd_option \
"MaxAuthTries" \
"3" \
"Limit authentication attempts - addresses SSH brute force and credential guessing attacks"



# Configure idle timeout - addresses abandoned SSH sessions and session hijacking risks
set_sshd_option \
"ClientAliveInterval" \
"300" \
"Set SSH idle timeout interval - addresses abandoned sessions and session hijacking"



# Configure idle timeout maximum count - addresses persistent inactive sessions
set_sshd_option \
"ClientAliveCountMax" \
"2" \
"Limit inactive SSH sessions - addresses unauthorized session persistence"



# Restrict SSH access - addresses unauthorized administrator access attempts
set_sshd_option \
"AllowUsers" \
"medadmin sysadmin" \
"Restrict SSH users - addresses unauthorized account access"



# Force SSH protocol version 2 - addresses legacy SSH protocol vulnerabilities
set_sshd_option \
"Protocol" \
"2" \
"Force SSH protocol version 2 - addresses insecure legacy SSH protocol usage"



# Reduce login window - addresses brute force timing and resource exhaustion attacks
set_sshd_option \
"LoginGraceTime" \
"60" \
"Reduce login grace period - addresses SSH brute force and connection exhaustion"



# Configure security banner - addresses unauthorized access deterrence requirements
set_sshd_option \
"Banner" \
"$BANNER" \
"Configure SSH warning banner - addresses unauthorized access and legal compliance requirements"



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
    echo "[!] Restoring backup configuration"

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
