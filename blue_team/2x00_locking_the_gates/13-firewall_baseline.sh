#!/bin/bash

set -euo pipefail

MANAGEMENT_NET="10.10.1.0/24"
APPLICATION_NET="10.10.2.0/24"

RULES=0

if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root"
    exit 1
fi

echo "[*] Configuring UFW..."

if ! dpkg -s ufw >/dev/null 2>&1; then
    apt-get update
    apt-get install -y ufw
fi

ufw --force reset >/dev/null

ufw default deny incoming >/dev/null
ufw default allow outgoing >/dev/null

echo "    Default incoming: deny"
echo "    Default outgoing: allow"

echo
echo "[*] Adding allow rules..."

ufw allow from "$MANAGEMENT_NET" to any port 22 proto tcp >/dev/null
echo "    22/tcp from $MANAGEMENT_NET   [ADDED] SSH - management only"
RULES=$((RULES+1))

ufw allow 80/tcp >/dev/null
echo "    80/tcp                     [ADDED] HTTP"
RULES=$((RULES+1))

ufw allow 443/tcp >/dev/null
echo "    443/tcp                    [ADDED] HTTPS"
RULES=$((RULES+1))

ufw allow from "$APPLICATION_NET" to any port 3306 proto tcp >/dev/null
echo "    3306/tcp from $APPLICATION_NET [ADDED] MySQL - app network only"
RULES=$((RULES+1))

echo
echo "[*] Enabling logging..."

ufw logging low >/dev/null

echo "    Logging: on (low)"

echo
echo "[*] Activating firewall..."

ufw --force enable >/dev/null

if ufw status | grep -q "Status: active"; then
    echo "    UFW: active"
else
    echo "    UFW: inactive"
    exit 1
fi

echo "    Rules: $RULES allow, default deny"

echo
echo "[*] Active firewall rules:"
ufw status numbered
