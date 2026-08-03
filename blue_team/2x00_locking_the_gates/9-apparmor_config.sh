#!/bin/bash

set -euo pipefail

PROFILE="/etc/apparmor.d/opt.meddefense.billing-app"

if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root"
    exit 1
fi


echo "[*] Checking AppArmor status..."

if ! command -v aa-status >/dev/null 2>&1; then
    echo "AppArmor is not installed."
    exit 1
fi

if [[ -d /sys/module/apparmor ]]; then
    echo "    AppArmor module: loaded"
else
    echo "    AppArmor module: not loaded"
    exit 1
fi

if systemctl is-active --quiet apparmor; then
    echo "    AppArmor service: active"
else
    echo "    AppArmor service: inactive"
    exit 1
fi


echo "[*] Profile enforcement:"


switch_profile() {

    local binary="$1"

    if aa-status | grep -A100 "profiles are in complain mode" | grep -q "$binary"; then

        aa-enforce "$binary" >/dev/null

        printf "    %-25s complain -> enforce  [ENFORCED]\n" "$binary"

    elif aa-status | grep -A100 "profiles are in enforce mode" | grep -q "$binary"; then

        printf "    %-25s enforce              [OK]\n" "$binary"

    else

        printf "    %-25s profile not found    [SKIPPED]\n" "$binary"

    fi
}


switch_profile "/usr/sbin/apache2"
switch_profile "/usr/sbin/mysqld"
switch_profile "/usr/sbin/sshd"


cat > "$PROFILE" <<'EOF'
#include <tunables/global>

profile opt.meddefense.billing-app /opt/meddefense/billing-app {

    #include <abstractions/base>

    /opt/meddefense/billing-app rix,

    /opt/meddefense/** rw,

    /etc/meddefense/** r,

    /var/lib/meddefense/** rw,

    /var/log/meddefense/** rw,

    /tmp/** rw,

    deny /** w,

}
EOF

apparmor_parser -r "$PROFILE"

aa-enforce "$PROFILE" >/dev/null 2>&1 || true

echo "[*] Custom profile: /opt/meddefense/billing-app   [CREATED] [ENFORCED]"


echo "[*] Unconfined network-exposed processes:"

UNCONFINED=0

while read -r process; do

    [[ -z "$process" ]] && continue

    printf "    %-25s [UNCONFINED - Profile recommended]\n" "$process"

    UNCONFINED=$((UNCONFINED + 1))

done < <(
    aa-status |
    awk '
        /processes are unconfined/ {flag=1; next}
        /^$/ {flag=0}
        flag {print $1}
    '
)


ENFORCE=$(aa-status | awk '/profiles are in enforce mode/ {print $1}')
COMPLAIN=$(aa-status | awk '/profiles are in complain mode/ {print $1}')

echo
echo "Profiles in enforce: $ENFORCE | Complain: $COMPLAIN | Unconfined: $UNCONFINED"
