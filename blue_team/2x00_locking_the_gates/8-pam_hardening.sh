#!/bin/bash

set -euo pipefail

PWQUALITY_CONF="/etc/security/pwquality.conf"
COMMON_AUTH="/etc/pam.d/common-auth"
COMMON_PASSWORD="/etc/pam.d/common-password"

if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root"
    exit 1
fi


echo "[*] Checking libpam-pwquality..."

if dpkg -s libpam-pwquality >/dev/null 2>&1; then

    VERSION=$(dpkg-query -W -f='${Version}' libpam-pwquality)
    echo "    Already installed: libpam-pwquality $VERSION"

else

    apt-get update
    apt-get install -y libpam-pwquality

    VERSION=$(dpkg-query -W -f='${Version}' libpam-pwquality)
    echo "    Installed: libpam-pwquality $VERSION"

fi


echo "[*] Configuring password quality ($PWQUALITY_CONF)..."

sed -i '/^minlen/d' "$PWQUALITY_CONF"
echo "minlen = 14" >> "$PWQUALITY_CONF"
echo "    minlen = 14                      [SET]"

sed -i '/^dcredit/d' "$PWQUALITY_CONF"
echo "dcredit = -1" >> "$PWQUALITY_CONF"
echo "    dcredit = -1                     [SET]"

sed -i '/^ucredit/d' "$PWQUALITY_CONF"
echo "ucredit = -1" >> "$PWQUALITY_CONF"
echo "    ucredit = -1                     [SET]"

sed -i '/^lcredit/d' "$PWQUALITY_CONF"
echo "lcredit = -1" >> "$PWQUALITY_CONF"
echo "    lcredit = -1                     [SET]"

sed -i '/^ocredit/d' "$PWQUALITY_CONF"
echo "ocredit = -1" >> "$PWQUALITY_CONF"
echo "    ocredit = -1                     [SET]"

sed -i '/^maxrepeat/d' "$PWQUALITY_CONF"
echo "maxrepeat = 3" >> "$PWQUALITY_CONF"
echo "    maxrepeat = 3                    [SET]"

sed -i '/^reject_username/d' "$PWQUALITY_CONF"
echo "reject_username" >> "$PWQUALITY_CONF"
echo "    reject_username                  [SET]"


echo "[*] Configuring account lockout (pam_faillock)..."

sed -i '/pam_faillock.so/d' "$COMMON_AUTH"

sed -i '1iauth required pam_faillock.so preauth silent deny=5 unlock_time=900 fail_interval=900' "$COMMON_AUTH"

echo 'auth [default=die] pam_faillock.so authfail deny=5 unlock_time=900 fail_interval=900' >> "$COMMON_AUTH"

echo 'account required pam_faillock.so' >> "$COMMON_AUTH"

echo "    deny = 5                         [SET]"
echo "    unlock_time = 900                [SET]"
echo "    fail_interval = 900              [SET]"


echo "[*] Configuring password history..."

sed -i '/pam_pwhistory.so/d' "$COMMON_PASSWORD"

sed -i '/pam_unix.so/ s/$/ remember=12/' "$COMMON_PASSWORD"

echo "password required pam_pwhistory.so remember=12 use_authtok" >> "$COMMON_PASSWORD"

echo "    remember = 12                    [SET]"


grep -q '^minlen = 14' "$PWQUALITY_CONF"
grep -q '^dcredit = -1' "$PWQUALITY_CONF"
grep -q '^ucredit = -1' "$PWQUALITY_CONF"
grep -q '^lcredit = -1' "$PWQUALITY_CONF"
grep -q '^ocredit = -1' "$PWQUALITY_CONF"
grep -q '^maxrepeat = 3' "$PWQUALITY_CONF"
grep -q '^reject_username' "$PWQUALITY_CONF"

grep -q 'deny=5' "$COMMON_AUTH"
grep -q 'unlock_time=900' "$COMMON_AUTH"
grep -q 'fail_interval=900' "$COMMON_AUTH"

grep -q 'remember=12' "$COMMON_PASSWORD"


echo
echo "Password minimum length: 14 | Lockout: 5 attempts / 15 min | History: 12"
