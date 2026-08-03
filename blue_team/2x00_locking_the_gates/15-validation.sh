#!/bin/bash

set -euo pipefail

PASS_COUNT=0
FAIL_COUNT=0

if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root"
    exit 1
fi


pass()
{
    echo "[PASS] $1"
    PASS_COUNT=$((PASS_COUNT+1))
}


fail()
{
    echo "[FAIL] $1"
    FAIL_COUNT=$((FAIL_COUNT+1))
}


check_value()
{
    local name="$1"
    local actual="$2"
    local expected="$3"

    if [[ "$actual" == "$expected" ]]; then
        pass "$name = $expected"
    else
        fail "$name = $actual (expected: $expected)"
    fi
}


echo "[*] Validating SSH hardening..."

SSHD="/etc/ssh/sshd_config"


get_sshd_value()
{
    local key="$1"

    grep -E "^[[:space:]]*$key[[:space:]]+" "$SSHD" \
    | tail -1 \
    | awk '{print $2}' \
    || echo "missing"
}


check_value \
"PermitRootLogin" \
"$(get_sshd_value PermitRootLogin)" \
"no"


check_value \
"PasswordAuthentication" \
"$(get_sshd_value PasswordAuthentication)" \
"no"


check_value \
"PermitEmptyPasswords" \
"$(get_sshd_value PermitEmptyPasswords)" \
"no"


check_value \
"X11Forwarding" \
"$(get_sshd_value X11Forwarding)" \
"no"


check_value \
"MaxAuthTries" \
"$(get_sshd_value MaxAuthTries)" \
"3"


check_value \
"ClientAliveInterval" \
"$(get_sshd_value ClientAliveInterval)" \
"300"


check_value \
"ClientAliveCountMax" \
"$(get_sshd_value ClientAliveCountMax)" \
"2"


if grep -Eq "^AllowUsers.*medadmin.*sysadmin" "$SSHD"; then
    pass "AllowUsers = medadmin sysadmin"
else
    fail "AllowUsers missing medadmin sysadmin"
fi


check_value \
"Protocol" \
"$(get_sshd_value Protocol)" \
"2"


check_value \
"LoginGraceTime" \
"$(get_sshd_value LoginGraceTime)" \
"60"


check_value \
"Banner" \
"$(get_sshd_value Banner)" \
"/etc/issue.net"


if sshd -t >/dev/null 2>&1; then
    pass "sshd configuration syntax"
else
    fail "sshd configuration syntax"
fi


if systemctl is-active --quiet ssh; then
    pass "ssh.service = active"
else
    fail "ssh.service inactive"
fi



echo
echo "[*] Validating kernel sysctl hardening..."


check_sysctl()
{
    local key="$1"
    local expected="$2"

    local path="/proc/sys/${key//./\/}"

    if [[ -f "$path" ]]; then

        actual=$(cat "$path")

        check_value "$key" "$actual" "$expected"

    else

        fail "$key unavailable"

    fi
}


check_sysctl net.ipv4.ip_forward 0
check_sysctl net.ipv4.conf.all.accept_redirects 0
check_sysctl net.ipv4.conf.default.accept_redirects 0
check_sysctl net.ipv4.conf.all.send_redirects 0
check_sysctl net.ipv4.conf.all.accept_source_route 0
check_sysctl net.ipv4.conf.all.log_martians 1
check_sysctl net.ipv4.tcp_syncookies 1
check_sysctl net.ipv4.icmp_echo_ignore_broadcasts 1
check_sysctl net.ipv6.conf.all.disable_ipv6 1
check_sysctl net.ipv6.conf.default.disable_ipv6 1
check_sysctl kernel.randomize_va_space 2
check_sysctl fs.suid_dumpable 0
check_sysctl kernel.dmesg_restrict 1
check_sysctl kernel.kptr_restrict 2



echo
echo "[*] Validating filesystem hardening..."


check_mount_options()
{
    local mountpoint="$1"

    if mountpoint -q "$mountpoint"; then

        opts=$(findmnt -no OPTIONS "$mountpoint")

        if [[ "$opts" == *noexec* &&
              "$opts" == *nosuid* &&
              "$opts" == *nodev* ]]; then

            pass "$mountpoint = noexec,nosuid,nodev"

        else

            fail "$mountpoint missing hardening options ($opts)"

        fi

    else

        fail "$mountpoint not mounted"

    fi
}


check_mount_options /tmp
check_mount_options /var/tmp
check_mount_options /dev/shm


if [[ -f /etc/cron.allow ]] &&
   [[ "$(stat -c %a /etc/cron.allow)" == "600" ]] &&
   [[ "$(stat -c %U /etc/cron.allow)" == "root" ]]; then

    pass "/etc/cron.allow = 600 root"

else

    fail "/etc/cron.allow permissions"

fi


if [[ ! -e /etc/cron.deny ]]; then

    pass "/etc/cron.deny removed"

else

    fail "/etc/cron.deny exists"

fi

#############################################
# 6 - Filesystem Hardening Validation
#############################################

echo
echo "[*] Filesystem hardening validation"

check_mount_options() {

    local mountpoint="$1"

    if mountpoint -q "$mountpoint"; then

        OPTIONS=$(findmnt -no OPTIONS "$mountpoint")

        if [[ "$OPTIONS" == *noexec* &&
              "$OPTIONS" == *nosuid* &&
              "$OPTIONS" == *nodev* ]]; then

            pass "$mountpoint mount options"

        else

            fail "$mountpoint mount options" \
            "noexec,nosuid,nodev"

        fi

    else

        fail "$mountpoint mounted" "mounted"

    fi
}


check_mount_options /tmp
check_mount_options /var/tmp
check_mount_options /dev/shm


check_file_permission() {

    local file="$1"
    local expected="$2"

    if [[ -e "$file" ]]; then

        MODE=$(stat -c "%a" "$file")

        if [[ "$MODE" == "$expected" ]]; then

            pass "$file permissions"

        else

            fail "$file permissions" "$expected"

        fi

    fi
}


check_file_permission /etc/cron.allow 600


#############################################
# 7 - Service Minimization Validation
#############################################

echo
echo "[*] Service minimization validation"


REQUIRED_SERVICES=(
"ssh.service"
"apache2.service"
"mysql.service"
"ufw.service"
"auditd.service"
"apparmor.service"
"cron.service"
"rsyslog.service"
"systemd-timesyncd.service"
)


for service in "${REQUIRED_SERVICES[@]}"; do

    if systemctl is-enabled "$service" >/dev/null 2>&1 &&
       systemctl is-active "$service" >/dev/null 2>&1; then

        pass "$service"

    else

        fail "$service" "enabled and active"

    fi

done


#############################################
# 8 - PAM Hardening Validation
#############################################

echo
echo "[*] PAM hardening validation"


PWQUALITY="/etc/security/pwquality.conf"


check_file_setting() {

    local file="$1"
    local pattern="$2"
    local name="$3"

    if grep -Eq "^$pattern" "$file"; then

        pass "$name"

    else

        fail "$name" "$pattern"

    fi

}


check_file_setting \
"$PWQUALITY" \
"minlen[[:space:]]*=[[:space:]]*14" \
"Password minimum length"


check_file_setting \
"$PWQUALITY" \
"dcredit[[:space:]]*=[[:space:]]*-1" \
"Password digit requirement"


check_file_setting \
"$PWQUALITY" \
"ucredit[[:space:]]*=[[:space:]]*-1" \
"Password uppercase requirement"


check_file_setting \
"$PWQUALITY" \
"lcredit[[:space:]]*=[[:space:]]*-1" \
"Password lowercase requirement"


check_file_setting \
"$PWQUALITY" \
"ocredit[[:space:]]*=[[:space:]]*-1" \
"Password special character requirement"


check_file_setting \
"$PWQUALITY" \
"maxrepeat[[:space:]]*=[[:space:]]*3" \
"Password repeat restriction"


if grep -q "reject_username" "$PWQUALITY"; then

    pass "Reject username"

else

    fail "Reject username" "enabled"

fi


if grep -q "deny=5" /etc/pam.d/common-auth &&
   grep -q "unlock_time=900" /etc/pam.d/common-auth &&
   grep -q "fail_interval=900" /etc/pam.d/common-auth; then

    pass "pam_faillock policy"

else

    fail "pam_faillock policy" \
    "deny=5 unlock_time=900 fail_interval=900"

fi


if grep -q "remember=12" /etc/pam.d/common-password; then

    pass "Password history remember=12"

else

    fail "Password history" "remember=12"

fi


#############################################
# 9 - AppArmor Validation
#############################################

echo
echo "[*] AppArmor validation"


if systemctl is-active --quiet apparmor; then

    pass "apparmor.service"

else

    fail "apparmor.service" "active"

fi


if aa-status | grep -q "profiles are in enforce mode"; then

    pass "AppArmor enforce profiles"

else

    fail "AppArmor enforce profiles" "enabled"

fi


if [[ -f /etc/apparmor.d/opt.meddefense.billing-app ]]; then

    pass "MedDefense AppArmor profile"

else

    fail "MedDefense AppArmor profile" "exists"

fi


#############################################
# 10 - Auditd Validation
#############################################

echo
echo "[*] Auditd validation"


if systemctl is-active --quiet auditd; then

    pass "auditd.service"

else

    fail "auditd.service" "active"

fi


if [[ -f /etc/audit/rules.d/meddefense.rules ]]; then

    pass "MedDefense audit rules file"

else

    fail "MedDefense audit rules file" "exists"

fi


AUDIT_RULES=$(auditctl -l | wc -l)


if [[ "$AUDIT_RULES" -ge 14 ]]; then

    pass "Audit rules loaded"

else

    fail "Audit rules loaded" ">=14 rules"

fi

#############################################
# 11 - Audit Coverage Validation
#############################################

echo
echo "[*] Audit coverage validation"


AUDIT_REPORT="audit_validation.json"


if [[ -f "$AUDIT_REPORT" ]]; then

    pass "Audit coverage report exists"

    if jq -e '.missed == 0' "$AUDIT_REPORT" >/dev/null 2>&1; then

        pass "Audit telemetry coverage"

    else

        fail "Audit telemetry coverage" "all tests captured"

    fi

else

    fail "Audit coverage report" "audit_validation.json exists"

fi



#############################################
# 12 - Logging Configuration Validation
#############################################

echo
echo "[*] Log configuration validation"


RSYSLOG_CONF="/etc/rsyslog.d/50-meddefense.conf"
LOGROTATE_CONF="/etc/logrotate.d/meddefense"


if [[ -f "$RSYSLOG_CONF" ]]; then

    pass "rsyslog configuration exists"

else

    fail "rsyslog configuration" "exists"

fi


if grep -q "auth,authpriv" "$RSYSLOG_CONF"; then

    pass "auth log routing"

else

    fail "auth log routing" "auth,authpriv.*"

fi


if grep -q "/var/log/syslog" "$RSYSLOG_CONF"; then

    pass "syslog routing"

else

    fail "syslog routing" "/var/log/syslog"

fi


if [[ -f "$LOGROTATE_CONF" ]]; then

    pass "logrotate policy exists"

else

    fail "logrotate policy" "exists"

fi


if grep -q "rotate 90" "$LOGROTATE_CONF"; then

    pass "auth.log retention 90 days"

else

    fail "auth.log retention" "rotate 90"

fi


if grep -q "rotate 60" "$LOGROTATE_CONF"; then

    pass "syslog retention 60 days"

else

    fail "syslog retention" "rotate 60"

fi



check_log_permission() {

    local logfile="$1"

    if [[ -f "$logfile" ]]; then

        OWNER=$(stat -c "%U:%G" "$logfile")
        MODE=$(stat -c "%a" "$logfile")

        if [[ "$OWNER" == "root:adm" &&
              "$MODE" == "640" ]]; then

            pass "$logfile permissions"

        else

            fail "$logfile permissions" "640 root:adm"

        fi

    else

        fail "$logfile" "exists"

    fi

}


check_log_permission /var/log/auth.log
check_log_permission /var/log/syslog



#############################################
# 13 - Firewall Validation
#############################################

echo
echo "[*] Firewall validation"


if command -v ufw >/dev/null 2>&1; then


    if ufw status | grep -q "Status: active"; then

        pass "UFW status"

    else

        fail "UFW status" "active"

    fi


    DEFAULTS=$(ufw status verbose)


    if grep -q "Default: deny (incoming)" <<<"$DEFAULTS"; then

        pass "Default incoming = deny"

    else

        fail "Default incoming" "deny"

    fi


    if grep -q "Default: allow (outgoing)" <<<"$DEFAULTS"; then

        pass "Default outgoing = allow"

    else

        fail "Default outgoing" "allow"

    fi


    if ufw status | grep -q "80/tcp"; then

        pass "HTTP firewall rule"

    else

        fail "HTTP firewall rule" "80/tcp"

    fi


    if ufw status | grep -q "443/tcp"; then

        pass "HTTPS firewall rule"

    else

        fail "HTTPS firewall rule" "443/tcp"

    fi


    if ufw status | grep -q "3306"; then

        pass "MySQL firewall rule"

    else

        fail "MySQL firewall rule" "3306"

    fi


else

    fail "Firewall tool" "ufw installed"

fi



#############################################
# Final Report
#############################################

echo
echo "==============================="
echo "Validation Summary"
echo "==============================="

echo "Passed: $PASS_COUNT"
echo "Failed: $FAIL_COUNT"


jq -n \
--arg timestamp "$(date --iso-8601=seconds)" \
--argjson passed "$PASS_COUNT" \
--argjson failed "$FAIL_COUNT" \
--argjson results "$RESULTS" \
'
{
    timestamp:$timestamp,
    passed:$passed,
    failed:$failed,
    controls:$results
}
' > validation_report.json


echo
echo "Report saved: validation_report.json"


if [[ "$FAIL_COUNT" -eq 0 ]]; then

    echo "Validation result: PASS"
    exit 0

else

    echo "Validation result: FAIL"
    exit 1

fi
