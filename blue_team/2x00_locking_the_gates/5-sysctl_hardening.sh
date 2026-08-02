#!/bin/bash

set -euo pipefail

SYSCTL_CONF="/etc/sysctl.conf"
BACKUP="/etc/sysctl.conf.bak"

PARAMETERS_APPLIED=0
PASS_COUNT=0
FAIL_COUNT=0

if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root"
    exit 1
fi

if [[ ! -f "$SYSCTL_CONF" ]]; then
    echo "Error: $SYSCTL_CONF not found"
    exit 1
fi

echo "[*] Backing up $SYSCTL_CONF"

cp "$SYSCTL_CONF" "$BACKUP"

echo "[*] Applying kernel hardening parameters..."

# Disable IPv4 forwarding - prevents packet forwarding/routing abuse
sed -i '/^net\.ipv4\.ip_forward/d' "$SYSCTL_CONF"
echo "net.ipv4.ip_forward = 0" >> "$SYSCTL_CONF"

# Disable ICMP redirects - mitigates MITM attacks
sed -i '/^net\.ipv4\.conf\.all\.accept_redirects/d' "$SYSCTL_CONF"
echo "net.ipv4.conf.all.accept_redirects = 0" >> "$SYSCTL_CONF"

# Disable ICMP redirects on new interfaces - mitigates MITM attacks
sed -i '/^net\.ipv4\.conf\.default\.accept_redirects/d' "$SYSCTL_CONF"
echo "net.ipv4.conf.default.accept_redirects = 0" >> "$SYSCTL_CONF"

# Disable sending ICMP redirects - prevents route manipulation
sed -i '/^net\.ipv4\.conf\.all\.send_redirects/d' "$SYSCTL_CONF"
echo "net.ipv4.conf.all.send_redirects = 0" >> "$SYSCTL_CONF"

# Disable source routed packets - prevents spoofing attacks
sed -i '/^net\.ipv4\.conf\.all\.accept_source_route/d' "$SYSCTL_CONF"
echo "net.ipv4.conf.all.accept_source_route = 0" >> "$SYSCTL_CONF"

# Log suspicious packets - improves attack detection
sed -i '/^net\.ipv4\.conf\.all\.log_martians/d' "$SYSCTL_CONF"
echo "net.ipv4.conf.all.log_martians = 1" >> "$SYSCTL_CONF"

# Enable SYN cookies - mitigates SYN flood attacks
sed -i '/^net\.ipv4\.tcp_syncookies/d' "$SYSCTL_CONF"
echo "net.ipv4.tcp_syncookies = 1" >> "$SYSCTL_CONF"

# Ignore broadcast ICMP requests - mitigates Smurf attacks
sed -i '/^net\.ipv4\.icmp_echo_ignore_broadcasts/d' "$SYSCTL_CONF"
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> "$SYSCTL_CONF"

# Disable IPv6
sed -i '/^net\.ipv6\.conf\.all\.disable_ipv6/d' "$SYSCTL_CONF"
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> "$SYSCTL_CONF"

# Disable IPv6 by default
sed -i '/^net\.ipv6\.conf\.default\.disable_ipv6/d' "$SYSCTL_CONF"
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> "$SYSCTL_CONF"

# Enable ASLR - mitigates memory corruption attacks
sed -i '/^kernel\.randomize_va_space/d' "$SYSCTL_CONF"
echo "kernel.randomize_va_space = 2" >> "$SYSCTL_CONF"

# Disable SUID core dumps - prevents credential leakage
sed -i '/^fs\.suid_dumpable/d' "$SYSCTL_CONF"
echo "fs.suid_dumpable = 0" >> "$SYSCTL_CONF"

# Restrict dmesg - prevents kernel information disclosure
sed -i '/^kernel\.dmesg_restrict/d' "$SYSCTL_CONF"
echo "kernel.dmesg_restrict = 1" >> "$SYSCTL_CONF"

# Hide kernel pointers - mitigates kernel exploitation
sed -i '/^kernel\.kptr_restrict/d' "$SYSCTL_CONF"
echo "kernel.kptr_restrict = 2" >> "$SYSCTL_CONF"

PARAMETERS_APPLIED=14

if ! sysctl -p "$SYSCTL_CONF"; then
    echo "[!] Failed to apply sysctl parameters"
    cp "$BACKUP" "$SYSCTL_CONF"
    sysctl -p  "$SYSCTL_CONF"
    exit 1
fi

check_parameter() {

    local key="$1"
    local expected="$2"

    local proc="/proc/sys/${key//./\/}"

    printf "%-45s" "$key = $expected"

    if [[ -f "$proc" ]] && [[ "$(cat "$proc")" == "$expected" ]]; then
        echo "[PASS]"
        PASS_COUNT=$((PASS_COUNT+1))
    else
        echo "[FAIL]"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
}

check_parameter net.ipv4.ip_forward 0
check_parameter net.ipv4.conf.all.accept_redirects 0
check_parameter net.ipv4.conf.default.accept_redirects 0
check_parameter net.ipv4.conf.all.send_redirects 0
check_parameter net.ipv4.conf.all.accept_source_route 0
check_parameter net.ipv4.conf.all.log_martians 1
check_parameter net.ipv4.tcp_syncookies 1
check_parameter net.ipv4.icmp_echo_ignore_broadcasts 1
check_parameter net.ipv6.conf.all.disable_ipv6 1
check_parameter net.ipv6.conf.default.disable_ipv6 1
check_parameter kernel.randomize_va_space 2
check_parameter fs.suid_dumpable 0
check_parameter kernel.dmesg_restrict 1
check_parameter kernel.kptr_restrict 2

echo "Parameters applied: $PARAMETERS_APPLIED"
echo "Verified PASS: $PASS_COUNT"
echo "Verified FAIL: $FAIL_COUNT
