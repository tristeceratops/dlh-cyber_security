#!/bin/bash

# Host and kernel
printf 'hostname=%s\n' "$(hostname)"
printf 'kernel_release=%s\n' "$(uname -r)"

# Distribution
if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    printf 'distribution=%s\n' "${PRETTY_NAME:-unknown}"
    printf 'patch_level=%s\n' "${VERSION_ID:-unknown}"
else
    printf 'distribution=unknown\n'
    printf 'patch_level=unknown\n'
fi

# Installed packages
if command -v dpkg-query >/dev/null 2>&1; then
    package_count=$(dpkg-query -W 2>/dev/null | wc -l)
    printf 'installed_package_count=%s\n' "$package_count"
else
    printf 'installed_package_count=unavailable\n'
fi

# Listening sockets
printf 'listening_sockets=\n'
if command -v ss >/dev/null 2>&1; then
    ss -tulnpH
else
    printf 'unavailable\n'
fi

# Active systemd services
printf 'active_systemd_services=\n'
if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --type=service --state=active --no-legend --no-pager
else
    printf 'unavailable\n'
fi

# sshd_config as key-value records
printf 'sshd_config=\n'
if [[ -r /etc/ssh/sshd_config ]]; then
    awk '
        /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
        {
            key=$1
            $1=""
            sub(/^[[:space:]]+/, "")
            print key "=" $0
        }
    ' /etc/ssh/sshd_config
else
    printf 'unavailable\n'
fi

# Sysctl security parameters
printf 'sysctl_security_parameters=\n'
if command -v sysctl >/dev/null 2>&1; then
    sysctl -a 2>/dev/null | awk -F= '
        $1 ~ /(randomize_va_space|dmesg_restrict|kptr_restrict|ptrace_scope|protected_hardlinks|protected_symlinks|suid_dumpable|unprivileged_bpf|unprivileged_userns_clone)/ {
            gsub(/[[:space:]]+$/, "", $1)
            gsub(/^[[:space:]]+/, "", $2)
            print $1 "=" $2
        }
    '
else
    printf 'unavailable\n'
fi

# SUID and SGID binaries
printf 'suid_sgid_binary_count='
find / -xdev -perm /6000 -type f -print 2>/dev/null | wc -l

# World-writable files
printf 'world_writable_file_count='
find / \
    -xdev \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -perm -0002 -type f -print 2>/dev/null |
    wc -l

# Firewall
printf 'firewall_ruleset_length='
if command -v nft >/dev/null 2>&1; then
    nft list ruleset 2>/dev/null | wc -c
else
    printf 'unavailable\n'
fi

# Telemetry
printf 'telemetry=\n'

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
        printf 'auditd=running\n'
    else
        printf 'auditd=not_running\n'
    fi

    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        printf 'rsyslog=running\n'
    else
        printf 'rsyslog=not_running\n'
    fi
else
    printf 'auditd=unavailable\n'
    printf 'rsyslog=unavailable\n'
fi

if command -v sysmon >/dev/null 2>&1 ||
    command -v sysmon-for-linux >/dev/null 2>&1 ||
    [[ -f /opt/sysmon/sysmon ]]; then
    printf 'sysmon_for_linux=present\n'
else
    printf 'sysmon_for_linux=not_present\n'
fi

exit 0
