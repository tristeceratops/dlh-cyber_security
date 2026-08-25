#!/bin/bash

# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

status=0

fail_control() {
    printf 'error=%s\n' "$1" >&2
    status=1
}

fail_environment() {
    printf 'error=%s\n' "$1" >&2
    exit 2
}

# Required commands
for command in hostname uname awk find wc; do
    if ! command -v "$command" >/dev/null 2>&1; then
        fail_environment "missing dependency: $command"
    fi
done

printf 'hostname=%s\n' "$(hostname)"
printf 'kernel_release=%s\n' "$(uname -r)"

# Distribution
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    printf 'distribution=%s\n' "${PRETTY_NAME:-unknown}"
    printf 'patch_level=%s\n' "${VERSION_ID:-unknown}"
else
    fail_environment "missing input file: /etc/os-release"
fi

# Installed packages
if command -v dpkg-query >/dev/null 2>&1; then
    if package_count=$(dpkg-query -W 2>/dev/null | wc -l); then
        printf 'installed_package_count=%s\n' "$package_count"
    else
        fail_control "dpkg-query failed"
        printf 'installed_package_count=unavailable\n'
    fi
else
    fail_environment "missing dependency: dpkg-query"
fi

# Listening sockets
printf 'listening_sockets=\n'
if command -v ss >/dev/null 2>&1; then
    if ! ss -tulnpH; then
        fail_control "ss failed"
    fi
else
    fail_environment "missing dependency: ss"
fi

# Active systemd services
printf 'active_systemd_services=\n'
if command -v systemctl >/dev/null 2>&1; then
    if ! systemctl list-units --type=service --state=active --no-legend --no-pager; then
        fail_control "systemctl failed"
    fi
else
    fail_environment "missing dependency: systemctl"
fi

# sshd_config
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
    fail_environment "missing input file: /etc/ssh/sshd_config"
fi

# Sysctl security parameters
printf 'sysctl_security_parameters=\n'
if command -v sysctl >/dev/null 2>&1; then
    if ! sysctl -a 2>/dev/null | awk -F= '
        $1 ~ /(randomize_va_space|dmesg_restrict|kptr_restrict|ptrace_scope|protected_hardlinks|protected_symlinks|suid_dumpable|unprivileged_bpf|unprivileged_userns_clone)/ {
            gsub(/[[:space:]]+$/, "", $1)
            gsub(/^[[:space:]]+/, "", $2)
            print $1 "=" $2
        }
    '; then
        fail_control "sysctl failed"
    fi
else
    fail_environment "missing dependency: sysctl"
fi

# SUID and SGID binaries
printf 'suid_sgid_binary_count='
if ! find / -xdev -perm /6000 -type f -print 2>/dev/null | wc -l; then
    fail_control "SUID/SGID search failed"
fi

# World-writable files
printf 'world_writable_file_count='
if ! find / \
    -xdev \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -perm -0002 -type f -print 2>/dev/null |
    wc -l; then
    fail_control "world-writable file search failed"
fi

# Firewall
printf 'firewall_ruleset_length='
if command -v nft >/dev/null 2>&1; then
    if ! nft list ruleset 2>/dev/null | wc -c; then
        fail_control "nft failed"
    fi
else
    fail_environment "missing dependency: nft"
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
    fail_environment "missing dependency: systemctl"
fi

if command -v sysmon >/dev/null 2>&1 ||
    command -v sysmon-for-linux >/dev/null 2>&1 ||
    [[ -f /opt/sysmon/sysmon ]]; then
    printf 'sysmon_for_linux=present\n'
else
    printf 'sysmon_for_linux=not_present\n'
fi

if [[ "$status" -eq 0 ]]; then
    printf 'result=success\n'
    exit 0
fi

printf 'result=controlled_failure\n'
exit 1
