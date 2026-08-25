#!/bin/bash

# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

OUTPUT_FILE="capstone.json"
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
for command in hostname uname awk find wc jq; do
    if ! command -v "$command" >/dev/null 2>&1; then
        fail_environment "missing dependency: $command"
    fi
done

# Host information
hostname_value=$(hostname)
kernel_release=$(uname -r)

# Distribution
if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    distribution="${PRETTY_NAME:-unknown}"
    patch_level="${VERSION_ID:-unknown}"
else
    fail_environment "missing input file: /etc/os-release"
fi

# Installed packages
if command -v dpkg-query >/dev/null 2>&1; then
    if package_count=$(dpkg-query -W 2>/dev/null | wc -l); then
        :
    else
        package_count=0
        fail_control "dpkg-query failed"
    fi
else
    fail_environment "missing dependency: dpkg-query"
fi

# Listening sockets
if command -v ss >/dev/null 2>&1; then
    if ! listening_sockets=$(ss -tulnpH 2>/dev/null); then
        listening_sockets=""
        fail_control "ss failed"
    fi
else
    fail_environment "missing dependency: ss"
fi

# Active systemd services
if command -v systemctl >/dev/null 2>&1; then
    if ! active_services=$(
        systemctl list-units \
            --type=service \
            --state=active \
            --no-legend \
            --no-pager 2>/dev/null
    ); then
        active_services=""
        fail_control "systemctl failed"
    fi
else
    fail_environment "missing dependency: systemctl"
fi

# sshd_config
if [[ -r /etc/ssh/sshd_config ]]; then
    sshd_config=$(
        awk '
            /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
            {
                key=$1
                $1=""
                sub(/^[[:space:]]+/, "")
                print key "=" $0
            }
        ' /etc/ssh/sshd_config
    )
else
    fail_environment "missing input file: /etc/ssh/sshd_config"
fi

# Sysctl security parameters
sysctl_json="{}"

if command -v sysctl >/dev/null 2>&1; then
    sysctl_params=(
        net.ipv4.ip_forward
        net.ipv4.conf.all.accept_redirects
        net.ipv4.conf.default.accept_redirects
        net.ipv4.conf.all.send_redirects
        net.ipv4.conf.all.accept_source_route
        net.ipv4.conf.all.log_martians
        net.ipv4.tcp_syncookies
        net.ipv4.icmp_echo_ignore_broadcasts
        net.ipv6.conf.all.disable_ipv6
        net.ipv6.conf.default.disable_ipv6
        kernel.randomize_va_space
        fs.suid_dumpable
        kernel.dmesg_restrict
        kernel.kptr_restrict
    )

    for parameter in "${sysctl_params[@]}"; do
        if value=$(sysctl -n "$parameter" 2>/dev/null); then
            sysctl_json=$(
                jq -c \
                    --arg key "$parameter" \
                    --arg value "$value" \
                    '. + {($key): $value}' <<< "$sysctl_json"
            )
        else
            sysctl_json=$(
                jq -c \
                    --arg key "$parameter" \
                    '. + {($key): null}' <<< "$sysctl_json"
            )
            fail_control "unable to read sysctl: $parameter"
        fi
    done
else
    fail_environment "missing dependency: sysctl"
fi

# SUID and SGID binaries
if ! suid_sgid_count=$(
    find / -xdev -perm /6000 -type f -print 2>/dev/null | wc -l
); then
    suid_sgid_count=0
    fail_control "SUID/SGID search failed"
fi

# World-writable files
if ! world_writable_count=$(
    find / \
        -xdev \
        -path /proc -prune -o \
        -path /sys -prune -o \
        -perm -0002 -type f -print 2>/dev/null |
        wc -l
); then
    world_writable_count=0
    fail_control "world-writable file search failed"
fi

# Firewall
if command -v nft >/dev/null 2>&1; then
    if ! firewall_ruleset_length=$(nft list ruleset 2>/dev/null | wc -c); then
        firewall_ruleset_length=0
        fail_control "nft failed"
    fi
else
    fail_environment "missing dependency: nft"
fi

# Telemetry
auditd_status="not_running"
rsyslog_status="not_running"

if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-active --quiet auditd 2>/dev/null; then
        auditd_status="running"
    fi

    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        rsyslog_status="running"
    fi
else
    fail_environment "missing dependency: systemctl"
fi

# Sysmon-for-Linux
sysmon_present=false

if command -v sysmon >/dev/null 2>&1 ||
    command -v sysmon-for-linux >/dev/null 2>&1 ||
    [[ -f /opt/sysmon/sysmon ]]; then
    sysmon_present=true
fi

# Build JSON
if ! jq -n \
    --arg hostname "$hostname_value" \
    --arg kernel_release "$kernel_release" \
    --arg distribution "$distribution" \
    --arg patch_level "$patch_level" \
    --argjson package_count "$package_count" \
    --arg listening_sockets "$listening_sockets" \
    --arg active_services "$active_services" \
    --arg sshd_config "$sshd_config" \
    --argjson sysctl_security_parameters "$sysctl_json" \
    --argjson suid_sgid_binary_count "$suid_sgid_count" \
    --argjson world_writable_file_count "$world_writable_count" \
    --argjson firewall_ruleset_length "$firewall_ruleset_length" \
    --arg auditd "$auditd_status" \
    --arg rsyslog "$rsyslog_status" \
    --argjson sysmon_for_linux "$sysmon_present" \
    '
    def lines:
        if . == "" then [] else split("\n") end;

    {
        hostname: $hostname,
        kernel_release: $kernel_release,
        distribution: $distribution,
        patch_level: $patch_level,

        installed_package_count: $package_count,

        listening_sockets: ($listening_sockets | lines),

        active_systemd_services: ($active_services | lines),

        sshd_config: (
            $sshd_config
            | lines
            | map(
                split("=")
                | {(.[0]): (.[1:] | join("="))}
            )
            | add // {}
        ),

        sysctl_security_parameters: $sysctl_security_parameters,

        suid_sgid_binary_count: $suid_sgid_binary_count,

        world_writable_file_count: $world_writable_file_count,

        firewall: {
            nft_ruleset_length: $firewall_ruleset_length
        },

        telemetry: {
            auditd: $auditd,
            rsyslog: $rsyslog,
            sysmon_for_linux: $sysmon_for_linux
        }
    }
    ' > "$OUTPUT_FILE"; then
    fail_control "failed to create $OUTPUT_FILE"
fi

if [[ "$status" -eq 0 ]]; then
    exit 0
fi

exit 1
