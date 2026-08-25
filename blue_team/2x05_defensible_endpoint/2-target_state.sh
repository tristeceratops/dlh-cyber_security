#!/bin/bash

# Exit codes:
# 0 = success
# 1 = controlled failure
# 2 = environment error

set -o pipefail

OUTPUT_FILE="capstone/target_state.json"
FORCE=false

if [[ "${1:-}" == "--force" ]]; then
    FORCE=true
elif [[ $# -gt 0 ]]; then
    printf 'error=unknown argument: %s\n' "$1" >&2
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    printf 'error=missing dependency: jq\n' >&2
    exit 2
fi

if [[ -e "$OUTPUT_FILE" && "$FORCE" != true ]]; then
    printf 'error=%s already exists, overwrite refused, use --force to overwrite\n' "$OUTPUT_FILE" >&2
    exit 1
fi

mkdir -p "$(dirname "$OUTPUT_FILE")" || {
    printf 'error=unable to create capstone directory\n' >&2
    exit 2
}

generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ') || {
    printf 'error=unable to generate timestamp\n' >&2
    exit 2
}

tmp_file=$(mktemp) || {
    printf 'error=unable to create temporary file\n' >&2
    exit 2
}

trap 'rm -f "$tmp_file"' EXIT

jq -n \
    --arg generated_at "$generated_at" \
'
{
  schema_version: "1.0",
  generated_at: $generated_at,
  controls: [

    {
      id: "LNX-SSH-01",
      platform: "linux",
      family: "hardening",
      description: "SSH must prohibit root login.",
      check_type: "grep_match",
      check_target: "/etc/ssh/sshd_config",
      expected_value: "PermitRootLogin no",
      source_project: "linux-hardening",
      severity: "critical"
    },
    {
      id: "LNX-SSH-02",
      platform: "linux",
      family: "hardening",
      description: "SSH must disable password authentication.",
      check_type: "grep_match",
      check_target: "/etc/ssh/sshd_config",
      expected_value: "PasswordAuthentication no",
      source_project: "linux-hardening",
      severity: "high"
    },
    {
      id: "LNX-SYS-01",
      platform: "linux",
      family: "hardening",
      description: "IPv4 forwarding must be disabled.",
      check_type: "grep_match",
      check_target: "/etc/sysctl.conf",
      expected_value: "net.ipv4.ip_forward=0",
      source_project: "linux-hardening",
      severity: "high"
    },
    {
      id: "LNX-SYS-02",
      platform: "linux",
      family: "hardening",
      description: "Kernel address space layout randomization must be fully enabled.",
      check_type: "grep_match",
      check_target: "/etc/sysctl.conf",
      expected_value: "kernel.randomize_va_space=2",
      source_project: "linux-hardening",
      severity: "high"
    },
    {
      id: "LNX-AUD-01",
      platform: "linux",
      family: "telemetry",
      description: "auditd must be active.",
      check_type: "command_exit_zero",
      check_target: "systemctl is-active --quiet auditd",
      expected_value: 0,
      source_project: "linux-telemetry",
      severity: "critical"
    },
    {
      id: "LNX-AUD-02",
      platform: "linux",
      family: "telemetry",
      description: "The Linux audit rules file must exist and contain loaded rules.",
      check_type: "file_exists",
      check_target: "/etc/audit/rules.d/audit.rules",
      expected_value: true,
      source_project: "linux-telemetry",
      severity: "high"
    },
    {
      id: "LNX-APP-01",
      platform: "linux",
      family: "hardening",
      description: "AppArmor must operate in enforce mode.",
      check_type: "grep_match",
      check_target: "/sys/kernel/security/apparmor/profiles",
      expected_value: "^[^[:space:]]+ \\([^)]*\\) enforce$",
      source_project: "linux-hardening",
      severity: "high"
    },
    {
      id: "LNX-LYN-01",
      platform: "linux",
      family: "hardening",
      description: "The Lynis hardening index must be at least 80.",
      check_type: "json_field_gte",
      check_target: "capstone/lynis.json.hardening_index",
      expected_value: 80,
      source_project: "linux-hardening",
      severity: "high"
    },

    {
      id: "WIN-FW-01",
      platform: "windows",
      family: "network",
      description: "Windows Firewall must use default-deny inbound behavior on every profile.",
      check_type: "json_field_equals",
      check_target: "capstone/windows_firewall.json.profiles[*].default_inbound",
      expected_value: "Block",
      source_project: "windows-hardening",
      severity: "critical"
    },
    {
      id: "WIN-PS-01",
      platform: "windows",
      family: "telemetry",
      description: "PowerShell Script Block Logging must be enabled.",
      check_type: "json_field_equals",
      check_target: "capstone/windows.json.powershell_script_block_logging.enabled",
      expected_value: true,
      source_project: "windows-telemetry",
      severity: "high"
    },
    {
      id: "WIN-SYM-01",
      platform: "windows",
      family: "telemetry",
      description: "The Sysmon service must be installed and running.",
      check_type: "json_field_equals",
      check_target: "capstone/windows.json.sysmon.state",
      expected_value: "Running",
      source_project: "windows-telemetry",
      severity: "critical"
    },
    {
      id: "WIN-AUD-01",
      platform: "windows",
      family: "telemetry",
      description: "Windows audit policy must cover the required audit subcategories.",
      check_type: "grep_match",
      check_target: "capstone/audit_policy.txt",
      expected_value: "(Account Logon|Logon|Object Access|Privilege Use)",
      source_project: "windows-telemetry",
      severity: "high"
    },
    {
      id: "WIN-CIS-01",
      platform: "windows",
      family: "hardening",
      description: "The CIS Level 1 pass rate must be at least 85 percent.",
      check_type: "json_field_gte",
      check_target: "capstone/cis.json.level_1_pass_rate",
      expected_value: 85,
      source_project: "windows-hardening",
      severity: "high"
    },

    {
      id: "LNX-EXP-01",
      platform: "linux",
      family: "handoff",
      description: "The structured JSON export path must exist.",
      check_type: "file_exists",
      check_target: "capstone/target_state.json",
      expected_value: true,
      source_project: "handoff",
      severity: "medium"
    },
    {
      id: "WIN-SYM-02",
      platform: "windows",
      family: "telemetry",
      description: "The Windows Sysmon event channel must contain events from the last 10 minutes.",
      check_type: "json_field_gte",
      check_target: "capstone/windows.json.sysmon.events_last_10_minutes",
      expected_value: 1,
      source_project: "windows-telemetry",
      severity: "high"
    },
    {
      id: "WIN-PS-02",
      platform: "windows",
      family: "telemetry",
      description: "The Script Block Logging event channel must contain events.",
      check_type: "json_field_gte",
      check_target: "capstone/windows.json.powershell_script_block_logging.event_channel_size_bytes",
      expected_value: 1,
      source_project: "windows-telemetry",
      severity: "medium"
    },

    {
      id: "LNX-PAT-01",
      platform: "linux",
      family: "patching",
      description: "The vulnerability inventory must be present.",
      check_type: "file_exists",
      check_target: "capstone/vulnerability_inventory.json",
      expected_value: true,
      source_project: "patching",
      severity: "high"
    },
    {
      id: "LNX-PAT-02",
      platform: "linux",
      family: "patching",
      description: "The patch plan must be present.",
      check_type: "file_exists",
      check_target: "capstone/patch_plan.json",
      expected_value: true,
      source_project: "patching",
      severity: "high"
    },
    {
      id: "LNX-PAT-03",
      platform: "linux",
      family: "patching",
      description: "The patch execution log must contain no failed entries.",
      check_type: "json_field_equals",
      check_target: "capstone/patch_execution_log.json.failed_count",
      expected_value: 0,
      source_project: "patching",
      severity: "critical"
    },
    {
      id: "LNX-PAT-04",
      platform: "linux",
      family: "patching",
      description: "Unattended upgrades must be configured with the mandated blacklist.",
      check_type: "grep_match",
      check_target: "/etc/apt/apt.conf.d/50unattended-upgrades",
      expected_value: "Unattended-Upgrade::Package-Blacklist",
      source_project: "patching",
      severity: "medium"
    },

    {
      id: "NET-NFT-01",
      platform: "network",
      family: "network",
      description: "The nftables ruleset must be loaded with default-deny inbound behavior.",
      check_type: "grep_match",
      check_target: "nft list ruleset",
      expected_value: "policy drop",
      source_project: "network-hardening",
      severity: "critical"
    },
    {
      id: "NET-SEG-01",
      platform: "network",
      family: "network",
      description: "Network segmentation rules must be present.",
      check_type: "file_exists",
      check_target: "capstone/segmentation_rules.json",
      expected_value: true,
      source_project: "network-segmentation",
      severity: "high"
    },
    {
      id: "NET-SUR-01",
      platform: "network",
      family: "network",
      description: "The Suricata custom rule file must contain at least six rules.",
      check_type: "json_field_gte",
      check_target: "capstone/suricata.json.custom_rule_count",
      expected_value: 6,
      source_project: "network-telemetry",
      severity: "high"
    },
    {
      id: "NET-SUR-02",
      platform: "network",
      family: "network",
      description: "Every Suricata rule must have fired against its target PCAP.",
      check_type: "json_field_equals",
      check_target: "capstone/suricata_validation.json.all_rules_fired",
      expected_value: true,
      source_project: "network-telemetry",
      severity: "high"
    },
    {
      id: "NET-DNS-01",
      platform: "network",
      family: "network",
      description: "The DNS filtering service must be active.",
      check_type: "command_exit_zero",
      check_target: "systemctl is-active --quiet dns-filter",
      expected_value: 0,
      source_project: "network-telemetry",
      severity: "high"
    },

    {
      id: "HND-CMP-01",
      platform: "both",
      family: "handoff",
      description: "The compliance report must be present.",
      check_type: "file_exists",
      check_target: "capstone/compliance.json",
      expected_value: true,
      source_project: "compliance",
      severity: "medium"
    },
    {
      id: "HND-MAN-01",
      platform: "both",
      family: "handoff",
      description: "The manifest must contain a SHA-256 hash for every exported file.",
      check_type: "grep_match",
      check_target: "capstone/manifest.json",
      expected_value: "sha256",
      source_project: "handoff",
      severity: "high"
    },
    {
      id: "HND-TEL-01",
      platform: "both",
      family: "handoff",
      description: "The telemetry export package must exist as a tar archive.",
      check_type: "file_exists",
      check_target: "capstone/telemetry_export.tar",
      expected_value: true,
      source_project: "handoff",
      severity: "medium"
    },
    {
      id: "HND-RUN-01",
      platform: "both",
      family: "handoff",
      description: "The handoff runbook script must exist and be executable.",
      check_type: "command_exit_zero",
      check_target: "test -x capstone/runbook.sh",
      expected_value: 0,
      source_project: "handoff",
      severity: "medium"
    }

  ]
}
' > "$tmp_file" || {
    printf 'error=failed to generate target state\n' >&2
    exit 1
}

if ! jq empty "$tmp_file" >/dev/null 2>&1; then
    printf 'error=generated target state is invalid JSON\n' >&2
    exit 1
fi

if ! mv "$tmp_file" "$OUTPUT_FILE"; then
    printf 'error=unable to write %s\n' "$OUTPUT_FILE" >&2
    exit 1
fi

trap - EXIT

exit 0
