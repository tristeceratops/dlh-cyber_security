#!/bin/bash

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
DATA_DIR="$SCRIPT_DIR/4x04"
REFERENCE_DIR="$DATA_DIR/reference"
BASELINE_DIR="$DATA_DIR/baseline"
SIEM_DIR="$DATA_DIR/siem_export"

ADVISORY_FILE="$REFERENCE_DIR/hc3_advisory_004.txt"
MAPPING_FILE="$REFERENCE_DIR/4x03_attack_mapping.json"

for required_file in \
	"$ADVISORY_FILE" \
	"$MAPPING_FILE" \
	"$BASELINE_DIR/robert_kim_activity.json" \
	"$SIEM_DIR/wazuh_alerts_14d.json" \
	"$SIEM_DIR/wazuh_raw_sysmon_14d.json"; do
	if [[ ! -f "$required_file" ]]; then
		printf 'ERROR: required input is missing: %s\n' "$required_file" >&2
		exit 1
	fi
done

if ! command -v jq >/dev/null 2>&1; then
	printf 'ERROR: jq is required to parse %s\n' "$MAPPING_FILE" >&2
	exit 1
fi

advisory_text=$(<"$ADVISORY_FILE")
for advisory_term in \
	"PsExec" \
	"Remote Process Creation via WMI" \
	"Interactive Remote Access via PSRemoting" \
	"Credential Access via LSASS Memory" \
	"Valid Accounts (Service Account Abuse)" \
	"exclusively between 01:00 and 05:00"; do
	if ! grep -Fqi -- "$advisory_term" <<<"$advisory_text"; then
		printf 'ERROR: advisory term not found: %s\n' "$advisory_term" >&2
		exit 1
	fi
done

coverage_summary=$(jq -r '
	.technique_count_summary
	| "\(.observed)/\(.total_in_threat_model) techniques (\(.percent_observed)%)"
' "$MAPPING_FILE")

technique_label() {
	case "$1" in
		T1021.002) printf 'SMB/Windows Admin Shares' ;;
		T1047) printf 'WMI' ;;
		T1021.006) printf 'Windows Remote Management' ;;
		T1003.001) printf 'LSASS Memory' ;;
		T1078.002) printf 'Domain Accounts' ;;
		*) printf 'Unknown technique' ;;
	esac
}

print_state() {
	local state=$1
	local score
	case "$state" in
		OBSERVED) score=3 ;;
		INFERRED) score=2 ;;
		"NOT COVERED") score=0 ;;
		*)
			printf 'ERROR: unsupported coverage state: %s\n' "$state" >&2
			exit 1
			;;
	esac

	while IFS= read -r technique_id; do
		[[ -z "$technique_id" ]] && continue
		printf '    %-10s %-32s %s\n' \
			"$technique_id" "$(technique_label "$technique_id")" "$state"
	done < <(jq -r --argjson expected_score "$score" '
		.techniques[]
		| select(.techniqueID as $id | ["T1021.002", "T1047", "T1021.006", "T1003.001", "T1078.002"] | index($id))
		| select(.score == $expected_score)
		| .techniqueID
	' "$MAPPING_FILE")
}

printf '\n================================================================\n'
printf '   THREAT HUNT BRIEF - HEALTHBANE Stage 4 (LOLBin Lateral Movement)\n'
printf '   Classification: TLP:AMBER\n'
printf '================================================================\n\n'

printf 'HC3 ADVISORY SUMMARY:\n'
printf '  Stage 4 TTPs:\n'
printf '\t[*] PsExec for remote command execution on servers\n'
printf '\t[*] WMI for remote process creation and enumeration\n'
printf '\t[*] PowerShell Remoting for interactive access and staging\n'
printf '\t[*] Credential dumping via LSASS memory access\n'
printf '\t[*] Service account abuse for lateral authentication\n'
printf '\t[*] Off-hours operations to avoid detection\n\n'

printf 'ATT&CK COVERAGE GAP ANALYSIS:\n'
printf '  Current coverage: %s\n' "$coverage_summary"
printf '  Stage 4 techniques by current state:\n'
printf '  OBSERVED:\n'
print_state OBSERVED
printf '  INFERRED:\n'
print_state INFERRED
printf '  NOT COVERED:\n'
print_state "NOT COVERED"
printf '\n  Advisory techniques in the NOT COVERED category:\n'
print_state "NOT COVERED"

printf '\nHUNT PRIORITY RANKING:\n'
printf '  P1: T1021.002 PsExec\n'
printf '  P2: T1003.001 LSASS\n'
printf '  P3: T1047 WMI\n'
printf '  P4: T1021.006 PSRemoting\n'
printf '  P5: T1078.002 Domain Accounts\n\n'

printf 'SCOPE:\n'
printf '  HEALTHBANE Stage 4 lateral movement and credential access\n'
printf '  MedDefense server segment and workstation-originated administration\n\n'

printf 'DATA SOURCES:\n'
printf '  Primary: siem_export/wazuh_alerts_14d.json\n'
printf '  Secondary: siem_export/wazuh_raw_sysmon_14d.json\n'
printf '  Baseline: baseline/robert_kim_activity.json\n'
printf '  Reference: reference/admin_schedule.txt\n'
printf '  Reference: reference/service_accounts.txt\n'
printf '  Reference: reference/network_topology.txt\n\n'

printf 'HUNT TARGETS:\n'
printf '  PsExec, WMI, PSRemoting, LSASS access, service-account logons, and off-hours activity\n\n'

printf 'FALSE-POSITIVE CONTROLS:\n'
printf '  Robert Kim schedule: authorized source hosts, tools, targets, and maintenance windows\n'
printf '  Service account matrix: authorized hosts, logon types, and authentication protocols\n'
printf '  Network topology: workstation, server, and administrative authorization boundaries\n\n'

printf 'TIME WINDOW: 14 days (2026-05-04 through 2026-05-18)\n'
printf '\n================================================================\n'
