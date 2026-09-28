#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES_DIR="${SCRIPT_DIR}/4x02/samples"
PDF_RULE_FILE="${SCRIPT_DIR}/9-yara_phishing_pdf.yar"
ARSENAL_RULE_FILE="${SCRIPT_DIR}/10-yara_arsenal.yar"

if ! command -v yara >/dev/null 2>&1; then
	printf 'ERROR: yara is required but was not found in PATH.\n' >&2
	exit 1
fi

for required_file in "$SAMPLES_DIR" "$PDF_RULE_FILE" "$ARSENAL_RULE_FILE"; do
	if [[ ! -e "$required_file" ]]; then
		printf 'ERROR: required path not found: %s\n' "$required_file" >&2
		exit 1
	fi
done

mapfile -t sample_files < <(find "$SAMPLES_DIR" -maxdepth 1 -type f \( -name '*.pdf' -o -name '*.eml' \) | sort)
if [[ "${#sample_files[@]}" -eq 0 ]]; then
	printf 'ERROR: no PDF or EML samples found in %s\n' "$SAMPLES_DIR" >&2
	exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

# Return 0 for a positive, 1 for a negative, and 2 for not applicable.
expected_result() {
	local rule_key="$1"
	local sample_name="$2"

	case "$rule_key:$sample_name" in
		pdf:phishing_sample.pdf|pdf:healthbane_lure_02.pdf) return 0 ;;
		pdf:clean_invoice.pdf|pdf:benign_invoice.pdf) return 1 ;;
		email:healthbane_email_01.eml|email:healthbane_email_02.eml|email:healthbane_email_03.eml) return 0 ;;
		email:benign_newsletter.eml) return 1 ;;
		composite:phishing_sample.pdf|composite:healthbane_lure_02.pdf) return 0 ;;
		composite:clean_invoice.pdf|composite:benign_invoice.pdf) return 1 ;;
		composite:healthbane_email_01.eml|composite:healthbane_email_02.eml|composite:healthbane_email_03.eml) return 0 ;;
		composite:benign_newsletter.eml) return 1 ;;
		*) return 2 ;;
	esac
}

rule_file_for() {
	case "$1" in
		pdf) printf '%s\n' "$PDF_RULE_FILE" ;;
		email|composite) printf '%s\n' "$ARSENAL_RULE_FILE" ;;
		*) return 1 ;;
	esac
}

rule_name_for() {
	case "$1" in
		pdf) printf '%s\n' 'HEALTHBANE_PDF_Credential_Harvesting' ;;
		email) printf '%s\n' 'HEALTHBANE_Email_Headers' ;;
		composite) printf '%s\n' 'HEALTHBANE_Campaign_Composite' ;;
		*) return 1 ;;
	esac
}

display_name_for() {
	case "$1" in
		pdf) printf '%s\n' 'HEALTHBANE_Phishing_PDF' ;;
		email) printf '%s\n' 'HEALTHBANE_Email_Headers' ;;
		composite) printf '%s\n' 'HEALTHBANE_Campaign_Composite' ;;
		*) return 1 ;;
	esac
}

explanation_for() {
	local outcome="$1"
	local rule_key="$2"
	local sample_name="$3"

	if [[ "$outcome" == FN ]]; then
		case "$rule_key:$sample_name" in
			email:healthbane_email_03.eml)
				printf '%s\n' 'The sample uses X-Mailer: PHPMailer 6.6.0 (custom build) rather than the exact version form; accept a PHPMailer custom-build variant while retaining sender/lure evidence.' ;;
			pdf:*)
				printf '%s\n' 'The lure lacks one required metadata family; allow equivalent creator strings or add a validated campaign-specific path/lure token without weakening the PDF and multi-indicator requirements.' ;;
			composite:*)
				printf '%s\n' 'The file contains campaign evidence in a representation not covered by the current independent families; add a narrow, sample-backed family rather than lowering all conditions.' ;;
			*) printf '%s\n' 'The rule condition does not cover a required sample characteristic; add a narrow validated variant.' ;;
		esac
	else
		case "$rule_key:$sample_name" in
			pdf:*)
				printf '%s\n' 'The file matched PDF tooling, path, and lure-text families; require stronger campaign-specific metadata or a known infrastructure marker before deployment.' ;;
			email:*)
				printf '%s\n' 'The message matched header, priority, sender-domain, and lure families; tighten the domain/header relationship or require an additional authentication failure.' ;;
			composite:*)
				printf '%s\n' 'The file contains enough independent lure families to satisfy the composite condition; add provenance or a stronger campaign marker if this is a benign match.' ;;
			*) printf '%s\n' 'Review the matched strings and add a narrow exclusion or stronger corroborating condition.' ;;
		esac
	fi
}

run_match() {
	local rule_key="$1"
	local sample_file="$2"
	local rule_file
	local rule_name
	local result_file
	local yara_status

	rule_file="$(rule_file_for "$rule_key")"
	rule_name="$(rule_name_for "$rule_key")"
	result_file="$tmpdir/${rule_key}_$(basename "$sample_file").out"

	set +e
	yara -w "$rule_file" "$sample_file" >"$result_file" 2>&1
	yara_status=$?
	set -e

	if [[ "$yara_status" -gt 1 ]]; then
		printf 'ERROR: YARA failed for %s on %s:\n%s\n' "$rule_name" "$sample_file" "$(cat "$result_file")" >&2
		return 1
	fi

	if awk -v target="$rule_name" '$1 == target { found=1 } END { exit !found }' "$result_file"; then
		return 0
	fi
	return 1
}

printf '=== YARA TESTING SUMMARY ===\n'
printf 'Samples scanned by every rule: %s\n\n' "${#sample_files[@]}"

for rule_key in pdf email composite; do
	display_name="$(display_name_for "$rule_key")"
	tp=0
	tn=0
	fp=0
	fn=0
	applicable=0
	scan_log="$tmpdir/${rule_key}.log"

	: > "$scan_log"
	for sample_file in "${sample_files[@]}"; do
		sample_name="$(basename "$sample_file")"
		if run_match "$rule_key" "$sample_file"; then
			matched=1
		else
			matched=0
		fi

		if expected_result "$rule_key" "$sample_name"; then
			expected=1
		else
			expected_status=$?
			if [[ "$expected_status" -eq 2 ]]; then
				expected=2
			else
				expected=0
			fi
		fi

		printf '%s\t%s\t%s\n' "$sample_name" "$matched" "$expected" >> "$scan_log"

		if [[ "$expected" -eq 2 ]]; then
			continue
		fi

		applicable=$((applicable + 1))
		if [[ "$expected" -eq 1 && "$matched" -eq 1 ]]; then
			tp=$((tp + 1))
		elif [[ "$expected" -eq 0 && "$matched" -eq 0 ]]; then
			tn=$((tn + 1))
		elif [[ "$expected" -eq 1 && "$matched" -eq 0 ]]; then
			fn=$((fn + 1))
			printf 'FN\t%s\t%s\n' "$rule_key" "$sample_name" >> "$tmpdir/findings.log"
		else
			fp=$((fp + 1))
			printf 'FP\t%s\t%s\n' "$rule_key" "$sample_name" >> "$tmpdir/findings.log"
		fi
	done

	detection_rate="$(awk -v tp="$tp" -v fn="$fn" 'BEGIN { if (tp + fn == 0) print "N/A"; else printf "%.1f%%", 100 * tp / (tp + fn) }')"
	false_positive_rate="$(awk -v fp="$fp" -v tn="$tn" 'BEGIN { if (fp + tn == 0) print "N/A"; else printf "%.1f%%", 100 * fp / (fp + tn) }')"
	precision="$(awk -v tp="$tp" -v fp="$fp" 'BEGIN { if (tp + fp == 0) print "N/A"; else printf "%.1f%%", 100 * tp / (tp + fp) }')"

	if [[ "$fp" -gt 0 || "$fn" -gt 0 ]]; then
		recommendation="TUNE"
	elif [[ "$applicable" -gt 0 ]]; then
		recommendation="DEPLOY"
	else
		recommendation="MONITOR"
	fi

	printf 'Rule: %s\n' "$display_name"
	printf 'TP: %s | TN: %s | FP: %s | FN: %s\n' "$tp" "$tn" "$fp" "$fn"
	printf 'Detection rate: %s\n' "$detection_rate"
	printf 'False positive rate: %s\n' "$false_positive_rate"
	printf 'Precision: %s\n' "$precision"
	printf 'Recommendation: %s\n\n' "$recommendation"
done

printf '=== FALSE RESULT REVIEW ===\n'
if [[ ! -s "$tmpdir/findings.log" ]]; then
	printf 'No false positives or false negatives in the applicable sample sets.\n'
else
	while IFS=$'\t' read -r outcome rule_key sample_name; do
		printf '%s: %s on %s\n' "$outcome" "$(display_name_for "$rule_key")" "$sample_name"
		printf 'Why / tuning: %s\n' "$(explanation_for "$outcome" "$rule_key" "$sample_name")"
	done < "$tmpdir/findings.log"
fi

printf '\n=== TESTING NOTES ===\n'
printf '%s\n' \
	'- Every rule was executed against every PDF and EML in the samples directory.' \
	'- Metrics exclude non-applicable file types: the PDF rule is scored on four PDFs; the email rule on four EML files; the composite rule on all eight.' \
	'- healthbane_email_03.eml is treated as a known header variant and is expected to match the corrected PHPMailer custom-build logic.' \
	'- A clean metric result is sample-scoped; review new benign corpora before broad deployment.'
