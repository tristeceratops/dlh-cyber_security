#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
INTAKE_FILE="${SCRIPT_DIR}/0-intel_intake.md"
COMMERCIAL_FILE="${SCRIPT_DIR}/4x02/commercial_feed_extract.json"

for required_file in "$INTAKE_FILE" "$COMMERCIAL_FILE"; do
	if [[ ! -f "$required_file" ]]; then
		printf 'ERROR: required local file not found: %s\n' "$required_file" >&2
		exit 1
	fi
done

if ! command -v python3 >/dev/null 2>&1; then
	printf 'ERROR: python3 is required to validate the local JSON feed.\n' >&2
	exit 1
fi

commercial_count="$(python3 - "$COMMERCIAL_FILE" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
	document = json.load(stream)

indicators = document.get("indicators", [])
declared_count = document.get("_metadata", {}).get("indicator_count")
if declared_count != len(indicators):
	raise SystemExit(
		f"commercial feed count mismatch: metadata={declared_count}, "
		f"parsed={len(indicators)}"
	)
print(len(indicators))
PY
)"

expected_lab_count="$(awk '/^Unique deduped:/ { print $3; exit }' "$INTAKE_FILE")"
if [[ -z "$expected_lab_count" ]]; then
	printf 'ERROR: could not read the expected deduplicated count from %s\n' "$INTAKE_FILE" >&2
	exit 1
fi

if ! grep -q '^### Indicators appearing in multiple sources$' "$INTAKE_FILE" \
	|| ! grep -q '^### Indicators appearing in only one source$' "$INTAKE_FILE"; then
	printf 'ERROR: consolidated indicator sections are missing from %s\n' "$INTAKE_FILE" >&2
	exit 1
fi

# Strict normalized ledger from Task 0. Source provenance is retained per value.
# Categories are operational judgments, not claims made by any single source.
read -r -d '' LEDGER <<'EOF' || true
domain	meddefense-portal.com	HC3;Acme;Researcher;MedDefense	ACTIONABLE	Observed phishing domain corroborated by four sources and tied to the MedDefense incident.	HIGH	
domain	medequip-supplies.net	HC3;Acme;Researcher	ACTIONABLE	Observed healthcare phishing domain corroborated by HC3, commercial data, and kit research.	HIGH	
domain	meddefense-benefits.org	HC3;Acme;MedDefense	ACTIONABLE	Observed phishing domain corroborated by sector and internal reporting.	HIGH	
domain	outlook-protection.com	HC3;Acme;Researcher	ACTIONABLE	Observed authenticated lookalike domain used for healthcare-themed phishing.	HIGH	
domain	healthbane-c2.net	HC3;Acme;Researcher	ACTIONABLE	C2 domain is corroborated by HC3, Acme, and the recovered kit configuration.	HIGH	
domain	data-sync.healthbane-c2.net	HC3;Acme	ACTIONABLE	HC3 packet evidence and Acme DNS-tunnel tagging identify the exfiltration endpoint.	HIGH	
domain	update-healthbane.net	HC3;Acme	ACTIONABLE	HC3 and Acme identify this as a second-stage delivery domain.	MEDIUM	Medium confidence because it is not present in the researcher or internal report.
domain	portal-secure-meddefense.com	HC3;Researcher	CONTEXTUAL	A staged kit domain was reported, but it was not active during observed emails.	MEDIUM	Staged infrastructure is not equivalent to observed victim traffic.
domain	rx-benefits-portal.com	Acme	CONTEXTUAL	Acme links it to a possible earlier campaign, but it predates HEALTHBANE and has no external corroboration.	LOW	Historical-correlation use only.
domain	healthcare-login.com	Acme	CONTEXTUAL	Acme reports it as sinkholed and useful only for historical correlation.	LOW	Do not treat as active infrastructure.
domain	verify-health-portal.net	Acme	CONTEXTUAL	The domain matches naming patterns but Acme observed no active phishing and has no external sources.	LOW	Pattern similarity is not direct evidence.
domain	secure-insurance-login.com	Acme	NOISE	Acme explicitly says this was an unreviewed ML name-similarity cluster.	LOW	Weak ML similarity only.
domain	claims-verify-portal.net	Acme	NOISE	Acme explicitly identifies keyword-only clustering with low evidence of association.	LOW	Keyword match only.
ip	91.234.99.107	HC3;Acme;Researcher;MedDefense	ACTIONABLE	The IP is tied to the confirmed phishing infrastructure by four sources.	HIGH	
ip	185.176.43.22	HC3;Acme;MedDefense	ACTIONABLE	The IP is tied to the confirmed phishing infrastructure by sector and internal reporting.	HIGH	
ip	164.90.218.73	HC3;Acme;MedDefense	ACTIONABLE	The IP is tied to the confirmed phishing infrastructure by sector and internal reporting.	HIGH	
ip	51.38.42.17	HC3;Acme	ACTIONABLE	HC3 and Acme identify the IP as phishing infrastructure.	HIGH	No independent researcher or internal telemetry for this IP.
ip	51.38.42.191	HC3;Acme;Researcher	ACTIONABLE	The C2 IP is corroborated by HC3, Acme, and the researcher’s kit configuration.	HIGH	
ip	45.77.218.9	HC3;Acme	ACTIONABLE	HC3 and Acme identify the IP as a second-stage C2 address.	MEDIUM	Not independently corroborated by the researcher or internal report.
ip	159.89.112.45	Acme	NOISE	Acme states this shared DigitalOcean IP hosts 200+ unrelated websites and should not be blocked.	LOW	Shared hosting creates a high false-positive risk.
ip	23.94.138.222	Acme	CONTEXTUAL	Acme labels it bulletproof-hosting and ML-clustered, but provides no external corroboration.	LOW	Investigate or monitor; do not block on this feed alone.
ip	104.168.34.58	Acme	NOISE	The value is only a low-confidence healthcare-keyword cluster with no external sources.	LOW	Weak keyword association.
ip	167.71.222.30	Acme;Researcher	CONTEXTUAL	The researcher describes VPS image reuse as a low-confidence operator-overlap hypothesis.	LOW	Infrastructure overlap is not proof of malicious use.
ip	192.99.207.114	Acme	NOISE	Acme explicitly identifies this as an OVH shared CDN and likely noise.	LOW	Shared CDN address.
ip	20.83.144.56	Acme	NOISE	Acme explicitly says this Azure CDN address is shared hosting and must not be blocked.	LOW	Explicit DO NOT BLOCK note.
ip	13.107.42.14	Acme	NOISE	Acme identifies this as a Microsoft Outlook.com IP and clustering-model noise.	LOW	Legitimate shared cloud service.
ip	172.67.192.40	Acme	NOISE	Acme identifies this as a Cloudflare front IP and not actionable.	LOW	Shared CDN/front-door address.
ip	104.21.35.7	Acme	NOISE	The address is a Cloudflare-only feed item with no corroboration.	LOW	Shared CDN/front-door address.
sha256	a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456	HC3;Acme;Researcher	ACTIONABLE	The macro document hash is corroborated by HC3, Acme, and the researcher.	HIGH	
sha256	b9c8a7d6e5f4321098765432109876543210fedcba9876543210fedcba987654	HC3;Acme	ACTIONABLE	The executable hash is corroborated by HC3 and Acme as a Stage 2 trojan.	HIGH	No internal endpoint match was found.
sha256	c7d6e5f4a3b291827364554637281900a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6	HC3;Acme;Researcher	ACTIONABLE	The PowerShell exfiltrator hash is corroborated by three sources.	HIGH	
sha256	2f4a6c8e0b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c3e5b7d9f1a3c5e7b9d1f	HC3;Researcher;MedDefense	ACTIONABLE	The lure PDF hash is directly observed in the internal investigation and corroborated by two sources.	HIGH	The source materials mark the lure hash MEDIUM, despite direct internal reporting.
sha256	dd5efb6d1ab4c67890abcdef1234567890abcdef1234567890abcdef12345678	HC3;Acme	ACTIONABLE	The dropper variant hash is corroborated by HC3 and Acme.	MEDIUM	Variant confidence is lower than the primary malware hashes.
sha256	ee1122334455667788990011223344556677889900aabbccddeeff0011223344	Acme	CONTEXTUAL	Acme reports a trojan variant, but it has only one sampled commercial source.	MEDIUM	Uncorroborated commercial-feed hash.
sha256	1122aabbccddeeff00112233445566778899aabbccddeeff0011223344556677	Acme	NOISE	Acme marks this as an unrelated malware-family cluster.	LOW	Explicit unrelated-cluster note.
sha256	3344556677889900aabbccddeeff00112233445566778899aabbccddeeff0011	Acme	NOISE	This is an uncorroborated unrelated-cluster hash.	LOW	Unreviewed commercial cluster.
sha256	5566778899aabbccddeeff00112233445566778899aabbccddeeff0011223344	Acme	NOISE	This is a low-confidence healthcare-keyword similarity hash with no corroboration.	LOW	Weak keyword similarity.
sha256	7788990011223344556677aabbccddeeff0011223344556677aabbccddeeff00	Acme	NOISE	This is an uncorroborated low-confidence clustering result.	LOW	Weak ML similarity.
sha256	ffaabbccdd0011223344556677889900aabbccddeeff00112233445566778899	Researcher	CONTEXTUAL	The hash identifies a recovered kit ZIP, not a malicious payload, and its provenance is uncertain.	MEDIUM	Kit may be vendor-supplied rather than operator-signed.
url	https://meddefense-portal.com/verify/staff	HC3;Acme;Researcher;MedDefense	ACTIONABLE	The normalized credential-capture endpoint is corroborated across all four sources.	HIGH	Query parameters were normalized away.
url	https://medequip-supplies.net/invoices/pay	HC3;Acme	ACTIONABLE	HC3 and Acme identify this as a credential-capture endpoint.	HIGH	Placeholder query parameters were normalized away.
url	https://meddefense-benefits.org/enroll	HC3;Acme	ACTIONABLE	HC3 and Acme identify this as a credential-capture endpoint.	HIGH	
url	https://healthbane-c2.net/update/svchost_update.exe	HC3;Acme	ACTIONABLE	HC3 and Acme identify this as the second-stage download URL.	HIGH	
url	https://outlook-protection.com/verify	Acme	CONTEXTUAL	Acme reports a phishing endpoint, but no other source supplies this exact URL.	MEDIUM	Domain is corroborated; endpoint path is not.
url	https://healthbane-c2.net/api/ingest	Researcher	CONTEXTUAL	The researcher recovered this exfiltration endpoint from kit configuration, but it lacks independent corroboration.	MEDIUM	Configuration evidence is indirect.
email	noreply@meddefense-portal.com	MedDefense	ACTIONABLE	The address was observed in a confirmed phishing email targeting MedDefense.	HIGH	Internal-only provenance.
email	invoices@medequip-supplies.net	MedDefense	ACTIONABLE	The address was observed in a confirmed phishing email targeting MedDefense.	HIGH	Internal-only provenance.
email	hr-notifications@meddefense-benefits.org	MedDefense	ACTIONABLE	The address was observed in a confirmed phishing email targeting MedDefense.	HIGH	Internal-only provenance.
EOF

ledger_count="$(printf '%s\n' "$LEDGER" | awk 'NF { count++ } END { print count + 0 }')"
if [[ "$ledger_count" -ne 48 ]]; then
	printf 'ERROR: embedded ledger contains %s values; expected 48 strict values.\n' "$ledger_count" >&2
	exit 1
fi

printf '# Indicator Triage\n\n'
printf '%s\n' "- Local commercial indicators validated: ${commercial_count}"
printf '%s\n' "- Task 0 lab reference unique count: ${expected_lab_count}"
printf '%s\n\n' "- Strict normalized ledger reviewed: ${ledger_count}"
printf '## Classifications\n\n'
printf '| Type | Indicator | Sources | Category | Justification | Confidence | Uncertainty |\n'
printf '|---|---|---|---|---|---|---|\n'
printf '%s\n' "$LEDGER" | awk -F '\t' '{ printf "| %s | `%s` | %s | **%s** | %s | %s | %s |\n", $1, $2, $3, $4, $5, $6, ($7 == "" ? "-" : $7) }'

actionable_count="$(printf '%s\n' "$LEDGER" | awk -F '\t' '$4 == "ACTIONABLE" { count++ } END { print count + 0 }')"
contextual_count="$(printf '%s\n' "$LEDGER" | awk -F '\t' '$4 == "CONTEXTUAL" { count++ } END { print count + 0 }')"
noise_count="$(printf '%s\n' "$LEDGER" | awk -F '\t' '$4 == "NOISE" { count++ } END { print count + 0 }')"

percentage() {
	awk -v count="$1" -v total="$ledger_count" 'BEGIN { printf "%.1f%%", (count / total) * 100 }'
}

printf '\n## Summary statistics\n\n'
printf '| Measure | Count | Percentage |\n'
printf '|---|---:|---:|\n'
printf '| Total indicators reviewed | %s | 100.0%% |\n' "$ledger_count"
printf '| ACTIONABLE | %s | %s |\n' "$actionable_count" "$(percentage "$actionable_count")"
printf '| CONTEXTUAL | %s | %s |\n' "$contextual_count" "$(percentage "$contextual_count")"
printf '| NOISE | %s | %s |\n' "$noise_count" "$(percentage "$noise_count")"

printf '\n### Top reasons for downgrade\n\n'
printf '%s\n' \
  '1. Shared hosting, CDN, Microsoft, and Cloudflare addresses create broad false-positive scope.' \
  '2. Commercial-only indicators are sampled, unreviewed, or clustered by weak ML or keyword similarity.' \
  '3. Historical, sinkholed, staged, or configuration-only infrastructure is not proof of current victim traffic.' \
  '4. Attribution labels such as VITALSCORE and APT-MEDAGENT do not independently establish maliciousness.'

printf '\n### Immediate detection set\n\n'
printf '%s\n' \
  '- Corroborated Stage 1 domains: meddefense-portal.com, medequip-supplies.net, meddefense-benefits.org, outlook-protection.com.' \
  '- C2 and delivery domains: healthbane-c2.net, data-sync.healthbane-c2.net, update-healthbane.net.' \
  '- Confirmed phishing/C2 IPs: 91.234.99.107, 185.176.43.22, 164.90.218.73, 51.38.42.17, 51.38.42.191, 45.77.218.9.' \
  '- Corroborated malware and lure hashes: a1b2c3d4..., b9c8a7d6..., c7d6e5f4..., 2f4a6c8e..., dd5efb6d....' \
  '- Behavioral detections: PHPMailer 6.6.0 with SPF failure, Office-to-PowerShell execution, suspicious Run-key or scheduled-task creation, and long base32-like DNS TXT labels at 10-15 second intervals.'

printf '\n> ACTIONABLE is not synonymous with confirmed MedDefense compromise. The local ledger contains %s ACTIONABLE, %s CONTEXTUAL, and %s NOISE values; the lab reference of 64 unique indicators is not silently treated as 64 safe block rules.\n' "$actionable_count" "$contextual_count" "$noise_count"
