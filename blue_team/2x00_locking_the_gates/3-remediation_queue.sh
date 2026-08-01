#!/bin/bash

set -euo pipefail


if [[ $# -ne 2 ]]; then
    echo "Usage: $0 <cis_profile.json> <lynis_findings.json>"
    exit 1
fi

CIS_PROFILE="$1"
LYNIS_FINDINGS="$2"

if [[ ! -f "$CIS_PROFILE" ]]; then
    echo "Error: CIS profile not found: $CIS_PROFILE"
    exit 1
fi

if [[ ! -f "$LYNIS_FINDINGS" ]]; then
    echo "Error: Lynis findings not found: $LYNIS_FINDINGS"
    exit 1
fi

GAP_ANALYSIS="gap_analysis.json"
REMEDIATION_QUEUE="remediation_queue.json"

jq \
    --slurpfile findings "$LYNIS_FINDINGS" '
{
  controls:
  [
    .controls[]
    |
    . as $control
    |
	    (
  [
    $findings[0].findings[]
    | . as $finding
    | select(
      	(
        	$control.lynis_mapping.test_ids
        	| index($finding.test_id)
      	)
      	or
      	(
          	any
          	(
            	$control.lynis_mapping.keywords[];
            	($finding.message | ascii_downcase)
            	| contains(. | ascii_downcase)
          	)
      	)
    	)
  	]
	) as $matches
    |
    . + {
    status:
	(
  	if ($matches | length) == 0 then
    		"compliant"
  	elif ($matches | any(.severity == "warning")) then
    		"non_compliant"
  	elif ($matches | any(.severity == "suggestion")) then
    		"partially_compliant"
  	else
    		"not_assessed"
  	end
	),
      matched_findings:
        (
          $matches
          |
          map({
            test_id,
            severity,
            message
          })
        )
    }
  ]
}
' "$CIS_PROFILE" > "$GAP_ANALYSIS"

jq '
{
  remediation_queue:
  (
    [
      .controls[]
      |
      select(
        .status=="non_compliant"
        or
        .status=="partially_compliant"
      )
      |
      {
        control_id,
        title,

        affected_asset: .asset_scope,

        remediation_script:
          .implementation_task,

        severity,

        matching_findings:
          .matched_findings,

        priority_score:
          (
            if .severity=="critical" then 100
            elif .severity=="high" then 85
            elif .severity=="medium" then 65
            else 40
            end
          ),

        operational_risk:
          .justification,

        expected_validation_check:
          .verification_method
      }
    ]
    |
    sort_by(.priority_score)
    |
    reverse
  )
}
' "$GAP_ANALYSIS" > "$REMEDIATION_QUEUE"

controls=$(jq '.controls | length' "$GAP_ANALYSIS")

compliant=$(jq '[.controls[] | select(.status=="compliant")] | length' "$GAP_ANALYSIS")

non=$(jq '[.controls[] | select(.status=="non_compliant")] | length' "$GAP_ANALYSIS")

partial=$(jq '[.controls[] | select(.status=="partially_compliant")] | length' "$GAP_ANALYSIS")

not_assessed=$(jq '[.controls[] | select(.status=="not_assessed")] | length' "$GAP_ANALYSIS")

queued=$(jq '.remediation_queue | length' "$REMEDIATION_QUEUE")

cat <<EOF
Controls assessed: $controls
Compliant: $compliant
Non-compliant: $non
Partially compliant: $partial
Not assessed: $not_assessed
Remediation actions queued: $queued
Report saved to: $GAP_ANALYSIS
Queue saved to: $REMEDIATION_QUEUE
EOF
