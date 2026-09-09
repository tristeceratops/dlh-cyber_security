# MedDefense SOC Triage Methodology

## Classification Taxonomy

* `true_positive`: Evidence confirms the detection represents the behavior targeted by the rule; example: `007 unknown_outbound_destination` identifies confirmed outbound communication to an unknown destination.
* `false_positive`: Evidence shows the detection matched expected activity or an incorrect condition; example: `001 ssh_brute_force` triggered by an approved administrative source.
* `benign`: Activity is genuine but presents no security concern and requires no corrective action; example: expected `011 patient_data_access` by an authorized clinical user.
* `escalated`: Available evidence is insufficient or indicates material risk requiring Tier 2 investigation; example: `010 credential_theft_chain` with unresolved account or host compromise indicators.

## Priority Ordering Rule

Work alerts in descending `priority_score`; break ties deterministically by earliest `event_summary.timestamp`, then `alert_id`. Override normal ordering when an alert has credible evidence of active compromise, confirmed malicious IOC activity, data exfiltration, or multiple correlated alerts indicating a developing incident. Critical alerts always supersede lower bands unless an active critical incident is already being contained.

## Evidence Requirement

Every classification must reference at least one `event_ref` from `enriched_events.json`. `true_positive` requires corroborating detection evidence such as `rule_id`, `event_summary`, and the relevant source/destination or process field. `false_positive` requires a field/value demonstrating expected or incorrect activity. `benign` requires a field/value establishing authorized or non-threatening activity. `escalated` requires the observed field/value creating unresolved security risk or evidentiary uncertainty.

## Escalation Criteria

* `priority_score >= 20 AND evidence indicates active compromise`
* `ioc.reputation == "malicious"`
* `multiple alerts correlate to the same host, account, or destination`
* `event_summary` indicates confirmed credential theft, lateral movement, or exfiltration
* evidence is contradictory or insufficient to safely classify the alert
* potential impact involves sensitive patient data or critical infrastructure

## SLA

* `critical`: 15 minutes
* `high`: 30 minutes
* `medium`: 60 minutes
* `low`: same day

## Documentation Standard

Every ticket must contain:

* `ticket_id`
* `alert_id`
* `classification`
* `justification`
* `evidence_refs`
* `ioc_hits`
* `attack_techniques`
* `recommended_action`
* `analyst_time_seconds`
* `created_at`

`justification` must identify the specific field and value driving every non-`benign` classification. `evidence_refs` must point to valid enriched-event `event_ref` values.

