# Detection Specification

## 1. Purpose

This specification defines the engineering standard for authoring, executing, validating, tuning, and prioritizing detections in the MedDefense detection catalog. It provides a consistent contract from Sigma rule development through alert generation and downstream 3x03 processing.

## 2. Inputs

* `$BASELINE_PKG/anomalies/anomalies_auth.json` — authentication anomalies.
* `$BASELINE_PKG/anomalies/anomalies_process.json` — process anomalies.
* `$BASELINE_PKG/anomalies/anomalies_network.json` — network anomalies.
* `$BASELINE_PKG/anomalies/correlated_anomalies.json` — cross-source correlations.
* `$BASELINE_PKG/anomalies/ranked_anomalies.json` — ranked anomaly ground truth.
* `$BASELINE_PKG/taxonomy/labeled_events.json` — labeled event ground truth.
* `$BASELINE_PKG/baselines/baseline_summary.json` — evaluation/baseline window.
* `$BASELINE_PKG/baselines/baseline_process.json` — approved process baseline.
* `$HANDOFF_DIR/evidence_handoff/data/normalized_events.json` — normalized detection evidence.
* `$HANDOFF_DIR/context/asset_inventory.json` — asset context.
* `$ASSETS_DIR/risk_register.json` — threat/risk scenarios.
* `rules/sigma/` — original Sigma rules.
* `rules/sigma/tuned/` — tuned rule variants.

Required environment variables are `$BASELINE_PKG`, `$HANDOFF_DIR`, and `$ASSETS_DIR`.

## 3. Rule Authoring Standard

Rules use Sigma YAML with `title`, UUID `id`, `status`, `description`, `logsource`, `detection`, `condition`, `level`, `tags`, and `falsepositives` as applicable. Rule filenames use a three-digit catalog prefix and descriptive snake_case name, for example `001_ssh_brute_force.yml`.

Every rule must contain at least one ATT&CK tag in the form `attack.tXXXX` or `attack.tXXXX.xxx`. Detection logic must be deterministic, explainable, and scoped to the relevant event category. False positives must document realistic MedDefense administrative, maintenance, monitoring, or security-testing activity.

## 4. Execution Model

`3-sigma_runner.sh` is the canonical execution engine. It loads the Sigma rule, preprocesses normalized evidence, evaluates selections and conditions, supports aggregation/timeframes, applies the requested evaluation window, and returns deterministic match records.

Preprocessing primitives may add derived fields such as `hour_of_day` and `baseline_seen`. Window semantics are inclusive: events whose timestamps fall between the supplied start and end timestamps are evaluated.

## 5. Quality Thresholds

A rule must meet all required shipping gates:

* **Precision:** ≥ 0.70.
* **Recall:** ≥ 0.60.
* **F1:** ≥ 0.65.
* **False-positive rate:** ≤ 0.20 per evaluation period.

Rules failing a gate remain experimental or require tuning. High-risk detections may ship with documented exceptions when recall is prioritized, but the exception must be approved during review.

## 6. Tuning Protocol

A noisy rule is tuned by identifying the dominant false-positive pattern from `fp_baseline.json` and match evidence, then adding the narrowest justified exclusion, filter, parent-process constraint, account scope, asset scope, or other deterministic condition.

The tuned variant is stored under `rules/sigma/tuned/` using the same filename as the original. Re-run the complete evaluation window and regenerate quality metrics; tuning must reduce false positives without causing an unacceptable loss of recall or F1. The tuned rule must pass the same shipping gates before replacing the original as the active rule.

## 7. Risk Ranking Model

`priority_score` combines detection quality with MedDefense business risk. For every threat scenario whose covered ATT&CK techniques intersect the rule, calculate `likelihood × impact` and sum the results as `risk_score`.

The final score is `risk_score × F1`. When F1 is zero, a floor of `risk_score × 0.1` is used so high-risk coverage is not ranked as completely irrelevant. Rules with no matching risk scenario have a priority score of zero and are reported as `ORPHAN`.

## 8. Outputs

`rule_quality.json` records TP, FP, FN, precision, recall, and F1 for each rule. `rule_prioritization.json` records risk and priority scoring.

`alert_queue.json` is a JSON array containing `alert_id`, `generated_at`, `rule_id`, `rule_title`, `rule_level`, `priority_score`, `event_ref`, `event_summary`, `asset_context`, `attack_techniques`, `status`, and `evidence_hash`.

`alert_id` is deterministic UUID5 from `rule_id + event_ref`; `event_ref` links to normalized evidence; `evidence_hash` is SHA-256 of the raw event. Alerts are deduplicated within 60 seconds by `(rule_id, hostname, user)`, sorted by priority descending, then event timestamp ascending. `alert_queue_schema.json` is the explicit interface contract consumed by downstream 3x03 processing.

## 9. Failure Modes

* **Invalid Sigma YAML/UUID:** dry-run or execution fails with a parse/validation error; no trustworthy alert output is produced.
* **Evidence schema mismatch:** runner returns zero/unexpected matches because required fields or derived fields are absent.
* **Incorrect evaluation window:** match counts and quality metrics differ unexpectedly from the baseline period.
* **Ground-truth mismatch:** TP/FN counts are implausible because event references or categories cannot be correlated.
* **Missing asset/risk context:** prioritization or alerts contain empty context, preventing reliable business-risk ranking.
* **Over-aggressive tuning:** FP count decreases while recall/F1 falls below the shipping threshold.

## 10. Reviewer Checklist

* [ ] Filename follows `NNN_descriptive_name.yml`.
* [ ] UUID, title, status, logsource, detection, level, tags, and false positives are present.
* [ ] Detection logic has at least one ATT&CK technique tag.
* [ ] Rule passes runner validation and the evaluation window.
* [ ] TP/FP/FN and precision/recall/F1 are calculated.
* [ ] All quality gates pass or an approved exception is documented.
* [ ] False positives are understood and tuning is evidence-based.
* [ ] Rule maps to at least one MedDefense risk scenario.
* [ ] Priority score is populated and reasonable.
* [ ] Alert output contains a valid event reference and evidence hash.
* [ ] No duplicate or conflicting active rule exists.
