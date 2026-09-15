# MedDefense Vendor Brief

## Purpose

This brief recommends the primary analyst interface for MedDefense based on the six investigations completed this week. It uses the counted workflow evidence from T13 and the operational trade-offs recorded in T12, without relying on marketing claims or feature matrices.

## Evaluation Methodology

The evaluation covered the anchor scenario and three investigation scenarios, each examined through both the CLI and Wazuh export/dashboard workflow. The scenarios represented credential theft, off-hours privileged access to PHI, medical-network egress, and a baseline comparison case.

For each interface, analysts recorded time to first answer, ordered actions, fields touched, event references, and confidence. The workflow comparison in T13 contains eight findings: four CLI findings and four Wazuh export findings. T12 then compared paired results by scenario, including time differences, action counts, evidence access, field translation, and operational causes.

The measurements represent this week’s observed investigation work, not a universal performance guarantee.

## Findings Summary

T13 recorded the following totals:

| Measure                    |         CLI | Wazuh export/dashboard |
| -------------------------- | ----------: | ---------------------: |
| Findings                   |           4 |                      4 |
| Total time to first answer | 928 seconds |            788 seconds |
| Average time               | 232 seconds |            197 seconds |
| Median time                | 247 seconds |            193 seconds |
| Total actions              |          39 |                     22 |

The Wazuh workflow therefore required **140 fewer seconds overall**, or approximately **15% less measured time**, and used **17 fewer recorded actions**. Its lower median also indicates a more consistent path across the tested cases, although the sample is small.

The results do not mean that Wazuh is always faster: the workflow comparison includes one scenario in which the export path took longer than the CLI path. The figures should therefore guide interface selection while remaining subject to validation against future cases.

## Strengths and Weaknesses per Interface

**CLI strengths and weaknesses.** The CLI provided direct access to enriched events and made chronological sorting, interval calculation, and precise filtering straightforward. T12 records that the CLI was advantageous where raw event structure and network timing were immediately available, particularly for the medical-egress investigation; it also avoided dashboard field omissions and hidden filters. However, the CLI required more manual actions overall, and T12 identifies repeated field inspection and evidence correlation as contributors to the higher action count. The CLI also places greater responsibility on the analyst to preserve reproducible queries, normalize fields, and document the investigation path.

**Wazuh export/dashboard strengths and weaknesses.** Wazuh was faster overall and reduced interaction effort through indexed filtering, visible event context, and dashboard aggregation. T12 records advantages from the shorter credential-theft investigation path and the faster anchor workflow, where rule, label, and event context were available together. Its weaknesses are dependency on correct field translation, export completeness, dashboard time-zone settings, and hidden filters. T12 also records that dashboard use can be slower when the required field is absent or when the analyst must drill through several panels to reconstruct a timeline.

## Recommendation

**MedDefense should select the Wazuh export/dashboard workflow as the primary analyst surface for routine triage and repeatable investigations.**

**The CLI should be retained as the secondary surface whenever exports are incomplete, field mappings are ambiguous, precise timeline calculations are required, or a dashboard result must be independently validated.**

## Operational Risks of Being Wrong

The following are planning estimates for a four-investigation weekly workload:

* **Selecting CLI as primary:** the measured difference of 140 seconds per four cases equals approximately **0.16 analyst hours per week** at the observed workload, excluding documentation overhead.
* **Selecting Wazuh without CLI fallback:** one incomplete or misleading export could require approximately **1–2 additional analyst hours per affected case** for reconstruction, validation, and evidence collection.
* **Missing field or time-zone translation errors:** an incorrect event window or field path could cause approximately **2–4 analyst hours per incident** in rework and supervisor review.
* **Failing to detect medical-data egress:** an overlooked network correlation could create **4–8 analyst hours** of urgent retrospective investigation, evidence preservation, and compliance coordination.
* **Over-trusting authorized activity:** incorrectly closing suspicious off-hours privileged access could create **3–6 analyst hours** of later case reopening, escalation, and audit explanation.

These estimates are operational planning values, not measured incident-loss amounts.

## Security+ 4.7 Considerations

Automation and efficiency favor Wazuh as the primary surface because indexed searches, reusable rules, and dashboard context reduce repeated analyst actions and support scaling. CLI fallback limits complexity, prevents technical debt from hidden field assumptions, and reduces the cost of incorrect automation or incomplete exports.

## Next Steps

1. **Detection engineering:** validate the ten-field translation table, document Wazuh decoder paths, and add regression tests for the six scenarios.
2. **Detection engineering:** preserve CLI queries for export validation, timeline reconstruction, and incomplete-data cases.
3. **Compliance:** archive T12, T13, the eight findings, the playbook, and the final manifest as the audit evidence set.
4. **Compliance:** approve the finding schema and require UTC windows, stable event references, and documented evidence gaps.
5. **SOC manager:** adopt Wazuh as primary, define CLI fallback triggers, and review the workflow after the next ten comparable investigations.

