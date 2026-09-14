# Cross-Platform Trade-off Analysis

Generated: `2026-09-14T00:00:00Z`

> **Note:** The anchor and scenario B measurements in this example are illustrative. Replace them with the measured values from the six actual findings before treating this table as final evidence.

## Method

Findings are paired by `scenario_id`.

Time delta is calculated as:

> **CLI time minus Wazuh export time**

A positive time delta means that the Wazuh export interface was faster.

Action-count delta is calculated as:

> **CLI action count minus Wazuh export action count**

A positive action-count delta means that the Wazuh export required fewer actions.

## Trade-off table

| Scenario | CLI time (s) | Export time (s) | Δ time (CLI − export) | CLI actions | Export actions | Δ actions | Faster interface | Cause |
|---|---:|---:|---:|---:|---:|---:|---|---|
| anchor | 30 | 24 | 6 | 6 | 5 | 1 | wazuh_export | native_field_surface |
| scenario_a | 52 | 33 | 19 | 8 | 4 | 4 | wazuh_export | native_field_surface |
| scenario_b | 40 | 25 | 15 | 7 | 6 | 1 | wazuh_export | context_join_ergonomics |
| scenario_c | 39 | 21 | 18 | 6 | 5 | 1 | wazuh_export | timeline_visualization |

## Attribution details

### anchor

- **Faster interface:** `wazuh_export`
- **Operational cause:** `native_field_surface`
- **Time delta:** 6 seconds, CLI minus export
- **Action-count delta:** 1, CLI minus export
- **Explanation:** Wazuh export was faster because the relevant structured fields reduced the effort required to isolate the signal.

### scenario_a

- **Faster interface:** `wazuh_export`
- **Operational cause:** `native_field_surface`
- **Time delta:** 19 seconds, CLI minus export
- **Action-count delta:** 4, CLI minus export
- **Explanation:** Wazuh export was faster because structured agent, event, process, and network fields reduced the effort required to isolate the credential-theft sequence.

### scenario_b

- **Faster interface:** `wazuh_export`
- **Operational cause:** `context_join_ergonomics`
- **Time delta:** 15 seconds, CLI minus export
- **Action-count delta:** 1, CLI minus export
- **Explanation:** Wazuh export was faster because the event fields and related asset context reduced the effort required to connect identity, privilege, timing, and data classification.

### scenario_c

- **Faster interface:** `wazuh_export`
- **Operational cause:** `timeline_visualization`
- **Time delta:** 18 seconds, CLI minus export
- **Action-count delta:** 1, CLI minus export
- **Explanation:** Wazuh export was faster because chronological event ordering and dashboard inspection made the repeated beacon interval easier to identify.

## Summary

- **Scenarios analyzed:** 4
- **Wazuh export advantages:** 4
- **CLI advantages:** 0
- **Ties:** 0

## Interpretation

In this illustrative comparison, Wazuh export is faster in all four scenarios. The measured advantage is attributed to structured field availability, easier context joining, and timeline-oriented inspection.

The final conclusion should be based only on the values generated from the six actual findings.
