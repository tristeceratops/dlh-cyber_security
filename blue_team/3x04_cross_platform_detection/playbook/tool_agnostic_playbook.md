# MedDefense Tool-Agnostic Investigation Playbook v1

## Purpose

This playbook defines a repeatable method for investigating endpoint, identity, and network-security scenarios using CLI evidence or Wazuh exports/dashboards. It provides a common evidence model for comparable findings across tools.

## Scope

Covers bounded investigations of suspicious authentication, privilege use, process execution, credential access, lateral movement, and medical-data egress. It does not cover containment, eradication, attribution, remediation, live response, or unsupported conclusions.

## Inputs

The analyst must have access to:

* **Enriched events**
* **Asset inventory**
* **Baseline**
* **Detection catalog**
* **Triage package**
* **IOC context**

These are mandatory inputs; do not substitute inferred data for missing artifacts.

## Workflow Steps

| Step               | CLI action                                                                             | Export/dashboard action                                             |
| ------------------ | -------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| **1. Define**      | Record scenario, host/user, UTC window, and hypothesis.                                | Confirm index, agent, time zone, filters, and time range.           |
| **2. Validate**    | Check asset role, zone, owner, data class, and baseline.                               | Check agent/asset metadata and displayed context.                   |
| **3. Find events** | Filter events by host, time, type, and indicator with `jq`.                            | Apply equivalent dashboard, KQL, or Lucene filters; export matches. |
| **4. Verify**      | Check timestamp, event ID, user, process, network fields, and message.                 | Inspect the same fields and preserve export identifiers.            |
| **5. Correlate**   | Sort chronologically, group entities, calculate intervals, compare baseline.           | Use tables/aggregations/traces and verify equivalent ordering.      |
| **6. Enrich**      | Consult detection catalog, triage package, and IOC context; map ATT&CK.                | Inspect rules, alerts, labels, IOC context, and displayed mappings. |
| **7. Assess**      | Separate facts from interpretation; document anomalies, benign explanations, and gaps. | Repeat key filters and record dashboard limitations/click path.     |
| **8. Record**      | Validate the locked finding schema and retain evidence references.                     | Create the same finding from exported evidence and compare results. |

## Field Name Translation Table

| Normalized schema | Wazuh field                                          |
| ----------------- | ---------------------------------------------------- |
| `timestamp`       | `@timestamp`                                         |
| `event_id`        | `id` / `winlog.event_id`                             |
| `host`            | `agent.name`                                         |
| `host_ip`         | `agent.ip`                                           |
| `user`            | `user.name`                                          |
| `process_name`    | `win.eventdata.image` / `process.name`               |
| `command_line`    | `win.eventdata.commandLine` / `process.command_line` |
| `source_ip`       | `data.srcip` / `source.ip`                           |
| `destination_ip`  | `data.dstip` / `destination.ip`                      |
| `message`         | `full_log` / `message`                               |

Verify actual paths against the Wazuh field mapping because decoder and integration versions can differ.

## Query Decomposition Rule

Every query must specify **filter, aggregation, and time window**.

* **Filter:** `jq` uses `select(...)`; Sigma uses `logsource` and `detection`; KQL uses Boolean field clauses; Lucene uses fielded terms and Boolean operators.
* **Aggregation:** `jq` uses `group_by`, `length`, and `sort_by`; Sigma uses supported condition/correlation logic; KQL uses aggregations/visualizations; Lucene uses dashboard terms, date histograms, or counts.
* **Time window:** use explicit UTC bounds. `jq` compares parsed timestamps; Sigma uses its rule/correlation window; KQL uses timestamp range clauses; Lucene uses `@timestamp:[start TO end]`.

A query is reproducible only when all three parts are recorded.

## Finding Schema

Each finding contains:

* `finding_id`: deterministic `scenario_id + "_" + interface`
* `scenario_id`: `anchor`, `scenario_a`, `scenario_b`, or `scenario_c`
* `interface`: `cli` or `wazuh_export`
* `investigation_start`, `investigation_end`: ISO 8601 UTC
* `time_to_first_answer_seconds`: integer
* `actions`: ordered list, maximum 20
* `fields_touched`: list
* `event_refs`: list
* `attack_techniques`
* `hypothesis`: maximum 2 sentences
* `confidence`: `low`, `medium`, or `high`
* `created_at`: ISO 8601 UTC

## Exit Criteria

The investigation is complete when scope and UTC window are defined, all six inputs are checked, events are reproducibly filtered, relevant fields and event references are preserved, the timeline and hypothesis are documented, ATT&CK mappings are supported, and evidence gaps are stated. It is ready for a finding when the locked schema validates and facts are separated from interpretation.

## Known Pitfalls

* **Time zones:** dashboard time may be local, so verify the dashboard time zone against recorded UTC bounds.
* **Field drift:** equivalent data can appear under `data.*`, `winlog.*`, `win.eventdata.*`, or ECS-style paths.
* **Sparse exports:** exports may omit fields available to CLI evidence; record omissions instead of guessing.
* **Duplicate identity:** timestamps/messages may repeat, so retain stable event IDs or deterministic references.
* **Aggregation mismatch:** hidden dashboard filters can change counts; reproduce filters explicitly.
* **Authorized activity:** legitimate medical access can still be anomalous when occurring off-hours or with unusual execution flags.
* **Network notation:** one interface may combine IP and port while another separates them; normalize before comparison.

