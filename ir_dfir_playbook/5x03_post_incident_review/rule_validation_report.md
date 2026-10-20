# Sigma Rule Validation Report

**Validation date:** 2026-10-20  
**Incident dataset:** `incident_sysmon.jsonl`  
**Clean baseline:** `clean_sysmon.jsonl`  
**Acceptance criteria:** Expected incident detection; clean-baseline false-positive rate below 0.1% of total events.

## 1. Executive summary

Both rules detected the expected incident activity. The initial validation of the PowerShell-to-developer-utility rule produced 14 clean-baseline matches, all attributed in the supplied results to legitimate MSBuild NuGet restore connections to `api.nuget.org`.

The initial false-positive rate was approximately **0.0049%**, below the 0.1% acceptance threshold. Nevertheless, the known benign pattern was selected for exclusion to improve precision. The post-tuning results reported zero clean-baseline matches.

| Rule | Incident matches | Incident match rate | Initial clean matches | Initial clean FP rate | Post-tuning clean matches |
|---|---:|---:|---:|---:|---:|
| PowerShell encoded-command rule | 2 | 0.042% | 0 | 0.000% | 0 |
| PowerShell spawning developer utilities (LOLBin) | 2 | 0.042% | 14 | 0.005% | 0 |

The incident match rate is the number of matched events divided by the 4,812 total incident events. The clean false-positive rate is the number of clean-baseline matches divided by 287,341 total clean events.

## 2. PowerShell encoded-command rule

**Result: PASS**

- Incident events: 4,812
- Matches: 2
- Match rate: 0.042%
- Clean-baseline events: 287,341
- Clean matches: 0
- False-positive rate: 0.000%

The rule fired on the incident dataset as expected. The two matches correspond to the encoded PowerShell activity identified in the supplied validation results. No clean-baseline matches were reported.

**Tuning decision:** No change required based on the supplied results. Preserve the existing detection logic and retain the rule in the validated set.

## 3. PowerShell-to-developer-utility (LOLBin) rule

**Initial result: REVIEW**

- Incident events: 4,812
- Matches: 2
- Match rate: 0.042%
- Clean-baseline events: 287,341
- Initial clean matches: 14
- Initial false-positive rate: 0.005% (rounded)

The rule detected the expected PowerShell-to-MSBuild behavior in the incident data. The supplied results identify the expected matches at:

- PID 8104 at `2026-04-14T02:46:58Z`
- PID 9201 at `2026-04-14T03:27:13Z`

The clean-baseline review identified 14 matches associated with legitimate MSBuild NuGet restore connections to `api.nuget.org`.

Although the initial false-positive rate was below the 0.1% threshold, these matches represented a known benign activity pattern. A targeted exclusion was selected rather than weakening the core detection.

### Tuning change

Add a filter for destination hostnames ending in `.nuget.org` and exclude those events from the rule's match condition.

Illustrative Sigma fragment:

```yaml
filter_nuget:
    DestinationHostname|endswith: '.nuget.org'

condition: selection_parent and selection_child and not filter_nuget
```

**Implementation note:** Integrate this filter into the existing rule using the field name and condition syntax supported by the actual event source and Sigma backend. Confirm that the rule's matched events expose `DestinationHostname` and that the filter excludes only the intended NuGet traffic. Do not apply a network-event filter to a process-creation rule unless the event schema and backend support that field for the relevant records.

### Post-tuning result

**Result: PASS, according to the supplied validation output**

- Clean-baseline matches after tuning: 0
- False-positive rate after tuning: 0.000%
- Incident detection: expected two matches retained in the supplied results

The post-tuning validation should be rerun against both datasets to verify that the exclusion removes the 14 benign matches without suppressing either expected incident detection. The results supplied for this report indicate zero clean matches after tuning.

## 4. Acceptance criteria

| Criterion | Result | Status |
|---|---|---|
| Encoded-command rule detects incident activity | 2 matches | PASS |
| Encoded-command rule avoids clean-baseline matches | 0 matches | PASS |
| LOLBin rule detects incident activity | 2 matches | PASS |
| LOLBin initial false-positive rate below 0.1% | Approximately 0.005% | PASS |
| Known NuGet restore matches addressed | Targeted hostname exclusion specified | TUNING |
| LOLBin post-tuning clean matches | 0 reported | PASS, pending independent rerun |

## 5. Final disposition

Retain the PowerShell encoded-command rule without changes based on the supplied results. Replace the original LOLBin rule with the tuned version after confirming that the filter is correctly integrated and that both incident matches remain present in a fresh validation run.

The reported post-tuning outcome is acceptable: both rules detect the expected incident activity, and the clean-baseline false-positive rate is 0.000%. This report records the supplied test results; it does not independently certify execution against the local datasets or confirm that the updated rule files have been written to disk.