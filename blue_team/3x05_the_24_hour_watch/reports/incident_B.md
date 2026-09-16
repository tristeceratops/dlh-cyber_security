## Incident Identifier
INC-20260916-B

## Executive Summary
INC-20260916-B is an external-communication incident affecting RAD-SRV-02. The investigation identified outbound communication to a supplied IOC while the associated change activity failed the owner and approved-scope checks. The activity is therefore assessed as true positive with high confidence because the observed actor and network scope were not covered by the approved change.

## Timeline
2026-09-16T11:21:07Z | RAD-SRV-02 | Authentication activity recorded for rad_admin_miller.
2026-09-16T11:23:14Z | RAD-SRV-02 | Process activity initiated an outbound network connection.
2026-09-16T11:24:32Z | RAD-SRV-02 | Connection established to 198[.]51[.]100[.]73 over TCP/443.
2026-09-16T11:26:18Z | RAD-SRV-02 | Outbound destination matched a supplied IOC feed entry.
2026-09-16T11:29:41Z | RAD-SRV-02 | Network telemetry recorded continued communication with the destination.
2026-09-16T11:33:06Z | RAD-SRV-02 | Activity remained outside the approved change scope.

## Affected Assets
| HOST | CRITICALITY | DATA_CLASS | ZONE |
|---|---|---|---|
| RAD-SRV-02 | CRITICAL | RADIOLOGY | CLINICAL-SERVER |

## Indicators of Compromise
| TYPE | VALUE | CONFIDENCE | SOURCE |
|---|---|---|---|
| ip | 198[.]51[.]100[.]73 | high | IOC feed |
| account | rad_admin_miller | high | IOC feed |

## ATT&CK Mapping
| TECHNIQUE | NAME | EVIDENCE |
|---|---|---|
| T1078 | Valid Accounts | Authentication activity was associated with the recorded administrative account. |
| T1071.001 | Web Protocols | Outbound communication occurred over TCP/443 to the IOC destination. |
| T1041 | Exfiltration Over C2 Channel | External communication followed authenticated activity and matched the supplied IOC. |

## Detection Performance
Rule fired: 004_unknown_destination
Rule fired: 015_suricata_c2_indicator
Rule fired: 009_external_admin_activity
Rule should have fired but did not: 018_change_scope_mismatch

## Recommended Actions
1. Isolate RAD-SRV-02 from unnecessary external network communication while preserving forensic evidence.
2. Validate and rotate credentials associated with rad_admin_miller.
3. Block 198[.]51[.]100[.]73 at applicable network-control points.
4. Review outbound traffic and process telemetry surrounding the incident window.
5. Reconcile the activity against CHG-2026-0341 and document the owner and scope mismatches.
6. Search other clinical-server assets for the same IOC and account activity.

## Evidence References
EVT-20260916-10117
EVT-20260916-10123
EVT-20260916-10131
EVT-20260916-10144
EVT-20260916-10152
EVT-20260916-10166
