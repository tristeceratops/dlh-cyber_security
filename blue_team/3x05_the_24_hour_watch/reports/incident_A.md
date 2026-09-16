## Incident Identifier
INC-20260916-A

## Executive Summary
INC-20260916-A is a credential-abuse incident affecting WIN-FIN-07 and associated privileged activity. The investigation identified an off-hours privileged login from an unseen source and activity associated with the adm_sync account. The finding is assessed with high confidence based on the recorded authentication, baseline deviation, and IOC evidence.

## Timeline
2026-09-16T10:41:18Z | WIN-FIN-07 | Successful privileged authentication for adm_sync from an unseen source address.
2026-09-16T10:42:03Z | WIN-FIN-07 | Baseline deviation recorded for off-hours authentication activity.
2026-09-16T10:43:11Z | WIN-FIN-07 | Source address matched a supplied IOC feed value.
2026-09-16T10:45:27Z | WIN-FIN-07 | Privileged account initiated a remote administrative session.
2026-09-16T10:47:02Z | WIN-FIN-07 | Authentication telemetry recorded continued activity for adm_sync.
2026-09-16T10:49:16Z | WIN-FIN-07 | Network activity followed the privileged authentication sequence.

## Affected Assets
| HOST | CRITICALITY | DATA_CLASS | ZONE |
|---|---|---|---|
| WIN-FIN-07 | HIGH | FINANCIAL | USER-ENDPOINT |

## Indicators of Compromise
| TYPE | VALUE | CONFIDENCE | SOURCE |
|---|---|---|---|
| account | adm_sync | high | IOC feed |
| ip | 10[.]44[.]91[.]18 | high | IOC feed |
| service_name | RemoteAssistSvc | high | IOC feed |

## ATT&CK Mapping
| TECHNIQUE | NAME | EVIDENCE |
|---|---|---|
| T1078 | Valid Accounts | Successful privileged authentication using adm_sync. |
| T1078.002 | Domain Accounts | Privileged account activity was recorded against the enterprise authentication infrastructure. |
| T1021 | Remote Services | Remote administrative activity followed the anomalous authentication. |

## Detection Performance
Rule fired: 002_offhours_priv
Rule fired: 015_privileged_authentication
Rule should have fired but did not: 003_unseen_privileged_source

## Recommended Actions
1. Disable or rotate credentials associated with adm_sync pending account-owner validation.
2. Review authentication and remote-session telemetry for WIN-FIN-07 across the surrounding incident window.
3. Search for the supplied IOC account and source address across enterprise authentication logs.
4. Validate whether RemoteAssistSvc is authorized on the affected endpoint.
5. Review privileged-account access controls and authentication-source restrictions.
6. Preserve relevant endpoint and authentication evidence for follow-on investigation.

## Evidence References
EVT-20260916-09117
EVT-20260916-09123
EVT-20260916-09131
EVT-20260916-09144
EVT-20260916-09152
EVT-20260916-09166
