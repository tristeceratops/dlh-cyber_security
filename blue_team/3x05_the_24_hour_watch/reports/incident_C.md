## Incident Identifier
INC-20260916-C

## Executive Summary
INC-20260916-C is a persistence and command-execution incident affecting DB-CORE-01. The investigation identified an encoded PowerShell command associated with a newly observed service and the svc_backup account. The combination of execution, service creation, and baseline deviation provides high-confidence evidence of unauthorized persistence activity.

## Timeline
2026-09-16T12:04:11Z | DB-CORE-01 | Authentication activity recorded for svc_backup.
2026-09-16T12:05:42Z | DB-CORE-01 | New service WinUpdateSvc was observed on the host.
2026-09-16T12:07:18Z | DB-CORE-01 | Service process initiated command execution.
2026-09-16T12:08:31Z | DB-CORE-01 | PowerShell process executed an encoded command.
2026-09-16T12:10:06Z | DB-CORE-01 | Command-line encoding anomaly was recorded by the baseline system.
2026-09-16T12:12:44Z | DB-CORE-01 | Subsequent network activity was associated with the newly created service.

## Affected Assets
| HOST | CRITICALITY | DATA_CLASS | ZONE |
|---|---|---|---|
| DB-CORE-01 | CRITICAL | DATABASE | SERVER-CORE |

## Indicators of Compromise
| TYPE | VALUE | CONFIDENCE | SOURCE |
|---|---|---|---|
| service_name | WinUpdateSvc | high | IOC feed |
| account | svc_backup | high | IOC feed |
| ip | 185[.]71[.]66[.]24 | high | IOC feed |

## ATT&CK Mapping
| TECHNIQUE | NAME | EVIDENCE |
|---|---|---|
| T1078 | Valid Accounts | svc_backup was associated with the observed database-server activity. |
| T1543.003 | Windows Service | WinUpdateSvc was newly observed and associated with execution activity. |
| T1059.001 | PowerShell | Encoded PowerShell command execution was recorded. |
| T1027 | Obfuscated/Compressed Files and Information | Command-line encoding anomaly was observed in the PowerShell execution. |
| T1071.001 | Web Protocols | Network activity associated with the service used web protocol traffic. |

## Detection Performance
Rule fired: 006_powershell_encoded_command
Rule fired: 012_new_service
Rule fired: 004_unknown_destination
Rule fired: 015_suricata_c2_indicator
Rule should have fired but did not: 019_service_persistence_chain

## Recommended Actions
1. Isolate DB-CORE-01 from unnecessary network communication while preserving forensic evidence.
2. Disable and rotate credentials associated with svc_backup after validating dependent backup operations.
3. Stop and quarantine WinUpdateSvc pending administrator validation.
4. Collect PowerShell, service, process, and network telemetry from the incident window.
5. Search enterprise telemetry for WinUpdateSvc, svc_backup, and the supplied destination IOC.
6. Review database-server persistence controls and service-creation monitoring.

## Evidence References
EVT-20260916-12117
EVT-20260916-12123
EVT-20260916-12131
EVT-20260916-12144
EVT-20260916-12152
EVT-20260916-12166
