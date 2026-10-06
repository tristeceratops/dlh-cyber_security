#!/bin/bash

set -euo pipefail

printf '\n================================================================\n'
printf '   DETECTION ENGINEERING - Hunt-Derived Rules\n'
printf '================================================================\n\n'

printf '=== WAZUH-STYLE RULE DRAFTS ===\n\n'
printf '[Rule 100100] PsExec from Non-Admin Workstation\n'
printf '  Behavior: PsExec execution from a source host other than WS-ADMIN-01\n'
printf '  Evidence: Hunt Task 4 - PsExec from WS-RECV-03 using svc_healthsync\n'
printf '  FP Rate: VERY LOW\n'
printf '  Baseline Logic: allow only WS-ADMIN-01, Robert Kim, approved server targets, and 08:00-18:00 weekday windows\n\n'

printf '[Rule 100101] LSASS Memory Access from Non-System Process\n'
printf '  Behavior: Non-allowlisted process accesses lsass.exe with memory-read rights\n'
printf '  Evidence: Hunt Task 6 - debug_tool.exe accessed lsass.exe with 0x1010\n'
printf '  FP Rate: LOW\n'
printf '  Baseline Logic: allow known system and security processes; alert on other SourceImage values\n\n'

printf '[Rule 100102] Service Account Interactive Logon from Workstation\n'
printf '  Behavior: svc_* account authenticates from a workstation or uses an unauthorized logon type\n'
printf '  Evidence: Hunt Task 9 - svc_healthsync used from WS-RECV-03 with NTLM\n'
printf '  FP Rate: VERY LOW\n'
printf '  Baseline Logic: compare TargetUserName, WorkstationName, LogonType, and authentication package with the service-account matrix\n\n'

printf '[Rule 100103] WMI Remote Child Process Anomaly\n'
printf '  Behavior: wmiprvse.exe spawns cmd.exe or powershell.exe on a protected server\n'
printf '  Evidence: Hunt Task 5 - WMI remote execution and enumeration on server targets\n'
printf '  FP Rate: MEDIUM\n'
printf '  Baseline Logic: allow documented WS-ADMIN-01 inventory windows; alert on other sources, targets, or off-hours activity\n\n'

printf '=== NETWORK RULE DRAFTS ===\n\n'
printf '[Rule 9000030] SMB Lateral Movement - PsExec Service Installation\n'
printf '  Behavior: SMB connection followed by ADMIN$ service installation and remote process creation\n'
printf '  Evidence: Hunt Task 4 - PsExec lateral movement to server targets\n'
printf '  FP Rate: LOW\n'
printf '  Baseline Logic: allow documented maintenance from WS-ADMIN-01; alert on workstation sources or off-hours sequences\n\n'

printf '=== DETECTION POSTURE UPDATE ===\n'
printf '  Before hunt: 55%% observed coverage\n'
printf '  After hunt: approximately 80%% coverage\n'
printf '  Improved ATT&CK coverage: T1021.002, T1003.001, T1047, T1021.006, T1078.002, T1550.002\n'
printf '  New posture: behavior-based host, identity, process, and network detections\n\n'

printf '================================================================\n'
