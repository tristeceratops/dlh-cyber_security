# The Complete Control Matrix

## Introduction

### Goal
Produce a consolidated, authoritative control inventory that integrates all controls identified throughout the project, mapped against the assets they protect.

### Context
You now have controls from multiple sources: the artifact analysis (Task 4), the physical observations (Task 3), the compensating controls you designed (Task 6) and various mentions throughout the incident analysis and data mapping. James Chen needs a single, definitive document.

"When the Board asks 'What security do we have ?' I need to hand them one page. Not five documents."

## Answer

The registry below consolidates the controls documented across Tasks 0, 3, 4, 6, and the later analysis notes. Effectiveness uses a simple three-point scale: Strong, Adequate, Weak. Where a control was designed as part of a compensating strategy, it is still classified by its direct function in the taxonomy and called out in the source note.

### Part 1: Control Registry

| Control ID | Control Name | Category | Function | Asset(s) Protected | Effectiveness | Evidence/Source |
|---|---|---|---|---|---|---|
| C-001 | Perimeter Firewall | Technical | Preventive | Internal network, DMZ, servers, VPN traffic | Adequate | [Task 4](./4-control_inventory.md); [Task 0](./0-environment_summary.md) |
| C-002 | Firewall Logging | Technical | Detective | Network traffic, firewall events | Weak | [Task 4](./4-control_inventory.md); [Task 5](./5-control_gaps.md) |
| C-003 | SSH Key-Based Authentication | Technical | Preventive | [ehr-srv-01](./7-asset_registry.md) | Strong | [Task 4](./4-control_inventory.md) |
| C-004 | Root Login Disabled | Technical | Preventive | Linux servers | Strong | [Task 4](./4-control_inventory.md) |
| C-005 | Password Policy | Administrative | Preventive | User accounts | Adequate | [Task 4](./4-control_inventory.md); [Task 0](./0-environment_summary.md) |
| C-006 | Account Lockout Policy | Administrative | Preventive | User accounts | Adequate | [Task 4](./4-control_inventory.md) |
| C-007 | Endpoint Protection (Sophos) | Technical | Preventive | Managed Windows workstations | Adequate | [Task 4](./4-control_inventory.md); [Task 0](./0-environment_summary.md) |
| C-008 | Scheduled Backups | Technical | Corrective | Critical servers, virtual machines, EHR, billing, file services | Weak | [Task 4](./4-control_inventory.md); [Task 5](./5-control_gaps.md) |
| C-009 | Visitor Access Control | Physical | Preventive | Main hospital entrance | Adequate | [Task 4](./4-control_inventory.md); [Task 3](./3-physical_assessment.md) |
| C-010 | CCTV Surveillance | Physical | Detective | Building entrances, parking areas | Adequate | [Task 4](./4-control_inventory.md); [Task 3](./3-physical_assessment.md) |
| C-011 | Security Awareness Training | Administrative | Preventive | Employees | Adequate | [Task 4](./4-control_inventory.md); [Task 5](./5-control_gaps.md) |
| C-012 | System and Security Logging | Technical | Detective | Network devices, servers, EHR systems | Weak | [Task 4](./4-control_inventory.md); [Task 5](./5-control_gaps.md) |
| C-013 | MFA for James Chen's Personal Account | Technical | Preventive | James Chen account and limited admin/cloud access | Weak | [Task 0](./0-environment_summary.md) |
| C-014 | HID Badge Access System | Physical | Preventive | Controlled doors, badge access audit | Weak | [Task 0](./0-environment_summary.md); [Task 3](./3-physical_assessment.md) |
| C-015 | Network Segmentation and Firewall ACLs | Technical | Preventive | MRI control workstation, PACS path, clinical network | Weak | [Task 6](./6-compensating_controls.md) |
| C-016 | Network Intrusion Detection/Monitoring | Technical | Detective | MRI VLAN and adjacent network paths | Weak | [Task 6](./6-compensating_controls.md); [Task 5](./5-control_gaps.md) |
| C-017 | Strict Access Control and Privileged Account Management | Administrative | Preventive | MRI workstation and radiology admin access | Weak | [Task 6](./6-compensating_controls.md) |
| C-018 | Physical Security Controls (MRI Operator Room) | Physical | Preventive | MRI control workstation, removable media handling | Weak | [Task 6](./6-compensating_controls.md) |

### Part 2: Updated Control Summary Matrix

Effectiveness scoring uses Strong = 3, Adequate = 2, Weak = 1. The average shown in each cell is the mean score for the controls in that category/function, rounded to the nearest label.

| Category | Preventive | Detective | Corrective | Compensating | Deterrent |
|---|---|---|---|---|---|
| Technical | 6 controls, avg 2.0 (Adequate) | 3 controls, avg 1.0 (Weak) | 1 control, avg 1.0 (Weak) | 0 controls, n/a | 0 controls, n/a |
| Administrative | 4 controls, avg 1.8 (Adequate) | 0 controls, n/a | 0 controls, n/a | 0 controls, n/a | 0 controls, n/a |
| Physical | 3 controls, avg 1.3 (Weak) | 1 control, avg 2.0 (Adequate) | 0 controls, n/a | 0 controls, n/a | 0 controls, n/a |

Note: the MRI compensating strategy from Task 6 is represented by the relevant technical, administrative, and physical controls above. The project did not identify a separately labeled compensating control that needed its own taxonomy bucket.

### Part 3: Control Coverage Map

In this section, the Compensating column captures controls that stand in for an ideal security posture on legacy or otherwise hard-to-fix assets, especially the MRI workstation scenario from Task 6.

| Critical Asset | Preventive | Detective | Corrective | Compensating | Coverage Assessment |
|---|---|---|---|---|---|
| [A-001 ehr-srv-01](./7-asset_registry.md) / EHR application tier | C-001, C-003, C-004, C-005, C-006, C-007, C-013 | C-002, C-012 | C-008 | None | Partially Protected - strong basic hardening, but no SIEM, no broad MFA, and recovery depends on same-site backups. |
| [A-002 ehr-db-01](./7-asset_registry.md) / EHR database | C-001, C-005, C-006, C-013, C-015 | C-002, C-012, C-016 | C-008 | None | Under-Protected - the database is exposed too broadly and lacks DB-specific segmentation and continuous monitoring. |
| [A-005 ad-dc-01](./7-asset_registry.md) / Primary domain controller | C-001, C-005, C-006, C-009, C-010, C-014 | C-002, C-012 | C-008 | None | Partially Protected - identity controls exist, but the environment still lacks mature detective coverage and resilient recovery. |
| [A-021 MRI-CTRL-WS (WS-RAD-01)](./7-asset_registry.md) / MRI control workstation | C-015, C-017, C-018 | C-016 | None identified | C-015, C-016, C-017, C-018 | Under-Protected - the key safeguards are compensating measures rather than established baseline controls, and the host remains EOL. |
| [A-013 FortiGate-100F](./7-asset_registry.md) / Perimeter firewall | C-005, C-006, C-009, C-010, C-014 | C-002, C-012 | None identified | None | Partially Protected - the firewall is physically and logically controlled, but there is no strong recovery plan for configuration loss and no centralized monitoring. |

The risk pattern is consistent across the environment: preventive controls exist, but detective and corrective depth is thin, and the most fragile assets rely on compensating measures rather than first-class security architecture.