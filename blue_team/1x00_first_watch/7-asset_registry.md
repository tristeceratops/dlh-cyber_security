# 7. The Asset Registry

## Introduction


### Goal
Build a comprehensive, structured asset inventory by consolidating information from multiple sources accumulated throughout the project.

### Context
James Chen needs a single authoritative source of truth for MedDefense assets. Right now, the information is scattered across your Environment Summary (Task 0), the incidents you analyzed (Tasks 1-2), the physical observations (Task 3), the controls you documented (Task 4) and the MRI situation (Task 6).

"I've also asked Sarah Park to pull a network scan summary," James says, handing you a new document. "Cross-reference everything. If an asset appears in one source but not another, I want to know about it."

---

## Asset Registry

| Asset ID | Name | Type | Location | Owner (Dept) | OS/Platform | Critical Services | Network Segment | Status | Notes |
|---|---|---|---|---|---|---|---|---|---|
| A-001 | ehr-srv-01 | Server | Central Hospital (Server Room) | Clinical Applications (IT) | Ubuntu 20.04 | EHR application/API | 10.10.2.0/24 | Active | In onboarding and scan; SSH hardened per control inventory. |
| A-002 | ehr-db-01 | Data Store | Central Hospital (Server Room) | Database Admin (IT) | PostgreSQL on Ubuntu 20.04 | EHR database backend | 10.10.2.0/24 | Active | Exposes 5432 broadly per scan notes; should be restricted to EHR app tier. |
| A-003 | pacs-srv-01 | Server | Central Hospital (Radiology backend) | Radiology + IT | Windows Server 2016 | PACS image storage/transfer | 10.10.2.0/24 | Active | Required endpoint for MRI study transfer. |
| A-004 | billing-srv-01 | Server | Central Hospital (Server Room) | Finance/Billing + IT | Ubuntu 18.04 | Claims and billing processing | 10.10.2.0/24 | Deprecated | EOL OS and repeat compromise history (ransomware + cryptominer symptom). |
| A-005 | ad-dc-01 | Server | Central Hospital (Server Room) | Identity Services (IT) | Windows Server 2019 | Active Directory auth/DNS | 10.10.2.0/24 | Active | Core identity infrastructure. |
| A-006 | ad-dc-02 | Server | Central Hospital (Server Room) | Identity Services (IT) | Windows Server 2019 | Active Directory redundancy | 10.10.2.0/24 | Active | Secondary DC for resiliency. |
| A-007 | file-srv-01 | Server | Central Hospital (Server Room) | Infrastructure (IT) | Windows Server 2016 | Department file shares | 10.10.2.0/24 | Active | Supports org-wide file services. |
| A-008 | print-srv-01 | Server | Central Hospital (Server Room) | Infrastructure (IT) | Windows Server 2012 R2 | Print queue/spooling | 10.10.2.0/24 | Deprecated | End of support (Oct 2023); appears in onboarding and scan. |
| A-009 | backup-srv-01 | Server | Central Hospital (Server Room) | Infrastructure (IT) | Ubuntu 22.04 (Veeam Agent) | Backup orchestration | 10.10.2.0/24 | Active | Nightly backup jobs documented. |
| A-010 | NAS-01 | Data Store | Central Hospital (Same rack as prod) | Infrastructure (IT) | Synology DSM 7 | Backup repository/network storage | 10.10.2.0/24 | Active | Same-room backup placement creates single-site risk. |
| A-011 | web-srv-01 | Application | Central Hospital (DMZ) | Web Services (IT/Marketing) | Ubuntu 20.04 | Public website + patient portal app stack | 10.10.2.0/24 (DMZ role documented) | Active | DMZ role documented in onboarding, reachable in scan. |
| A-012 | ws-srv-01 | Server | Westside Clinic (Server Closet) | Westside Operations + IT | Windows Server 2016 | Local file sharing/scheduling | 10.10.10.0/24 | Active | Westside core server confirmed by scan. |
| A-013 | FortiGate-100F | Network Device | Central Hospital perimeter | Network Team (IT) | Fortinet FortiOS | Perimeter firewall, VPN termination, ACLs | Core transit across 10.10.0.0/16 | Active | Control inventory identifies as primary perimeter control. |
| A-014 | Westside-Netgear-Router | Network Device | Westside Clinic edge | Network Team (IT) | Netgear firmware | Site-to-site IPSec to Central | 10.10.10.0/24 gateway | Active | Consumer-grade device for clinic edge; scanned at 10.10.10.1. |
| A-015 | Cisco-Core-Switch | Network Device | Central Hospital MDF | Network Team (IT) | Cisco IOS (model unknown) | Core switching for hospital network | 10.10.0.0/16 core | Active | Model unresolved in onboarding; no full segmentation enforced. |
| A-016 | Central-UniFi-AP-Fleet | Network Device | Central Hospital floors/lobby/cafe/garage/basement/ER | Network Team (IT) | Ubiquiti UniFi | Corporate/staff wireless access | 10.10.1.0/24 mgmt presence | Active | 12 APs in onboarding and scan (AP-1F-01..AP-ER). |
| A-017 | Central-Windows-Workstations-Fleet | Endpoint | Central Hospital clinical/admin areas | IT Desktop Support + Department Managers | Windows 10 (19045) | EHR access, admin operations | 10.10.1.0/24 | Active | ~320 documented; scan confirms many WS-* hosts (~290 additional omitted). |
| A-018 | HQ-Workstation-Fleet | Endpoint | Corporate HQ | IT Desktop Support | Windows 10/11 | Corporate admin/finance/legal workflows | 10.10.20.0/24 | Active | ~120 HQ workstations observed in scan. |
| A-019 | HQ-Laptop-Fleet | Endpoint | Corporate HQ / mobile users | IT Desktop Support | Windows 11 | Mobile workforce access | 10.10.20.0/24 (intermittent) | Active | Intermittent appearance in scan aligns with mobile usage. |
| A-020 | ER-Thin-Client-Fleet | Endpoint | Central Hospital ER | Clinical IT (IT) | Linux thin client | Clinical terminal access | 10.10.1.0/24 | Active | Identified as TC-ER-* in scan; onboarding estimated ~60 thin clients. |
| A-021 | MRI-CTRL-WS (WS-RAD-01) | IoT Medical | Central Hospital Radiology MRI suite | Radiology + Biomed + IT | Windows XP Embedded / XP SP3 signature | MRI control workstation and PACS transfer | 10.10.1.70 on flat internal network | Deprecated | Explicitly EOL, cannot be patched due certification constraints. |
| A-022 | Siemens-MAGNETOM-MRI | IoT Medical | Central Hospital Radiology | Radiology + Biomed | Vendor embedded platform | MRI imaging acquisition | Coupled to MRI control network path | Active | Business-critical imaging device; relies on legacy control station. |
| A-023 | Philips-IntelliVue-Monitor-Fleet | IoT Medical | ICU/ER/3F and other care units | Clinical Engineering (Biomed) | Philips IntelliVue firmware | Bedside monitoring and vitals telemetry | 10.10.3.0/24 | Active | ~80 documented; scan shows many MON-* devices (65 additional omitted). |
| A-024 | BD-Alaris-Pump-Fleet | IoT Medical | ICU/ER/3F and other care units | Clinical Engineering (Biomed) | BD Alaris fw 12.1.2 | Infusion pump control/monitoring | 10.10.3.0/24 | Active | Known vulnerable firmware; broad management-plane exposure. |
| A-025 | Nurse-Call-System | Physical Infrastructure | Central Hospital nursing units | Facilities + Nursing Ops + IT | IP-based nurse call platform | Nurse alerting/dispatch | 10.10.3.0/24 | Active | Hosts NURSE-CALL-01/02 discovered in scan. |
| A-026 | HID-Badge-Access-System | Physical Infrastructure | Central Hospital controlled doors | Facilities Security + IT | HID Global platform integrated with AD | Door access control and audit | 10.10.3.0/24 | Active | Multiple badge-reader endpoints found in scan. |
| A-027 | UNKNOWN-01 | Server | Central Hospital server subnet | Unknown (possible unsanctioned owner) | Linux 4.x | SSH + web services on 8888/9090 | 10.10.2.99 | Shadow IT (unmanaged) | Explicitly undocumented in scan note. |
| A-028 | WESTSIDE-UNKNOWN-3000 | Server | Westside Clinic subnet | Unknown (possible unsanctioned owner) | Linux 5.x | SSH + HTTP + port 3000 service | 10.10.10.200 | Shadow IT (unmanaged) | Explicitly undocumented in scan note; likely ad hoc tool host. |
| A-029 | Physician-iPad-Fleet | Endpoint | Central Hospital / provider mobile use | Clinical Leadership + IT | iPadOS (unknown versions) | Mobile chart/review workflows | Unknown / likely Wi-Fi segment | Unknown | Documented in onboarding (~25), not identifiable in scan summary. |
| A-030 | GE-Revolution-CT | IoT Medical | Central Hospital Radiology | Radiology + Biomed | OS unknown | CT imaging | Not clearly mapped in scan | Unknown | Documented in onboarding; no clear matching hostname in scan export. |
| A-031 | Westside-XRAY-WS (WS-WC-XRAY) | IoT Medical | Westside Clinic Imaging | Westside Imaging + Biomed + IT | Vendor-specific (unknown) | X-ray workstation integration | 10.10.10.100 | Active | Appears in scan but was not explicitly itemized in prior documentation. |
| A-032 | Patient-Portal-Service | Application | Public-facing (DMZ-backed) | Clinical Applications + Web Services | Web app on Linux backend | Patient results/portal access | Internet -> DMZ -> internal dependencies | Active | Broken access control incident indicates application-layer risk (Task 1). |
| A-033 | Microsoft-365-Tenant | Application | Cloud (SaaS) | IT + all departments | Microsoft 365 E3 | Email/collaboration/productivity | Internet (cloud) | Active | Critical enterprise SaaS documented in onboarding. |
| A-034 | DrPatel-Personal-NAS | Data Store | Cardiology office | Cardiology (unapproved) | NAS appliance | Research data storage | Wall port / unknown segment | Shadow IT | Personal device plugged into office wall port; migrate data to approved storage and retire the device. |
| A-035 | Marketing-Shared-Google-Drive | Application | Cloud (personal account) | Marketing (unapproved) | Google Drive / Gmail | Media files and press communications | Internet (cloud) | Shadow IT | Shared drive linked to personal Gmail; migrate content to approved corporate collaboration platform. |
| A-036 | Second-Floor-Raspberry-Pi-Monitor | Network Device | Central Hospital second floor | Unknown (previous intern / Marcus request) | Raspberry Pi / Linux | Network monitoring / telemetry | Unknown | Shadow IT | Unmanaged monitoring device with no current owner; remove and rebuild under IT governance if still needed. |

## Reconciliation Notes

### 1) In Network Scan But Not In Prior Documentation

- A-027 `UNKNOWN-01` (10.10.2.99): undocumented Linux host in server subnet; classify as **Shadow IT (unmanaged)** pending owner attribution.
- A-028 `WESTSIDE-UNKNOWN-3000` (10.10.10.200): undocumented Linux device at Westside; classify as **Shadow IT (unmanaged)**.
- A-031 `Westside-XRAY-WS` (10.10.10.100): scan identifies a vendor-specific X-ray workstation not explicitly enumerated in earlier task inventories.
- Additional explicitly named endpoints in scan (for example TC-ER-* and department-specific WS-* patterns) exceed the granularity of the onboarding inventory and indicate the documented endpoint inventory was high-level rather than complete.

### 2) In Documentation But Not Clearly Visible In Network Scan

- `Siemens-MAGNETOM-MRI` hardware node (A-022) appears only indirectly via its control workstation (A-021); likely non-IP scanner component or not separately responding.
- `GE-Revolution-CT` (A-030) was documented in onboarding but has no unambiguous hostname/IP in this scan output.
- `Physician-iPad-Fleet` (A-029) documented (~25 devices) but not visible in scan summary, likely due to Wi-Fi segmentation differences, power state, or scan window timing.
- `Unknown server (Westside)` from onboarding appears unresolved; may correspond to A-028 but ownership/function are still unverified.

### 3) Cross-Source Discrepancies / Contradictions

- **Network architecture contradiction resolved by scan evidence:** onboarding described a flat 10.10.0.0/16 and uncertainty around segmentation; scan confirms effective flat reachability across subnets with no enforced isolation.
- **DMZ documentation vs observed exposure context:** web server is documented as DMZ-hosted, but broad east-west reachability elsewhere suggests internal boundary controls are weaker than expected in practice.
- **Asset count drift:** onboarding endpoint counts are approximate and 8 months old; scan shows comparable but not exact numbers (for example HQ laptops ~25 observed vs ~30 documented).
- **Legacy risk confirmation:** Task 6 flagged MRI Windows XP risk; scan independently confirms EOL host `WS-RAD-01` at 10.10.1.70.
- **Control efficacy gap:** Task 4 control set (firewall, endpoint tooling) coexists with scan evidence of broadly exposed management/data ports (3306, 5432, 5000/5001, 3389), indicating control scope/segmentation mismatch rather than full absence of controls.