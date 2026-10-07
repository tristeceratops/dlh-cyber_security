#!/bin/bash

INVENTORY="4x05/reference/meddefense_asset_inventory.txt"

if [ ! -f "$INVENTORY" ]; then
    echo "ERROR: Missing $INVENTORY"
    exit 1
fi

echo "================================================================"
echo "   DATA EXPOSURE ASSESSMENT"
echo "   HEALTHBANE vs MedDefense Health Systems"
echo "================================================================"
echo

echo "COMPROMISED SYSTEM MAPPING:"
echo
printf "  %-16s %-22s %-16s %-20s\n" \
    "Host" "Role" "Sensitivity" "Access Level"
printf "  %-16s %-22s %-16s %-20s\n" \
    "----------------" "----------------------" "----------------" "--------------------"

printf "  %-16s %-22s %-16s %-20s\n" \
    "WS-RECV-03" "Records workstation" "MEDIUM-HIGH" "CONFIRMED ACCESS"
printf "  %-16s %-22s %-16s %-20s\n" \
    "SRV-HEALTH-DB" "Patient health DB" "CRITICAL / PHI" "CONFIRMED ACCESS"
printf "  %-16s %-22s %-16s %-20s\n" \
    "SRV-INS-DB" "Insurance / billing" "HIGH / PII+PHI" "PROBABLE ACCESS"
printf "  %-16s %-22s %-16s %-20s\n" \
    "SRV-FILE-01" "Department file server" "MEDIUM" "NO DIRECT ACCESS"
printf "  %-16s %-22s %-16s %-20s\n" \
    "SRV-DC-01" "Domain Controller" "HIGH" "POSSIBLE ACCESS"

echo
echo "ACCESS BASIS:"
echo
echo "  WS-RECV-03:"
echo "    Confirmed compromised pivot host."
echo "    Data staging occurred under C:\\Users\\Public\\Tmp."
echo
echo "  SRV-HEALTH-DB:"
echo "    CONFIRMED. 4x05 memory evidence shows sync_healthdata.ps1"
echo "    querying SRV-HEALTH-DB / health_records."
echo "    Results were written to query_results.csv and subsequently"
echo "    compressed into staging archives."
echo
echo "  SRV-INS-DB:"
echo "    PROBABLE. 4x04 confirms PsExec, WMI and PSRemoting access"
echo "    from WS-RECV-03. The host contains claims, billing and"
echo "    diagnosis-linked member data. Direct database reads were"
echo "    not independently recovered."
echo
echo "  SRV-FILE-01:"
echo "    NO DIRECT ACCESS EVIDENCE. It was not identified as a lateral"
echo "    movement target in 4x04 and no file-server collection artifact"
echo "    was recovered in 4x05."
echo
echo "  SRV-DC-01:"
echo "    POSSIBLE. 4x04 confirms PsExec/PSRemoting access and"
echo "    Get-ADUser execution. AD authentication material was therefore"
echo "    accessible, but no evidence shows that NTDS.dit or domain"
echo "    credential stores were dumped from the DC."

echo
echo "EXFILTRATION STATUS:"
echo
echo "  Data staged on WS-RECV-03:              YES"
echo "  Recovered staging artifacts:            3"
echo "  query_results.csv:                      8.4 MB"
echo "  staging_export_001.zip:                14.2 MB"
echo "  staging_export_002.zip:                11.8 MB"
echo "  Total recovered staging size:           34.4 MB"
echo
echo "  Data transmitted externally:             YES"
echo "  Primary destination:                    185.220.101.45:443"
echo "  Protocol:                               HTTPS / established C2"
echo "  Confirmed exfiltration bursts:"
echo "    2026-05-08  14,219,484 bytes"
echo "    2026-05-11  11,802,944 bytes"
echo "    2026-05-13   8,419,232 bytes"
echo "    --------------------------------"
echo "    Total       34,441,660 bytes"
echo
echo "  Firewall comparison:"
echo "    EXFIL_BURST outbound total:           34,441,660 bytes"
echo "    Recovered staging artifacts:          34,441,660 bytes"
echo "    Assessment:                           SIZE MATCH"
echo
echo "  Secondary C2:"
echo "    203.0.113.47:8443"
echo "    14,218 bytes outbound observed."
echo "    This traffic is insufficient to attribute the main data"
echo "    transfer to the secondary channel."
echo
echo "  CONCLUSION:"
echo "    Data staging is confirmed and the recovered staging volume"
echo "    exactly matches the firewall-recorded exfiltration bursts"
echo "    over the known C2 at 185.220.101.45:443."
echo "    The evidence therefore supports COMPLETED TRANSMISSION of"
echo "    the recovered staging volume, rather than an exfiltration"
echo "    attempt interrupted before transmission."
echo
echo "  Containment:"
echo "    WS-RECV-03 isolation: 2026-05-18 13:42 CDT"
echo "    Memory capture:       2026-05-18 14:18 CDT"
echo "    Disk imaging:         2026-05-18 19:45 CDT"

echo
echo "DATA EXPOSURE BY TYPE:"
echo
echo "  PATIENT HEALTH RECORDS (PHI)"
echo "    Status:               CONFIRMED ACCESSED AND EXFILTRATED"
echo "    Source:               SRV-HEALTH-DB / health_records"
echo "    Evidence:"
echo "      - sync_healthdata.ps1 queries health_records"
echo "      - query_results.csv recovered from WS-RECV-03"
echo "      - staging archives recovered"
echo "      - 34,441,660-byte firewall exfiltration matches staging"
echo "    Estimated affected dataset:"
echo "      Up to approximately 47,000 patient identities are present"
echo "      in the database. The exact number of records represented"
echo "      by the recovered CSV/archive contents was not established."
echo
echo "  INSURANCE / BILLING DATA"
echo "    Status:               POTENTIALLY EXPOSED"
echo "    Source:               SRV-INS-DB"
echo "    Evidence:"
echo "      - PsExec access confirmed"
echo "      - WMI access confirmed"
echo "      - PSRemoting confirmed"
echo "      - svc_healthsync was abused for lateral movement"
echo "    Limitation:"
echo "      No recovered artifact directly proves that claims or billing"
echo "      tables were queried or included in the exfiltrated archives."
echo "    Inventory scope:      ~51,000 member identities"
echo
echo "  EMPLOYEE RECORDS"
echo "    Status:               NOT EXPOSED"
echo "    Evidence:"
echo "      - No HR-system access identified"
echo "      - No employee-record staging artifact recovered"
echo "      - No evidence of collection from employee benefit data"
echo "    Inventory scope:      ~320 employee records on SRV-FILE-01"
echo
echo "  OPERATIONAL DATA"
echo "    Status:               POTENTIALLY EXPOSED"
echo "    Evidence:"
echo "      - Domain Controller accessed remotely"
echo "      - Get-ADUser executed on SRV-DC-01"
echo "      - Internal authentication/domain information was therefore"
echo "        exposed to the attacker"
echo "    Limitation:"
echo "      No evidence establishes bulk export of AD databases or"
echo "      Group Policy data."
echo
echo "  FILE-SERVER IMAGING DATA"
echo "    Status:               NOT EXPOSED"
echo "    Evidence:"
echo "      No lateral-movement event or collection artifact identifies"
echo "      SRV-FILE-01 / shared\\imaging as a collection source."

echo
echo "REGULATORY ASSESSMENT:"
echo
echo "  HIPAA breach notification threshold:    LIKELY MET"
echo
echo "  Basis:"
echo "    1. SRV-HEALTH-DB is classified as CRITICAL PHI."
echo "    2. Unauthorized access to health_records is directly evidenced."
echo "    3. Query results were recovered from attacker staging."
echo "    4. The staging volume matches 34,441,660 bytes transmitted"
echo "       to the known external C2."
echo "    5. The inventory identifies approximately 47,000 patient"
echo "       identities in the affected database."
echo
echo "  Important qualification:"
echo "    This script provides an incident-response assessment, not a"
echo "    final legal determination. HIPAA notification obligations"
echo "    require the organization's formal breach-risk assessment."
echo
echo "  Estimated scope:"
echo "    Confirmed PHI source:       ~47,000 patient identities"
echo "    Potential secondary source: ~51,000 insurance members"
echo "    Employee records:            ~320"
echo "    Imaging records:             ~8,400"
echo "    These figures must NOT be added directly because populations"
echo "    overlap. The inventory estimates a combined maximum cohort of"
echo "    approximately 50,000-55,000 deduplicated individuals if all"
echo "    three PHI sources were ultimately confirmed exposed."

echo
echo "MITIGATING FACTORS:"
echo "  [*] Incident response isolated WS-RECV-03 after detection."
echo "  [*] Memory and disk evidence were acquired for reconstruction."
echo "  [*] Patient SSNs are encrypted at rest on SRV-HEALTH-DB."
echo "  [*] Database access controls limited normal service-account use."
echo "  [*] svc_healthsync access from WS-RECV-03 was anomalous and"
echo "      detectable because the inventory defines a restricted"
echo "      source path."
echo "  [*] No evidence currently confirms access to every PHI source."
echo
echo "LIMITATIONS:"
echo "  [*] Exact records contained in the 34.4 MB export were not"
echo "      reconstructed from the supplied evidence."
echo "  [*] SRV-INS-DB access is confirmed, but direct data reads are"
echo "      not confirmed."
echo "  [*] SRV-DC-01 access is confirmed, but bulk credential/database"
echo "      extraction from the DC is not confirmed."
echo "  [*] The disk-analysis timestamps for the staging artifacts are"
echo "      reported as Feb 10-11, while the primary IR timeline is"
echo "      May 2026. This affects precise temporal placement but does"
echo "      not remove the recovered-artifact or firewall evidence."
echo
echo "RECOMMENDED ACTION:"
echo "  Treat the incident as a potential reportable PHI breach and"
echo "  initiate formal HIPAA breach-risk assessment immediately."
echo "  Preserve the recovered CSV/ZIP artifacts, reconstruct their"
echo "  record contents, and determine whether SRV-INS-DB data was"
echo "  included before finalizing the notification population."
echo
echo "================================================================"