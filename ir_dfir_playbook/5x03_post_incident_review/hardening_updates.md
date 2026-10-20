# Hardening Updates: IR-2026-0414-01

**Incident:** IR-2026-0414-01  
**Related evidence:** `forensic_findings_summary.md`  
**Implementation status:** Proposed — configuration and validation required  
**Gap mapping note:** Confirm all GAP IDs against Task 2's authoritative gap register before closing remediation tickets. GAP-003 and GAP-004 are used for PowerShell hardening as specified in the task example; other IDs below are provisional mappings, not independently verified Task 2 identifiers.

---

## HRD-001: PowerShell Constrained Language Mode

**Closes:** GAP-003, GAP-004

**Incident evidence:**
- PowerShell PID 7812 launched MSBuild PID 8104 on `WST-WS-031`.
- The PowerShell command used execution-policy bypass, hidden-window, and encoded-command options.
- PowerShell PID 4402 also launched MSBuild PID 5108 on `WST-WS-017`.
- Forensic evidence confirmed the MSBuild execution technique associated with ATT&CK T1127.001.

**Configuration:**

**Preferred enforcement:** Deploy an application control policy using Windows Defender Application Control (WDAC) or AppLocker to enforce Constrained Language Mode for standard users. A registry preference alone should not be treated as a reliable security boundary.

- GPO policy path for application control: configure and deploy the organization's WDAC policy or AppLocker policy through Group Policy and the relevant endpoint-management process.
- Legacy PowerShell lockdown registry setting, where supported for the environment:
  - Key: `HKLM\System\CurrentControlSet\Control\Session Manager\Environment`
  - Value name: `__PSLockdownPolicy`
  - Value type: `REG_SZ`
  - Value data: `4`

**Important implementation note:** `__PSLockdownPolicy` is not the preferred enterprise enforcement mechanism and must not be relied on as the sole control. Validate the actual language mode and the application-control policy in effect. Use WDAC/AppLocker enforcement to prevent users from bypassing the intended restriction by changing their execution context or launching alternative tools.

**Effect:** Constrained Language Mode restricts access to many .NET and other language features available in Full Language Mode. This reduces the ability of untrusted PowerShell scripts to use .NET type instantiation and related techniques. It does not, by itself, block every script-block operation or prevent every LOLBin execution technique.

**Applies to:** Standard, non-administrative accounts on clinical and administrative workstations, including `WST-WS-031` and `WST-WS-017`. Validate compatibility with clinical applications and approved administration workflows before broad enforcement.

**Validation:**

Run as a standard user:

```powershell
$ExecutionContext.SessionState.LanguageMode
```

**Expected:** `ConstrainedLanguage`

Also verify that the effective WDAC/AppLocker policy is enforced and that an unapproved PowerShell test script cannot instantiate a prohibited .NET type.

**Gap IDs addressed:** GAP-003, GAP-004.

---

## HRD-002: AppLocker rule restricting MSBuild.exe

**Closes:** GAP-004; confirm the corresponding Task 2 mapping before closure.

**Incident evidence:**
- `WST-WS-031`: PowerShell PID 7812 launched `MSBuild.exe` PID 8104.
- `WST-WS-017`: PowerShell PID 4402 launched `MSBuild.exe` PID 5108.
- Memory analysis identified an executable anonymous VAD region in the MSBuild process, and network evidence showed outbound connections to the identified command-and-control infrastructure.
- The evidence supports restricting MSBuild execution to approved build and administrative contexts.

**Configuration:**

Use AppLocker's **Executable** rule collection in enforced mode. Create allow rules for the approved administrative group and explicitly named CI/CD service accounts. Ensure there are no broader existing allow rules that unintentionally authorize MSBuild for standard users.

- GPO path: `Computer Configuration > Windows Settings > Security Settings > Application Control Policies > AppLocker > Executable Rules`
- Rule collection: Executable
- Enforcement: `Enforce rules`
- Target executable: `MSBuild.exe`
- Authorized principals:
  - `BUILTIN\Administrators`
  - Explicitly approved CI/CD service accounts, identified by their actual domain and account names.
- Standard users: no effective allow rule for MSBuild.

**Illustrative XML structure:**

The following shows the intended allow-rule structure. Replace the placeholder service-account SID and confirm the path or publisher condition matches the deployed MSBuild installation. Generate and validate the final XML against the AppLocker schema before deployment.

```xml
<AppLockerPolicy Version="1">
  <RuleCollection Type="Exe" EnforcementMode="Enabled">
    <FilePathRule
      Id="11111111-1111-4111-8111-111111111111"
      Name="Allow MSBuild for Administrators"
      Description="Allow MSBuild only for approved administrators"
      UserOrGroupSid="S-1-5-32-544"
      Action="Allow">
      <Conditions>
        <FilePathCondition
          Path="%PROGRAMFILES%\Microsoft Visual Studio\*\MSBuild\*\Bin\MSBuild.exe" />
      </Conditions>
    </FilePathRule>

    <FilePathRule
      Id="22222222-2222-4222-8222-222222222222"
      Name="Allow MSBuild for approved CI service account"
      Description="Replace placeholder SID with approved CI service account SID"
      UserOrGroupSid="REPLACE_WITH_APPROVED_CI_ACCOUNT_SID"
      Action="Allow">
      <Conditions>
        <FilePathCondition
          Path="%PROGRAMFILES%\Microsoft Visual Studio\*\MSBuild\*\Bin\MSBuild.exe" />
      </Conditions>
    </FilePathRule>
  </RuleCollection>
</AppLockerPolicy>
```

**Important implementation notes:**
- The XML above is a structural example, not a complete production policy. Replace the placeholder SID with the real service-account SID; add a separate allow rule for each approved account or approved CI/CD group.
- Confirm all legitimate MSBuild locations, including any installed .NET SDK or Visual Studio Build Tools paths. A rule covering only one path may miss other copies.
- AppLocker allow rules work as part of the effective rule collection. Review existing broad publisher/path rules and test the resulting policy; do not assume a new allow rule alone denies all other users.
- Test in audit mode first, then enforce after validating clinical applications and CI/CD workloads.
- If stronger application-control guarantees are required, evaluate WDAC with a policy that constrains both the executable and the permitted execution context.

**Effect:** Restricts MSBuild execution to explicitly approved administrators and CI/CD identities, reducing the ability of a compromised standard account to use MSBuild as a proxy execution utility.

**Validation:**

As a standard user, attempt to launch the approved MSBuild executable. The attempt should be blocked and recorded in the AppLocker event log. Then verify that an approved CI/CD service account can run the expected build successfully.

**Gap IDs addressed:** GAP-004; reconcile against the authoritative Task 2 gap register.

---

## HRD-003: Conditional Access for VPN authentication from unfamiliar geographies

**Closes:** GAP-001; confirm the corresponding Task 2 mapping before closure.

**Incident evidence:**
- The compromised Office 365 session was first observed at `2026-04-13T18:14:41Z`.
- The origin IP was reported as `45.63.9.88`, geolocated to Russia in the supplied incident summary.
- Azure AD risk signals were suppressed by a Conditional Access rule that relied on a compliant-device requirement.
- The origin and legitimacy of the session remain an investigation item in the incident summary.

**Configuration:**

Configure Microsoft Entra Conditional Access and Identity Protection to challenge or block high-risk sign-ins, including unfamiliar sign-in properties and unexpected geographic access. A device-compliance requirement must not be treated as a substitute for evaluating sign-in risk.

**Policy logic:**

1. **Users:** Include VPN users and other in-scope workforce accounts; exclude emergency-access accounts only through a documented, monitored exception.
2. **Applications:** Include the VPN enterprise application and relevant authentication resources.
3. **Conditions:** Evaluate sign-in risk and unfamiliar sign-in properties. Where supported by the organization's identity-risk tooling, compare the sign-in country with the countries observed for that account during the preceding 30 days.
4. **Grant controls:**
   - Block sign-in when the origin is a prohibited or high-confidence malicious location.
   - Otherwise require step-up multifactor authentication for an unfamiliar country or elevated sign-in risk.
   - Do not grant access solely because the device is marked compliant.
5. **Logging:** Retain sign-in logs and risk detections so that the triggering country, risk decision, and resulting access decision can be audited.

**Implementation limitation:** Standard Conditional Access named locations do not natively implement an arbitrary per-user rolling 30-day country baseline. For that exact requirement, use an identity-risk detection or a supported SIEM/automation workflow that maintains the baseline and raises an appropriate risk signal or initiates a supported access response. Validate the chosen implementation before representing it as an enforced 30-day comparison.

**Effect:** Reduces the likelihood that a stolen session or password can be used from an unfamiliar geography without an additional identity challenge. It also closes the gap created when device compliance is used as the only meaningful access gate.

**Validation:**

Use a controlled test account to simulate an unfamiliar-country sign-in through the approved test process. Confirm in Entra sign-in logs that the policy requires MFA or blocks access, and verify that a compliant-device claim does not override the configured risk decision.

**Gap IDs addressed:** GAP-001; reconcile against the authoritative Task 2 gap register.

---

## HRD-004: Windows Defender Credential Guard

**Closes:** GAP-005; confirm the corresponding Task 2 mapping before closure.

**Incident evidence:**
- Forensic memory analysis found NTLM hash material for `MEDDEFENSE\dmarsh` in LSASS at capture time.
- The finding is consistent with exposure of credential material on the compromised host.
- Credential Guard can isolate supported secrets using virtualization-based security, reducing the ability of ordinary operating-system processes to access protected credential material.

**Configuration:**

**GPO path:**

`Computer Configuration > Administrative Templates > System > Device Guard > Turn On Virtualization Based Security`

Configure the policy to enable virtualization-based security and Credential Guard using the settings supported by the deployed Windows version and organizational security baseline.

**Registry verification:**

Key:

`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`

Value:

- Name: `LsaCfgFlags`
- Type: `REG_DWORD`
- Data:
  - `1` — enable Credential Guard with UEFI lock.
  - `2` — enable Credential Guard without UEFI lock.

Use the organization's approved deployment method and consider the operational and recovery implications of UEFI lock before deployment. The registry value alone is not proof that Credential Guard is running.

**Supported operating systems:**

- Windows 10 Enterprise and Education editions that meet the relevant hardware and virtualization requirements.
- Windows 11 Enterprise and Education editions that meet the relevant requirements; some eligible configurations enable Credential Guard by default, depending on OS release and device configuration.
- Windows Server 2016 and later versions, subject to the edition, hardware, and virtualization requirements of the specific release.

Verify current Microsoft support requirements against the exact Windows build, edition, firmware, and virtualization configuration in use. Credential Guard is not supported on every Windows edition or every hardware configuration.

**Prerequisites and rollout:**
- Enable and validate virtualization-based security.
- Confirm UEFI/firmware virtualization support and required security configuration.
- Validate compatibility with the endpoint's security software and authentication workflows.
- Deploy first to a representative test group, then to clinical and administrative workstations.
- Monitor the Credential Guard operational status and investigate devices where the feature is configured but not running.

**Effect:** Isolates supported credential material in a hypervisor-protected environment, reducing exposure to credential theft from LSASS. It does not eliminate all credential theft techniques or protect every type of secret.

**Validation:**

Run from an elevated PowerShell session:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard `
  -Namespace root\Microsoft\Windows\DeviceGuard |
  Select-Object -ExpandProperty SecurityServicesRunning
```

Confirm the output includes the Credential Guard service indicator (`1`) on the relevant system. Also verify the effective Device Guard policy and check the system's virtualization-based security status. A configured registry value alone is insufficient.

**Gap IDs addressed:** GAP-005; reconcile against the authoritative Task 2 gap register.

---

## Implementation and validation checklist

- [ ] Reconcile all GAP IDs with the Task 2 gap register before changing ticket status.
- [ ] Deploy PowerShell restrictions to a pilot group and verify the effective language mode.
- [ ] Validate AppLocker rules in audit mode; confirm that approved CI/CD builds continue to work.
- [ ] Enforce the MSBuild restriction and verify both denied standard-user execution and allowed approved execution.
- [ ] Test the Conditional Access unfamiliar-geography flow using a controlled account; confirm risk decisions in sign-in logs.
- [ ] Enable Credential Guard on supported pilot endpoints and verify that it is actually running.
- [ ] Record deployment scope, exceptions, test evidence, and remediation ticket references.
- [ ] Reassess the original incident IOCs and monitor for recurrence after controls are enforced.

**Completion criterion:** A control is not considered closed solely because its policy or registry setting exists. Closure requires the corresponding validation test to demonstrate that the intended enforcement is active and that required clinical and CI/CD workflows remain operational.