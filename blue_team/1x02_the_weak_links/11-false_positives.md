# The False Positives

## Introduction

### Goal
Identify and document false positives in the scan report, and understand why validation before action is essential.

### Context
Acting on a false positive wastes resources. Ignoring a true positive creates risk. Telling the difference is one of the most underrated skills in vulnerability management.

The scan report contains 2-3 findings that, upon investigation, are not actual vulnerabilities in MedDefense's specific context. The scanner noted them for investigation by SecurePoint, who flagged at least one explicitly. Your job is to find them all and prove why they are false positives.

## Answer

# False Positive Analysis

Automated vulnerability scanners can generate findings based on version detection, configuration assumptions, or incomplete context. The following findings require validation before remediation effort is committed.

---

## Finding ID: 020

**Reported Vulnerability:**  
OpenSSH Version Outdated — CVE-2023-38408 on 10.10.2.40 (backup-srv-01)

**Why It Is a False Positive:**  
The scanner identified OpenSSH 8.9p1 as vulnerable because the version matches affected releases. However, CVE-2023-38408 requires a specific attack condition: SSH agent forwarding with PKCS#11 support enabled and an attacker-controlled remote system.

The scan report itself notes that this vulnerability may be a false positive because:
- SSH agent forwarding is unlikely on a backup server.
- The vulnerable functionality may not be enabled.
- The server role does not normally expose this attack path.

A vulnerable version string alone does not confirm exploitability.

**Validation Method:**  
Perform manual verification:
- Check SSH daemon configuration:
  - `AllowAgentForwarding`
  - `ForwardAgent`
- Review user SSH configurations.
- Confirm whether `ssh-agent` is running.
- Verify whether PKCS#11 providers are configured.
- Confirm OpenSSH package version and patch status from Ubuntu repositories.

If the vulnerable feature is disabled, the finding should be downgraded or closed.

**Risk of Acting on This FP:**  
Treating this as a confirmed critical vulnerability could waste:
- Patch testing resources.
- Maintenance windows.
- Backup server downtime.
- Engineering effort that could be spent on higher-risk issues.

It may also introduce unnecessary change risk to a production backup system.

**Risk of Not Validating:**  
If the vulnerability is actually exploitable and SSH agent forwarding is enabled:
- Attackers could compromise administrator sessions.
- Credentials could be stolen.
- The backup environment could become a pivot point for ransomware.

---

# Finding ID: 013

**Reported Vulnerability:**  
SSL Certificate Expiration Warning on 10.10.2.50 (Patient Portal)

**Why It Is a False Positive:**  
The scanner reports that the Let's Encrypt certificate expires in 23 days and that auto-renewal is not configured.

This may be a false positive because:
- Let's Encrypt certificates are commonly renewed automatically by external ACME clients.
- The scanner may only inspect the current certificate and not the renewal mechanism.
- Renewal may occur through another management system.

The absence of evidence from the scan does not prove that renewal is not configured.

**Validation Method:**  
Confirm manually:
- Check the server for ACME clients such as Certbot.
- Review scheduled tasks or cron jobs.
- Perform a renewal simulation:
  - `certbot renew --dry-run`
- Verify certificate monitoring and deployment procedures.

**Risk of Acting on This FP:**  
Treating it as a confirmed issue may waste:
- Certificate replacement effort.
- Administrator time.
- Unnecessary emergency renewal activities.

It may also cause unnecessary configuration changes to a functioning certificate process.

**Risk of Not Validating:**  
If the finding is accurate:
- The patient portal certificate could expire.
- Patients may receive browser security warnings.
- Portal availability and trust could be impacted.

---

# Finding ID: 020 (Additional Consideration)

**Reported Vulnerability:**  
OpenSSH CVE-2023-38408 severity rated CVSS 9.8.

**Why Scanner Confidence Is Limited:**  
The vulnerability severity is based on the theoretical maximum impact, but exploitation depends on environmental conditions. The scanner detected software version only and did not prove:
- SSH agent forwarding usage.
- PKCS#11 provider availability.
- User workflow exposure.

This is a common limitation of version-based vulnerability detection.

---

# Expected False Positive Rate for Automated Scanners

For a vulnerability scan containing **31 findings**, a reasonable expected false positive rate for an automated scanner is approximately:

| Scanner Type | Expected False Positive Rate |
|---|---|
| Well-configured authenticated vulnerability scanner | 5–10% |
| Unauthenticated network scan | 10–20% or higher |
| Complex enterprise environments | 10–30% possible |

For this report, SecurePoint itself estimated a typical false positive rate of **5–10%**.

This means approximately:

- **2–3 findings out of 31** may require additional validation before remediation.

---

# Why Manual Validation Is Essential

Automated scanners are valuable for identifying potential weaknesses, but they cannot fully understand business context, architecture, or operational constraints.

Manual validation is required because:

1. **Version detection does not always equal vulnerability**
   - A vulnerable software version may have vendor backports or compensating controls.

2. **Exploit conditions may not exist**
   - Some vulnerabilities require specific configurations, privileges, or user actions.

3. **Business context affects severity**
   - A vulnerability on a test server and the same vulnerability on an EHR database have very different impacts.

4. **Remediation can introduce operational risk**
   - Patching or changing configurations on medical systems can affect patient care.

5. **Resources must be prioritized**
   - Security teams should focus first on confirmed, exploitable risks rather than spending limited time fixing theoretical issues.

Manual validation ensures remediation resources are invested in vulnerabilities that represent real organizational risk.