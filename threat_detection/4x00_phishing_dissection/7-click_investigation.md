## Click Investigation — Diane Marsh / WS-NURSE-04

### Confirmed Facts

The evidence batch confirms that:

- **User:** Diane Marsh
- **Workstation:** WS-NURSE-04
- **Email:** Email 2 — `noreply@meddefense-portal.com`
- **Recipient:** `dmarsh@meddefense.com`
- **Sender:** `"MedDefense IT Security" <noreply@meddefense-portal.com>`
- **Subject:** `ACTION REQUIRED: Portal re-verification needed within 24 hours`
- **Reported activity:** Diane Marsh **clicked the Email 2 link from WS-NURSE-04**.
- **Clicked URL:** `https://meddefense-portal.com/verify/staff?id=dmarsh&token=a8f3e2d1`
- **Defanged URL:** `hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`
- **URL domain:** `meddefense-portal.com`
- **Email sending IP:** `91.234.99.107`
- **Email timestamp:** `14 Apr 2026 19:47:48 UTC`
- **Email authentication:**
  - SPF: **Fail**
  - DKIM: **None**
  - DMARC: **Fail**
- **Sending infrastructure:** `mail.meddefense-portal.com` using PHPMailer 6.6.0.
- The email claims to be MedDefense IT Security but uses `meddefense-portal.com` rather than the organization's legitimate `meddefense.com`.
- The URL contains the recipient identifier `dmarsh` and a token parameter.
- The email threatens suspension of portal, scheduling, EHR gateway, and shift-swap access if verification is not completed within 24 hours.
- The email uses high-priority indicators including `X-Priority: 1`, `X-MSMail-Priority: High`, and `Importance: High`.

**Important IP distinction:** `91.234.99.107` is confirmed as the **email's sending IP**. The evidence provided does **not** give the source IP used by Diane's workstation when she clicked the link. Therefore, `91.234.99.107` must not be reported as Diane's click-source IP.

The exact **click timestamp and click-source IP are not present in the supplied evidence**. They must be obtained from endpoint, proxy, DNS, browser, or other available telemetry.

### Key Unknowns

The reported click establishes interaction with the phishing URL, but the available evidence does not establish what happened after the click.

The following remain unknown:

- Exact timestamp of the click.
- Source IP associated with the click.
- Whether the URL successfully loaded.
- Whether the phishing page displayed a login form.
- Whether Diane entered her username.
- Whether Diane entered her password.
- Whether an MFA code or approval was provided.
- Whether the attacker received any credentials.
- Whether the URL redirected to another domain.
- Whether a file was downloaded.
- Whether any process executed on WS-NURSE-04 after the click.
- Whether the account was subsequently accessed by an unauthorized party.
- Whether mailbox rules, MFA settings, passwords, sessions, or group memberships were changed.

Because no endpoint or SIEM logs are provided, **no compromise should be declared or ruled out from the click alone**.

### Why the Click Is Serious

The click is significant because the destination is a credential-harvesting phishing portal using a lookalike MedDefense domain.

Several indicators make the event high risk:

- `meddefense-portal.com` is not `meddefense.com`.
- SPF failed for the sending domain.
- DKIM was absent.
- DMARC failed.
- The message impersonates MedDefense IT Security.
- The message uses a 24-hour deadline to create urgency.
- It threatens loss of access to scheduling, EHR gateway, and shift-swap systems.
- The URL is specifically constructed for staff verification and contains Diane's identifier: `id=dmarsh`.
- The user actually clicked the link.

A click does **not** prove that credentials were entered. However, once a user reaches a credential-harvesting page, credentials can potentially be exposed if the user submits them. An attacker could then attempt to reuse those credentials against the organization's identity systems, email, VPN, EHR-related services, or other applications.

Therefore, the appropriate assessment is **potential credential exposure pending endpoint and identity verification**, rather than confirmed account compromise.

### Endpoint Checks To Perform

The following are recommended follow-up checks if endpoint or management telemetry is available for **WS-NURSE-04**.

1. **Browser history**
   - Confirm the exact time the browser accessed `meddefense-portal.com`.
   - Identify the browser used.
   - Determine whether the page redirected to another URL or domain.
   - Check for subsequent access to authentication or suspicious domains.

2. **Browser download history**
   - Determine whether the click caused a file download.
   - Record filename, extension, timestamp, source URL, and file hash.
   - Do not open suspicious files directly on the workstation.

3. **File creation**
   - Check files created or modified around the click time.
   - Pay particular attention to `.exe`, `.dll`, `.ps1`, `.bat`, `.cmd`, `.js`, `.vbs`, `.zip`, `.iso`, `.lnk`, and unexpected document files.

4. **Process execution**
   - Review processes created around the click.
   - Determine whether the browser spawned an unusual child process.
   - Check for unexpected executables or scripting engines.

5. **PowerShell and command-line activity**
   - Review PowerShell and `cmd.exe` activity around the click.
   - Look for commands associated with downloads, credential access, script execution, or persistence.

6. **Endpoint security telemetry**
   - If available, review EDR/Sysmon/Wazuh or equivalent telemetry around the click.
   - These are **recommended follow-up checks only**; the current investigation does not claim that those logs were searched.

7. **Browser credential activity**
   - Determine whether the browser submitted information to the phishing domain, where such telemetry is available and collection is permitted.
   - Review relevant browser artifacts without unnecessarily exposing stored credentials.

### Account Checks To Perform

The identity/account investigation should focus on activity occurring after the reported click.

1. **Failed logons**
   - Search for unusual failed authentication attempts involving Diane's account.
   - Look for repeated failures or authentication from unfamiliar sources.

2. **Successful logons**
   - Review successful authentication events after the click.
   - Compare source IP, geographic location, device, browser, and user-agent information with Diane's normal activity.

3. **MFA activity**
   - Check for unexpected MFA prompts.
   - Determine whether Diane received MFA requests she did not initiate.
   - Check for unauthorized MFA approvals or newly registered authentication methods.

4. **Password changes**
   - Determine whether the account password was changed after the click.
   - Verify whether any change was initiated by Diane or by an administrator.

5. **Session/token activity**
   - Look for unusual new sessions or tokens after the click.
   - Consider revoking active sessions if credential exposure cannot be ruled out.

6. **Mailbox rules**
   - Check for newly created forwarding, redirect, deletion, or concealment rules.
   - Pay particular attention to rules that hide security notifications or redirect organizational email externally.

7. **Group membership and permissions**
   - Check for unexpected group membership changes.
   - Review newly assigned roles, permissions, delegated access, or application permissions.

8. **Post-click email activity**
   - Check for suspicious outbound messages or unusual mailbox access.
   - Search for evidence that the compromised account may have been used to target other employees.

### Decision Matrix

| Outcome | Evidence required | Assessment | Response |
|---|---|---|---|
| **No compromise found** | Click confirmed, but no evidence of credential submission, suspicious downloads/execution, abnormal logons, MFA abuse, password changes, or account changes. | Phishing interaction confirmed, but no evidence of compromise is identified. | Consider password reset according to policy, verify MFA, educate the user, and monitor the account. |
| **Possible credential exposure** | Click confirmed and evidence suggests the phishing page was used for login or credentials/MFA information may have been submitted, but no unauthorized account activity is confirmed. | Credentials may have been exposed, but account compromise is not confirmed. | Reset the password immediately, revoke active sessions/tokens, verify MFA, review account activity and mailbox rules, and increase monitoring. |
| **Confirmed compromise** | Unauthorized successful authentication, MFA abuse, password change, mailbox manipulation, privilege change, or other verified attacker activity is identified after the click. | Evidence supports actual account compromise. | Contain the account, reset credentials, revoke sessions, secure MFA, remove unauthorized changes, investigate the endpoint, and expand the investigation to related systems/accounts. |

### Recommended Containment

1. **Interview Diane Marsh**
   - Confirm what happened after clicking.
   - Ask whether she entered her username or password.
   - Ask whether she entered or approved an MFA request.
   - Ask whether anything downloaded or appeared unusual.

2. **Reset the password if credential exposure cannot be ruled out**
   - This is particularly appropriate if Diane confirms entering credentials on the phishing site or if the investigation cannot determine whether credentials were submitted.

3. **Revoke active sessions/tokens**
   - Invalidate existing authentication sessions where supported by the organization's identity platform.

4. **Verify MFA**
   - Confirm that existing MFA methods are legitimate.
   - Remove unauthorized methods if discovered.
   - Investigate unexpected MFA prompts.

5. **Preserve evidence**
   - Preserve the original email, browser artifacts, relevant timestamps, and available endpoint/account telemetry before making destructive changes where practical.

6. **Monitor the account**
   - Monitor for unusual successful and failed logons.
   - Monitor MFA prompts.
   - Monitor password and account changes.
   - Monitor mailbox rules and suspicious outbound email.

7. **Block or monitor the phishing domain**
   - Add `meddefense-portal.com` to appropriate organizational blocking or monitoring controls.
   - Search for other users who may have received or clicked the same URL.

8. **Investigate WS-NURSE-04 if endpoint evidence indicates further activity**
   - If the endpoint shows downloads, script execution, suspicious processes, or other malicious activity, follow the organization's endpoint containment procedure.

### Conclusion

The evidence confirms that **Diane Marsh on WS-NURSE-04 clicked the Email 2 credential-harvesting link**:

`hxxps://meddefense-portal[.]com/verify/staff?id=dmarsh&token=a8f3e2d1`

The email is strongly suspicious because it impersonates MedDefense IT Security, uses the lookalike domain `meddefense-portal.com`, fails SPF and DMARC, has no DKIM signature, and uses urgency and threatened loss of access to pressure the recipient.

The click is therefore a **high-risk phishing event with potential credential exposure**.

However, the available evidence does **not** establish that Diane entered credentials, that credentials were successfully captured, or that the account was subsequently compromised. The exact click timestamp and click-source IP are also not present in the supplied evidence. The confirmed `91.234.99.107` value is the **email sender's IP**, not Diane's workstation IP.

The next investigation priority is therefore to correlate the reported click with browser/endpoint telemetry and identity-provider activity to determine whether the event ends as **no compromise found, possible credential exposure, or confirmed compromise**.