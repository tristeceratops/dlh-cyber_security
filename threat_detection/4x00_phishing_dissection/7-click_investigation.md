## Click Investigation — Diane Marsh / WS-NURSE-04

### Confirmed Facts

Based on the supplied evidence and the previous email analysis:

- User: **Diane Marsh**
- Workstation: **WS-NURSE-04**
- Relevant email: **E7 — Benefits enrollment phishing lure**
- Email pretext: The message claimed to be from **MedDefense Human Resources Benefits Administration** and stated that open enrollment was closing imminently.
- Credential-harvesting URL: `https://meddefense-benefits.org/enroll`
- Defanged URL: `hxxps://meddefense-benefits[.]org/enroll`
- Domain: `meddefense-benefits.org`
- The domain is a lookalike of the legitimate MedDefense domain, `meddefense.com`.
- The email requested the recipient to use the external enrollment portal.
- The message used urgency, fear, scarcity, and impersonation to encourage the recipient to act.
- Authentication results for E7:
  - SPF: **Fail**
  - DKIM: **None**
  - DMARC: **Fail**
- E7 sending IP: **164.90.218.73**
- The email used external PHP/PHPMailer infrastructure.
- The email claimed the recipient had not completed benefits re-enrollment and threatened loss of coverage.
- A reported click on the credential-harvesting portal is the trigger for this investigation.

The **exact click timestamp and source IP are not established in the evidence available here**. The E7 sending IP (`164.90.218.73`) is the mail-sender IP and should not be incorrectly treated as the user's click-source IP.

### Key Unknowns

The reported click establishes that the suspicious URL was accessed, but it does **not by itself prove that credentials were entered or successfully captured**.

The following facts remain to be established:

- Exact click timestamp.
- Source IP associated with the click.
- Whether the click originated from WS-NURSE-04 or another device.
- Whether the phishing page actually loaded successfully.
- Whether Diane entered a username, password, MFA code, or other information.
- Whether the phishing site received or processed submitted credentials.
- Whether credentials were subsequently used by an attacker.
- Whether browser activity caused a download or additional redirect.
- Whether any malicious process or file executed after the click.
- Whether the account experienced suspicious authentication activity after the click.

### Endpoint Checks To Perform

If endpoint or browser logs are available, perform the following checks on **WS-NURSE-04**:

1. **Browser history**
   - Confirm the exact time the browser accessed `meddefense-benefits.org`.
   - Identify the browser used.
   - Review redirects immediately before and after the phishing URL.
   - Check whether the browser accessed additional suspicious domains.

2. **Downloaded files**
   - Check the user's Downloads directory and browser download history.
   - Identify files created around the click time.
   - Record filenames, extensions, timestamps, hashes, and origin URLs.
   - Do not open suspicious files directly on the workstation.

3. **Process execution**
   - Check for unusual processes created around the click time.
   - Look for unexpected scripting engines, browsers, archive utilities, or executables.
   - If available, review process-creation telemetry for child processes spawned by the browser.

4. **PowerShell and command-line activity**
   - Review PowerShell and `cmd.exe` activity around the click.
   - Look for commands that downloaded files, executed scripts, modified credentials, or established persistence.
   - These are recommended follow-up checks; no PowerShell, Sysmon, Wazuh, or Windows Security log search is being claimed here.

5. **File creation and modification**
   - Review recently created or modified files around the click timestamp.
   - Pay particular attention to executable, script, archive, shortcut, and document files.
   - Compare timestamps with the reported click.

6. **Browser/session artifacts**
   - Review cookies, session activity, saved credentials, and autofill activity where appropriate and permitted by organizational policy.
   - Determine whether the browser submitted data to the suspicious domain.

### Account Checks To Perform

The potentially more serious consequence of a credential-harvesting click is account compromise. Review identity-provider and authentication telemetry for the affected account:

1. **Failed logons**
   - Look for failed authentication attempts immediately before and after the reported click.
   - Identify repeated attempts or unusual geographic/network sources.

2. **Successful logons**
   - Identify successful logins from unusual IP addresses, locations, devices, browsers, or user agents.
   - Compare them with the user's normal activity.

3. **MFA activity**
   - Check for unexpected MFA prompts.
   - Look for MFA approvals that the user did not initiate.
   - Check for changes to registered authentication methods.

4. **Password changes**
   - Check whether the password was changed after the phishing click.
   - Identify who or what initiated the change.

5. **Session/token activity**
   - Check for newly issued sessions or authentication tokens from unusual sources.
   - Determine whether existing sessions should be revoked.

6. **Mailbox rules**
   - Look for newly created forwarding, deletion, redirect, or concealment rules.
   - Pay particular attention to rules targeting security notifications or financial communications.

7. **Account and group changes**
   - Check for unexpected group membership changes.
   - Review privilege changes, role assignments, application permissions, and delegated access.

8. **Email activity**
   - Check for suspicious outbound messages.
   - Look for unauthorized access to sensitive messages or attempts to continue the phishing campaign internally.

### Decision Matrix

| Outcome | Evidence | Assessment | Required response |
|---|---|---|---|
| **No compromise found** | Click confirmed, but no credential submission, suspicious downloads, malicious execution, abnormal authentication, MFA abuse, password changes, or mailbox/account changes are identified. | Exposure to the phishing site occurred, but available evidence does not show compromise. | Reset credentials as a precaution according to policy, revoke sessions where appropriate, educate the user, and continue short-term monitoring. |
| **Possible credential exposure** | Click confirmed and there is evidence that a login form was reached or credentials may have been submitted, but there is no confirmed malicious account activity. | Credentials may have been exposed even though account takeover has not been demonstrated. | Immediately reset the password, revoke active sessions/tokens, verify MFA, review authentication history and mailbox rules, and monitor closely for follow-on activity. |
| **Confirmed compromise** | Evidence shows successful attacker authentication, unauthorized MFA activity, password/account changes, malicious mailbox rules, unauthorized access, or other verified attacker activity following the click. | Account compromise is supported by evidence. | Contain the account immediately, reset credentials, revoke sessions/tokens, secure MFA, remove unauthorized changes, investigate endpoint activity, and expand the investigation to related accounts and systems. |

### Recommended Containment

1. **Reset the affected user's password** if credential exposure cannot be ruled out.
2. **Revoke active sessions and authentication tokens** where supported by the identity platform.
3. **Verify MFA configuration** and remove any authentication method that the user did not intentionally register.
4. **Interview Diane Marsh** to establish:
   - Whether she entered a username.
   - Whether she entered a password.
   - Whether she entered an MFA code.
   - Whether she downloaded or opened anything.
   - Whether she noticed redirects or unusual browser behavior.
5. **Preserve relevant evidence** before making changes where possible, including browser history, timestamps, email headers, and endpoint artifacts.
6. **Monitor the account** for unusual successful or failed logons, MFA prompts, password changes, mailbox-rule changes, and other identity activity.
7. **Block or monitor the phishing domain** `meddefense-benefits.org` through appropriate organizational email, DNS, proxy, or endpoint controls.
8. **Search for the same phishing domain across the environment** to identify other potentially affected users.
9. If endpoint evidence indicates malicious execution, **isolate WS-NURSE-04 according to incident-response procedures** and begin endpoint investigation.
10. Do not assume that a click alone means the endpoint is infected. The primary immediate concern is **potential credential exposure**, followed by determining whether there is evidence of account takeover or endpoint compromise.

### Conclusion

The reported click is significant because `meddefense-benefits.org` is a lookalike domain used in a benefits-enrollment credential-harvesting pretext. The associated email has failed SPF and DMARC authentication, no DKIM signature, an external sending infrastructure, and strong social-engineering indicators.

A click confirms interaction with the suspicious lure, but **does not by itself establish credential theft or account compromise**. The investigation should therefore focus on determining whether credentials or MFA information were submitted and whether there was subsequent abnormal identity or endpoint activity.

The available evidence confirms the E7 phishing indicators and the mail-sender IP `164.90.218.73`, but the **exact click timestamp and click-source IP are not available in the evidence currently provided**. Those values should be obtained from browser, proxy, DNS, identity-provider, or other relevant telemetry rather than inferred from the email's sending headers.