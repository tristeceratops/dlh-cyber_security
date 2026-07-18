# The CVE Ecosystem
## Introduction
### Goal
Navigate the National Vulnerability Database to research specific CVEs and understand the global vulnerability identification system.
### Context
Every CVE in that scan report is an entry in a global registry. Behind each identifier is a story: who discovered the flaw, what it affects, how severe it is, whether a patch exists, whether an exploit exists. The NVD is where those stories live.

You will use NVD constantly as a security professional. This task builds the navigation reflex.
## Answer

### Critical: CVE-2021-44790
```
CVE ID: CVE-2021-44790
NVD URL: https://nvd.nist.gov/vuln/detail/CVE-2021-44790
Description: Possibility of creating a buffer overflow in the mod_lua multipart parser by sending a crafted request body through Apache HTTP Server 2.4.51 and earlier.
Affected Products: Fedora 34 to Fedora 36, Debian 10.0 to Debian 11.0, mac OS X 10.15.7
CVSS v3.1 Vector String:  CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSS Base Score: 9.8 Critical
CWE: CWE-787 Out-of-bounds Write
References: 
	- Vendor Advisory: http://httpd.apache.org/security/vulnerabilities_24.html
	- Exploit: http://packetstormsecurity.com/files/171631/Apache-2.4.x-Buffer-Overflow.html
	- Third Party Advisory: https://nvd.nist.gov/vuln/detail/CVE-2021-44790#vulnConfigurationsArea
Published Date: 12/20/2021
Last Modified: 06/17/2026
```
### High: CVE-2020-25165
```
CVE ID: CVE-2020-25165
NVD URL: https://nvd.nist.gov/vuln/detail/CVE-2020-25165
Description: Using a vulnerabilty inside authentification process between BD Alaris PC Unit, Model 8015, Versions 9.33.1 and earlier and the DB Alaris Systems Manager, Versions 4.33 and earlier, one attacker could perform a denial-of-service attack on the BD Alaris PC Unit by modifying the configuration headers of data in transit.
Affected Products: BD Alaris PC Unit, Model 8015, Versions 9.33.1; BD Alaris Systems Manager, Versions 4.33; and every earliers versions of theses two products.
CVSS v3.1 Vector String: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H
CVSS Base Score: 7.5 High
CWE: CWE-287 Improper Authentication
References: 
	- Third Party Advisory, US Government: https://us-cert.cisa.gov/ics/advisories/icsma-20-317-01
Published Date: 11/13/2020
Last Modified: 06/16/2026
```
### Medium: CVE-2023-38408
```
CVE ID: CVE-2023-38408
NVD URL: https://nvd.nist.gov/vuln/detail/CVE-2023-38408
Description: Vulnerabilty lead to remote code execution due to an insufficient search path in OpenSSH.
Affected Products: OpenSSH 9.3, Fedora 37, Fedora 38
CVSS v3.1 Vector String: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
CVSS Base Score: 9.8 Critical
CWE: CWE-428 Unquoted Search Path or Element
References: 
	- Exploit, Third Party Advisory: http://packetstormsecurity.com/files/173661/OpenSSH-Forwarded-SSH-Agent-Remote-Code-Execution.html
	- Patch: https://github.com/openbsd/src/commit/7bc29a9d5cd697290aa056e94ecee6253d3425f8
	- Vendo Advisory: https://www.openssh.com/security.html
Published Date: 07/19/2023
Last Modified: 06/17/2026
```

- What is the structure of a CVE ID ? (What do the year and number signify ?)
	- CVE-2023-38408 -> [CVE]-[Year of publication]-[Unique ID for the year]
- What is a CNA (CVE Numbering Authority) and what role does it play ?
	- CNAs are vendor, researcher, open source, CERT, hosted service, bug bounty provider, and consortium organizations authorized by the CVE Program to assign CVE IDs to vulnerabilities and publish CVE Records within their own specific scopes of coverage. 
- What lifecycle states can a CVE have ? (Reserved, Published, Rejected, explain each.)
	- A CNA has reserved a CVE ID. This is the initial state of a CVE ID. Published: A CNA has populated the data associated with the CVE ID and published the CVE Record. Rejected: The CVE ID and the associated CVE Record should no longer be used.
- Find one CVE on NVD that has a status of "Rejected." Why was it rejected ?
	- CVE-2026-8762 was rejected because the originally reported behaviour was not a security vulnerabilty.