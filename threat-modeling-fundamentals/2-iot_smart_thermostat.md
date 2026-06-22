# IoT Smart Thermostat
## Scenario
```
A smart thermostat device:

	Connects to home Wi-Fi
	Controls heating/cooling systems
	Collects temperature data
	Receives commands from mobile app
	Updates firmware over-the-air
```

## Questions
```
	1) Identify IoT-specific threats that don't typically apply to web applications. List at least five.

	2) What happens if an attacker gains physical access to the device? Describe the attack chain and potential impacts.

	3) Design security controls for the OTA (Over-The-Air) update process. What are the essential security requirements?
```

## Answers
### IOT-specific threats
| **IoT-Specific Threat** | **Why it is IoT-specific** | **Potential Impact** | **Suggested Mitigation** |
| --- | --- | --- | --- |
| **Physical tampering** | The device is installed in a home, so an attacker can touch the hardware directly in a way that is uncommon for web apps. | The thermostat may be reset, modified, or forced into a malicious state. | Use tamper resistance, secure enclosures, tamper detection, and disable sensitive features when tamper events are detected. |
| **JTAG/UART debug access** | Many embedded devices expose hardware debug ports that are not present in typical web applications. | An attacker can inspect memory, extract secrets, or rewrite firmware. | Disable debug ports in production, fuse off debug access where possible, and physically protect test pads. |
| **Weak default credentials** | IoT devices often ship with easy-to-guess passwords or pairing codes. | Local or remote takeover of the thermostat and its connected accounts. | Require unique device credentials, force password changes at setup, and block factory-default credentials from being used. |
| **Firmware reverse engineering** | Attackers can extract and analyze device firmware, which is a common embedded-device risk. | Discovery of hardcoded keys, hidden endpoints, or logic flaws that enable compromise. | Use secure boot, code signing, obfuscation where appropriate, and remove secrets from firmware images. |
| **Supply-chain compromise** | IoT devices rely on hardware vendors, firmware builders, and cloud services that can be targeted before deployment. | Malicious firmware or backdoored components may ship to many homes at once. | Verify build pipelines, sign releases, track components, and validate firmware provenance. |
| **Long lifecycle and patch lag** | Thermostats can remain deployed for years and may not receive frequent updates like web apps do. | Old vulnerabilities remain exploitable for a long time, increasing exposure. | Provide automatic updates, long-term support, and secure update validation. |
| **Side-channel leakage** | Embedded devices can leak information through power, timing, or radio behavior. | Secrets such as keys or authentication material may be inferred. | Use hardened crypto implementations, limit observable behavior, and protect key storage with secure hardware. |

### Attack chain and potential impacts
1. The attacker gains physical access to the thermostat in a hallway, home, or rental property.
2. They open the casing and locate exposed JTAG or UART test pads on the board.
3. Using inexpensive hardware tools, they connect to the debug interface and obtain a shell or readout access.
4. They dump firmware, memory, or configuration data from the device.
5. The extracted data reveals Wi-Fi credentials, API tokens, device secrets, or keys used for cloud communication.
6. The attacker reuses those credentials to join the home network and impersonate the thermostat or mobile app.
7. From the network foothold, they can pivot to other IoT devices, intercept traffic, or reach local admin interfaces.
8. They manipulate thermostat settings, disable climate control, or maintain persistence for later access.
9. The real-world impact can include uncomfortable or unsafe home temperatures, increased energy costs, loss of privacy, and a wider home network compromise that could enable burglary or broader device takeover.

### OTA (Over-The-Air) design security controls
| **Priority** | **Security Requirement** | **Why it matters** |
| --- | --- | --- |
| **1** | **Digital signature on firmware** | The device must verify that every update is signed by a trusted vendor key so malicious firmware cannot be installed. |
| **2** | **Secure boot** | The thermostat should only boot trusted firmware and reject modified images at startup. |
| **3** | **TLS for update transport** | Firmware and metadata must travel over an encrypted, authenticated channel to resist interception and man-in-the-middle attacks. |
| **4** | **Integrity verification** | The device should hash and verify the firmware package before installation to detect corruption or tampering. |
| **5** | **Anti-rollback protection** | The thermostat must reject older vulnerable firmware versions so attackers cannot downgrade it to a known-bad build. |
| **6** | **Authenticated update server** | The device should only fetch updates from approved infrastructure with server identity validation. |
| **7** | **Safe recovery and fail-safe update process** | If an update fails, the device should keep a known-good image or roll back safely rather than becoming unusable. |
| **8** | **Least-privilege update agent** | The updater should run with only the permissions needed to install firmware and should not expose unnecessary system access. |
| **9** | **Version pinning and release metadata checks** | The device should validate release version, device model compatibility, and update channel to prevent cross-device or forged-package installs. |
| **10** | **Audit logging for update events** | Update attempts, failures, and successful installs should be recorded for troubleshooting and incident response. |

These OTA controls together ensure authenticity, integrity, confidentiality in transit, and protection against downgrade or device-bricking attacks.