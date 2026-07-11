# 2. The Symptom Trap

## Introduction

### Goal
Develop the analytical reflex to look beyond visible symptoms and identify root causes in security events.

### Context
Remember the sticky note on Marcus's monitor ? "Check billing-srv-01, something is wrong." This is the server that got hit by ransomware in January (Incident A). It was rebuilt, but the performance issues Marcus noticed started before the ransomware and have returned after the rebuild.

The IT team has flagged billing-srv-01 three times in the last two months for "performance degradation." Each time, the sysadmin restarted the server, which temporarily resolved the issue. The sysadmin's latest ticket reads: "Recurring CPU saturation on billing-srv-01. Probably undersized for the billing workload. Recommend hardware upgrade or migration to a more powerful VM."

James Chen is not convinced. Neither was Marcus. James asks you to take a closer look.

## Answer
Process: ` 8834 www-data  20   0  458392  24816   3204 R  94.2   3.1  16421:33 ./kworker -o stratum+tcp://pool.monero.org:4443 --threads 4 --donate-level 0`

**Explanation of the process behavior:**

`kworker` (kernel worker) is a legitimate Linux kernel process that executes deferred background tasks scheduled by the Linux kernel through workqueues. It handles operations such as hardware interrupts, disk I/O, and other kernel maintenance activities. Genuine `kworker` processes are not expected to create arbitrary user files or launch user-space programs. Because of this, attackers sometimes disguise malware as `kworker` to evade detection, making such behavior a strong indicator of compromise.

In this case, `kworker` is being used to disguise a malicious cryptocurrency miner that connects to `stratum+tcp://pool.monero.org:4443`. `Stratum` is a mining protocol commonly used by cryptocurrency mining software, and `pool.monero.org` is a Monero mining pool. The server's performance degradation is caused by the hidden crypto miner consuming CPU resources.

The recurring performance degradation is only the visible symptom of the compromise. The primary security violations occur earlier in the attack. First, **Integrity** is compromised because the attacker has installed and executed unauthorized software disguised as `kworker`, modifying the server's intended software state and abusing its computing resources for cryptocurrency mining. Second, **Confidentiality** is compromised because the attacker has gained unauthorized access to the system, allowing them to deploy and control the malware. These compromises ultimately affect **Availability**, as the crypto miner monopolizes CPU resources and causes the billing service to become slow or unresponsive.

Migrating the server to a larger or more powerful VM **would not solve the problem**. It would only reduce or temporarily hide the performance symptoms by providing additional CPU resources, while the malicious mining process would continue running and the server would remain compromised. The malware would simply consume the extra resources over time, leaving the underlying security breach unresolved. The real solution is to remove the malicious process, terminate its external mining connections, investigate how the attacker gained access, patch the underlying vulnerability (such as the outdated Apache installation), and fully remediate the system.

The January ransomware attack and the current crypto-miner infection on the same server suggest a persistent weakness in the server's security posture rather than isolated incidents. The evidence indicates that the server was likely rebuilt without identifying and fixing the underlying Apache vulnerability, allowing attackers to exploit the same entry point with a different payload. Rather than asking whether the server needs more hardware, the key question is: **Why was the original vulnerability not identified and patched after the ransomware incident, allowing the system to be compromised again?**