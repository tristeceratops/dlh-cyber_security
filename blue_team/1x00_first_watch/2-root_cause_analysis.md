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

Explanation of the process behavior: 

`kworker` (kernel worker) is a legitimate Linux kernel process that executes deferred background tasks scheduled by the kernel through workqueues. It handles operations such as hardware interrupts, disk I/O, and other kernel maintenance activities. Because genuine kworker processes are not expected to create arbitrary user files or launch user-space programs, attackers may masquerade as kworker to evade detection, making such behavior a useful indicator of suspicious activity.

In our case, `kworker` is used to disguise a malicious process: `stratum+tcp://pool.monero.org:4443`. `stratum` is a mining protocol used by blockchain based cryptocurrency systems and `pool.monero.org` is a decentralized mining pool. The performance issue came from a malicous crypto mining hidden on the server, probably using the same flaw as the previous attack.

The recurring performance degradation is only the visible symptom of the compromise, the primary security violations occur earlier in the attack. First, **Integrity** is compromised because the attacker has installed and executed a malicious process disguised as `kworker`, modifying the server's intended software state and abusing its resources for unauthorized cryptocurrency mining. Second, **Confidentiality** is compromised because the attacker has gained unauthorized access to the system, allowing them to deploy and control the malware, which implies the security boundary protecting the server has already been breached. These compromises ultimately lead to an **Availability** impact, as the crypto miner consumes nearly all CPU resources, causing the billing service to suffer severe performance degradation.

The sysadmin's solution of migrating the server to a more powerful and modern VM would not fix it. There is a high probability that the same vulnerability used by the January ransomware was used again. The Apache version is highly vulnerable and is probably the cause of these two attacks. The priority would be to clean the server by closing the malicious process and external connections and updating Apache.

The January ransomware attack and the current crypto-miner infection on the same server suggest a persistent weakness in the server's security posture rather than isolated incidents. The evidence indicates that the server was likely rebuilt without addressing the underlying Apache vulnerability, allowing attackers to exploit the same entry point with a different payload. Instead of asking whether the server needs more hardware, the key question is: **Why was the original vulnerability not identified and patched after the ransomware incident, allowing the system to be compromised again?**
