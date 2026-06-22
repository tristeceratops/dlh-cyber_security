# 3. Financial Trading Platform
## Scenario
```
A trading platform allows users to:

	View real-time stock prices
	Execute buy/sell orders
	Transfer funds between accounts
	Set up automated trading rules

The system requirements include:

	High availability (99.99% uptime)
	Low latency (<100ms for trades)
	Regulatory compliance (SEC, FINRA)
```

## Questions
```
	1) Which CIA component is most critical for this system and why? Can security requirements conflict with performance requirements?

	2) Threat model the "automated trading rules" feature. What are the top three risks and how would you mitigate them?

	3) An attacker compromises a user account. What defense-in-depth controls should limit the damage? List at least five layers of security.
```

## Answers
### CIA most critical component
**Integrity is the most critical CIA component for a trading platform.** In this system, incorrect or manipulated prices, orders, account balances, or trade instructions can cause direct financial loss, legal exposure, and regulatory violations. A confidentiality leak is serious, but a platform that executes the wrong trade, transfers money to the wrong account, or records false balances can damage the business immediately and irreversibly.

Yes, security requirements can conflict with performance requirements. Strong authentication, encryption, audit logging, and transaction validation all add processing overhead, and some checks can increase latency beyond the <100ms target if they are placed on the critical trade path. The right approach is to apply security controls without breaking market responsiveness: keep low-latency trade execution on the hot path, pre-authenticate sessions, cache safe state where possible, and move heavier checks such as fraud review, log analysis, and post-trade reconciliation off the synchronous execution path.

### "Automated trading rules" threat modeling
| **Risk** | **Threat Description** | **Potential Impact** | **Suggested Mitigation** |
| --- | --- | --- | --- |
| **Malicious rule or logic bug drains funds** | An attacker creates or modifies an automated rule to buy aggressively, sell at a loss, or repeatedly transfer funds until the account is emptied. A coding bug in the rule engine can have the same effect. | Direct financial loss, forced liquidation, margin issues, and regulatory complaints. | Require approval workflows for new or modified rules, enforce per-rule and per-day loss limits, apply transaction caps, and add an emergency kill switch that can disable all automated trading immediately. Run rules in a sandbox or simulation mode before allowing live execution. |
| **Race conditions and stale market data** | The rule engine reacts to outdated quotes or multiple triggers at once, causing duplicate orders, conflicting actions, or trades placed after the market moved. | Overtrading, bad fills, unintended positions, and losses from delayed or duplicated execution. | Use atomic order submission, idempotency controls, sequence numbers, market-data freshness checks, and concurrency-safe locking around rule evaluation and order placement. |
| **Unauthorized rule modification** | A compromised account, stolen session, or API abuse changes thresholds, symbols, or beneficiary settings so the rule behaves differently from what the user intended. | Hidden trade manipulation, unauthorized withdrawals, and difficulty proving user intent. | Protect rule changes with step-up authentication, signed change confirmation, version history, tamper-evident audit logs, and alerts for high-risk edits. Require a review queue for changes that increase risk exposure. |

Top risks are reduced further by keeping automated rules constrained: simulate before activation, require explicit opt-in for live trading, and stop execution automatically if losses, volume, or behavior drift beyond approved bounds.

### Defense-in-depth layers of security
| **Layer** | **Control** | **How it limits damage after account compromise** |
| --- | --- | --- |
| **1** | **Multi-factor authentication** | A stolen password alone is not enough to take over the account or approve sensitive actions. |
| **2** | **Session management and revocation** | Suspicious sessions can be invalidated quickly, and short-lived tokens reduce how long a hijacked session stays usable. |
| **3** | **Device binding and trusted-device checks** | Trades or transfers from a new device can require extra verification, making credential theft less useful. |
| **4** | **Geolocation and impossible-travel detection** | Logins or trades from unusual regions or rapid location changes can trigger step-up verification or blocking. |
| **5** | **Velocity checks and transaction limits** | Caps on trade size, transfer frequency, and daily loss prevent a compromised account from being emptied in a single burst. |
| **6** | **Manual approval for high-risk actions** | Large transfers, unusual trades, or changes to automated rules can require human confirmation before execution. |
| **7** | **Anomaly detection and behavioral analytics** | Abnormal trading patterns, sudden symbol changes, or new payee activity can be detected and stopped early. |
| **8** | **Account freeze and emergency kill switch** | Security staff or the user can freeze trading and transfers immediately when compromise is suspected. |
| **9** | **Beneficiary and rule-change whitelists** | Restricting which accounts, symbols, or destinations can be used reduces what a compromised account can abuse. |
| **10** | **Audit trails and alerting** | Tamper-evident logs, trade confirmations, and real-time alerts help detect abuse quickly and support incident response. |

These controls work together so that even if one layer fails, the attacker still has to defeat authentication, device trust, limits, monitoring, and manual review before causing major financial damage.