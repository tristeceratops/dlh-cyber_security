# E-commerce Platform
## Scenario
```
You are threat modeling an e-commerce platform where users can:
    Browse products (no authentication required)
    Add items to cart (no authentication required)
    Checkout and pay (authentication required)
    View order history (authentication required)

The system architecture includes:
    React frontend
    Node.js API backend
    PostgreSQL database
    Stripe payment integration
```

## Questions
```
    1) Identify three STRIDE threats for the checkout process. For each threat, specify:

    STRIDE category
    Threat description
    Potential impact
    Suggested mitigation

    2) What trust boundaries exist in this system? Describe at least three.

    3) Rate the threat of SQL injection in the product search functionality using DREAD (provide scores for each factor and justify them).

```
## Answers
### STRIDE threats
| **STRIDE Category** | **Threat** | **Affected Component / Data Flow** | **Potential Impact** | **Suggested Mitigation** |
| --- | --- | --- | --- | --- |
| **Spoofing** | An attacker reuses a stolen JWT or session cookie to act as a legitimate customer during checkout. | Browser session, authentication service, checkout API, order history | Unauthorized purchases, access to saved addresses, and exposure of order history. | Use HTTPS everywhere, `HttpOnly` and `Secure` cookies, `SameSite` protection, short-lived tokens, session rotation, logout revocation, and MFA for sensitive actions. |
| **Tampering** | The attacker modifies the checkout request in the browser or intercepts it and changes the price, quantity, or shipping details before the server processes payment. | React frontend to Node.js API | Underpayment, fraudulent orders, incorrect shipping, or loss of revenue. | Enforce server-side validation and pricing, recalculate totals on the server, ignore client-supplied prices, validate item IDs and quantities, and use signed order/session data. |
| **Information Disclosure** | Cardholder or payment-related data is exposed in transit, logs, or client-side code during checkout. | Browser, Node.js API, Stripe integration | Leakage of payment details, privacy violations, fraud risk, and compliance exposure. | Tokenize payment data, send card details only to Stripe or a PCI-compliant payment flow, avoid logging sensitive values, use HTTPS, and follow PCI DSS requirements. |

### Trust boundaries
1. **User browser -> React frontend runtime**: The user's device and browser are untrusted, so all input from forms, cookies, and local storage must be treated as attacker-controlled.
2. **React frontend -> Node.js API**: Data crossing from the client application to the backend API is a major trust boundary because requests can be intercepted, modified, replayed, or forged.
3. **Node.js API -> PostgreSQL database**: The application layer must not trust any database input, and the database should only accept parameterized queries from a least-privilege service account.
4. **Node.js API -> Stripe**: Payment and card-related data leaves the application boundary and enters a third-party service, so the integration must assume an external trust domain with strict validation and token-based payment handling.

### DREAD SQL Injection threat
| **DREAD Factor** | **Score** | **Justification** |
| --- | --- | --- |
| **Damage** | 9 | A successful SQL injection in product search can expose or alter database records, including product data and potentially customer data if the query is reused or chained. The business and privacy impact is high. |
| **Reproducibility** | 8 | If the search endpoint is vulnerable, the attack can usually be repeated reliably with the same crafted payloads until the issue is fixed. |
| **Exploitability** | 8 | Product search is easy to discover, and SQL injection payloads are widely known and simple to automate against web forms or query parameters. |
| **Affected Users** | 9 | A breach could impact many or all users because the search feature is public and the backend database is shared across the whole platform. |
| **Discoverability** | 8 | Search endpoints are typically visible in the UI and easy to enumerate, making the vulnerable attack surface straightforward to find. |

**Total DREAD score: 42/50**

SQL injection is a high-severity threat here because the search feature is public, the backend likely builds database queries from user input, and a single weakness could expose a broad portion of the platform's data.