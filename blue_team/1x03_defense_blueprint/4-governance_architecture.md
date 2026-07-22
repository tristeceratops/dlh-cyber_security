# The Governance Architecture

## Introduction

### Goal
Design the security governance structure that MedDefense needs to execute and sustain a security program.

### Context
A strategy without governance is a document that sits on a shelf. Governance defines who is responsible, who makes decisions, who is accountable and how the program is sustained beyond the initial implementation.

James Chen raises this concern: "Right now, security decisions are made by whoever shouts loudest. Sarah thinks she owns endpoint security because IT manages the endpoints. I think I own it because it is a security function. Dr. Patel in Cardiology thinks he can do whatever he wants with his data because he is a physician. We need clear roles."

## Answer


# Part 1 – RACI Matrix

| Activity | CEO | Deputy CISO (James) | IT Director (Sarah) | Dept Heads | Security Analyst (You) |
|----------|-----|----------------------|---------------------|------------|------------------------|
| Security budget approval | **A** | **C** | I | I | C |
| Vulnerability remediation | I | **A** | **R** | C | **R** |
| Incident response execution | I | **A** | **R** | C | **R** |
| Security policy approval | **A** | **R** | C | C | C |
| Risk acceptance decisions | **A** | **R** | C | C | I |
| Security awareness training | I | **A** | C | **R** | **R** |
| Vendor risk assessment | I | **A** | C | C | **R** |
| Audit coordination | I | **A** | C | C | **R** |

**Legend**
- **R (Responsible):** Performs the work.
- **A (Accountable):** Final decision-maker and owner.
- **C (Consulted):** Provides expertise or input.
- **I (Informed):** Kept informed of progress or outcome.

---

# Part 2 – Role Definitions

| Role | Assigned To | Explanation |
|------|-------------|-------------|
| **Data Owner** | Department Heads (Clinical Director, HR Director, Finance Director) | Own the business data, decide who may access it, and define classification and retention requirements. |
| **Data Controller** | MedDefense Health Systems (represented by Executive Management/CEO) | Determines why and how personal data is processed, making the organization legally responsible for compliance (e.g., HIPAA/GDPR). |
| **Data Processor** | Third-party service providers (Microsoft 365, cloud vendors, backup providers, external laboratories) | Process MedDefense data on behalf of the organization according to contractual agreements. |
| **Data Custodian (Steward)** | IT Director (Sarah) and IT Operations Team | Implement technical controls such as backups, permissions, encryption, patching, and system maintenance to protect the data. |

---

# Part 3 – The vacant CISO Question

The absence of a dedicated CISO leaves MedDefense without a single executive accountable for cybersecurity strategy, governance, and Board reporting. James, as Deputy CISO, manages operational security but lacks the authority and time to fully develop governance, oversee risk management, and coordinate long-term security initiatives while supporting daily operations. Given the fixed **$120,000 annual security budget**, hiring a full-time CISO would consume a large portion of available funding (typically $180k–250k+ annually). A **virtual CISO (vCISO)** is therefore the most realistic option in the short term: it provides executive security leadership, governance, regulatory guidance, and Board reporting at a fraction of the cost, while allowing James and the Security Analyst to continue handling day-to-day technical operations. As MedDefense's security program matures and the budget increases, transitioning to a full-time CISO can be reconsidered.
