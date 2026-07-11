# 1. The First Incidents

## Introduction

### Goal
Learn to classify security events using the CIA Triad as an analytical framework.

### Context
While reading Marcus's notes from the onboarding packet, you find a section titled "Incident Log, Last 6 Months." It is a rough list of security-relevant events that occurred at MedDefense. Some were handled. Some were not. None were formally classified.

Before you can assess the security posture, you need to understand what has already gone wrong. More importantly, you need a framework to describe how it went wrong. That framework is the CIA Triad:

-	Confidentiality: Information was accessed by someone who should not have seen it.

-	Integrity: Information or a system was modified without authorization.

-	Availability: A service, system or data became inaccessible when it was needed.

Every security incident impacts at least one of these pillars. Some impact more than one.

---

## Incident log analyse
| Incident | Primary CIA Pillar | Justification | Secondary CIA Pillar (if applicable) | Secondary Impact Explanation |
|----------|---------------------|---------------|--------------------------------------|------------------------------|
| **A – Ransomware on Billing Server** | **Availability** | The ransomware encrypted the billing server, preventing the finance team from processing insurance claims for four days. | **Integrity** | The encryption altered the system's data into an unusable state, and outdated backups increased the risk of data inconsistency or permanent data loss. |
| **B – Patient Portal Broken Access Control** | **Confidentiality** | Unauthorized patients could access other patients' laboratory results by manipulating the URL, exposing sensitive medical information. | None | / |
| **C – Incorrect Medication Dosages** | **Integrity** | A faulty database update script overwrote medication dosage values, causing incorrect information to be displayed across all sites. | **Availability** | Although the system remained online, the incorrect data made it unsafe to rely on until corrected, effectively reducing the usability of the system. |
| **D – Website Defacement** | **Integrity** | Attackers altered the website's homepage by replacing legitimate content with a political message. | **Availability** | While the site remained accessible, legitimate content was unavailable until restoration from backup. |
| **E – EHR Database Migration Outage** | **Availability** | The EHR system was unavailable for nine hours, preventing physicians from accessing electronic health records during patient care. | None | / |
| **F – Unauthorized Personal Laptop on Internal Network** | **Confidentiality** | An unmanaged personal laptop with access to the internal network increased the risk of unauthorized exposure of sensitive corporate and HR data. | **Integrity** | An untrusted device on the internal network could potentially modify, introduce malware, or corrupt organizational data and systems. |