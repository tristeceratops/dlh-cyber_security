# The Shadow Systems

## Introduction

### Goal
Identify and assess unmanaged assets that exist outside the organization's official IT governance, and determine the appropriate response for each.

### Context
You are cross-referencing your Asset Registry (Task 7) with the network scan when the IT helpdesk lead, Mike Torres, stops by your desk.

"Hey, you're the new security person, right ? I should probably mention a few things. Dr. Patel in Cardiology bought a personal NAS drive and plugged it into the wall port in his office. He stores research data on it, says the hospital's shared drive is too slow. Oh, and the marketing team has been using a shared Google Drive for media files and press communications. It's linked to someone's personal Gmail. Also, there's a Raspberry Pi somewhere on the second floor of Central that the previous intern set up. I think Marcus actually asked him to set it up as some kind of network monitor, but nobody has touched it since they both left."

## Answer

### 1. Personal NAS in Cardiology

**Risk Assessment**

- **Likely data:** cardiology research datasets, export files, drafts, and potentially PHI if patient identifiers were copied with the research material.
- **Controls that do not cover it:** the NAS is not covered by managed endpoint protection (C-007), central logging (C-012), or scheduled backups (C-008) because it sits outside IT governance. It also bypasses network segmentation assumptions because it is simply plugged into an office wall port.
- **Worst-case scenario:** the NAS is encrypted by ransomware or quietly exfiltrated, exposing sensitive research data and any embedded patient information. Because it is unmanaged, IT may not notice the device until the data has already been copied, altered, or destroyed.

**Recommended Response: Migrate**

Move the research data to an approved cardiology or research storage location under IT control, then decommission the personal NAS. The business need is the data, not the hardware, and approved storage can be monitored, backed up, and governed properly. If the team later needs local performance, IT should provide an approved file service or sanctioned NAS under formal management rather than leaving a consumer device in place.

**Asset Registry Update**

- Add [A-034 DrPatel-Personal-NAS](./7-asset_registry.md) with Status: Shadow IT.

### 2. Shared Google Drive Linked to Personal Gmail

**Risk Assessment**

- **Likely data:** marketing media files, press communications, campaign drafts, event assets, and possibly internal messaging about upcoming announcements or vendor coordination.
- **Controls that do not cover it:** this storage is outside the corporate Microsoft 365 tenant and therefore outside the normal internal logging and review path (C-012). It is also not protected by the organization’s managed endpoint controls or password policy in a way the hospital can enforce, and MFA is only confirmed for James Chen’s account, not for a personal Gmail-linked collaboration space.
- **Worst-case scenario:** a compromise of the personal Gmail account or accidental external sharing exposes press materials, internal plans, or embargoed announcements. That could create reputational damage, leaks of strategic communications, and uncontrolled distribution of business content that should remain internal until publication.

**Recommended Response: Migrate**

Move the files and collaboration workflow into an approved corporate platform such as Microsoft 365/SharePoint or another IT-managed service, then retire the personal Google Drive. The content is business data, but the account and storage model are not governable enough for ongoing use. Migration preserves the work product while putting authentication, logging, and retention back under MedDefense control.

**Asset Registry Update**

- Add [A-035 Marketing-Shared-Google-Drive](./7-asset_registry.md) with Status: Shadow IT.

### 3. Unmanaged Raspberry Pi Network Monitor

**Risk Assessment**

- **Likely data:** network telemetry, device names, IP addresses, and possibly packet contents or credentials if it is doing passive monitoring or packet capture.
- **Controls that do not cover it:** because it is unmanaged and likely Linux-based, it is not covered by the Sophos endpoint control (C-007). There is no evidence of centralized logging or active monitoring for it (C-012), and it has none of the compensating controls designed for legacy systems in Task 6 because it was never brought under a formal exception process.
- **Worst-case scenario:** the Pi becomes a hidden foothold on the network, silently captures traffic, or is repurposed by an attacker as a backdoor into the hospital environment. If it is left running unmonitored, it can also become a false sense of security by failing without anyone noticing.

**Recommended Response: Decommission**

Remove the Raspberry Pi from the network and physically recover the device. If MedDefense still needs a network-monitoring capability, rebuild it as an approved IT project on managed hardware with logging, ownership, patching, and documented purpose. Because the current device has no clear owner and no governance trail, keeping it alive would preserve risk without preserving trust.

**Asset Registry Update**

- Add [A-036 Second-Floor-Raspberry-Pi-Monitor](./7-asset_registry.md) with Status: Shadow IT.

### Shadow IT Policy Recommendation

The most effective policy change would be a mandatory IT registration and approval rule for any device, cloud service, or data repository used for hospital work, enforced through department manager sign-off and periodic network discovery review. If staff know they cannot keep using unapproved systems without losing support, access, or budget approval, shadow IT will be harder to start and much easier to eliminate early.