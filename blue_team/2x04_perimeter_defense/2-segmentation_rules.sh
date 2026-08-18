#!/bin/bash

set -euo pipefail

OUTPUT="segmentation_rules.json"

ZONES_JSON=$(jq -n '[
  {
    name: "DMZ",
    cidr: "10.10.2.0/24",
    purpose: "Public-facing services",
    default_inbound: "drop",
    default_outbound: {
      action: "accept",
      restrictions: ["no_mgmt_access", "no_meddev_access"]
    }
  },
  {
    name: "INTERNAL",
    cidr: "10.10.1.0/24",
    purpose: "Clinical applications and databases",
    default_inbound: "drop",
    default_outbound: {
      action: "accept",
      restrictions: ["no_meddev_access"]
    }
  },
  {
    name: "MGMT",
    cidr: "192.168.10.0/24",
    purpose: "Administration and management",
    default_inbound: "drop",
    default_outbound: {
      action: "accept",
      restrictions: []
    }
  },
  {
    name: "MEDDEV",
    cidr: "10.10.3.0/24",
    purpose: "Medical device VLAN",
    default_inbound: "drop",
    default_outbound: {
      action: "accept",
      restrictions: [
        "no_dmz_access",
        "no_public_internet_access"
      ]
    }
  }
]')


FLOWS_JSON=$(jq -n '[
  {
    src_zone: "MGMT",
    dst_zone: "INTERNAL",
    proto: "tcp",
    dport: 22,
    justification: "Administration of internal hosts",
    action: "allow"
  },

  {
    src_zone: "MGMT",
    dst_zone: "DMZ",
    proto: "tcp",
    dport: 22,
    justification: "Administration of DMZ hosts",
    action: "allow"
  },

  {
    src_zone: "INTERNAL",
    dst_zone: "INTERNAL",
    src_hosts: ["clinical-workstations"],
    dst_hosts: ["internal-server-hosts"],
    proto: "tcp",
    dport: 443,
    justification: "Clinical workstation access to internal application servers",
    action: "allow"
  },

  {
    src_zone: "INTERNAL",
    dst_zone: "INTERNAL",
    src_hosts: ["clinical-workstations"],
    dst_hosts: ["internal-server-hosts"],
    proto: "tcp",
    dport: 3306,
    justification: "Clinical workstation access to internal database servers",
    action: "allow"
  },

  {
    src_zone: "DMZ",
    dst_zone: "INTERNAL",
    src_hosts: ["dmz-app-01", "dmz-app-02"],
    dst_hosts: ["internal-databases"],
    proto: "tcp",
    dport: 3306,
    justification: "DMZ application access to internal databases",
    action: "allow"
  },

  {
    src_zone: "MEDDEV",
    dst_zone: "INTERNAL",
    dst_hosts: ["internal-pacs"],
    proto: "tcp",
    dport: 4242,
    justification: "DICOM imaging to PACS",
    action: "allow"
  },

  {
    src_zone: "MEDDEV",
    dst_zone: "INTERNAL",
    dst_hosts: ["internal-ehr"],
    proto: "tcp",
    dport: 443,
    justification: "EHR web integration for device display",
    action: "allow"
  },

  {
    src_zone: "MGMT",
    dst_zone: "MEDDEV",
    proto: "tcp",
    dport: 22,
    justification: "Administration of medical devices",
    action: "allow"
  },

  {
    src_zone: "MGMT",
    dst_zone: "MEDDEV",
    proto: "tcp",
    dport: 4242,
    justification: "Medical device management using DICOM",
    action: "allow"
  },

  {
    src_zone: "ALL",
    dst_zone: "MGMT",
    dst_hosts: ["mgmt-resolver"],
    proto: "udp",
    dport: 53,
    justification: "DNS resolution through management resolver",
    action: "allow"
  },

  {
    src_zone: "ALL",
    dst_zone: "MGMT",
    dst_hosts: ["mgmt-resolver"],
    proto: "tcp",
    dport: 53,
    justification: "TCP DNS resolution through management resolver",
    action: "allow"
  }
]')

DENY_JSON=$(jq -n \
  --arg zones "$ZONES_JSON" \
  --arg flows "$FLOWS_JSON" '
  ($zones | fromjson) as $zones_obj |
  ($flows | fromjson) as $flows_obj |

  [
    $zones_obj[].name as $src |
    $zones_obj[].name as $dst |

    select($src != $dst) |

    select(
      [
        $flows_obj[] |
        select(
          (.dst_zone == $dst) and
          (.src_zone == $src or .src_zone == "ALL")
        )
      ] | length == 0
    ) |

    {
      src_zone: $src,
      dst_zone: $dst,
      action: "deny_all",
      justification: "No cross-zone flows are authorized"
    }
  ]
')

jq -n \
  --arg zones "$ZONES_JSON" \
  --arg flows "$FLOWS_JSON" \
  --arg denies "$DENY_JSON" '
  ($zones | fromjson) as $zones_obj |
  ($flows | fromjson) as $flows_obj |
  ($denies | fromjson) as $denies_obj |

  ($flows_obj + $denies_obj) as $all_flows |

  {
    zones: $zones_obj,
    flows: $all_flows,
    summary: {
      flow_count: ($all_flows | length),
      allow_count: ($flows_obj | length),
      deny_count: ($denies_obj | length),
      cross_zone_pairs: (
        [
          $zones_obj[].name as $src |
          $zones_obj[].name as $dst |
          select($src != $dst) |
          {
            src_zone: $src,
            dst_zone: $dst
          }
        ] | length
      )
    }
  }
' > "$OUTPUT"

