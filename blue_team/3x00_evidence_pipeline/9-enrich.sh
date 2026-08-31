#!/bin/bash

set -euo pipefail

INPUT="${1:-cleaned_events.json}"
ASSET_INVENTORY="${2:-"$HOME/evidence_pack_primary/context/asset_inventory.json"}"
NETWORK_ZONES="${3:-"$HOME/evidence_pack_primary/context/network_zones.json"}"
OUTPUT="${4:-enriched_events.json}"

python3 -W error - "$INPUT" "$ASSET_INVENTORY" "$NETWORK_ZONES" "$OUTPUT" <<'PY'
import ipaddress
import json
import sys
from pathlib import Path


input_path = Path(sys.argv[1])
asset_inventory_path = Path(sys.argv[2])
network_zones_path = Path(sys.argv[3])
output_path = Path(sys.argv[4])


def load_json(path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def asset_context(asset):
    return {
        "role": asset.get("role"),
        "criticality": asset.get("criticality"),
        "os": asset.get("os"),
        "owner": asset.get("owner"),
        "zone": asset.get("zone"),
    }


def build_asset_indexes(document):
    assets = document.get("assets")

    if not isinstance(assets, list):
        raise ValueError(
            "asset inventory must contain an 'assets' array"
        )

    hostname_index = {}
    ip_index = {}

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        hostname = asset.get("hostname")
        address = asset.get("ip")

        if isinstance(hostname, str) and hostname.strip():
            hostname_index[hostname.strip().lower()] = asset_context(asset)

        if isinstance(address, str) and address.strip():
            try:
                normalized_ip = str(ipaddress.ip_address(address.strip()))
            except ValueError:
                continue

            ip_index.setdefault(normalized_ip, asset_context(asset))

    return hostname_index, ip_index


def build_zone_index(document):
    zones = document.get("zones")

    if not isinstance(zones, list):
        raise ValueError(
            "network zones document must contain a 'zones' array"
        )

    zone_index = []

    for zone in zones:
        if not isinstance(zone, dict):
            continue

        zone_id = zone.get("zone_id")
        cidrs = zone.get("cidrs")

        if not isinstance(zone_id, str) or not zone_id.strip():
            continue

        if not isinstance(cidrs, list):
            continue

        for cidr in cidrs:
            if not isinstance(cidr, str):
                continue

            try:
                network = ipaddress.ip_network(
                    cidr.strip(),
                    strict=False,
                )
            except ValueError:
                continue

            zone_index.append((network, zone_id.strip()))

    # Longest-prefix matching makes overlapping CIDR results deterministic.
    zone_index.sort(
        key=lambda item: (
            item[0].version,
            -item[0].prefixlen,
            str(item[0].network_address),
        )
    )

    return zone_index


def resolve_zone(value, zone_index):
    if not isinstance(value, str) or not value.strip():
        return "unknown"

    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return "unknown"

    for network, zone_id in zone_index:
        if address.version == network.version and address in network:
            return zone_id

    return "unknown"


def resolve_asset(event, hostname_index, ip_index):
    hostname = event.get("hostname")

    # Use hostname only when it is a real-looking asset hostname.
    if isinstance(hostname, str):
        normalized_hostname = hostname.strip().lower()

        if normalized_hostname not in ("", "network", "unknown"):
            asset = hostname_index.get(normalized_hostname)

            if asset is not None:
                return asset

    # Firewall events commonly use hostname="network". Prefer the
    # internal source IP, then fall back to the destination IP.
    for field in ("src_ip", "dst_ip"):
        value = event.get(field)

        if not isinstance(value, str) or not value.strip():
            continue

        try:
            normalized_ip = str(ipaddress.ip_address(value.strip()))
        except ValueError:
            continue

        asset = ip_index.get(normalized_ip)

        if asset is not None:
            return asset

    return None


def percentage(count, total):
    if total == 0:
        return 0.0
    return count * 100.0 / total


asset_document = load_json(asset_inventory_path)
zone_document = load_json(network_zones_path)

hostname_index, ip_index = build_asset_indexes(asset_document)
zone_index = build_zone_index(zone_document)

total_events = 0
asset_context_added = 0
src_zone_resolved = 0
dst_zone_resolved = 0
unknown_hosts = 0

enriched_events = []

with input_path.open("r", encoding="utf-8") as handle:
    for line_number, line in enumerate(handle, start=1):
        if not line.strip():
            continue

        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"invalid JSON on input line {line_number}: {exc}"
            ) from exc

        if not isinstance(event, dict):
            raise ValueError(
                f"input line {line_number} is not a JSON object"
            )

        total_events += 1
        enriched_event = dict(event)

        asset = resolve_asset(
            event,
            hostname_index,
            ip_index,
        )

        if asset is None:
            unknown_hosts += 1
        else:
            enriched_event["asset"] = asset
            asset_context_added += 1

        if "src_ip" in event and event.get("src_ip") is not None:
            src_zone = resolve_zone(event.get("src_ip"), zone_index)
            enriched_event["src_zone"] = src_zone

            if src_zone != "unknown":
                src_zone_resolved += 1

        if "dst_ip" in event and event.get("dst_ip") is not None:
            dst_zone = resolve_zone(event.get("dst_ip"), zone_index)
            enriched_event["dst_zone"] = dst_zone

            if dst_zone != "unknown":
                dst_zone_resolved += 1

        enriched_events.append(enriched_event)


with output_path.open("w", encoding="utf-8") as handle:
    for event in enriched_events:
        handle.write(
            json.dumps(
                event,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )


print(f"events processed    : {total_events}")
print(
    "asset context added : "
    f"{asset_context_added} "
    f"({percentage(asset_context_added, total_events):.2f}%)"
)
print(
    "src_zone resolved   : "
    f"{src_zone_resolved} "
    f"({percentage(src_zone_resolved, total_events):.2f}%)"
)
print(
    "dst_zone resolved   : "
    f"{dst_zone_resolved} "
    f"({percentage(dst_zone_resolved, total_events):.2f}%)"
)
print(f"unknown hosts       : {unknown_hosts}")
print(f"{output_path.name} written")
PY

