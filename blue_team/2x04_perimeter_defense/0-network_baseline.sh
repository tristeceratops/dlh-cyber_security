#!/bin/bash

if [[ $EUID -ne 0 ]]; then
    echo "Error: this script must be run as root (sudo)." >&2
    exit 1
fi

# get name, MAC, link state and all assigned addresses 
ADDRS=$(ip -j addr show | jq -c '[.[] | {
  name: .ifname,
  mac: .address,
  link_state: .flags,
  addresses: [.addr_info[] | {family: .family, address: .local, prefixlen: .prefixlen}]
}]')

# Capture the routing table with ip -j route show including the default gateway
ROUTES=$(ip -j route show)

# Capture the ARP neighbors table with ip -j neigh show and retain IP, MAC and state
ARP=$(ip -j neigh show | jq -c '.[] | {IP: .dst, MAC: .lladdr, state: .state}')

# Enumerate listening TCP and UDP sockets with ss -tulnpH and resolve each socket to its owning process and PID
SOCKETS=$(ss -H -tulnp |
awk '
{
    users = $7
    sub(/^users:\(\(/, "", users)
    sub(/\)\)$/, "", users)
    n = split(users, u, /\),\(/)

    for (i = 1; i <= n; i++) {
        split(u[i], f, ",")

        process = f[1]
        sub(/^"/, "", process)
        sub(/"$/, "", process)

        pid = f[2]; sub(/^pid=/, "", pid)
        fd  = f[3]; sub(/^fd=/, "", fd)

        printf "{\"netid\":\"%s\",\"state\":\"%s\",\"local\":\"%s\",\"peer\":\"%s\",\"process\":\"%s\",\"pid\":%s,\"fd\":%s}\n", \
            $1, $2, $5, $6, process, pid, fd
    }
}' |
jq -c -s .)

# Enumerate established outbound connections with ss -tnpH state established and resolve each to its owning process
OUTBOUNDS=$(ss -tnpH state established |
awk '
{
    users = $7
    sub(/^users:\(\(/, "", users)
    sub(/\)\)$/, "", users)
    n = split(users, u, /\),\(/)

    for (i = 1; i <= n; i++) {
        split(u[i], f, ",")

        process = f[1]
        sub(/^"/, "", process)
        sub(/"$/, "", process)

        printf "{\"netid\":\"%s\",\"state\":\"%s\",\"local\":\"%s\",\"peer\":\"%s\",\"process\":\"%s\",\"pid\":%s,\"fd\":%s}\n", \
            $1, $2, $5, $6, process
    }
}' |
jq -c -s .)

# Capture the DNS resolver configuration from /etc/resolv.conf and resolvectl status --no-pager if systemd-resolved is active
if systemctl is-active --quiet systemd-resolved; then
    RESOLV_CONF=$(cat /etc/resolv.conf)
    RESOLVECTL_STATUS=$(resolvectl status --no-pager)
fi

if systemctl is-active --quiet systemd-resolved; then
    RESOLV_CONF=$(cat /etc/resolv.conf)
    RESOLVECTL_STATUS=$(resolvectl status --no-pager)

    DNS_RESOLVERS=$(jq -n \
        --arg resolv_conf "$RESOLV_CONF" \
        --arg resolvectl_status "$RESOLVECTL_STATUS" \
        '{
            systemd_resolved: true,
            resolv_conf: $resolv_conf,
            resolvectl_status: $resolvectl_status
        }')
else
    DNS_RESOLVERS='{"systemd_resolved":false}'
fi

# Emit network_baseline.json with top-level keys: timestamp, hostname, interfaces, routes, neighbors, listening_sockets, established_connections, dns_resolvers
TIMESTAMP=$(date --iso-8601=seconds)
HOSTNAME=$(hostname)

TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

printf '%s\n' "$ADDRS"      > "$TMPDIR/interfaces.json"
printf '%s\n' "$ROUTES"     > "$TMPDIR/routes.json"
printf '%s\n' "$ARP"        > "$TMPDIR/neighbors.json"
printf '%s\n' "$SOCKETS"    > "$TMPDIR/sockets.json"
printf '%s\n' "$OUTBOUNDS"  > "$TMPDIR/connections.json"
printf '%s\n' "$DNS_RESOLVERS" > "$TMPDIR/dns.json"

jq -n \
    --arg timestamp "$TIMESTAMP" \
    --arg hostname "$HOSTNAME" \
    --argfile interfaces "$TMPDIR/interfaces.json" \
    --argfile routes "$TMPDIR/routes.json" \
    --argfile neighbors "$TMPDIR/neighbors.json" \
    --argfile listening_sockets "$TMPDIR/sockets.json" \
    --argfile established_connections "$TMPDIR/connections.json" \
    --argfile dns_resolvers "$TMPDIR/dns.json" \
    '{
        timestamp: $timestamp,
        hostname: $hostname,
        interfaces: $interfaces,
        routes: $routes,
        neighbors: $neighbors,
        listening_sockets: $listening_sockets,
        established_connections: $established_connections,
        dns_resolvers: $dns_resolvers
    }' > network_baseline.json
