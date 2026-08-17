#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "Error: this script must be run as root (sudo)." >&2
	exit 1
fi

SOURCE="network_baseline.json"
OUTPUT="attack_surface.json"

CATALOG="service_catalog.json"
CRITICALITY="service_criticality.json"

if [ ! -f "$SOURCE" ]; then
	echo "$SOURCE not found in current folder." >&2
	exit 1
fi


CATALOG_JSON=$(cat "$CATALOG")
CRITICALITY_JSON=$(cat "$CRITICALITY")

ENRICHED_SOCKETS=$(
jq -c '.listening_sockets[]' "$SOURCE" |
while IFS= read -r socket; do

	PID=$(jq -r '.pid' <<< "$socket")

	BINARY=$(readlink -f "/proc/$PID/exe" 2>/dev/null)

	PACKAGE=""
	if [ -n "$BINARY" ]; then
		PACKAGE=$(dpkg -S "$BINARY" 2>/dev/null |
			cut -d: -f1 |
			head -n1)
		if [ -z "$PACKAGE" ] && [[ "$BINARY" == /usr/lib/* ]]; then
			PACKAGE=$(dpkg -S "/lib/${BINARY#/usr/lib/}" 2>/dev/null |
				cut -d: -f1 |
				head -n1)
		fi
	fi

	SERVICE=""
	if [ -n "$PID" ] && [ "$PID" != "null" ]; then
		if SERVICE=$(systemctl show "$PID" -p Id --value 2>/dev/null) && [[ "$SERVICE" == *.service ]]; then
			:
		else
			SERVICE=$(grep -oE '[^/]+\.service' /proc/$PID/cgroup | head -n1)

		 	[[ "$SERVICE" == *.service ]] || SERVICE=""
		fi
	fi

	FUNCTION=$(jq -r \
		--arg service "$SERVICE" \
		'.[] | select(.service == $service) | .function' \
		<<< "$CATALOG_JSON" |
		head -n1)

	[ -n "$FUNCTION" ] || FUNCTION="unknown"

	CRITICAL_VALUE=$(jq -r \
		--arg service "$SERVICE" \
		'.[] | select(.service == $service) | .criticality' \
		<<< "$CRITICALITY_JSON" | 
		head -n1)

	jq -c \
		--arg binary "$BINARY" \
		--arg package "$PACKAGE" \
		--arg service "$SERVICE" \
		--arg function "$FUNCTION" \
		--arg criticality "$CRITICAL_VALUE" \
		'. + {
		binary: (if $binary == "" then null else $binary end),
		package: (if $package == "" then null else $package end),
		service: (if $service == "" then null else $service end),
		function: $function,
		criticality: $criticality
	}' <<< "$socket"

done | jq -s . )

EXPOSED_SOCKETS=$(jq -c '
	map(
		select(
			((.peer | startswith("0.0.0.0:"))
			and
			(.function == "database" or .function == "rpc"))
			or
			(.function == "telnet"
			or .function == "ftp"
			or .function == "snmpv1"
			or .function == "snmpv2c"
			or .function == "rlogin"
			or .function == "nfs v2/v3")
		)
	)
' <<< "$ENRICHED_SOCKETS")

TIMESTAMP=$(date --iso-8601=seconds)
HOSTNAME=$(hostname)

jq -n \
    --arg generated_at "$TIMESTAMP" \
    --arg hostname "$HOSTNAME" \
    --argjson sockets "$EXPOSED_SOCKETS" \
'
def parse_local:
    if startswith("[") then
        capture("^\\[(?<addr>[^]]+)\\]:(?<port>[0-9]+)$")
        | {bind_addr: .addr, port: (.port | tonumber)}
    else
        capture("^(?<addr>.*):(?<port>[0-9]+)$")
        | {bind_addr: .addr, port: (.port | tonumber)}
    end;

{
    generated_at: $generated_at,
    hostname: $hostname,

    sockets: [
        $sockets[] |
        . as $socket |

        ($socket.local | parse_local) as $local |

        {
            proto: $socket.netid,
            port: $local.port,
            bind_addr: $local.bind_addr,
            process: $socket.process,
            package: $socket.package,
            function: $socket.function,
            criticality: $socket.criticality,

            exposure_flags: [
                if ($socket.peer | startswith("0.0.0.0:"))
                   and ($socket.function == "database" or $socket.function == "rpc")
                then "wildcard_bind_database_or_rpc"
                else empty
                end,

                if $socket.function == "telnet"
                then "insecure_telnet"
                else empty
                end,

                if $socket.function == "ftp"
                then "insecure_ftp"
                else empty
                end,

                if $socket.function == "snmpv1"
                then "insecure_snmpv1"
                else empty
                end,

                if $socket.function == "snmpv2c"
                then "insecure_snmpv2c"
                else empty
                end,

                if $socket.function == "rlogin"
                then "insecure_rlogin"
                else empty
                end,

                if $socket.function == "nfs v2/v3"
                then "insecure_nfs_v2_v3"
                else empty
                end
            ]
        }
    ],

    summary: {
        flagged: ($sockets | length),

        by_severity: {
            critical: ([$sockets[] | select(.criticality == "critical")] | length),
            high:     ([$sockets[] | select(.criticality == "high")] | length),
            medium:   ([$sockets[] | select(.criticality == "medium")] | length),
            low:      ([$sockets[] | select(.criticality == "low")] | length)
        }
    }
}
' > $OUTPUT

