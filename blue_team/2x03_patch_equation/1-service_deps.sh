#!/bin/bash

OUTPUT_FILE="service_dependency_map.json"
CRIT_FILE="service_criticality.json"

> "$OUTPUT_FILE"

active_services=$(systemctl list-units \
    --type=service \
    --state=active \
    --no-legend \
    --no-pager | awk '{print $1}')

for service in $active_services; do

    exec_path=""
    main_pid=$(systemctl show -p MainPID --value "$service" 2>/dev/null)

    if [[ "$main_pid" =~ ^[0-9]+$ ]] && [ "$main_pid" -ne 0 ]; then
        exec_path=$(readlink -f "/proc/$main_pid/exe" 2>/dev/null)
    fi

    if [ -z "$exec_path" ] || [ ! -f "$exec_path" ]; then
        exec_path=$(
            systemctl show -p ExecStart --value "$service" 2>/dev/null |
            grep -o 'path=[^ ;]*' |
            cut -d= -f2 |
            head -n1
        )
    fi

    owning_package="unknown"
    json_array="[]"

    if [ -n "$exec_path" ] && [ -f "$exec_path" ]; then

        owning_package=$(
            dpkg -S "$exec_path" 2>/dev/null |
            awk -F: '{print $1}' |
            awk '{print $1}' |
            head -n1
        )

        [ -z "$owning_package" ] && owning_package="unknown"

        pkg_list="$owning_package"

        libs=$(
            ldd "$exec_path" 2>/dev/null |
            awk '
                /=>/ && $3 ~ /^\// { print $3 }
                !/=>/ && $1 ~ /^\// { print $1 }
            ' |
            sort -u
        )

        for lib in $libs; do
            lib_pkg=$(
                dpkg -S "$lib" 2>/dev/null |
                awk -F: '{print $1}' |
                awk '{print $1}' |
                head -n1
            )

            if [ -n "$lib_pkg" ]; then
                pkg_list="$pkg_list
$lib_pkg"
            fi
        done

        unique_pkgs=$(
            printf '%s\n' "$pkg_list" |
            grep -v '^unknown$' |
            sort -u
        )

        if [ -n "$unique_pkgs" ]; then
            json_array=$(printf '%s\n' "$unique_pkgs" | jq -R . | jq -s -c .)
        fi
    fi

    criticality="low"

    if [ -f "$CRIT_FILE" ]; then
        crit_val=$(
            jq -r --arg srv "$service" \
                '.[$srv] // empty' \
                "$CRIT_FILE" 2>/dev/null
        )

        case "$crit_val" in
            critical|high|medium|low)
                criticality="$crit_val"
                ;;
        esac
    fi

    restart_required_on_patch=true

    jq -n -c \
        --arg srv "$service" \
        --arg exec "$exec_path" \
        --arg own "$owning_package" \
        --argjson links "$json_array" \
        --arg crit "$criticality" \
        --argjson restart "$restart_required_on_patch" \
        '{
            service: $srv,
            exec_path: $exec,
            owning_package: $own,
            linked_packages: $links,
            criticality: $crit,
            restart_required_on_patch: $restart
        }' >> "$OUTPUT_FILE"

done

jq -c . "$OUTPUT_FILE" >/dev/null

