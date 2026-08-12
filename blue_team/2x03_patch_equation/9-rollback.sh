#!/bin/bash

SNAPSHOT_FILE="pre_patch_state.json"
DEPENDENCY_FILE="service_dependency_map.json"

PACKAGE_NAME="$1"

get_current_version() {
    dpkg-query -W -f='${Version}' "$PACKAGE_NAME" 2>/dev/null || echo "unknown"
}

get_target_version() {
    jq -r --arg package "$PACKAGE_NAME" \
        '.packages[$package] // empty' \
        "$SNAPSHOT_FILE" 2>/dev/null
}

validate_argument() {
    if [ -z "$PACKAGE_NAME" ]; then
        echo "Usage: $0 <package>"
        exit 1
    fi
}

validate_snapshot() {
    if [ ! -f "$SNAPSHOT_FILE" ]; then
        echo "Error: $SNAPSHOT_FILE not found."
        exit 1
    fi

    TARGET_VERSION=$(get_target_version)

    if [ -z "$TARGET_VERSION" ] || [ "$TARGET_VERSION" = "null" ]; then
        echo "Error: Package $PACKAGE_NAME missing from snapshot."
        exit 1
    fi
}

validate_version() {
    echo "[*] Target version from pre_patch_state.json: $TARGET_VERSION"

    if ! apt-cache madison "$PACKAGE_NAME" | grep -Fq "$TARGET_VERSION"; then
        echo "Error: Version not available."
        exit 1
    fi

    echo "[*] Version available in cache or repository: yes"
}

downgrade_package() {
    echo -n "[*] Downgrading $PACKAGE_NAME...                              "

    if DEBIAN_FRONTEND=noninteractive \
        apt-get install -y --allow-downgrades \
        "$PACKAGE_NAME=$TARGET_VERSION" >/dev/null 2>&1; then
        echo "OK"
    else
        echo "FAIL"
        exit 1
    fi
}

hold_package() {
    echo -n "[*] apt-mark hold $PACKAGE_NAME                               "

    if apt-mark hold "$PACKAGE_NAME" >/dev/null 2>&1; then
        echo "OK"
    else
        echo "FAIL"
        exit 1
    fi
}

get_affected_services() {
    if [ ! -f "$DEPENDENCY_FILE" ]; then
        return 0
    fi

    jq -r \
        --arg package "$PACKAGE_NAME" \
        'to_entries[]
         | select(.value.linked_packages != null)
         | select(.value.linked_packages[] == $package)
         | .key' \
        "$DEPENDENCY_FILE" 2>/dev/null
}

validate_services() {
    echo "[*] Re-running probes for affected services..."

    while IFS= read -r service_name; do
        [ -z "$service_name" ] && continue

        echo -n "    $service_name probe                                  "

        if systemctl is-active --quiet "$service_name"; then
            echo "PASS"
        else
            echo "FAIL"
            exit 1
        fi
    done < <(get_affected_services)
}

print_result() {
    echo "ROLLBACK: success"
    echo "from $CURRENT_VERSION to $TARGET_VERSION"
}

main() {
    validate_argument

    CURRENT_VERSION=$(get_current_version)

    validate_snapshot
    validate_version
    downgrade_package
    hold_package
    validate_services
    print_result

    exit 0
}

main

