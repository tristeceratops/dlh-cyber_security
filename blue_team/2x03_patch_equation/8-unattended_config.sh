#!/bin/bash

set -u

MAIN_CONF="/etc/apt/apt.conf.d/50unattended-upgrades"
AUTO_CONF="/etc/apt/apt.conf.d/20auto-upgrades"
REPORT_PATH="unattended_config.json"

PACKAGE_STATE=""
DAILY_TIMER_STATE="inactive"
UPGRADE_TIMER_STATE="inactive"
UPGRADE_COUNT=0
BLACKLIST_COUNT=0
HELD_COUNT=0
DRY_OUTPUT=""

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[-] This script must be run as root."
        echo "    Use: sudo $0"
        exit 1
    fi
}

install_dependency() {
    printf "[*] unattended-upgrades: "

    if dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null |
        grep -q "install ok installed"; then
        echo "already installed"
        PACKAGE_STATE="already_installed"
        return 0
    fi

    echo "installing..."

    if DEBIAN_FRONTEND=noninteractive \
        apt-get install -y unattended-upgrades >/dev/null 2>&1; then
        echo "    installed"
        PACKAGE_STATE="installed_now"
        return 0
    fi

    echo "    installation failed"
    PACKAGE_STATE="installation_failed"
    return 1
}

write_file() {
    local target="$1"
    local content="$2"

    printf "[*] Writing %s...   " "$target"

    if printf '%s\n' "$content" > "$target"; then
        echo "OK"
        return 0
    fi

    echo "FAILED"
    return 1
}

write_main_config() {
    local content

    content='Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};

Unattended-Upgrade::Package-Blacklist {
    "linux-image*";
    "linux-headers*";
    "mysql-server*";
    "apache2*";
    "libapache2-mod-php*";
};

Unattended-Upgrade::Automatic-Reboot "false";

Unattended-Upgrade::Remove-Unused-Kernel-Packages "false";

Unattended-Upgrade::Mail "";

Unattended-Upgrade::MailReport "never";'

    write_file "$MAIN_CONF" "$content"
}

write_auto_config() {
    local content

    content='APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";'

    write_file "$AUTO_CONF" "$content"
}

configure_timers() {
    local timer
    local failed=0

    printf "[*] Configuring timers...\n"

    for timer in apt-daily.timer apt-daily-upgrade.timer; do
        printf "    %-30s " "$timer"

        if systemctl enable "$timer" >/dev/null 2>&1 &&
           systemctl start "$timer" >/dev/null 2>&1; then
            echo "OK"
        else
            echo "FAILED"
            failed=1
        fi
    done

    DAILY_TIMER_STATE=$(systemctl is-active apt-daily.timer 2>/dev/null || echo "inactive")
    UPGRADE_TIMER_STATE=$(systemctl is-active apt-daily-upgrade.timer 2>/dev/null || echo "inactive")

    echo "    apt-daily.timer:         ${DAILY_TIMER_STATE}"
    echo "    apt-daily-upgrade.timer: ${UPGRADE_TIMER_STATE}"

    [ "$failed" -eq 0 ]
}

run_dry_check() {
    echo "[*] Dry run..."

    DRY_OUTPUT=$(unattended-upgrades --dry-run --debug 2>&1 || true)

    UPGRADE_COUNT=$(
        printf '%s\n' "$DRY_OUTPUT" |
            grep -c "Inst " 2>/dev/null || true
    )
    UPGRADE_COUNT=$((UPGRADE_COUNT + 0))

    BLACKLIST_COUNT=$(
        printf '%s\n' "$DRY_OUTPUT" |
            grep -iE "blacklist|Skipping.*blacklist|Not upgrading.*blacklist" |
            grep -cE "linux-image|linux-headers|mysql-server|apache2|libapache2-mod-php" \
            2>/dev/null || true
    )
    BLACKLIST_COUNT=$((BLACKLIST_COUNT + 0))

    HELD_COUNT=$(
        printf '%s\n' "$DRY_OUTPUT" |
            grep -cE "on hold|held back" 2>/dev/null || true
    )
    HELD_COUNT=$((HELD_COUNT + 0))

    echo "would upgrade:       ${UPGRADE_COUNT}"
    echo "skipped (blacklist): ${BLACKLIST_COUNT}"
    echo "skipped (held):      ${HELD_COUNT}"
}

write_report() {
    jq -n \
        --arg installed "$PACKAGE_STATE" \
        --arg main_conf "$MAIN_CONF" \
        --arg auto_conf "$AUTO_CONF" \
        --arg daily "$DAILY_TIMER_STATE" \
        --arg upgrade "$UPGRADE_TIMER_STATE" \
        --argjson upgrades "$UPGRADE_COUNT" \
        --argjson blacklist "$BLACKLIST_COUNT" \
        --argjson held "$HELD_COUNT" \
        '{
            installed: $installed,
            config_paths: [
                $main_conf,
                $auto_conf
            ],
            blacklist: [
                "linux-image*",
                "linux-headers*",
                "mysql-server*",
                "apache2*",
                "libapache2-mod-php*"
            ],
            timer_state: {
                "apt-daily.timer": $daily,
                "apt-daily-upgrade.timer": $upgrade
            },
            dry_run_summary: {
                would_upgrade: $upgrades,
                skipped_blacklisted: $blacklist,
                skipped_held: $held
            }
        }' > "$REPORT_PATH"
}

main() {
    require_root

    install_dependency || exit 1

    write_main_config || exit 1
    write_auto_config || exit 1

    configure_timers || exit 1

    run_dry_check

    write_report

    echo "Report saved to: ${REPORT_PATH}"
}

main "$@"

