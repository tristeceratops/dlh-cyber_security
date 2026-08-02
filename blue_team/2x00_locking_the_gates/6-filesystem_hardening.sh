#!/bin/bash

set -euo pipefail

SUID_REMOVED=0
SGID_REMOVED=0
WORLD_FIXED=0


if [[ $EUID -ne 0 ]]; then
    echo "Error: run this script as root"
    exit 1
fi


echo "[*] Checking SUID binaries..."


SUID_WHITELIST=(
"/usr/bin/passwd"
"/usr/bin/sudo"
"/usr/bin/su"
"/usr/bin/chsh"
"/usr/bin/chfn"
"/usr/bin/gpasswd"
"/usr/bin/newgrp"
"/usr/bin/mount"
"/usr/bin/umount"
"/usr/bin/fusermount3"
"/usr/bin/pkexec"
"/usr/lib/openssh/ssh-keysign"
"/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
"/usr/lib/snapd/snap-confine"
"/usr/bin/at"
"/usr/bin/crontab"
"/usr/bin/chage"
)


is_suid_whitelisted() {

    local file="$1"

    for allowed in "${SUID_WHITELIST[@]}"; do
        [[ "$file" == "$allowed" ]] && return 0
    done

    return 1
}



mapfile -t SUID_FILES < <(
    find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -path /dev -prune -o \
    -type f -perm -4000 -print 2>/dev/null
)


echo "Found ${#SUID_FILES[@]} SUID binaries"


SUID_ALLOWED=0
SUID_UNEXPECTED=0


for file in "${SUID_FILES[@]}"; do

    if is_suid_whitelisted "$file"; then

        SUID_ALLOWED=$((SUID_ALLOWED+1))

    else

        SUID_UNEXPECTED=$((SUID_UNEXPECTED+1))


        FSTYPE=$(findmnt -no FSTYPE "$file" 2>/dev/null || true)

        if [[ "$FSTYPE" == "squashfs" ]]; then

            echo "  $file [SKIPPED - READ ONLY]"

        elif chmod u-s "$file"; then

            echo "  $file [SUID REMOVED]"
            SUID_REMOVED=$((SUID_REMOVED+1))

        else

            echo "  $file [FAILED]"

        fi

    fi

done


echo "Whitelisted: $SUID_ALLOWED"
echo "Non-whitelisted: $SUID_UNEXPECTED"



echo
echo "[*] Checking SGID binaries..."



SGID_WHITELIST=(
"/usr/bin/wall"
"/usr/bin/write"
"/usr/bin/crontab"
"/usr/bin/expiry"
"/usr/bin/ssh-agent"
"/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
)



is_sgid_whitelisted() {

    local file="$1"

    for allowed in "${SGID_WHITELIST[@]}"; do
        [[ "$file" == "$allowed" ]] && return 0
    done

    return 1
}



mapfile -t SGID_FILES < <(
    find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -path /dev -prune -o \
    -type f -perm -2000 -print 2>/dev/null
)



echo "Found ${#SGID_FILES[@]} SGID binaries"



SGID_ALLOWED=0
SGID_UNEXPECTED=0



for file in "${SGID_FILES[@]}"; do


    if is_sgid_whitelisted "$file"; then

        SGID_ALLOWED=$((SGID_ALLOWED+1))

    else

        SGID_UNEXPECTED=$((SGID_UNEXPECTED+1))


        FSTYPE=$(findmnt -no FSTYPE "$file" 2>/dev/null || true)


        if [[ "$FSTYPE" == "squashfs" ]]; then

            echo "  $file [SKIPPED - READ ONLY]"

        elif chmod g-s "$file"; then

            echo "  $file [SGID REMOVED]"
            SGID_REMOVED=$((SGID_REMOVED+1))

        else

            echo "  $file [FAILED]"

        fi

    fi

done


echo "Whitelisted: $SGID_ALLOWED"
echo "Non-whitelisted: $SGID_UNEXPECTED"



echo
echo "[*] Checking world writable files..."



mapfile -t WORLD_WRITABLE < <(
    find / \
    -path /proc -prune -o \
    -path /sys -prune -o \
    -path /dev -prune -o \
    -type f -perm -0002 -print 2>/dev/null
)



echo "Found ${#WORLD_WRITABLE[@]} world-writable files"



for file in "${WORLD_WRITABLE[@]}"; do


    if chmod o-w "$file"; then

        echo "  $file [FIXED]"
        WORLD_FIXED=$((WORLD_FIXED+1))

    else

        echo "  $file [FAILED]"

    fi

done



echo
echo "[*] Checking mount options..."



harden_mount() {

    local mountpoint="$1"


    if mountpoint -q "$mountpoint"; then


        OPTIONS=$(findmnt -no OPTIONS "$mountpoint")


        if [[ "$OPTIONS" == *noexec* &&
              "$OPTIONS" == *nosuid* &&
              "$OPTIONS" == *nodev* ]]; then


            echo "$mountpoint: noexec,nosuid,nodev [OK]"


        else


            if mount -o remount,noexec,nosuid,nodev "$mountpoint"; then

                echo "$mountpoint: noexec,nosuid,nodev [APPLIED]"

            else

                echo "$mountpoint: noexec,nosuid,nodev [FAILED]"

            fi


        fi


    else

        echo "$mountpoint: not mounted [SKIPPED]"

    fi

}



harden_mount /tmp
harden_mount /var/tmp
harden_mount /dev/shm



echo
echo "[*] Restricting cron access..."



echo "root" > /etc/cron.allow
chmod 600 /etc/cron.allow

rm -f /etc/cron.deny



echo
echo "==============================="
echo "Filesystem hardening summary"
echo "==============================="
echo "SUID remediated: $SUID_REMOVED"
echo "SGID remediated: $SGID_REMOVED"
echo "World-writable fixed: $WORLD_FIXED"
