#!/bin/bash

# 12-luks_manager.sh
# Usage:
#   sudo ./12-luks_manager.sh create <size>
#   sudo ./12-luks_manager.sh open
#   sudo ./12-luks_manager.sh close

set -e

VOLUME="encrypted_volume.img"
MAPPER="secure_vol"
MOUNT_POINT="/mnt/secure_vol"

case "$1" in

create)
    if [ -z "$2" ]; then
        echo "Usage: sudo $0 create <size>"
        echo "Example: sudo $0 create 100M"
        exit 1
    fi

    echo "[+] Creating encrypted volume of size $2..."

    # Create empty file
    fallocate -l "$2" "$VOLUME"

    # Format as LUKS
    cryptsetup luksFormat "$VOLUME"

    echo "[+] Opening LUKS volume..."
    cryptsetup luksOpen "$VOLUME" "$MAPPER"

    # Create filesystem
    mkfs.ext4 "/dev/mapper/$MAPPER"

    # Close after creation
    cryptsetup luksClose "$MAPPER"

    echo "[+] LUKS volume created successfully."
    ;;

open)
    echo "[+] Opening encrypted volume..."

    cryptsetup luksOpen "$VOLUME" "$MAPPER"

    mkdir -p "$MOUNT_POINT"

    mount "/dev/mapper/$MAPPER" "$MOUNT_POINT"

    echo "[+] Volume mounted at $MOUNT_POINT"
    ;;

close)
    echo "[+] Closing encrypted volume..."

    umount "$MOUNT_POINT"

    cryptsetup luksClose "$MAPPER"

    echo "[+] Volume unmounted and closed."
    ;;

*)
    echo "Usage:"
    echo "  sudo $0 create <size>"
    echo "  sudo $0 open"
    echo "  sudo $0 close"
    exit 1
    ;;

esac
