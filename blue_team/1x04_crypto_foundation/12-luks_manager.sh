#!/bin/bash

# 12-luks_manager.sh
# Usage:
#   sudo ./12-luks_manager.sh create
#   sudo ./12-luks_manager.sh open
#   sudo ./12-luks_manager.sh close

set -e

VOLUME="encrypted_volume.img"
MAPPER="secure_vol"
MOUNT_POINT="/mnt/secure_vol"
SIZE="500"

case "$1" in

create)
    echo "[+] Creating a ${SIZE}MB file to use as a virtual disk..."

    # Create 500MB file using dd
    dd if=/dev/zero of="$VOLUME" bs=1M count="$SIZE" status=progress

    echo "[+] Formatting file with LUKS encryption..."

    # Format with LUKS
    cryptsetup luksFormat "$VOLUME"

    echo "[+] Opening encrypted volume..."

    # Open the encrypted volume
    cryptsetup luksOpen "$VOLUME" "$MAPPER"

    echo "[+] Creating ext4 filesystem..."

    # Create filesystem
    mkfs.ext4 "/dev/mapper/$MAPPER"

    echo "[+] Closing encrypted volume..."

    # Unmount and close
    cryptsetup luksClose "$MAPPER"

    echo "[+] LUKS volume created successfully."
    ;;

open)
    echo "[+] Opening encrypted volume..."

    # Open the encrypted volume
    cryptsetup luksOpen "$VOLUME" "$MAPPER"

    # Create mount point
    mkdir -p "$MOUNT_POINT"

    echo "[+] Mounting encrypted filesystem..."

    # Mount volume
    mount "/dev/mapper/$MAPPER" "$MOUNT_POINT"

    echo "[+] Volume mounted at $MOUNT_POINT"
    ;;

close)
    echo "[+] Unmounting encrypted volume..."

    # Unmount filesystem
    umount "$MOUNT_POINT"

    echo "[+] Closing LUKS volume..."

    # Close encrypted volume
    cryptsetup luksClose "$MAPPER"

    echo "[+] Volume unmounted and closed."
    ;;

*)
    echo "Usage:"
    echo "  sudo $0 create"
    echo "  sudo $0 open"
    echo "  sudo $0 close"
    exit 1
    ;;

esac