#!/bin/bash

set -euo pipefail

HOSTNAME=$(hostname)
OS=$(lsb_release -d -s)
KERNEL=$(uname -a)
UPTIME=$(uptime -p)
SERVICE=$(sudo systemctl list-units --type=service --all | grep running | wc -l)
PORTS=$(sudo ss -tulnp | wc -l)
SUID=$(sudo find / -perm -4000 -type f 2>/dev/null | wc -l)
SGID=$(sudo find / -perm -2000 -type f 2>/dev/null | wc -l)
WORLD=$(sudo find / \
  -type f -perm -0002 \
  ! -path "/proc/*" \
  ! -path "/sys/*" \
  ! -path "/dev/*" \
  2>/dev/null | wc -l)
SYSCTL=$(sudo sysctl -a)
SSH=$(sudo cat /etc/ssh/sshd_config | grep -v '#' | grep -v '^$')
SUDO=$(sudo -l)

echo "Hostname: $HOSTNAME"
echo "OS: $OS"
echo "Kernel: $KERNEL"
echo "Uptime: $UPTIME"
echo "Running services: $SERVICE"
echo "Open ports: $PORTS"
echo "SUID binaries: $SUID"
echo "SGID binaries: $SGID"
echo "World-writable files: $WORLD"
echo "Sysctl: $SYSCTL"
echo "SSH: $SSH"
echo "Sudo: SUDO"
