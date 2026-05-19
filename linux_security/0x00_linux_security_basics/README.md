# Explanations

Concise descriptions of the Linux security helper scripts.

- `0-login.sh`: `sudo last -F -5` — show recent logins with full timestamps (limits to recent entries in the script).
- `1-active-connections.sh`: `sudo ss -antp` — show TCP connections with numeric addresses and process info (`-a` all, `-n` numeric, `-t` tcp, `-p` processes).
- `2-incoming_connections.sh`: `sudo ufw allow 80/tcp` — allow incoming TCP port 80 via UFW.
- `3-firewall_rules.sh`: `sudo iptables -L -v` — list iptables rules in verbose mode.
- `4-network_services.sh`: `sudo netstat -tulnp` — list listening TCP/UDP services with process IDs and names.
- `5-audit_system.sh`: `sudo lynis audit system` — run a Lynis security audit.
- `6-capture_analyze.sh`: `sudo tcpdump -c 5` — capture 5 packets with `tcpdump` for quick analysis.
- `7-scan.sh`: `sudo nmap -sn "$1"` — perform a ping scan (`-sn`) of a network or host.

These scripts show common commands and flags used for inspecting connections, firewall rules, packet capture and basic auditing.
