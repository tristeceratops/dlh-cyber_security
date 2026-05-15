# IP Configuration
| Task | Windows | Linux |
|------|---------|-------|
| View IP config | ipconfig | ip addr show |
| Detailed IP info | ipconfig /all | ip addr show / ifconfig -a |
| Release DHCP | ipconfig /release | sudo dhclient -r |
| Renew DHCP | ipconfig /renew | sudo dhclient |
| View routing table | route print | ip route show |
| Add static route | route add 10.0.0.0 mask 255.0.0.0 192.168.1.1 | ip route add 10.0.0.0/8 via 192.168.1.1 |
| Delete route | route delete 10.0.0.0 | ip route del 10.0.0.0/8 |
# Connectivity Testing
| Task | Windows | Linux |
|------|---------|-------|
| Ping | ping hostname | ping hostname |
| Ping count | ping -n 5 hostname | ping -c 5 hostname |
| Continuous ping | ping -t hostname | ping hostname |
| Traceroute | tracert hostname | traceroute hostname |
| Traceroute no DNS | tracert -d hostname | traceroute -n hostname |
| Path MTU | ping -f -l 1472 hostname | ping -M do -s 1472 hostname |
# DNS
| Task | Windows | Linux |
|------|---------|-------|
| Lookup | nslookup hostname | dig hostname / host hostname |
| Specific server | nslookup hostname 8.8.8.8 | dig @8.8.8.8 hostname |
| MX records | nslookup -type=MX domain | dig domain MX |
| NS records | nslookup -type=NS domain | dig domain NS |
| Reverse lookup | nslookup IP | dig -x IP |
| Clear cache | ipconfig /flushdns | sudo systemd-resolve --flush-caches |
| View cache | ipconfig /displaydns | sudo systemd-resolve --statistics |
# ARP
| Task | Windows | Linux |
|------|---------|-------|
| View ARP cache | arp -a | arp -n / ip neigh show |
| Add entry | arp -s IP MAC | ip neigh add IP lladdr MAC dev eth0 |
| Delete entry | arp -d IP | ip neigh del IP dev eth0 |
| Clear cache | arp -d * | ip neigh flush all |
# Ports and Connections
| Task                      | Windows                                      | Linux                                |
| ------------------------- | -------------------------------------------- | ------------------------------------ |
| All connections           | `netstat -an`                                | `ss -an` / `netstat -an`            |
| Listening ports           | `netstat -an \| findstr LISTEN`              | `ss -tuln`                           |
| With process IDs          | `netstat -ano`                               | `ss -tulnp`                          |
| Specific port             | `netstat -an \| findstr :80`                 | `ss -an \| grep :80`                 |
| Test port                 | `Test-NetConnection host -Port 80`           | `nc -vz host 80` / `telnet host 80` |
| Kill connection / process | `taskkill /PID <PID> /F` / Use Task Manager | `kill <PID>`                         |

# Wireless
| Task | Windows | Linux |
|------|---------|-------|
| List networks |	netsh wlan show networks |	nmcli dev wifi list |
| Detailed scan |	netsh wlan show networks mode=bssid | sudo iwlist wlan0 scan |
| Current connection 	netsh wlan show interfaces | iwconfig / nmcli con show |
| Connect |	netsh wlan connect name="SSID" 	nmcli dev wifi connect SSID
| Disconnect | netsh wlan disconnect | nmcli dev disconnect wlan0 |
| Show profiles |	netsh wlan show profiles | nmcli con show |
| Show password |	netsh wlan show profile name="SSID" key=clear |	Check NetworkManager files |
# Packet Capture
| Task | Command |
|------|---------|
| Capture all |	tcpdump -i eth0 |
| Capture to file |	tcpdump -i eth0 -w capture.pcap |
| Read file |	tcpdump -r capture.pcap |
| Filter by host |	tcpdump host 192.168.1.1 |
| Filter by port |	tcpdump port 80 |
| Filter by protocol |	tcpdump icmp |
| Verbose |	tcpdump -v / -vv / -vvv |
# Network Scanning (Authorized Only!)
| Task | nmap Command |
|------|--------------|
| Ping sweep | nmap -sn 192.168.1.0/24 |
| Port scan |	nmap 192.168.1.1 |
| All ports |	nmap -p- 192.168.1.1 |
| Service detection |	nmap -sV 192.168.1.1 |
| OS detection |	nmap -O 192.168.1.1 |
| Aggressive scan |	nmap -A 192.168.1.1 |
| UDP scan |	nmap -sU 192.168.1.1 |
| Stealth scan | nmap -sS 192.168.1.1 |
# File Transfer
| Task | Command |
|------|---------|
| SCP upload | scp file.txt user@host:/path/ |
| SCP download | scp user@host:/path/file.txt ./ |
| SCP directory | scp -r folder/ user@host:/path/ |
| SFTP connect | sftp user@host |
| FTP connect |	ftp host |
| Curl GET | curl http://example.com |
| Curl POST |	curl -X POST -d "data" http://example.com |
| Download file |	wget http://example.com/file |
# Remote Access
| Task | Command |
|------|---------|
| SSH connect | ssh user@hostname |
| SSH with port |	ssh -p 2222 user@hostname |
| SSH with key |	ssh -i key.pem user@hostname |
| SSH tunnel | ssh -L 8080:localhost:80 user@host |
| RDP (Windows) |	mstsc /v:hostname |
| RDP (Linux) |	rdesktop hostname / xfreerdp /v:hostname |
# Cisco IOS Quick Reference
``` bash
! Basic commands
enable                          # Enter privileged mode
configure terminal              # Enter config mode
show running-config             # View configuration
show interfaces                 # Interface status
show ip interface brief         # IP summary
show ip route                   # Routing table
show mac address-table          # MAC table
show vlan brief                 # VLAN info
copy running-config startup-config  # Save config

! Interface config
interface GigabitEthernet0/1
  ip address 192.168.1.1 255.255.255.0
  no shutdown

! VLAN config
vlan 10
  name Sales
interface GigabitEthernet0/1
  switchport mode access
  switchport access vlan 10
```

# PowerShell Networking
``` powershell
# Get network info
Get-NetIPAddress
Get-NetAdapter
Get-NetRoute

# Test connectivity
Test-Connection google.com
Test-NetConnection google.com -Port 443

# DNS
Resolve-DnsName google.com
Clear-DnsClientCache

# Firewall
Get-NetFirewallRule
New-NetFirewallRule -DisplayName "Block Port" -Direction Inbound -LocalPort 23 -Action Block
```

# Quick Troubleshooting Flow
``` bash
# 1. Check local TCP/IP
ping 127.0.0.1

# 2. Check NIC
ping 

# 3. Check gateway
ping 

# 4. Check remote IP
ping 8.8.8.8

# 5. Check DNS
ping google.com
nslookup google.com
```
