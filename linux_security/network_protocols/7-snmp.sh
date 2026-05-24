#!/bin/bash
sudo cat /etc/snmp/snmpd.conf | grep -Ev '^\s*#|^\s*$' | grep 'public'
