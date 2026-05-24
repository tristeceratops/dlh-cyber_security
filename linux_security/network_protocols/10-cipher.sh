#!/bin/bash
sudo nmap -p 443 --script ssl-enum-ciphers $1
