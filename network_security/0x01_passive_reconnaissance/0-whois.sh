#!/bin/bash
whois $1 | grep -E '^(Registrant|Admin|Tech)' | awk -F ':' '{print $1","$2 " "}' > $1.csv
