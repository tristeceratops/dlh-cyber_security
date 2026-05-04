#!/bin/bash
if [ "$#" -ne 2 ]; then echo "Usage: $0 <file> <sha256>"; exit 1; fi
if [ "$(sha256sum "$1" | awk '{print $1}')" = "$2" ]; then echo "$1: OK"; else echo "$1: KO"; fi
