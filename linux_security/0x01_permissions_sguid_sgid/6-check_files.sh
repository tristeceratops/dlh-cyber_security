#!/bin/bash
sudo find "$1" \( -perm -4000 -o -perm -2000 \) -type f -mtime -1 -exec ls -ldb {} \; 2>/dev/null
