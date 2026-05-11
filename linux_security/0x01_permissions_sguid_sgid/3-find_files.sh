#!/bin/bash
sudo find $1 -user root -perm -4000 -exec ls -ldb {} \; 2>/dev/null
