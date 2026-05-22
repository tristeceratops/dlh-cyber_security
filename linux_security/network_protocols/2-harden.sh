#!/bin/bash
find / -perm /o+w -type d -print -exec chmod u+w,go-w {} \; 2> /dev/null
