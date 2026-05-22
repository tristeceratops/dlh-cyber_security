#!/bin/bash
find / -xdev -perm -0002 -type d -print -exec chmod o-w {} \; 2> /dev/null
