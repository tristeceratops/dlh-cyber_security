#!/bin/bash
sed -n -r "s/^ID=([A-Za-z]+)/\1/p" /usr/lib/os-release
