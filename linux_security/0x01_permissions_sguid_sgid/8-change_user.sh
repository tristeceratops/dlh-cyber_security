#!/bin/bash
sudo find "$1" -user user2 -type f -exec chown user3 {} \; 2>/dev/null
