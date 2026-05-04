#!/bin/bash
ssh-keygen -b 4096 -f $1 -P "$1secret" -t rsa
