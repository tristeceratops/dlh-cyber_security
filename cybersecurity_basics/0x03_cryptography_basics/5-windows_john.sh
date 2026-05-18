#!/bin/bash
john --format=nt --wordlist=/usr/share/wordlists/rockyou.txt "$1"
