#!/bin/bash
sudo useradd -m $1
echo "$2" | sudo passwd $1
