#!/bin/bash
sudo addgroup $1
sudo chown :$1 $2
chmod g+rx $2
