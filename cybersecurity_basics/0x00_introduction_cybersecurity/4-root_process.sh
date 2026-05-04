#!/bin/bash
ps aux | grep "^$1" | grep -Ev "^(\S+\s+){4}0" | grep -Ev "^(\S+\s+){5}0"
