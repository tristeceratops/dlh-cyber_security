#!/bin/bash
ps aux | grep -Ev "^(\S+\s+){4}0|^(\S+\s+){5}0"
