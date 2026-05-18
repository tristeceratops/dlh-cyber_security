#!/bin/bash
for a in $(cat "$1"); do for b in $(cat "$2"); do echo "$a$b"; done; done
