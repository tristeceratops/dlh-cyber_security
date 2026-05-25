#!/bin/bash
(for t in A AAAA MX NS SOA TXT CNAME; do dig $1 $t; done) | grep -v "^;" | grep -v "^$"
