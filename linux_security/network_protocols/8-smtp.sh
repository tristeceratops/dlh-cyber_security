#!/bin/bash
postconf smtpd_tls_security_level | grep '^smtpd_tls_security_level' | grep -Eq '=\s*(may|encrypt)' && postconf smtpd_tls_security_level || echo "STARTTLS not configured"
