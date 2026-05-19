# Explanations

Quick descriptions of hashing and cracking exercises in this folder.

- `0-sha1.sh`: `echo -n "$1" | sha1sum` — compute SHA-1 hash of input (no trailing newline via `-n`).
- `1-sha256.sh`: `echo -n "$1" | sha256sum` — compute SHA-256 hash.
- `2-md5.sh`: `echo -n "$1" | md5sum` — compute MD5 hash.
- `3-password_hash.sh`: `echo -n "$1$(openssl rand -hex 8)" | openssl dgst -sha512` — hash a salted value with OpenSSL SHA-512.
- `4-wordlist_john.sh`: `john --format=Raw-MD5 --wordlist=/usr/share/wordlists/rockyou.txt "$1"` — run John the Ripper with a wordlist.
- `5-windows_john.sh`: `john --format=nt --wordlist=...` — cracking NT (Windows) hashes.
- `6-crack_john.sh`: `john --format=Raw-SHA256 "$1"` — John for SHA-256 hashes.
- `7-crack_hashcat.sh`: `hashcat -m 0 -a 0 hash.txt /usr/share/wordlists/rockyou.txt` — Hashcat straight attack (`-m` hash type, `-a` attack mode).
- `8-combination_hashcat.sh`: `hashcat -a 1 --stdout "$1" "$2"` — generate combination outputs.
- `9-attack_hashcat.sh`: `hashcat -m 0 -a 1 "$1" wordlist1.txt wordlist2.txt` — combination attack with two wordlists.

Notes: `--wordlist` points to a wordlist (e.g., `rockyou.txt`), `-m` selects hash type, and `-a` selects attack mode in `hashcat`/`john`.
