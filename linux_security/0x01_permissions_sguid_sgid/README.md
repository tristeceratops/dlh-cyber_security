# Explanations

Descriptions of permission and user-management helper scripts.

- `0-add_user.sh`: `sudo useradd -m $1` to create a user with home; `echo "$2" | sudo passwd $1` sets the password from stdin.
- `1-add_group.sh`: `sudo addgroup $1` creates a group; `chown :$1 $2` changes file group; `chmod g+rx $2` grants group read/execute.
- `2-sudo_nopass.sh`: writes `"$1 ALL=(ALL) NOPASSWD:ALL"` into `/etc/sudoers.d/$1` via `tee` to grant passwordless sudo.
- `3-find_files.sh`: `find $1 -user root -perm -4000 -exec ls -ldb {} \;` — locate files owned by root with SUID bit (`-perm -4000`).
- `4-find_suid.sh`: `find $1 -type f -perm -4000` — list SUID files.
- `5-find_sgid.sh`: `find $1 -type f -perm -2000` — list SGID files.
- `6-check_files.sh`: `find "${1}" \( -perm -4000 -o -perm -2000 \) -mtime -1 -exec ls -ldb {} \;` — find recently modified SUID/SGID files.
- `7-file_read.sh`: `find "$1" -type f -exec chmod o=r {} \;` — make files world-readable.
- `8-change_user.sh`: `find "$1" -user user2 -type f -exec chown user3 {} \;` — change owner of files matching criteria.
- `9-empty_file.sh`: `find "$1" -type f -empty -exec chmod 777 {} \;` — set permissions on empty files.

These scripts demonstrate `useradd`, `passwd`, `addgroup`, `chown`, `chmod`, and `find` with permission flags (`-perm`) and SUID/SGID detection.
