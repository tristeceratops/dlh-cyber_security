# Explanations

Short descriptions of SELinux/AppArmor helper scripts in this folder.

- `0-analyse_mode.sh`: `sudo sestatus` — shows SELinux status and current mode.
- `1-security_match.sh`: `sudo aa-status` — AppArmor profile status (AppArmor equivalent).
- `2-list_http.sh`: `sudo semanage port -l | grep http` — list ports labeled for HTTP services.
- `3-add_port.sh`: `sudo semanage port -a -t http_port_t -p tcp 81` — add TCP port `81` to SELinux `http_port_t` type (`-a` add, `-t` type, `-p` protocol). stderr redirected to `/dev/null` in the script.
- `4-list_user.sh`: `sudo semanage user -l` — list SELinux user mappings.
- `5-add_selinux.sh`: `sudo semanage login -a -s user_u $1` — map a login name to an SELinux user (`-a` add, `-s` set SELinux user).
- `6-list_booleans.sh`: `sudo semanage boolean -l` — list SELinux booleans.
- `7-set_sendmail.sh`: `sudo setsebool -P httpd_can_sendmail on` — persistently set SELinux boolean (`-P` persistent) to allow `httpd` to send mail.

These scripts demonstrate common `semanage`, `sestatus`, and `setsebool` usage for managing SELinux policies and booleans.
