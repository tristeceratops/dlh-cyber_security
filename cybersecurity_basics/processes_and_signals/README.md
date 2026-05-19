# Explanations

Short descriptions of process and signal exercises.

- `0-what-is-my-pid`: `echo $$` — prints the script's PID via `$$`.
- `1-list_your_processes`: `ps aux --forest` — show full process list with hierarchy.
- `2-show_your_bash_pid`: `ps aux --forest | grep "bash"` — list processes matching `bash` (uses `grep`).
- `3-show_your_bash_pid_made_easy`: `pgrep -l bash` — show PIDs and names matching `bash` (`pgrep -l`).
- `4-to_infinity_and_beyond`: loop printing text with `sleep` to simulate a long-running process.
- `5-dont_stop_me_now`: `kill "$(pgrep -f 4-to_infinity_and_beyond)"` — kill by PID from `pgrep -f`.
- `6-stop_me_if_you_can` & `67-stop_me_if_you_can`: `pkill -f <pattern>` — kills processes matching the pattern; supports signals like `-SIGKILL`.
- `7-highlander`: shows `trap '...' SIGTERM` to catch signals and act on them.
- `8-beheaded_process`: uses `pkill -SIGKILL -f 7-highlander` to force-kill a process.
- `9-process_and_pid_file`: demonstrates `trap` handling and managing a `/tmp/myscript.pid` pidfile.
- `manage_my_process`: infinite loop writing to `/tmp/my_process` (managed by `manage_my_process` control script).

These exercises illustrate `ps`, `pgrep`/`pkill`, `kill`, signal trapping (`trap`), and pidfile patterns used in process management.
