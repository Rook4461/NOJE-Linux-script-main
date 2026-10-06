# NOJE Linux Security Script

A modular Bash menu framework for defensive Linux administration. The current menu is only a framework; it does not perform hardening or auditing actions by itself.

## Run

On the target Linux machine, run `bash The_Script.sh` from this project directory. The menu discovers installed functions under `functions/` automatically.

## Add a function

Create a separate plugin directory containing `plugin.conf` and `run.sh`. See [functions/README.md](functions/README.md) for the plugin format and the ignored starter template in `functions/_template/`.

Keep each function self-contained and review its behavior before running it with elevated privileges.
