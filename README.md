# NOJE Linux Security Script

A modular Bash menu framework for defensive Linux administration and CyberPatriot-style Ubuntu review. Plugins audit accounts, password policy, system services, software, and user-home media. Destructive actions require operator confirmation.

## Run

On the target Linux machine, run `bash The_Script.sh` from this project directory. The menu discovers installed functions under `functions/` automatically.

## Add a function

Create a separate plugin directory containing `plugin.conf` and `run.sh`. See [functions/README.md](functions/README.md) for the plugin format and the ignored starter template in `functions/_template/`.

Keep each function self-contained and review its behavior before running it with elevated privileges.

## Recommended Ubuntu 24.04 workflow

1. Run the user audit and verify authorized accounts and administrator group membership.
2. Apply the password policy, then use the password submenu to update only the intended accounts.
3. Run the system audit and review running services. The service audit protects SSH and `scoreengine`; disable a flagged service only after confirming it is not required.
4. Review software and remove only confirmed unauthorized tools. In Software Review, use the Chrome setup action to install Google Chrome system-wide and set it as the default for existing interactive accounts with homes under `/home`.
5. Review user-home media and suspicious paths. Confirm every removal and verify the file is gone.

The plugins protect the authorized accounts listed in the competition scenario from deletion or administrator-rights removal. They do not automatically decide whether an unknown package or media file is business-critical.
