# Adding a function plugin

The menu discovers plugins automatically. Each function lives in its own directory, so contributors can usually work on separate plugin directories without editing the menu script.

## Plugin layout

Create a directory under `functions/` with a `plugin.conf` file and a `run.sh` entry point:

```text
functions/
  10-user-audit/
    plugin.conf
    run.sh
```

Use a numeric prefix to keep menu ordering predictable. The menu scans directories in shell glob order; prefixes such as `10-`, `20-`, and `30-` make that order clear. Do not use an underscore prefix for active plugins; underscore-prefixed directories are ignored and reserved for templates/support material.

### `plugin.conf`

```text
name=User audit
description=Review local user accounts
```

Only `name` and `description` are read. Keep one setting per line. These files are parsed as plain text, not sourced as shell code.

### `run.sh`

Put the plugin's implementation in its own Bash script. It is started as a separate process via Bash, so variables and shell options won't leak into the menu. It inherits the current working directory and terminal. Return a nonzero exit status on failure; the menu reports the status and remains available.

The `_template` directory contains an unlisted placeholder. Copy it to a new non-underscore directory, then change the name and description. Do not edit `The_Script.sh` to register plugins.

The numbered directories currently in this folder cover user auditing, password policy setup, system security review, malware review, and software review. Some remain starter entries; each can be implemented independently without changing the menu.

## Framework behavior

- Menu numbers are generated from installed plugins each time the menu appears; `0` or `q` exits.
- A plugin is listed only when it has both `plugin.conf`, a non-empty `name`, and `run.sh`.
- The framework does not grant privileges or change system settings. Each future plugin should clearly document and control its own actions.
