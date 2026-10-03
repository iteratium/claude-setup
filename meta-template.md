# Claude Setup Bootstrap

You (Claude) are setting up your own user-level configuration on this machine
from this repo. Run the steps in order. Every step is idempotent: re-running
this file updates the setup in place, so skip work whose result is already
current and never duplicate content. Creating and updating the files listed
below is the expected result of this request; no per-file confirmation needed.

What gets installed (target dir: `$CLAUDE_CONFIG_DIR`, default `~/.claude`):

| Source | Target | How |
|---|---|---|
| `files/CLAUDE.template.md` | `CLAUDE.md` | `install.sh` (keeps generated toolchain block) |
| `files/settings.json` | `settings.json` | `install.sh` deep-merges into existing settings |
| `files/hooks/guard-bash.sh` | `hooks/guard-bash.sh` | `install.sh` |
| `files/skills/*` | `skills/*` | `install.sh` |
| — | `~/Projects/Scratch/` | `install.sh` creates it |
| `plugins` list in `install.sh` | Ponytail, Agent Skills (user scope) | `install.sh` adds marketplaces + installs via `claude plugin` |
| — | toolchain block in `CLAUDE.md` | Step 3 (you generate) |

Hard rules live in `settings.json` and the hook, not in prose. Don't restate
them in `CLAUDE.md`, and never set `permissions.defaultMode`; that's the
user's choice.

## Step 1: Prerequisites

Check: `jq`, `gh` (also `gh auth status`), `rg` (a Claude Code shell function
counts as present), and on Linux `pkexec` (polkit). Without `pkexec`, root
commands get handed to the user instead; mention that, it isn't a blocker.

For anything missing or unauthenticated: show the install/auth command for this
system's package manager and run it only after the user approves, or let them
run it with `! <command>`. If declined, note it and continue, except for `jq`:
the hook blocks all Bash without it, so stop setup if `jq` is declined.

## Step 2: Install files

1. Run `./install.sh --dry-run` and summarise the changes for the user.
2. If an existing `CLAUDE.md` has content not from this repo's template, or
   existing settings would change beyond the added keys, show what will be
   replaced (backups are kept as `<file>.bak.<timestamp>`) and get approval.
3. Run `./install.sh`. It ends by running the hook test suite; all cases must
   pass. On failure, stop and report the failing cases.

## Step 3: Toolchain block

Detect, don't assume (the `system-info` skill gives OS details). Replace
everything between the `BEGIN toolchain` and `END toolchain` markers in `<target>/CLAUDE.md` with at most 6 lines that
record only choices Claude couldn't guess:

- System package manager to use (e.g. `dnf`, `apt`, `brew`)
- Default language runtimes/versions when several are installed
- Container runtime and how to invoke it (e.g. podman, not docker)
- Default shell, if not bash

Style: terse directives ("Packages: use dnf"), no prose, no raw paths or
version dumps. This file loads every session; every line costs context.

## Step 4: Finish

Report a short table of each step: done, skipped (already current), or blocked
(why). Tell the user to start a new Claude Code session so the hook and
permission rules load, and that `/hooks`, `/permissions` and `/skills` show
them.
