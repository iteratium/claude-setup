# claude-setup

Portable user-level Claude Code configuration.

## New machine

```sh
git clone <this repo> && cd claude-setup
claude
> Set yourself up using meta-template.md
```

Claude checks prerequisites (`jq`, `gh`, `rg`), runs `install.sh`, fills in
the toolchain section, then reports what it did. Re-run
the same prompt any time to update; it's idempotent.

On Windows, use WSL2 and run the steps above inside it.

## Layout

- `meta-template.md`: bootstrap instructions Claude follows (read once, not loaded per session)
- `install.sh [--dry-run]`: copies/merges `files/` into `~/.claude`, backs up anything it changes
- `files/CLAUDE.template.md`: soft guidance, loaded every session; keep it short
- `files/settings.json`: `Read` deny rules for secrets + hook registration
- `files/hooks/guard-bash.sh`: denies deletes outside `/tmp`, `$TMPDIR` and `~/Projects/Scratch`, package removal, secret reads, and sudo/su/run0 (Claude uses pkexec instead); asks before git commit, push, branch creation, and git/gh commands that discard work or delete refs (`reset --hard`, `restore`, `branch -D`, `stash drop`, `gh pr merge`, ...)
- `files/hooks/test-guard-bash.sh`: test table for the hook; add a case for every rule change
- `files/skills/system-info/`: on-demand host details (CPU, RAM, GPU/VRAM/driver); only its description loads per session

## Where a rule belongs

- Must never/always happen: hook or `settings.json` permissions
- Preference or convention: `CLAUDE.template.md`, one terse line
- Only sometimes relevant: a skill or `~/.claude/rules/` file, not CLAUDE.md
