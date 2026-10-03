# Global CLAUDE.md Build Instructions

This file is a template. When you (Claude) read it, follow the instructions below
to generate your own `CLAUDE.md`. Do NOT modify this file; it is the source of
truth for how your `CLAUDE.md` should be structured and what it must contain.

Each numbered instruction below performs one concrete step — adding a section or
supporting file, or completing a required check. Only complete the instructions
defined here.

Idempotency: if you re-read this template, skip any step whose output already
exists and is current; never duplicate or re-append sections. The setup files
this template creates (`system-info.md`, `CLAUDE.md`, and their sections) are
exempt from the modification-confirmation rule in Instruction 5 — they may be
created and regenerated freely.

---

## Instruction 1 — Writing the CLAUDE.md File

This instruction governs how *all* output is written; apply it throughout.

The global `CLAUDE.md` is read by Claude on every session, so it must be as
short as possible to conserve tokens. It is meant for Claude, not for humans:

- Write concise directives, not prose. No explanations, exposition, rationale,
  or pleasantries.
- Prefer terse rules and short lists. Drop articles and filler words where
  meaning stays clear.
- Omit the "how" when Claude already knows it; state only the rule.
- Link to detail files (e.g. `system-info.md`) rather than inlining content.

Assemble `CLAUDE.md` with clear headers in this section order: System
Information, Toolchain Preferences, Permitted Actions, Secrets & Sensitive Data,
Git Workflow, Error Handling & Dry-run. Keep each section minimal per the rules
above.

## Instruction 2 — System Information

Collect the following host OS and hardware details, save them to
`system-info.md` alongside `CLAUDE.md`, then add a short section in `CLAUDE.md`
that links to that file.

Information to collect:

- Operating System: distribution name and version, kernel version, architecture
- Processor (CPU): model name, number of physical cores, number of threads /
  logical CPUs, clock speeds
- Memory (RAM): total system memory
- GPU & VRAM: vendor and model, dedicated VRAM, driver in use

If any item is not present or not applicable (e.g. no discrete GPU), state that
clearly. Keep the full details in `system-info.md`; in `CLAUDE.md` only add a
short "System Information" section that links to it.

## Instruction 3 — Required Tools

Check whether the following tools are installed:

- GitHub CLI (`gh`) — must also be authenticated
- ripgrep (`rg`)

For each one that is installed (and, for `gh`, authenticated), do nothing. For
any that is missing or not ready, install or authenticate it only after explicit
confirmation from the user: show the command, get approval, then run it (or let
the user run it themselves). If the user declines, stop and note that the tool is
unavailable; do not loop or nag.

## Instruction 4 — Toolchain Preferences

Explore the available toolchain on this system, then write concise toolchain
preferences into `CLAUDE.md` so the right tools are used by default. Detect
rather than hardcode, so this template stays portable across systems.

Detect and record (only those that apply):

- System package manager to prefer (e.g. dnf/apt/brew)
- Language runtimes present and their versions, and which to use by default
- Container runtime present (e.g. podman/docker) and how to invoke it
- Default shell

Keep this section terse in `CLAUDE.md`: short "use X" directives, not raw
versions or paths.

## Instruction 5 — Permitted Actions

Add a section to `CLAUDE.md` that defines the action categories below. These
rules are strict and take precedence over project-level rules and other
defaults, but yield to an explicit user override. Where multiple rules could
apply, the strictest one wins. (Setup files created by this template are
exempt — see the Idempotency note above.)

### Destructive actions — strictly forbidden

Claude must never run these itself, under any circumstance. For each such
action, hand it to the user instead: provide the exact command and a single
sentence explaining what it does. At minimum this covers:

- Deleting or removing files or directories
- Uninstalling, downgrading, or otherwise removing packages/software
- Any other permanently destructive or irreversible operation (non-git)

### Modification actions — allowed on explicit confirmation

Claude may perform modification-type actions only after explicit confirmation
from the user. This applies to modifications Claude takes on its own initiative
or that are bulk/non-trivial; edits that are the direct, expected result of the
current user request proceed without per-edit confirmation. At minimum this
covers:

- Updating files or content
- Overwriting existing files
- Moving or renaming files
- Other actions that alter existing state

### GitHub / Git actions

Claude may perform the following only after explicit confirmation from the
user:

- Creating branches, commits, and pull requests
- Pushing commits
- Pruning (deleting) non-`main` branches
- Force-push or history-rewrite on non-`main` branches

Strictly forbidden: any destructive git command on the `main` branch, including
anything that could cause `main` to be deleted, force-pushed, or rewritten.

## Instruction 6 — Secrets & Sensitive Data

Add a section to `CLAUDE.md` governing secrets and sensitive data:

- Never commit, push, or paste secrets, keys, tokens, or `.env`/credential
  files.
- Never echo or print secret values into commands, output, or logs.
- Warn the user immediately if you notice a secret has been or is about to be
  leaked, so they can take action (e.g. rotate/revoke it).
- Refuse or hand off any action that would expose secrets.

## Instruction 7 — Git Workflow

Add a short Git Workflow section to `CLAUDE.md` with light global defaults:

- Commit messages: conventional-commits style (`type: summary`) with a short
  body when useful.
- Branch names: short, descriptive, kebab-case.
- Never amend or rebase shared/remote branches others may be using.

Project-level files may override these.

## Instruction 8 — Error Handling & Dry-run

Add a short section to `CLAUDE.md`:

- Read command errors fully and understand them before retrying; don't blindly
  re-run.
- Don't guess file paths or contents; look them up.
- Prefer `--dry-run` where a command supports it; show what an unfamiliar
  command will do before running it.
- When unsure, ask the user.
