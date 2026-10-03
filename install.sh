#!/usr/bin/env bash
# Installs files/ into ~/.claude (or $CLAUDE_CONFIG_DIR). Idempotent: unchanged
# targets are left alone; changed ones are backed up to <file>.bak.<timestamp>.
# Usage: install.sh [--dry-run]   (--dry-run prints diffs, writes nothing)
# CLAUDE_SETUP_SCRATCH overrides ~/Projects/Scratch (for tests only; the hook
# assumes the default).

set -euo pipefail

repo=$(cd "$(dirname "$0")" && pwd)
dest=${CLAUDE_CONFIG_DIR:-$HOME/.claude}
dry=0
[[ ${1:-} == --dry-run ]] && dry=1
stamp=$(date +%Y%m%d-%H%M%S)

command -v jq >/dev/null || { echo "install: jq is required" >&2; exit 1; }

work=$(mktemp -d)
trap 'command rm -rf "$work"' EXIT

# place <new-content-file> <target> [mode]
place() {
  local new=$1 target=$2 mode=${3:-644}
  if [[ -f $target ]] && cmp -s "$new" "$target"; then
    echo "unchanged  $target"
    return
  fi
  if ((dry)); then
    echo "would write $target"
    diff -u "$target" "$new" 2>/dev/null || true
    return
  fi
  mkdir -p "$(dirname "$target")"
  if [[ -f $target ]]; then
    cp -p "$target" "$target.bak.$stamp"
    echo "backed up  $target -> $target.bak.$stamp"
  fi
  install -m "$mode" "$new" "$target"
  echo "wrote      $target"
}

# Hook
cp "$repo/files/hooks/guard-bash.sh" "$work/guard-bash.sh"
place "$work/guard-bash.sh" "$dest/hooks/guard-bash.sh" 755

# Skills: mirror files/skills/ into <dest>/skills/, keeping the executable bit.
while IFS= read -r -d '' f; do
  rel=${f#"$repo/files/"}
  mode=644
  [[ -x $f ]] && mode=755
  place "$f" "$dest/$rel" "$mode"
done < <(find "$repo/files/skills" -type f -print0)

# Settings: deep-merge; objects merge recursively, arrays union in order, scalars from files/ win.
fragment="$repo/files/settings.json"
if [[ $dest != "$HOME/.claude" ]]; then
  jq --arg p "$dest/hooks/guard-bash.sh" \
    '(.hooks.PreToolUse[].hooks[] | select(.command | endswith("guard-bash.sh")) | .command) = $p' \
    "$fragment" >"$work/fragment.json"
  fragment="$work/fragment.json"
fi
existing="$dest/settings.json"
[[ -f $existing ]] || { echo '{}' >"$work/empty.json"; existing="$work/empty.json"; }
jq -s '
  def m($a; $b):
    if ($a|type) == "object" and ($b|type) == "object" then
      reduce (($a + $b) | keys_unsorted[]) as $k ({}; .[$k] = m($a[$k]; $b[$k]))
    elif ($a|type) == "array" and ($b|type) == "array" then
      reduce ($a + $b)[] as $x ([]; if any(.[]; . == $x) then . else . + [$x] end)
    elif $b == null then $a
    else $b end;
  m(.[0]; .[1])' "$existing" "$fragment" >"$work/settings.json"
place "$work/settings.json" "$dest/settings.json"

# CLAUDE.md: template, keeping the generated toolchain block from any existing file.
begin='<!-- BEGIN toolchain'
end='<!-- END toolchain'
block=""
[[ -f $dest/CLAUDE.md ]] &&
  block=$(awk -v b="$begin" -v e="$end" 'index($0,e)==1{f=0} f{print} index($0,b)==1{f=1}' "$dest/CLAUDE.md")
blk=$block awk -v b="$begin" '{print} index($0,b)==1 && ENVIRON["blk"]!=""{print ENVIRON["blk"]}' \
  "$repo/files/CLAUDE.template.md" >"$work/CLAUDE.md"
place "$work/CLAUDE.md" "$dest/CLAUDE.md"

# Plugins: "<marketplace GitHub repo> <plugin>@<marketplace name>". Already
# installed ones are left alone; `claude plugin update` refreshes them.
plugins=(
  "dietrichgebert/ponytail ponytail@ponytail"
  "addyosmani/agent-skills agent-skills@addy-agent-skills"
)
if ! command -v claude >/dev/null; then
  echo "skipped    plugins (claude CLI not on PATH)"
else
  have_mkts=$(claude plugin marketplace list --json | jq -r '.[].name')
  have_plugins=$(claude plugin list --json | jq -r '.[].id')
  for entry in "${plugins[@]}"; do
    read -r repo_src id <<<"$entry"
    mkt=${id#*@}
    if ! grep -qxF "$mkt" <<<"$have_mkts"; then
      if ((dry)); then echo "would add  marketplace $mkt ($repo_src)"
      else claude plugin marketplace add "$repo_src" >/dev/null && echo "added      marketplace $mkt"
      fi
    fi
    if grep -qxF "$id" <<<"$have_plugins"; then echo "unchanged  plugin $id"
    elif ((dry)); then echo "would install plugin $id"
    else claude plugin install "$id" --scope user >/dev/null && echo "installed  plugin $id"
    fi
  done
fi

# Scratch dir for throwaway projects (an allowed delete root in the hook).
scratch=${CLAUDE_SETUP_SCRATCH:-$HOME/Projects/Scratch}
if [[ -d $scratch ]]; then echo "unchanged  $scratch"
elif ((dry)); then echo "would create $scratch"
else mkdir -p "$scratch" && echo "created    $scratch"
fi

# Verify the installed hook (or the repo copy on a dry run).
if ((dry)); then
  bash "$repo/files/hooks/test-guard-bash.sh" "$repo/files/hooks/guard-bash.sh"
else
  bash "$repo/files/hooks/test-guard-bash.sh" "$dest/hooks/guard-bash.sh"
fi
