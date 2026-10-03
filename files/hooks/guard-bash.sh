#!/usr/bin/env bash
# PreToolUse hook for the Bash tool.
#   deny: destructive commands (delete files, remove packages, wipe disks,
#         destructive git on protected branches, reading secret files)
#   ask:  git write operations (commit, push, branch create/delete, rewrite)
# Matches the common spellings (/bin/rm, sudo rm, bash -c 'rm', xargs rm, ...),
# not every possible one: this is defense in depth, not a security boundary.
# Input: hook JSON on stdin. Output: decision JSON, or nothing to defer.

set -o pipefail

PROTECTED_BRANCHES=" main master "

if ! command -v jq >/dev/null 2>&1; then
  echo "guard-bash: jq is not installed, so every Bash command is blocked. Ask the user to install jq." >&2
  exit 2
fi

input=$(cat)
cmd=$(jq -r '.tool_input.command // empty' <<<"$input")
cwd=$(jq -r '.cwd // empty' <<<"$input")
[[ -n $cmd ]] || exit 0

HANDOFF="Claude must not run this. Give the user the exact command and one sentence on what it does; they can run it themselves with '! <command>'."

SECRET_RE='(^|[/[:space:]=])\.env(\.[[:alnum:]_-]+)?([[:space:]]|$)|\.ssh/|(^|/)id_(rsa|dsa|ecdsa|ed25519)([[:space:]]|$)|\.aws/credentials|\.gnupg/|\.netrc|\.pgpass|\.config/gh/hosts\.yml|\.docker/config\.json|\.kube/config'
SECRET_OK_RE='\.env\.(example|sample|template)'

ask_reasons=()

decide() {
  jq -n --arg d "$1" --arg r "$2" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: $d, permissionDecisionReason: $r}}'
  exit 0
}
deny() { decide deny "$1 $HANDOFF"; }
ask() { ask_reasons+=("$1"); }

current_branch() { git -C "${cwd:-.}" rev-parse --abbrev-ref HEAD 2>/dev/null; }
is_protected() { [[ -n $1 && $PROTECTED_BRANCHES == *" ${1#refs/heads/} "* ]]; }

# First argument that is not an option.
first_word() {
  local a
  for a in "$@"; do [[ $a == -* ]] || { printf '%s' "$a"; return; }; done
}

git_push() {
  local force=0 del=0 all=0 remote_seen=0 a dst
  local -a dsts=()
  for a in "$@"; do
    case $a in
      -f|--force|--force-with-lease*|--force-if-includes) force=1 ;;
      -d|--delete) del=1 ;;
      --mirror) deny "'git push --mirror' can overwrite or delete every remote branch." ;;
      --prune) ask "git push --prune deletes remote branches" ;;
      --all|--branches) all=1 ;;
      -*) ;;
      *)
        if ((remote_seen == 0)); then remote_seen=1; continue; fi
        [[ $a == +* ]] && force=1
        a=${a#+}
        if [[ $a == :* ]]; then del=1; dst=${a#:}
        elif [[ $a == *:* ]]; then dst=${a#*:}
        else dst=$a
        fi
        [[ $dst == HEAD ]] && dst=$(current_branch)
        dsts+=("${dst#refs/heads/}")
        ;;
    esac
  done
  ((${#dsts[@]} == 0)) && dsts=("$(current_branch)")
  ((all)) && dsts+=(main master)
  if ((force || del)); then
    for dst in "${dsts[@]}"; do
      is_protected "$dst" && deny "Force-pushing or deleting '$dst' is forbidden."
    done
  fi
  ask "git push"
}

git_branch() {
  local a mode=create name="" force=0
  local -a names=()
  for a in "$@"; do
    case $a in
      -d|-D|--delete|-[a-zA-Z]*[dD]) mode=delete ;;
      -m|-M|--move|-c|-C|--copy) mode=rename ;;
      -f|--force) force=1 ;;
      -l|--list|-a|--all|-r|--remotes|-v|-vv|--verbose|--show-current|--contains|--no-contains|--merged|--no-merged|--points-at|--format*|--sort*) return ;;
      -*) ;;
      *) names+=("$a") ;;
    esac
  done
  ((${#names[@]})) || return
  case $mode in
    delete|rename)
      for name in "${names[@]}"; do
        is_protected "$name" && deny "Deleting or renaming '$name' is forbidden."
      done
      ask "git branch $mode" ;;
    create)
      ((force)) && is_protected "${names[0]}" && deny "Force-resetting '${names[0]}' is forbidden."
      ask "git branch (creates a branch)" ;;
  esac
}

check_git() {
  local j=0 sub branch r
  local -a args=("$@") rest
  while ((j < ${#args[@]})); do
    case ${args[j]} in
      -C|-c|--git-dir|--work-tree|--namespace) ((j += 2)) ;;
      -*) ((j++)) ;;
      *) break ;;
    esac
  done
  sub=${args[j]}
  rest=("${args[@]:j+1}")
  r=" ${rest[*]} "
  branch=$(current_branch)

  case $sub in
    clean)
      [[ $r =~ [[:space:]](-[a-zA-Z]*n[a-zA-Z]*|--dry-run)[[:space:]] ]] || deny "'git clean' deletes untracked files." ;;
    rm)
      [[ $r == *" --cached "* ]] || deny "'git rm' deletes files." ;;
    push)
      git_push "${rest[@]}" ;;
    commit)
      [[ $r == *" --amend "* ]] && is_protected "$branch" && deny "Amending on '$branch' rewrites protected history."
      ask "git commit" ;;
    rebase|filter-branch|filter-repo)
      is_protected "$branch" && deny "'git $sub' on '$branch' rewrites protected history."
      ask "git $sub rewrites history" ;;
    reset)
      if is_protected "$branch" && [[ $r =~ [[:space:]](--hard|--soft|--keep|--merge|HEAD[~^]|@[~^]|[0-9a-f]{7,40}|origin/)[^[:space:]]*[[:space:]] ]]; then
        deny "'git reset' on '$branch' rewrites protected history or discards work."
      fi
      [[ $r == *" --hard "* ]] && ask "git reset --hard discards changes" ;;
    branch)
      git_branch "${rest[@]}" ;;
    checkout)
      [[ $r =~ [[:space:]]-[bB][[:space:]] ]] && ask "git checkout -b (creates a branch)" ;;
    switch)
      [[ $r =~ [[:space:]](-c|-C|--create|--force-create)[[:space:]] ]] && ask "git switch -c (creates a branch)" ;;
    update-ref)
      [[ $r == *" -d "* ]] && for a in "${rest[@]}"; do
        is_protected "$a" && deny "Deleting '$a' is forbidden."
      done
      ask "git update-ref" ;;
  esac
}

check_segment() {
  local -a w args
  local i=0 j n t prog a sub argstr
  read -ra w <<<"$1"
  n=${#w[@]}
  for ((j = 0; j < n; j++)); do w[j]=${w[j]//[\'\"]/}; done

  # Skip wrappers, shell keywords, and env assignments to reach the real command.
  while ((i < n)); do
    t=${w[i]}
    if [[ $t =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then ((i++)); continue; fi
    case $t in
      sudo|doas|env|command|builtin|exec|nohup|nice|ionice|time|timeout|stdbuf|xargs|noglob|then|do|else|elif|if|while|until|!|\\)
        ((i++))
        while ((i < n)); do
          case ${w[i]} in
            -u|-g|-U|-C|-D|-h|-p|-r|-t|-n|-I|-P|-L|-d|-E|-s|-a|-c|--user|--group) ((i += 2)) ;;
            -*) ((i++)) ;;
            *)
              if [[ ${w[i]} =~ ^[0-9.]+[smhd]?$ || ${w[i]} =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then ((i++)); else break; fi ;;
          esac
        done ;;
      *) break ;;
    esac
  done
  ((i < n)) || return

  prog=${w[i]##*/}
  args=("${w[@]:i+1}")
  argstr=" ${args[*]} "
  sub=$(first_word "${args[@]}")

  case $prog in
    rm|rmdir|unlink|shred|srm|wipefs|truncate|mkfs|mkfs.*|fdisk|sfdisk|parted|blkdiscard)
      deny "'$prog' deletes or destroys data." ;;
    dd)
      [[ $argstr == *" of="* ]] && deny "'dd of=' overwrites a file or device." ;;
    find)
      [[ $argstr == *" -delete "* || $argstr =~ -(exec|execdir|ok|okdir)[[:space:]]+([^[:space:]]*/)?(rm|rmdir|unlink|shred)[[:space:]] ]] &&
        deny "'find' with -delete or -exec rm deletes files." ;;
    sh|bash|zsh|dash|ksh|fish)
      for ((j = 0; j < ${#args[@]}; j++)); do
        [[ ${args[j]} =~ ^-[a-z]*c$ ]] && { check_segment "${args[*]:j+1}"; break; }
      done ;;
    eval)
      check_segment "${args[*]}" ;;
    dnf|dnf5|yum|microdnf|zypper)
      case $sub in remove|erase|autoremove|downgrade|distro-sync|rm) deny "'$prog $sub' removes or downgrades packages." ;; esac
      [[ $sub == history && $argstr =~ [[:space:]](undo|rollback)[[:space:]] ]] && deny "'$prog history undo/rollback' can remove packages." ;;
    apt|apt-get|aptitude)
      case $sub in remove|purge|autoremove|autopurge) deny "'$prog $sub' removes packages." ;; esac ;;
    brew|port)
      case $sub in uninstall|remove|rm|untap|autoremove) deny "'$prog $sub' removes packages." ;; esac ;;
    pacman|yay|paru)
      [[ $argstr =~ [[:space:]]-R[a-zA-Z]*[[:space:]] ]] && deny "'$prog -R' removes packages." ;;
    rpm)
      [[ $argstr =~ [[:space:]](-e|--erase)[[:space:]] ]] && deny "'rpm -e' removes packages." ;;
    dpkg)
      [[ $argstr =~ [[:space:]](-r|-P|--remove|--purge)[[:space:]] ]] && deny "'dpkg $sub' removes packages." ;;
    flatpak|snap)
      case $sub in uninstall|remove) deny "'$prog $sub' removes software." ;; esac ;;
    pip|pip3|pipx|cargo|gem)
      [[ $sub == uninstall ]] && deny "'$prog uninstall' removes packages." ;;
    uv)
      [[ $argstr =~ [[:space:]](pip|tool)[[:space:]]+uninstall[[:space:]] ]] && deny "'uv uninstall' removes packages." ;;
    python|python3)
      [[ $argstr =~ -m[[:space:]]+pip[[:space:]]+uninstall ]] && deny "'pip uninstall' removes packages." ;;
    npm|pnpm|yarn|bun)
      [[ $argstr =~ [[:space:]](uninstall|remove|rm|un|r)[[:space:]] && $argstr =~ [[:space:]](-g|--global|global)[[:space:]] ]] &&
        deny "Removing global $prog packages is forbidden." ;;
    git)
      check_git "${args[@]}" ;;
    gh)
      [[ $argstr =~ [[:space:]](repo|release)[[:space:]]+delete[[:space:]] ]] && deny "'gh $sub delete' is irreversible."
      [[ $argstr =~ [[:space:]]pr[[:space:]]+(create|merge)[[:space:]] ]] && ask "gh pr create/merge" ;;
  esac

  if [[ " ${w[*]:i} " =~ $SECRET_RE && ! " ${w[*]:i} " =~ $SECRET_OK_RE ]]; then
    case $prog in
      cat|less|more|head|tail|bat|batcat|grep|egrep|fgrep|rg|ag|sed|awk|gawk|cut|sort|uniq|strings|xxd|od|hexdump|base64|cp|mv|scp|rsync|curl|wget|nc|ncat|tee|source|.|vi|vim|nvim|nano|emacs|code|jq|yq|diff|zip|tar|gpg|openssl|python|python3|node|ruby|perl)
        deny "Reading or copying secret/credential files is forbidden." ;;
      git)
        [[ $(first_word "${args[@]}") == add ]] && deny "Staging secret/credential files is forbidden." ;;
    esac
  fi
}

# Split compound commands into simple ones; over-splitting only costs false positives.
s=${cmd//$'\\\n'/ }
for sep in '&&' '||' '|&' ';' '|' '&' '$(' '`' '(' ')' '{' '}'; do
  s=${s//"$sep"/$'\n'}
done
while IFS= read -r seg; do
  check_segment "$seg"
done <<<"$s"

if ((${#ask_reasons[@]})); then
  reason=$(printf '%s, ' "${ask_reasons[@]}")
  decide ask "Needs user confirmation: ${reason%, }."
fi
exit 0
