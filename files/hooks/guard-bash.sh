#!/usr/bin/env bash
# PreToolUse hook for the Bash tool.
#   deny: deletes outside the allowed roots (/tmp, $TMPDIR, ~/Projects/Scratch),
#         package removal, disk wiping, reading secret files, sudo/su/run0 (use pkexec)
#   ask:  git commit, git push, branch creation, gh pr create, and git/gh commands
#         that discard work or delete refs (reset --hard, restore, branch -D,
#         stash drop, push --force, gh pr merge, ...)
# Commands are lexed quote-aware, so quoted text (commit messages, heredocs) is
# never mistaken for a command. Defense in depth, not a boundary: code run via
# interpreters (python -c, perl -e) or scripts on disk is not inspected.
# Input: hook JSON on stdin. Output: decision JSON, or nothing to defer.
# GUARD_DELETE_ROOTS (colon-separated) overrides the allowed roots, for tests.

set -o pipefail
export LC_ALL=C

if ! command -v jq >/dev/null 2>&1; then
  echo "guard-bash: jq is not installed, so every Bash command is blocked. Ask the user to install jq." >&2
  exit 2
fi

input=$(cat)
cmd=$(jq -r '.tool_input.command // empty' <<<"$input")
start_cwd=$(jq -r '.cwd // empty' <<<"$input")
[[ -n $cmd ]] || exit 0

ALLOWED=()
IFS=: read -ra _roots <<<"${GUARD_DELETE_ROOTS:-/tmp:${TMPDIR:-}:$HOME/Projects/Scratch}"
for _r in "${_roots[@]}"; do
  [[ -n $_r ]] && _r=$(cd -P "$_r" 2>/dev/null && pwd -P) && ALLOWED+=("$_r")
done

HANDOFF="Do not run this or work around it. Hand it to the user: give the exact command (with sudo, not pkexec, if it needs root) and one sentence on what it does, for them to run in their own terminal."
SECRET_RE='(^|[/[:space:]=@:])\.env(\.[[:alnum:]_-]+)?([[:space:]]|$)|\.ssh/|(^|[/[:space:]=@:])id_(rsa|dsa|ecdsa|ed25519)([[:space:]]|$)|\.aws/credentials|\.gnupg/|\.netrc|\.pgpass|\.config/gh/hosts\.yml|\.docker/config\.json|\.kube/config|\.git-credentials|\.npmrc|\.pypirc|\.claude/\.credentials\.json|\.config/gcloud/|\.azure/|\.vault-token|\.password-store/|\.local/share/keyrings/|[^/[:space:]]\.(pem|key|p12|pfx)([[:space:]]|$)'
SECRET_OK_RE='\.env\.(example|sample|template)([[:space:]]|$)'

CWD=$(cd -P "$start_cwd" 2>/dev/null && pwd -P)  # effective cwd; "" = unknown
ask_reasons=()
OPS=()

decide() {
  jq -n --arg d "$1" --arg r "$2" \
    '{hookSpecificOutput: {hookEventName: "PreToolUse", permissionDecision: $d, permissionDecisionReason: $r}}'
  exit 0
}
deny() { decide deny "$1 $HANDOFF"; }
deny_root() {
  decide deny "Root needed: rerun it with pkexec instead of sudo/su/run0, using absolute paths (the user authenticates in a polkit dialog). If pkexec is unavailable or fails, hand the command to the user using sudo."
}
ask() { ask_reasons+=("$1"); }

# --- paths -------------------------------------------------------------------

lexnorm() { # lexically normalise an absolute path
  local -a parts out=()
  local part
  IFS=/ read -ra parts <<<"$1"
  for part in "${parts[@]}"; do
    case $part in
      '' | .) ;;
      ..) ((${#out[@]})) && unset 'out[${#out[@]}-1]' ;;
      *) out+=("$part") ;;
    esac
  done
  printf '/%s' "${out[@]}"
}

# Absolute physical path of $1 relative to directory $2, resolving symlinks in
# the parent. Prints nothing if it can't be known statically.
resolve() {
  local p=$1 base=$2 dir name
  # Expansions, ~user and brace lists ({a,../b} can expand past a root) are unknowable.
  [[ $p == *'$'* || $p == *'`'* || $p == '~'[!/]* || $p == *'{'*'}'* ]] && return
  case $p in
    '~') p=$HOME ;;
    '~/'*) p=$HOME/${p#'~/'} ;;
    /*) ;;
    *) [[ -n $base ]] || return; p=$base/$p ;;
  esac
  if [[ $p == */ || $p == */. || $p == */.. ]] && [[ -d $p ]]; then
    (cd -P "$p" 2>/dev/null && pwd -P)
    return
  fi
  # A glob with a trailing slash matches symlinked dirs too, and rm follows them.
  [[ $p == */ && $p == *[\*\?\[]* ]] && return
  while [[ $p == */ && $p != / ]]; do p=${p%/}; done
  dir=${p%/*} name=${p##*/}
  [[ -n $dir ]] || dir=/
  [[ $dir == *[\*\?\[]* ]] && return
  if [[ -d $dir ]]; then
    dir=$(cd -P "$dir" 2>/dev/null && pwd -P) || return
  else
    dir=$(lexnorm "$dir")
  fi
  if [[ $name == . || $name == .. ]]; then lexnorm "$dir/$name"; else printf '%s\n' "${dir%/}/$name"; fi
}

inside_allowed() { # inside_allowed <path> [contents]: "contents" also accepts a root itself
  local r
  for r in "${ALLOWED[@]}"; do
    [[ $1 == "$r"/?* ]] && return 0
    [[ $2 == contents && $1 == "$r" ]] && return 0
  done
  return 1
}

# check_paths <what> <base-dir> <paths...>: deny unless every path is strictly
# inside an allowed root. With CONTENTS_ONLY=1 (the command deletes what's
# under a path, never the path itself) a root itself is accepted too.
check_paths() {
  local what=$1 base=$2 p r
  shift 2
  ((via_xargs)) && deny "$what with paths read from stdin can't be checked."
  (($#)) || deny "$what with no paths that can be checked."
  for p in "$@"; do
    r=$(resolve "$p" "$base")
    [[ -n $r ]] && inside_allowed "$r" "${CONTENTS_ONLY:+contents}" || deny "$what outside /tmp and ~/Projects/Scratch ($p)."
  done
}

is_secret() { [[ " $1 " =~ $SECRET_RE && ! " $1 " =~ $SECRET_OK_RE ]]; }

# secret_word <word> <base-dir>: true if the word names a secret file as written,
# relative to base, through a symlink, or as a glob that matches one.
secret_word() {
  local p=$1 e
  [[ $p == *[[:space:]]* ]] && return 1 # text such as a commit message, not a path
  is_secret "$p" && return 0
  [[ $p == -* || $p == *[\$\`]* ]] && return 1
  case $p in
    '~' | '~/'*) p=$HOME${p#'~'} ;;
    /*) ;;
    *) [[ -n $2 ]] || return 1; p=$2/$p ;;
  esac
  if [[ $p == *[\*\?\[]* ]]; then
    while IFS= read -r e; do is_secret "$e" && return 0; done < <(compgen -G "$p" 2>/dev/null | head -n 500)
    return 1
  fi
  [[ -e $p ]] && e=$(readlink -f -- "$p" 2>/dev/null) && [[ -n $e ]] && p=$e
  is_secret "$p"
}

# operands " -opt-with-value ... " args...: non-option args into OPS.
operands() {
  local valopts=$1 a end=0
  shift
  OPS=()
  while (($#)); do
    a=$1
    shift
    if ((end)) || [[ $a != -* || $a == - ]]; then OPS+=("$a")
    elif [[ $a == -- ]]; then end=1
    elif [[ $valopts == *" $a "* ]]; then shift
    fi
  done
}

# --- git ---------------------------------------------------------------------

git_branch() {
  local a create=1 named=0 del=0
  for a in "$@"; do
    [[ $a == --delete || $a =~ ^-[a-zA-Z]*[dD] ]] && del=1
    case $a in
      -c | -C | --copy | -f | --force) ;;
      --list | --all | --remotes | --verbose | --show-current | --contains | --no-contains | --merged | --no-merged | \
        --points-at | --format* | --sort* | --delete | --move | --edit-description | --unset-upstream | \
        --set-upstream-to* | -u | -[dDmMlarv]* | -[a-zA-Z]*[dDmMlarv]*) create=0 ;;
      -*) ;;
      *) named=1 ;;
    esac
  done
  ((del)) && ask "git branch -d/-D (deletes a branch)"
  ((create && named)) && ask "git branch (creates a branch)"
}

check_git() {
  local j=0 gcwd=$ccwd sub r p
  local -a a=("$@") rest
  while ((j < ${#a[@]})); do
    case ${a[j]} in
      -C) gcwd=$(resolve "${a[j + 1]}" "$gcwd"); ((j += 2)) ;;
      -c | --git-dir | --work-tree | --namespace | --exec-path) ((j += 2)) ;;
      -*) ((j++)) ;;
      *) break ;;
    esac
  done
  sub=${a[j]}
  rest=("${a[@]:j+1}")
  r=" ${rest[*]} "
  case $sub in
    commit) ask "git commit" ;;
    push)
      if [[ $r =~ \ (-[a-zA-Z]*[fd][a-zA-Z]*|--force[a-z-]*|--delete|--mirror|--prune)(=[^[:space:]]*)?\  || $r =~ \ [+:][^[:space:]] ]]; then
        ask "git push --force/--delete (rewrites or deletes remote refs)"
      else
        ask "git push"
      fi ;;
    checkout)
      if [[ $r =~ \ (-[a-zA-Z]*[bBt]|--orphan|--track) ]]; then
        ask "git checkout -b (creates a branch)"
      elif [[ $r =~ \ (--|-f|--force)\  ]]; then
        ask "git checkout of paths or --force (discards uncommitted changes)"
      else
        operands "" "${rest[@]}"
        for p in "${OPS[@]}"; do
          p=$(resolve "$p" "$gcwd")
          [[ -n $p && -e $p ]] && { ask "git checkout of paths (discards uncommitted changes)"; break; }
        done
      fi ;;
    switch)
      [[ $r =~ \ (-[a-zA-Z]*[cC]|--create|--force-create|--orphan) ]] && ask "git switch -c (creates a branch)"
      [[ $r =~ \ (-f|--force|--discard-changes)\  ]] && ask "git switch --discard-changes (discards uncommitted changes)" ;;
    restore)
      [[ $r =~ \ (--staged|-S)\  && ! $r =~ \ (--worktree|-W)\  ]] || ask "git restore (discards uncommitted changes)" ;;
    reset)
      [[ $r =~ \ (--hard|--merge)\  ]] && ask "git reset --hard (discards uncommitted changes)" ;;
    stash)
      [[ ${rest[0]} == drop || ${rest[0]} == clear ]] && ask "git stash ${rest[0]} (deletes stashed changes)" ;;
    branch) git_branch "${rest[@]}" ;;
    update-ref)
      [[ $r =~ \ (-d|--stdin)\  ]] && ask "git update-ref -d (deletes a ref)" ;;
    reflog)
      [[ ${rest[0]} == expire || ${rest[0]} == delete ]] && ask "git reflog ${rest[0]} (drops recovery points)" ;;
    prune) ask "git prune (deletes unreachable commits)" ;;
    gc) [[ $r == *" --prune=now "* ]] && ask "git gc --prune=now (deletes unreachable commits)" ;;
    filter-branch | filter-repo) ask "git $sub (rewrites history)" ;;
    worktree)
      [[ ${rest[0]} == add ]] && ask "git worktree add (creates a branch)"
      [[ ${rest[0]} == remove ]] && ask "git worktree remove (deletes a worktree)" ;;
    rm)
      if [[ $r != *" --cached "* ]]; then
        operands " --pathspec-from-file " "${rest[@]}"
        check_paths "'git rm'" "$gcwd" "${OPS[@]}"
      fi ;;
    clean)
      if ! [[ $r =~ \ (-[a-zA-Z]*n[a-zA-Z]*|--dry-run)\  ]]; then
        operands " -e --exclude " "${rest[@]}"
        ((${#OPS[@]})) || OPS=(.)
        CONTENTS_ONLY=1 check_paths "'git clean'" "$gcwd" "${OPS[@]}"
      fi ;;
  esac
}

# --- one simple command --------------------------------------------------------

check_words() {
  local -a w=("$@") args
  local i=0 n=$# t prog valopts cmdopts pos relex root=0 via_xargs=0 ccwd=$CWD saved d argstr sub j rx="" has_rx=0 scan=1
  # Skip assignments, wrappers (and their options), and shell keywords. A wrapper
  # whose option or operands hold a command string (env -S, flock -c, watch)
  # has that string lexed as a command of its own.
  while ((i < n)); do
    t=${w[i]}
    if [[ $t =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then ((i++)); continue; fi
    valopts="" cmdopts="" pos=0 relex=0
    case $t in
      sudo | doas) root=1; valopts=" -u -g -U -C -D -h -p -r -t -T --user --group --chdir --prompt " ;;
      run0) root=1; valopts=" -u -g -D --user --group --chdir --setenv --unit --property --description --slice --nice --machine " ;;
      pkexec) valopts=" --user " ;;
      runuser) valopts=" -u -g -G -s --user --group --supp-group --shell "; cmdopts=" -c --command " ;;
      env) valopts=" -u -C --unset --chdir "; cmdopts=" -S --split-string " ;;
      nice) valopts=" -n --adjustment " ;;
      ionice) valopts=" -c -n -p -t --class --classdata " ;;
      timeout) valopts=" -s -k --signal --kill-after "; pos=1 ;;
      stdbuf) valopts=" -i -o -e " ;;
      xargs) via_xargs=1; valopts=" -I -i -n -P -L -d -E -s -a --max-args --max-procs --delimiter --arg-file " ;;
      parallel) via_xargs=1; relex=1; valopts=" -j -S -a --jobs --sshlogin --arg-file " ;;
      watch) relex=1; valopts=" -n --interval " ;;
      flock) pos=1; valopts=" -w -E --timeout --conflict-exit-code "; cmdopts=" -c --command " ;;
      taskset) pos=1 ;;
      chrt) pos=1; valopts=" -T -P -D --sched-runtime --sched-period --sched-deadline " ;;
      unshare) valopts=" -S -G -R -w --setuid --setgid --root --wd " ;;
      nsenter) valopts=" -t -S -G --target --setuid --setgid " ;;
      systemd-run) valopts=" -u -p -E -H -M --unit --property --setenv --host --machine --description --slice --uid --gid --nice --working-directory --on-active --on-boot --on-startup --on-calendar " ;;
      strace) valopts=" -o -e -p -s -u -E -a -b -I -O -P -S -X " ;;
      ltrace) valopts=" -o -e -p -s -u -a -n -l -E -x -w " ;;
      time) valopts=" -f -o --format --output " ;;
      exec) valopts=" -a " ;;
      function) pos=1 ;;
      setsid | busybox | toybox | nohup | command | builtin | noglob | coproc | then | do | else | elif | if | while | until | '!' | '{' | '}') ;;
      *) break ;;
    esac
    ((i++))
    while ((i < n)); do
      t=${w[i]}
      if [[ $t == -- ]]; then ((i++)); break; fi
      if [[ $t == -* ]]; then
        [[ $t =~ ^(-[CDRw]|--chdir|--root|--wd|--working-directory)(=|$) ]] && ccwd=""
        if [[ -n $cmdopts && $cmdopts == *" ${t%%=*} "* ]]; then
          if [[ $t == *=* ]]; then rx="${t#*=} ${w[*]:i+1}"; else rx="${w[*]:i+1}"; fi
          has_rx=1 i=$n
          break
        fi
        if [[ $valopts == *" $t "* ]]; then ((i += 2)); else ((i++)); fi
      elif ((pos > 0)); then ((pos--)); ((i++))
      elif [[ $t =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then ((i++))
      else break
      fi
    done
    if ((relex && !has_rx)); then rx="${w[*]:i}" has_rx=1 i=$n; fi
  done
  if ((has_rx)); then saved=$CWD; CWD=$ccwd; lex "$rx"; CWD=$saved; fi
  if ((i >= n)); then ((root)) && deny_root; return; fi

  prog=${w[i]##*/}
  args=("${w[@]:i+1}")
  argstr=" ${args[*]} "
  operands "" "${args[@]}"
  sub=${OPS[0]}

  case $prog in
    cd | pushd | popd)
      # In a pipeline cd runs in a subshell. One that may not run (after && or ||,
      # in a block or function body) makes the cwd unknown once its list ends.
      if [[ $seg_prev != '|' && $seg_next != '|' ]]; then
        if [[ $prog == popd ]]; then
          CWD=""
        else
          d=${OPS[0]:-$HOME}
          [[ $d == - ]] || d=$(resolve "$d" "$CWD")
          if [[ $d == /* ]]; then CWD=$(cd -P "$d" 2>/dev/null && pwd -P); else CWD=""; fi
        fi
        if [[ $seg_prev == '&&' || $seg_prev == '||' || $seg_prev == ')' || ${w[0]} =~ ^(then|else|elif|do|\{)$ ]] || ((blk)); then
          list_cond=1
        fi
      fi ;;
    rm | rmdir | unlink | srm)
      check_paths "'$prog'" "$ccwd" "${OPS[@]}" ;;
    shred)
      operands " -n -s --iterations --size " "${args[@]}"
      check_paths "'shred'" "$ccwd" "${OPS[@]}" ;;
    truncate)
      operands " -s -r --size --reference " "${args[@]}"
      check_paths "'truncate'" "$ccwd" "${OPS[@]}" ;;
    find)
      local -a starts=() clause=()
      local k=0 fdel=0 follow=0
      while ((k < ${#args[@]})) && [[ ${args[k]} =~ ^-([HLP]|O[0-9]*|D)$ ]]; do # global options
        [[ ${args[k]} == -L ]] && follow=1
        [[ ${args[k]} == -D ]] && ((k++))
        ((k++))
      done
      for (( ; k < ${#args[@]}; k++)); do
        t=${args[k]}
        [[ $t == -* || $t == '(' || $t == '!' ]] && break
        starts+=("$t")
      done
      [[ $argstr == *" -delete "* ]] && fdel=1
      [[ $argstr == *" -follow "* ]] && follow=1
      # -exec clauses: a delete program deletes under the start paths; anything
      # else is checked as a command of its own.
      for (( ; k < ${#args[@]}; k++)); do
        [[ ${args[k]} =~ ^-(exec|execdir|ok|okdir)$ ]] || continue
        clause=()
        for ((k++; k < ${#args[@]}; k++)); do
          [[ ${args[k]} == ';' || ${args[k]} == + ]] && break
          clause+=("${args[k]}")
        done
        ((${#clause[@]})) || continue
        case ${clause[0]##*/} in
          rm | rmdir | unlink | shred | srm) fdel=1 ;;
          *) saved=$CWD; check_words "${clause[@]}"; CWD=$saved ;;
        esac
      done
      if ((fdel)); then
        ((follow)) && deny "'find -L' deleting can follow symlinks out of /tmp and ~/Projects/Scratch."
        ((${#starts[@]})) || starts=(.)
        CONTENTS_ONLY=1 check_paths "'find' deleting" "$ccwd" "${starts[@]}"
      fi ;;
    rsync)
      if [[ $argstr =~ \ --(del|delete[a-z-]*|remove-source-files|remove-sent-files)\  ]]; then
        ((${#OPS[@]})) || deny "'rsync --delete' with no paths that can be checked."
        [[ ${OPS[${#OPS[@]} - 1]} == *:* ]] && deny "'rsync --delete' to a remote can't be checked."
        if [[ $argstr =~ \ --remove-(source|sent)-files\  ]]; then
          check_paths "'rsync --remove-source-files'" "$ccwd" "${OPS[@]}"
        else
          check_paths "'rsync --delete'" "$ccwd" "${OPS[${#OPS[@]} - 1]}"
        fi
      fi ;;
    dd)
      for t in "${args[@]}"; do [[ $t == of=* ]] && check_paths "'dd of='" "$ccwd" "${t#of=}"; done ;;
    wipefs | mkfs | mkfs.* | mkswap | fdisk | sfdisk | gdisk | parted | blkdiscard)
      deny "'$prog' destroys data on a disk." ;;
    sh | bash | zsh | dash | ksh | fish)
      for ((j = 0; j < ${#args[@]}; j++)); do
        if [[ ${args[j]} =~ ^-[a-zA-Z]*c$ ]]; then
          saved=$CWD; CWD=$ccwd; lex "${args[j + 1]}"; CWD=$saved
          break
        fi
      done ;;
    eval)
      saved=$CWD; CWD=$ccwd; lex "${args[*]}"; CWD=$saved ;;
    su)
      deny_root ;;
    dnf | dnf5 | yum | microdnf | zypper)
      case $sub in remove | erase | autoremove | downgrade | distro-sync | rm) deny "'$prog $sub' removes or downgrades packages." ;; esac
      [[ $sub == history && $argstr =~ \ (undo|rollback)\  ]] && deny "'$prog history undo/rollback' can remove packages." ;;
    apt | apt-get | aptitude)
      case $sub in remove | purge | autoremove | autopurge) deny "'$prog $sub' removes packages." ;; esac ;;
    brew | port)
      case $sub in uninstall | remove | rm | untap | autoremove) deny "'$prog $sub' removes packages." ;; esac ;;
    pacman | yay | paru)
      [[ $argstr =~ \ -R[a-zA-Z]*\  ]] && deny "'$prog -R' removes packages." ;;
    rpm)
      [[ $argstr =~ \ (-e|--erase)\  ]] && deny "'rpm -e' removes packages." ;;
    dpkg)
      [[ $argstr =~ \ (-r|-P|--remove|--purge)\  ]] && deny "'dpkg' package removal." ;;
    flatpak | snap)
      case $sub in uninstall | remove) deny "'$prog $sub' removes software." ;; esac ;;
    pip | pip3 | pipx | cargo | gem)
      [[ $sub == uninstall ]] && deny "'$prog uninstall' removes packages." ;;
    uv)
      [[ $argstr =~ \ (pip|tool)\ +uninstall\  ]] && deny "'uv uninstall' removes packages." ;;
    python | python3)
      [[ $argstr =~ -m\ +pip\ +uninstall ]] && deny "'pip uninstall' removes packages." ;;
    npm | pnpm | yarn | bun)
      [[ $argstr =~ \ (uninstall|remove|rm|un|r)\  && $argstr =~ \ (-g|--global|global)\  ]] &&
        deny "Removing global $prog packages." ;;
    git)
      check_git "${args[@]}" ;;
    gh)
      [[ $argstr =~ \ (repo|release)\ +delete\  ]] && deny "'gh $sub delete' is irreversible."
      [[ $argstr =~ \ pr\ +create\  ]] && ask "gh pr create (pushes the branch)"
      [[ $argstr =~ \ pr\ +merge\  ]] && ask "gh pr merge"
      [[ $argstr =~ \ [a-z-]+\ +delete\  ]] && ask "gh $sub delete"
      [[ $argstr =~ \ (-X\ ?|--method[\ =])(DELETE|delete)\  ]] && ask "gh api DELETE" ;;
  esac

  # Secrets: deny naming a secret file, unless the program only touches metadata.
  case $prog in
    ls | stat | file | test | '[' | '[[' | chmod | chown | chgrp | mkdir | touch | ssh | ssh-add | ssh-keygen | ssh-copy-id | \
      echo | printf | which | type | realpath | readlink | dirname | basename | du | wc | rm | rmdir | unlink | shred | trash | \
      cd | pushd) scan=0 ;;
    find) [[ $argstr =~ \ -(exec|execdir|ok|okdir)\  ]] || scan=0 ;;
    git) case $sub in status | rm | check-ignore | ls-files) scan=0 ;; esac ;;
  esac
  if ((scan)); then
    for t in "${w[@]:i}"; do
      secret_word "$t" "$ccwd" && deny "Reading, copying or staging secret/credential files ($t)."
    done
  fi
  for t in "${rin[@]}"; do
    secret_word "$t" "$ccwd" && deny "Reading secret/credential files ($t)."
  done

  ((root)) && deny_root
}

# --- lexer -------------------------------------------------------------------
# lex <string>: split a command line into simple commands, quote-aware, and run
# check_words on each. Substitutions ($(...), `...`, <(...)) and (( arithmetic ))
# are checked recursively; subshells and backgrounded lists restore the cwd;
# heredoc bodies and output redirect targets are skipped, input redirect targets
# kept in rin. flush/endseg/subst/arith_end and check_words work on lex's locals
# (bash dynamic scope): seg_prev/seg_next are the separators around the current
# command, list_cond is set when a cd in the current list may not have run.

flush() {
  if ((have)); then
    if ((drop)); then
      ((drop_in)) && rin+=("$word")
      drop=0 drop_in=0
    else
      words+=("$word")
    fi
  fi
  word="" have=0
}

endseg() {
  if ((${#words[@]})); then
    case ${words[0]} in fi | done | esac | '}') ((blk > 0)) && ((blk--)) ;; esac
    check_words "${words[@]}"
    case ${words[0]} in if | while | until | for | case | select | '{') ((blk++)) ;; esac
  fi
  words=() rin=()
}

subst() { # subst <start> <closer>: check s[start..closer) and set SUB_END
  local k=$1 close=$2 depth=1 ch q="" saved=$CWD
  while ((k < n)); do
    ch=${s:k:1}
    if [[ -n $q ]]; then [[ $ch == "$q" ]] && q=""
    elif [[ $ch == \\ ]]; then ((k++))
    elif [[ $close == ')' ]]; then
      case $ch in
        \' | \") q=$ch ;;
        '(') ((depth++)) ;;
        ')') ((--depth == 0)) && break ;;
      esac
    elif [[ $ch == '`' ]]; then break
    fi
    ((k++))
  done
  lex "${s:$1:k-$1}"
  CWD=$saved
  SUB_END=$k
}

arith_end() { # arith_end <start>: if s[start..] closes with '))', set ARITH_END to its first ')'
  local k=$1 depth=0 ch q=""
  while ((k < n)); do
    ch=${s:k:1}
    if [[ -n $q ]]; then [[ $ch == "$q" ]] && q=""
    else
      case $ch in
        \' | \") q=$ch ;;
        \\) ((k++)) ;;
        '(') ((depth++)) ;;
        ')')
          if ((depth == 0)); then
            [[ ${s:k+1:1} == ')' ]] && { ARITH_END=$k; return 0; }
            return 1
          fi
          ((depth--)) ;;
      esac
    fi
    ((k++))
  done
  return 1
}

lex() {
  local s=$1 n=${#1} i=0 c c2 sep word="" have=0 sq=0 dq=0 drop=0 drop_in=0 hd="" hd_strip=0 line j arith asaved
  local seg_prev=';' seg_next=';' list_start=$CWD list_cond=0 blk=0
  local -a words=() rin=() stack=() lstack=() cstack=()
  while ((i < n)); do
    c=${s:i:1}
    if ((sq)); then
      if [[ $c == \' ]]; then sq=0; else word+=$c; fi
      ((i++)); continue
    fi
    if ((dq)); then
      case $c in
        \") dq=0 ;;
        \\)
          c2=${s:i+1:1}
          case $c2 in
            \$ | '`' | \" | \\) word+=$c2; ((i++)) ;;
            $'\n') ((i++)) ;;
            *) word+=$c ;;
          esac ;;
        \$)
          if [[ ${s:i+1:1} == '(' ]]; then subst $((i + 2)) ')'; i=$SUB_END; word+='$(...)'; else word+=$c; fi ;;
        '`') subst $((i + 1)) '`'; i=$SUB_END; word+='$(...)' ;;
        *) word+=$c ;;
      esac
      ((i++)); continue
    fi
    case $c in
      \') sq=1; have=1 ;;
      \") dq=1; have=1 ;;
      \\)
        c2=${s:i+1:1}
        [[ $c2 != $'\n' ]] && { word+=$c2; have=1; }
        ((i++)) ;;
      ' ' | $'\t') flush ;;
      '#')
        if ((have)); then word+=$c
        else while ((i + 1 < n)) && [[ ${s:i+1:1} != $'\n' ]]; do ((i++)); done
        fi ;;
      \$)
        if [[ ${s:i+1:1} == '(' ]]; then subst $((i + 2)) ')'; i=$SUB_END; word+='$(...)'; else word+=$c; fi
        have=1 ;;
      '`') subst $((i + 1)) '`'; i=$SUB_END; word+='$(...)'; have=1 ;;
      '<' | '>')
        if [[ ${s:i+1:1} == '(' ]]; then
          subst $((i + 2)) ')'; i=$SUB_END; word+='$(...)'; have=1
        else
          [[ $word =~ ^[0-9]+$ ]] && word="" have=0
          flush
          if [[ $c == '<' && ${s:i+1:1} == '<' && ${s:i+2:1} != '<' ]]; then
            ((i += 2))
            [[ ${s:i:1} == - ]] && { hd_strip=1; ((i++)); }
            while [[ ${s:i:1} == ' ' || ${s:i:1} == $'\t' ]]; do ((i++)); done
            hd=""
            while ((i < n)); do
              case ${s:i:1} in ' ' | $'\t' | $'\n' | ';' | '&' | '|' | '<' | '>' | ')') break ;; esac
              hd+=${s:i:1}; ((i++))
            done
            hd=${hd//[\'\"\\]/}
            ((i--))
          else
            drop_in=0
            [[ $c == '<' && ${s:i+1:1} != '<' ]] && drop_in=1
            while [[ ${s:i+1:1} == [\<\>\&\|] ]]; do ((i++)); done
            drop=1
          fi
        fi ;;
      ';' | '&' | '|' | $'\n' | '(' | ')')
        if [[ $c == '&' && ${s:i+1:1} == '>' ]]; then
          flush
          while [[ ${s:i+1:1} == [\>\&] ]]; do ((i++)); done
          drop=1 drop_in=0
        elif [[ $c == '(' && ${s:i+1:1} == '(' ]] && arith_end $((i + 2)); then
          # (( arithmetic )): << and >> are shifts, not heredocs or redirects.
          flush
          seg_next=';'
          endseg
          arith=${s:i+2:ARITH_END-i-2}
          arith=${arith//'<<'/  }
          arith=${arith//'>>'/  }
          asaved=$CWD; lex "$arith"; CWD=$asaved
          i=$((ARITH_END + 1))
        else
          sep=$c
          case $c in
            $'\n') sep=';' ;;
            '&') [[ ${s:i+1:1} == '&' ]] && sep='&&' ;;
            '|') [[ ${s:i+1:1} == '|' ]] && sep='||' ;;
          esac
          flush
          seg_next=$sep
          endseg
          case $sep in
            '(')
              stack+=("$CWD"); lstack+=("$list_start"); cstack+=("$list_cond")
              list_start=$CWD list_cond=0 ;;
            ')')
              if ((${#stack[@]})); then
                j=$((${#stack[@]} - 1))
                CWD=${stack[j]} list_start=${lstack[j]} list_cond=${cstack[j]}
                unset 'stack[j]' 'lstack[j]' 'cstack[j]'
              else
                CWD=""
              fi ;;
            ';') ((list_cond)) && CWD=""; list_cond=0 list_start=$CWD ;;
            '&') CWD=$list_start list_cond=0 ;; # backgrounded list ran in a subshell
            '||') ((list_cond)) && CWD="" ;;
          esac
          seg_prev=$sep
          if [[ $c == $'\n' && -n $hd ]]; then
            if ((hd_strip)); then # <<-: delimiter may be tab-indented; go line by line
              while ((i < n)); do
                line=${s:i+1}
                line=${line%%$'\n'*}
                i=$((i + 1 + ${#line}))
                while [[ $line == $'\t'* ]]; do line=${line#$'\t'}; done
                [[ $line == "$hd" ]] && break
              done
            else # body ends at the first line equal to $hd
              line=${s:i}
              if [[ $line == *$'\n'"$hd"$'\n'* ]]; then
                j=${line%%$'\n'"$hd"$'\n'*}
                i=$((i + ${#j} + 1 + ${#hd}))
              else
                i=$n
              fi
            fi
            hd="" hd_strip=0
          fi
          [[ $c == [\;\&\|] && ${s:i+1:1} == [\;\&\|] ]] && ((i++))
        fi ;;
      *) word+=$c; have=1 ;;
    esac
    ((i++))
  done
  flush
  seg_next=';'
  endseg
}

lex "$cmd"

if ((${#ask_reasons[@]})); then
  reason=$(printf '%s, ' "${ask_reasons[@]}")
  decide ask "Needs user confirmation: ${reason%, }."
fi
exit 0
