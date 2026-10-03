#!/usr/bin/env bash
# PreToolUse hook for the Bash tool.
#   deny: deletes outside the allowed roots (/tmp, $TMPDIR, ~/Projects/Scratch),
#         package removal, disk wiping, reading secret files, sudo/su (use pkexec)
#   ask:  git commit, git push, branch creation, gh pr create
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
SECRET_RE='(^|[/[:space:]=])\.env(\.[[:alnum:]_-]+)?([[:space:]]|$)|\.ssh/|(^|/)id_(rsa|dsa|ecdsa|ed25519)([[:space:]]|$)|\.aws/credentials|\.gnupg/|\.netrc|\.pgpass|\.config/gh/hosts\.yml|\.docker/config\.json|\.kube/config'
SECRET_OK_RE='\.env\.(example|sample|template)'

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
  decide deny "Root needed: rerun it with pkexec instead of sudo/su, using absolute paths (the user authenticates in a polkit dialog). If pkexec is unavailable or fails, hand the command to the user using sudo."
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
  [[ $p == *'$'* || $p == *'`'* || $p == '~'[!/]* ]] && return
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
  local a create=1 named=0
  for a in "$@"; do
    case $a in
      -c | -C | --copy | -f | --force) ;;
      --list | --all | --remotes | --verbose | --show-current | --contains | --no-contains | --merged | --no-merged | \
        --points-at | --format* | --sort* | --delete | --move | --edit-description | --unset-upstream | \
        --set-upstream-to* | -u | -[dDmMlarv]* | -[a-zA-Z]*[dDmMlarv]*) create=0 ;;
      -*) ;;
      *) named=1 ;;
    esac
  done
  ((create && named)) && ask "git branch (creates a branch)"
}

check_git() {
  local j=0 gcwd=$ccwd sub r
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
    push) ask "git push" ;;
    checkout) [[ $r =~ \ (-b|-B|--orphan)\  ]] && ask "git checkout -b (creates a branch)" ;;
    switch) [[ $r =~ \ (-c|-C|--create|--force-create|--orphan)\  ]] && ask "git switch -c (creates a branch)" ;;
    branch) git_branch "${rest[@]}" ;;
    worktree) [[ ${rest[0]} == add ]] && ask "git worktree add (creates a branch)" ;;
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
  local i=0 n=$# t prog valopts pos root=0 via_xargs=0 ccwd=$CWD saved d argstr sub j
  # Skip assignments, wrappers (and their options), and shell keywords.
  while ((i < n)); do
    t=${w[i]}
    if [[ $t =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then ((i++)); continue; fi
    valopts="" pos=0
    case $t in
      sudo | doas) root=1; valopts=" -u -g -U -C -D -h -p -r -t -T --user --group --chdir --prompt " ;;
      pkexec) valopts=" --user " ;;
      env) valopts=" -u -C -S --unset --chdir --split-string " ;;
      nice) valopts=" -n --adjustment " ;;
      ionice) valopts=" -c -n -p -t --class --classdata " ;;
      timeout) valopts=" -s -k --signal --kill-after "; pos=1 ;;
      stdbuf) valopts=" -i -o -e " ;;
      xargs) via_xargs=1; valopts=" -I -i -n -P -L -d -E -s -a --max-args --max-procs --delimiter --arg-file " ;;
      time) valopts=" -f -o --format --output " ;;
      exec) valopts=" -a " ;;
      nohup | command | builtin | noglob | then | do | else | elif | if | while | until | '!' | '{' | '}') ;;
      *) break ;;
    esac
    ((i++))
    while ((i < n)); do
      t=${w[i]}
      if [[ $t == -- ]]; then ((i++)); break; fi
      if [[ $t == -* ]]; then
        [[ $t == -C || $t == -D || $t == --chdir* ]] && ccwd=""
        if [[ $valopts == *" $t "* ]]; then ((i += 2)); else ((i++)); fi
      elif ((pos > 0)); then ((pos--)); ((i++))
      elif [[ $t =~ ^[A-Za-z_][A-Za-z0-9_]*= ]]; then ((i++))
      else break
      fi
    done
  done
  if ((i >= n)); then ((root)) && deny_root; return; fi

  prog=${w[i]##*/}
  args=("${w[@]:i+1}")
  argstr=" ${args[*]} "
  operands "" "${args[@]}"
  sub=${OPS[0]}

  case $prog in
    cd | pushd)
      d=${OPS[0]:-$HOME}
      [[ $d == - ]] || d=$(resolve "$d" "$CWD")
      if [[ $d == /* ]]; then CWD=$(cd -P "$d" 2>/dev/null && pwd -P); else CWD=""; fi ;;
    popd) CWD="" ;;
    rm | rmdir | unlink | srm)
      check_paths "'$prog'" "$ccwd" "${OPS[@]}" ;;
    shred)
      operands " -n -s --iterations --size " "${args[@]}"
      check_paths "'shred'" "$ccwd" "${OPS[@]}" ;;
    truncate)
      operands " -s -r --size --reference " "${args[@]}"
      check_paths "'truncate'" "$ccwd" "${OPS[@]}" ;;
    find)
      if [[ $argstr == *" -delete "* || $argstr =~ \ -(exec|execdir|ok|okdir)\ +([^ ]*/)?(rm|rmdir|unlink|shred)\  ]]; then
        local -a starts=()
        for t in "${args[@]}"; do [[ $t == -* || $t == '(' || $t == '!' ]] && break; starts+=("$t"); done
        ((${#starts[@]})) || starts=(.)
        CONTENTS_ONLY=1 check_paths "'find' deleting" "$ccwd" "${starts[@]}"
      fi ;;
    rsync)
      if [[ $argstr =~ \ --(delete[a-z-]*|remove-source-files)\  ]]; then
        ((${#OPS[@]})) || deny "'rsync --delete' with no paths that can be checked."
        [[ ${OPS[${#OPS[@]} - 1]} == *:* ]] && deny "'rsync --delete' to a remote can't be checked."
        if [[ $argstr == *" --remove-source-files "* ]]; then
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
      [[ $argstr =~ \ pr\ +create\  ]] && ask "gh pr create (pushes the branch)" ;;
  esac

  if [[ " ${w[*]:i} " =~ $SECRET_RE && ! " ${w[*]:i} " =~ $SECRET_OK_RE ]]; then
    case $prog in
      cat | less | more | head | tail | bat | batcat | grep | egrep | fgrep | rg | ag | sed | awk | gawk | cut | sort | uniq | \
        strings | xxd | od | hexdump | base64 | cp | mv | scp | rsync | curl | wget | nc | ncat | tee | source | . | vi | vim | \
        nvim | nano | emacs | code | jq | yq | diff | zip | tar | gpg | openssl | python | python3 | node | ruby | perl)
        deny "Reading or copying secret/credential files." ;;
      git)
        [[ $sub == add ]] && deny "Staging secret/credential files." ;;
    esac
  fi

  ((root)) && deny_root
}

# --- lexer -------------------------------------------------------------------
# lex <string>: split a command line into simple commands, quote-aware, and run
# check_words on each. Substitutions ($(...), `...`, <(...)) are checked
# recursively; subshells restore the cwd; heredoc bodies and redirect targets
# are skipped. flush/endseg/subst work on lex's locals (bash dynamic scope).

flush() {
  if ((have)); then
    if ((drop)); then drop=0; else words+=("$word"); fi
  fi
  word="" have=0
}

endseg() {
  ((${#words[@]})) && check_words "${words[@]}"
  words=()
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

lex() {
  local s=$1 n=${#1} i=0 c c2 word="" have=0 sq=0 dq=0 drop=0 hd="" hd_strip=0 line j
  local -a words=() stack=()
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
            while [[ ${s:i+1:1} == [\<\>\&\|] ]]; do ((i++)); done
            drop=1
          fi
        fi ;;
      ';' | '&' | '|' | $'\n' | '(' | ')')
        if [[ $c == '&' && ${s:i+1:1} == '>' ]]; then
          flush
          while [[ ${s:i+1:1} == [\>\&] ]]; do ((i++)); done
          drop=1
        else
          flush
          endseg
          case $c in
            '(') stack+=("$CWD") ;;
            ')')
              if ((${#stack[@]})); then CWD=${stack[${#stack[@]} - 1]}; unset 'stack[${#stack[@]}-1]'; else CWD=""; fi ;;
            $'\n')
              if [[ -n $hd ]]; then
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
              fi ;;
            *) [[ ${s:i+1:1} == [\;\&\|] ]] && ((i++)) ;;
          esac
        fi ;;
      *) word+=$c; have=1 ;;
    esac
    ((i++))
  done
  flush
  endseg
}

lex "$cmd"

if ((${#ask_reasons[@]})); then
  reason=$(printf '%s, ' "${ask_reasons[@]}")
  decide ask "Needs user confirmation: ${reason%, }."
fi
exit 0
