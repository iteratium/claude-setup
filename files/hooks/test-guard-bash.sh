#!/usr/bin/env bash
# Table-driven tests for guard-bash.sh. Usage: test-guard-bash.sh [path/to/guard-bash.sh]
# Exits non-zero if any case gets the wrong decision. Runs in a temp sandbox:
# $A is the only allowed delete root; $P is a protected project (a git repo).

hook=${1:-"$(dirname "$0")/guard-bash.sh"}
tmp=$(cd -P "$(mktemp -d)" && pwd -P)
trap 'command rm -rf "$tmp"' EXIT

A=$tmp/allowed P=$tmp/project
mkdir -p "$A/dir" "$A/scratch/proj" "$P/src"
git init -q -b main "$P"
ln -s "$P" "$A/link"          # symlink inside the allowed root pointing out of it
export GUARD_DELETE_ROOTS=$A

pass=0 fail=0
check() { # check <deny|ask|none> <cwd> <command>
  local want=$1 dir=$2 cmd=$3 got
  got=$(jq -n --arg c "$cmd" --arg d "$dir" '{tool_name:"Bash",tool_input:{command:$c},cwd:$d}' |
    "$hook" | jq -r '.hookSpecificOutput.permissionDecision // empty')
  got=${got:-none}
  if [[ $got == "$want" ]]; then ((pass++)); else ((fail++)); printf 'FAIL want=%s got=%s (cwd %s): %s\n' "$want" "$got" "${dir#$tmp/}" "$cmd"; fi
}

# --- deletes outside the allowed roots: deny ---
check deny "$P" 'rm -rf build/'
check deny "$P" '/bin/rm foo'
check deny "$P" 'rm foo 2>/dev/null'
check deny "$P" 'rm -rf -- -weird'
check deny "$P" "rm -rf $A"
check deny "$P" "rm -rf $A/"
check deny "$P" "rm -rf $A/../project/src"
check deny "$P" "rm -rf $A/link/src"
check deny "$P" 'rm -rf "$HOME/x"'
check deny "$P" 'rm -rf ~/x'
check deny "$P" "cd $A && cd .. && rm x"
check deny "$P" "(cd $A; rm x); rm y"
check deny "$P" "bash -c 'cd $A; rm x'; rm y"
check deny "$P" "echo \"; cd $A ;\" ; rm important"
check deny "$P" 'cd - && rm x'
check deny "$P" "find $A | xargs rm"
check deny "$P" 'find . -name "*.o" -delete'
check deny "$P" 'find src -type f -exec rm {} \;'
check deny "$P" 'rmdir src'
check deny "$P" 'unlink src/a'
check deny "$P" 'shred -u -n 3 secret'
check deny "$P" 'truncate -s 0 log.txt'
check deny "$P" 'git rm file.txt'
check deny "$P" 'git clean -fd'
check deny "$P" 'git -C src clean -fdx'
check deny "$P" "rsync -a --delete src/ dst/"
check deny "$P" "rsync -a --delete $A/src/ host:dst/"
check deny "$P" 'dd if=/dev/zero of=/dev/sda bs=1M'
check deny "$P" 'mkfs.ext4 /dev/sdb1'
check deny "$P" 'echo $(rm -rf src)'
check deny "$P" 'ls `rm -rf src`'
check deny "$P" "sh -c \"rm -rf src\""
check deny "$P" 'eval rm src/a'
check deny "$P" 'timeout 30 rm x'
check deny "$P" 'FOO=1 nice -n 5 rm x'

# --- deletes inside the allowed roots: allowed ---
check none "$P" "rm $A/x"
check none "$P" "rm -rf $A/dir/"
check none "$P" "rm -rf $A/dir/*"
check none "$P" "rm $A/link"
check none "$P" "rm -rf $A/scratch/proj"
check none "$P" "cd $A && rm -rf dir"
check none "$A" 'rm -rf dir build'
check none "$A" 'rm -rf dir 2>/dev/null || true'
check none "$P" "find $A/dir -name '*.o' -delete"
check none "$P" "rmdir $A/dir"
check none "$A" 'git clean -fd'
check none "$P" "rsync -a --delete src/ $A/dst/"
check none "$P" "dd if=/dev/zero of=$A/blob bs=1M count=1"
check none "$P" "pkexec rm -rf $A/root-owned"
check none "$P" "pkexec /usr/bin/rm $A/x"

# --- root: sudo/su redirect to pkexec (deny), pkexec allowed ---
check deny "$P" 'sudo dnf install htop'
check deny "$P" 'sudo -E rm x'
check deny "$P" "sudo rm $A/x"
check deny "$P" 'sudo -i'
check deny "$P" 'sudo -u root -- systemctl restart foo'
check deny "$P" 'su -c "systemctl restart foo"'
check deny "$P" 'doas reboot'
check none "$P" 'pkexec dnf install -y htop'
check none "$P" 'pkexec /usr/bin/systemctl restart foo'
check none "$P" 'echo "run sudo dnf install x yourself"'

# --- package removal: deny (even via pkexec) ---
check deny "$P" 'pkexec dnf remove vim'
check deny "$P" 'dnf -y erase vim'
check deny "$P" 'apt-get purge vim'
check deny "$P" 'brew uninstall jq'
check deny "$P" 'pacman -Rns foo'
check deny "$P" 'rpm -e foo'
check deny "$P" 'pip uninstall requests'
check deny "$P" 'python3 -m pip uninstall requests'
check deny "$P" 'npm uninstall -g typescript'
check deny "$P" 'flatpak uninstall org.foo'
check deny "$P" 'gh repo delete foo/bar'
check none "$P" 'npm uninstall lodash'
check none "$P" 'dnf list installed'

# --- secrets ---
check deny "$P" 'cat .env'
check deny "$P" 'cat ~/.ssh/id_ed25519'
check deny "$P" 'grep TOKEN config/.env.production'
check deny "$P" 'git add .env'
check deny "$P" 'cp ~/.config/gh/hosts.yml /tmp/x'
check none "$P" 'cat .env.example'
check none "$P" 'ls ~/.ssh'

# --- git: ask for commit, push, branch creation; nothing else ---
check ask "$P" 'git commit -m "feat: x"'
check ask "$P" 'git commit --amend --no-edit'
check ask "$P" 'git -C . commit -m x'
check ask "$P" 'git add -A && git commit -m x'
check ask "$P" 'git push'
check ask "$P" 'git push --force origin main'
check ask "$P" 'git checkout -b new-thing'
check ask "$P" 'git switch -c new-thing'
check ask "$P" 'git branch new-thing'
check ask "$P" 'git branch -c old new'
check ask "$P" 'git worktree add ../wt'
check ask "$P" 'gh pr create --fill'
check none "$P" 'git status'
check none "$P" 'git branch'
check none "$P" 'git branch -a'
check none "$P" 'git branch --show-current'
check none "$P" 'git branch -D old-branch'
check none "$P" 'git checkout main'
check none "$P" 'git rebase main'
check none "$P" 'git reset --hard'
check none "$P" 'git rm --cached file'
check none "$P" 'git clean -n'

# --- quoted text and heredocs are data, not commands ---
check ask "$P" 'git commit -m "chore: rm stale files; rm -rf build"'
check none "$P" 'echo "rm -rf /"'
check none "$P" "echo 'sudo rm -rf / ; dnf remove x'"
check none "$P" 'rg "rm -rf" src/'
check none "$P" $'cat > notes.md <<\'EOF\'\nrm -rf /\nsudo dnf remove vim\nEOF'
check none "$P" $'cat <<-EOF > notes.md\n\trm -rf src\n\tEOF\nls'
check deny "$P" $'cat > notes.md <<EOF\nhello\nEOF\nrm -rf src'
check none "$P" 'ls -la # rm -rf src'
check none "$P" 'npm run build > /dev/null 2>&1 && echo ok'

# --- speed: a large heredoc must stay fast ---
big=$(printf 'line %s rm -rf / ; sudo x\n' $(seq 1 2000))
start=$(date +%s)
check none "$P" "cat > big.txt <<'EOF'"$'\n'"$big"$'\n'"EOF"
(($(date +%s) - start <= 5)) || { ((fail++)); echo "FAIL large heredoc took over 5s"; }

echo "guard-bash: $pass passed, $fail failed"
((fail == 0))
