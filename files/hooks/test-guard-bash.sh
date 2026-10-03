#!/usr/bin/env bash
# Table-driven tests for guard-bash.sh. Usage: test-guard-bash.sh [path/to/guard-bash.sh]
# Exits non-zero if any case gets the wrong decision.

hook=${1:-"$(dirname "$0")/guard-bash.sh"}
tmp=$(mktemp -d)
trap 'command rm -rf "$tmp"' EXIT

# Two repos: one on main, one on a feature branch.
for b in main feature; do
  git init -q -b "$b" "$tmp/$b"
  git -C "$tmp/$b" -c user.name=t -c user.email=t@t commit -q --allow-empty -m init
done

pass=0 fail=0
check() { # expected(deny|ask|none) repo command
  local want=$1 repo=$2 cmd=$3 got
  got=$(jq -n --arg c "$cmd" --arg d "$tmp/$repo" '{tool_name:"Bash",tool_input:{command:$c},cwd:$d}' |
    "$hook" | jq -r '.hookSpecificOutput.permissionDecision // empty')
  got=${got:-none}
  if [[ $got == "$want" ]]; then ((pass++)); else ((fail++)); printf 'FAIL [%s] want=%s got=%s: %s\n' "$repo" "$want" "$got" "$cmd"; fi
}

# Destructive file operations
check deny feature 'rm -rf build/'
check deny feature '/bin/rm foo'
check deny feature 'sudo rm -f /etc/foo'
check deny feature 'sudo -u root rm x'
check deny feature 'FOO=bar rm x'
check deny feature 'timeout 30 rm x'
check deny feature "bash -c 'rm -rf x'"
check deny feature "sh -lc \"cd /tmp && rm x\""
check deny feature 'eval rm x'
check deny feature 'ls && rm x'
check deny feature 'echo $(rm x)'
check deny feature 'find . -name "*.o" -delete'
check deny feature 'find . -type f -exec rm {} \;'
check deny feature 'find . | xargs rm'
check deny feature 'dd if=/dev/zero of=/dev/sda'
check deny feature 'rmdir empty'
check deny feature 'shred -u secret'
check deny feature 'git clean -fd'
check deny feature 'git rm file.txt'
# Package removal
check deny feature 'sudo dnf remove vim'
check deny feature 'dnf -y erase vim'
check deny feature 'sudo apt-get purge vim'
check deny feature 'brew uninstall jq'
check deny feature 'pacman -Rns foo'
check deny feature 'rpm -e foo'
check deny feature 'pip uninstall requests'
check deny feature 'python3 -m pip uninstall requests'
check deny feature 'npm uninstall -g typescript'
check deny feature 'flatpak uninstall org.foo'
# Secrets
check deny feature 'cat .env'
check deny feature 'cat ~/.ssh/id_ed25519'
check deny feature 'grep TOKEN config/.env.production'
check deny feature 'cat ~/.aws/credentials'
check deny feature 'git add .env'
check deny feature 'cp ~/.config/gh/hosts.yml /tmp/x'
# Destructive git on main
check deny main 'git push --force'
check deny main 'git push -f origin main'
check deny feature 'git push --force origin main'
check deny feature 'git push origin +main'
check deny feature 'git push origin :main'
check deny feature 'git push origin --delete main'
check deny feature 'git -C . push --force origin main'
check deny feature 'git push --mirror'
check deny feature 'git branch -D main'
check deny feature 'git branch -m main old'
check deny main 'git reset --hard HEAD~1'
check deny main 'git rebase -i HEAD~3'
check deny main 'git commit --amend'
check deny main 'git filter-branch --all'
check deny feature 'gh repo delete foo/bar'

# Git write operations: ask
check ask main 'git commit -m "feat: x"'
check ask feature 'git push'
check ask feature 'git push -u origin feature'
check ask feature 'git push --force origin feature'
check ask feature 'git branch -D old-branch'
check ask feature 'git branch new-thing'
check ask feature 'git checkout -b new-thing'
check ask feature 'git switch -c new-thing'
check ask feature 'git rebase main'
check ask feature 'git commit --amend'
check ask feature 'git reset --hard'
check ask feature 'gh pr create --fill'
check ask feature 'git add -A && git commit -m "x"'

# Allowed: no decision
check none feature 'ls -la'
check none feature 'git status'
check none feature 'git log --oneline -5'
check none feature 'git diff main'
check none feature 'git branch'
check none feature 'git branch -a'
check none feature 'git branch --show-current'
check none feature 'git add src/'
check none feature 'git clean -n'
check none feature 'git rm --cached file'
check none feature 'npm install lodash'
check none feature 'npm uninstall lodash'
check none feature 'dnf list installed'
check none feature 'cat .env.example'
check none feature 'ls ~/.ssh'
check none feature 'rg "rm -rf" src/'
check none feature 'echo "use rm carefully"'
check none feature 'grep -r environment src/'
check none feature 'npm run format'
check none feature 'go test ./...'

echo "guard-bash: $pass passed, $fail failed"
((fail == 0))
