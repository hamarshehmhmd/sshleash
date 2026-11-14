#!/usr/bin/env bash
# Real two-hop demo: laptop -> devbox (agent forwarded) -> gitserver, with two
# unprivileged sshd processes on 127.0.0.1. Writes to ~/.ssh, so it only runs
# on a throwaway CI machine (CI=true). Prints a transcript to stdout.
set -euo pipefail
[ "${CI:-}" = "true" ] || { echo "refusing to run outside CI (it edits ~/.ssh)"; exit 2; }
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
LAB=$(mktemp -d /tmp/lab.XXXX)
mkdir -p ~/.ssh && chmod 700 ~/.ssh
export NO_COLOR=1

eval "$(ssh-agent -s -a "$LAB/agent.sock")" >/dev/null
ssh-keygen -q -t ed25519 -N '' -C 'laptop-key' -f "$LAB/laptop-key"
ssh-keygen -q -t ed25519 -N '' -C 'deploy-bot' -f "$LAB/deploy-bot"
ssh-add -q "$LAB/laptop-key" "$LAB/deploy-bot"
cat "$LAB/laptop-key.pub" "$LAB/deploy-bot.pub" > "$LAB/authorized_keys"
: > ~/.ssh/known_hosts
port=2201
for h in devbox gitserver; do
  ssh-keygen -q -t ed25519 -N '' -f "$LAB/${h}_host"
  cat > "$LAB/${h}.conf" <<CONF
Port $port
ListenAddress 127.0.0.1
HostKey $LAB/${h}_host
PidFile $LAB/${h}.pid
AuthorizedKeysFile $LAB/authorized_keys
UsePAM no
StrictModes no
PasswordAuthentication no
AllowAgentForwarding yes
CONF
  "$SSHD" -f "$LAB/${h}.conf"
  echo "$h $(cut -d' ' -f1,2 "$LAB/${h}_host.pub")" >> ~/.ssh/known_hosts
  cat >> ~/.ssh/config <<CONF
Host $h
  HostName 127.0.0.1
  Port $port
  HostKeyAlias $h
  IdentityFile /nonexistent
CONF
  port=$((port+1))
done
cat >> ~/.ssh/config <<CONF
Host devbox
  ForwardAgent ~/.ssh/sshleash.sock
CONF
mkdir -p ~/.config/sshleash
cat > ~/.config/sshleash/policy.toml <<'POL'
[[rule]]
name = "devbox never sees the deploy key"
key = "deploy-bot"
via = ["devbox"]
action = "deny"

[[rule]]
name = "laptop key: no logins from devbox onwards"
key = "laptop-key"
forwarded = true
host = ["gitserver"]
action = "deny"

[default]
action = "allow"
POL
sshleash run --quiet >/dev/null 2>&1 &
sleep 1
export SSH_AUTH_SOCK=~/.ssh/sshleash.sock

run() { echo "\$ $*"; set +e; bash -c "$*" 2>&1; set -e; echo; }
run "grep -A1 'Host devbox' ~/.ssh/config | tail -2"
run "cat ~/.config/sshleash/policy.toml | grep -E '^(name|key|via|forwarded|host|action)'"
run "ssh devbox 'echo on \$(hostname -s)-as-devbox; ssh-add -l'"
run "ssh devbox 'ssh gitserver echo hello from gitserver'"
run "sshleash log -n 6"
kill %1 || true
