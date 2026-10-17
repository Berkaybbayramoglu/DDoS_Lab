#!/bin/bash
# Creates the lab-only SSH key that lets the server push the replay files to the traffic
# containers and start them (server/13_launch_replay.sh). Run once before building the lab.
# The key is generated locally and is never committed (see .gitignore); it only opens the
# ubuntu account of the lab's own traffic containers on the isolated lab network.
#   usage: make_lab_key.sh [--force]
set -eu
LAB=$(cd "$(dirname "$0")/../lucid-ddos" && pwd)
KEY=$LAB/server/.ssh/id_ed25519
if [ -f "$KEY" ] && [ "${1:-}" != "--force" ]; then
  echo "key exists: $KEY (use --force to replace it)"; exit 0
fi
mkdir -p "$LAB/server/.ssh"
rm -f "$KEY" "$KEY.pub"
ssh-keygen -q -t ed25519 -N "" -C lucid-ddos-lab -f "$KEY"
printf 'Host attacker1 attacker2 client\n    User ubuntu\n    StrictHostKeyChecking no\n    UserKnownHostsFile /dev/null\n    LogLevel ERROR\n' \
  > "$LAB/server/.ssh/config"
for c in attacker1 attacker2 client; do
  mkdir -p "$LAB/$c/.ssh"
  cp "$KEY.pub" "$LAB/$c/.ssh/authorized_keys"
done
echo "-> $KEY (+ authorized_keys for attacker1, attacker2, client)"
