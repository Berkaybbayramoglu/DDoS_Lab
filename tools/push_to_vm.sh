#!/bin/bash
# Copies the lucid-ddos lab of this repository into the Labtainer VM's labs
# directory, replacing the copy there. The VM must accept SSH, e.g. a VirtualBox NAT rule
#   VBoxManage controlvm LabtainerVM24 natpf1 "ssh,tcp,127.0.0.1,2222,,22"
# Then, inside the VM:  cd $LABTAINER_DIR/scripts/labtainer-student && rebuild lucid-ddos
#   usage: push_to_vm.sh [ssh target] [ssh port]
set -eu
TARGET=${1:-student@127.0.0.1}; PORT=${2:-2222}
cd "$(dirname "$0")/.."
tar cf - --exclude=__pycache__ --exclude='*.tar' --exclude='*.tar.gz' \
    --exclude=lucid-ddos/server/work --exclude=lucid-ddos/server/models \
    --exclude=lucid-ddos/server/results --exclude=lucid-ddos/server/replay lucid-ddos |
  ssh -p "$PORT" "$TARGET" 'L=$HOME/labtainer/trunk/labs; rm -rf "$L/lucid-ddos" && tar xf - -C "$L" && echo "-> $L/lucid-ddos"'
