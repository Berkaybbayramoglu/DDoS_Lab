#!/bin/bash
# Builds the three developer images used by the tools in this folder (plain Docker, no Labtainer):
#   lucid-server    lab scripts, web server and packet capture
#   lucid-attacker  attacker, benign users and replay
#   lucid-ethtool   offload switch used while recording
set -eu
cd "$(dirname "$0")/docker"
for name in lucid-server lucid-attacker lucid-ethtool; do
  docker build -q -t "$name" -f "Dockerfile.$name" . >/dev/null && echo "built $name"
done
