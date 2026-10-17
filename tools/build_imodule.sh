#!/bin/bash
# Builds imodule.tar, the file a student adds to Labtainer with `imodule <url>` (as Labtainer's
# create-imodules.sh does): the git-tracked config/, instr_config/, docs/ and bin/ of the lab, with
# every file's time set to its last commit (Labtainer compares file times when deciding whether
# to rebuild). The container images themselves come from Docker Hub.
#   usage: build_imodule.sh [output]       (default: imodule.tar in the repository root)
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$(realpath -m "${1:-$ROOT/imodule.tar}")
LAB=lucid-ddos
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
cd "$ROOT"
for part in config instr_config docs bin; do
  git ls-files "$LAB/$part" | while read -r f; do
    mkdir -p "$WORK/$(dirname "$f")"
    cp -p "$f" "$WORK/$f"
    touch -d "@$(git log -1 --format=%ct -- "$f")" "$WORK/$f"
  done
done
tar -cz -f "$OUT" -C "$WORK" .
echo "-> $OUT"
tar -tzf "$OUT" | sed 's/^/   /'
