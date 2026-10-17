#!/bin/bash
# Builds the four Labtainer images of lucid-ddos the way Labtainer's buildImage.sh does, so that CI
# can build (and publish) them without a Labtainer installation:
#   <lab>.<container>.student.tar.gz      the container folder for the home directory, with _bin in
#                                         .local/bin and the lab config in .local/config
#   sys_<lab>.<container>.student.tar.gz  the container's _system folder (unpacked at /)
#   home_tar/home.tar, sys_tar/sys.tar    the large-file folders, packed as CheckTars.py does
#                                         (home.tar gzip'ed with owner 1000 and its file list in
#                                         config/<container>-home_tar.list; sys.tar owned by root)
# then the two-stage docker build of buildImage.sh (second stage: chown root:root /var), plus the
# label Labtainer's distrib/relabel.sh adds before publishing: base=<base image>.<its image id>
# (a student's Labtainer refuses a published image without it).
# Archives carry uid/gid 1000, as when Labtainer builds on its VM. Outputs of the lab scripts
# (work/, models/, results/, replay/, __pycache__) are left out.
#   usage: build_labtainer_images.sh [base registry]       (default: labtainers)
#   result: images lucid-ddos.<container>.student
set -eu
LAB=$(cd "$(dirname "$0")/../lucid-ddos" && pwd)
NAME=$(basename "$LAB")
BASE_REGISTRY=${1:-labtainers}
VERSION=${LABTAINER_FRAMEWORK_VERSION:-3}
OWNER="--owner=1000 --group=1000 --numeric-owner"
D="docker --context default"
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# USER / PASSWORD of every container from start.config (Labtainer defaults: ubuntu / user name)
containers=$(awk '$1 == "CONTAINER" {print $2}' "$LAB/config/start.config")
setting() {   # setting <container> <key>
  awk -v c="$1" -v k="$2" '$1 == "CONTAINER" {in_c = ($2 == c)} in_c && $1 == k {print $2; exit}' "$LAB/config/start.config"
}

# pass 1 (CheckTars.py): home_tar / sys_tar archives and the home_tar manifests in the lab config
CONFIG=$WORK/config
cp -pr "$LAB/config" "$CONFIG"; rm -f "$CONFIG"/*-home_tar.list
for c in $containers; do
  ctx=$WORK/$c; mkdir -p "$ctx/home_tar" "$ctx/sys_tar"
  for dir in home_tar sys_tar; do
    src=$LAB/$c/$dir; out=$ctx/$dir/${dir%_tar}.tar
    entries=$( (ls -A -1 "$src" 2>/dev/null || true) | grep -v "^${dir%_tar}.tar$" || true)
    if [ -z "$entries" ]; then
      tar cf "$out" --files-from /dev/null
    elif [ $dir = home_tar ]; then
      (cd "$src" && tar czvf "$out" --owner=:1000 --group=:1000 $entries > "$CONFIG/$c-home_tar.list")
    else
      (cd "$src" && tar czf "$out" --owner=root --group=root $entries)
    fi
  done
done

# pass 2 (buildImage.sh): home and _system archives, then the docker build
for c in $containers; do
  img=$NAME.$c.student
  user=$(setting "$c" USER); user=${user:-ubuntu}
  password=$(setting "$c" PASSWORD); password=${password:-$user}
  ctx=$WORK/$c; home=$WORK/home_$c
  mkdir -p "$home/.local/bin" "$home/.local/result"
  cp -pr "$CONFIG" "$home/.local/"
  if [ -d "$LAB/$c/_bin" ]; then cp -p "$LAB/$c/_bin/"* "$home/.local/bin/"; fi
  chmod a+x "$home/.local/bin/"* 2>/dev/null || true
  (cd "$LAB/$c" && tar cf - --exclude=./_bin --exclude=./_system --exclude=./home_tar --exclude=./sys_tar \
       --exclude='*.tar' --exclude='*.tar.gz' --exclude=./work --exclude=./models --exclude=./results \
       --exclude=./replay --exclude=./data --exclude=__pycache__ .) | tar xf - -C "$home"
  mkdir -p "$LAB/$c/_system"
  (cd "$LAB/$c/_system" && tar $OWNER -czvf "$ctx/sys_$img.tar.gz" . > "$home/.local/sys_manifest.list")
  (cd "$home" && tar $OWNER -czf "$ctx/$img.tar.gz" .)
  cp "$LAB/dockerfiles/Dockerfile.$img" "$ctx/"
  echo "== building $img (user $user, base registry $BASE_REGISTRY)"
  $D build -q --pull --build-arg lab="$img" --build-arg labdir=. --build-arg imagedir=. \
      --build-arg user_name="$user" --build-arg password="$password" --build-arg apt_source=archive.ubuntu.com \
      --build-arg registry="$BASE_REGISTRY" --build-arg version="$VERSION" \
      -f "$ctx/Dockerfile.$img" -t "$img.tmp" "$ctx" >/dev/null
  base=$(awk '$1 == "FROM" {print $2; exit}' "$ctx/Dockerfile.$img"); base=${base/\$registry/$BASE_REGISTRY}
  base_id=$(python3 "$(dirname "$0")/base_image_id.py" "$base")   # config digest, as on Labtainer's VM
  printf 'FROM %s.tmp\nRUN chown root:root /var\nLABEL base=%s.%s\n' "$img" "$base" "$base_id" | $D build -q -t "$img" - >/dev/null
  $D rmi "$img.tmp" >/dev/null
  echo "   -> $img (base $base.$base_id)"
done
