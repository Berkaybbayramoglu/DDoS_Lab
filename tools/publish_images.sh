#!/bin/bash
# Publishes the four Labtainer images (built by build_labtainer_images.sh) to Docker Hub under two
# names each:
#   <user>/lucid-ddos.<container>.student:latest   the name Labtainer pulls (REGISTRY <user> in
#                                                  config/start.config), plus :<version>
#   <user>/ddos_lab:<container>                    all four in one repository, plus :<container>-<version>
# Needs a prior `docker login`.
#   usage: publish_images.sh <docker hub user> [version tag]
set -eu
USER_NS=${1:?usage: publish_images.sh <docker hub user> [version tag]}
VERSION=${2:-}
D="docker --context default"
for c in server attacker1 attacker2 client; do
  img=lucid-ddos.$c.student
  targets="$USER_NS/$img:latest $USER_NS/ddos_lab:$c"
  [ -n "$VERSION" ] && targets="$targets $USER_NS/$img:$VERSION $USER_NS/ddos_lab:$c-$VERSION"
  for t in $targets; do
    $D tag "$img" "$t"
    $D push -q "$t" >/dev/null
    echo "pushed $t"
  done
done
